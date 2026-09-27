//! La vue vulnérabilités : les images scannées par Trivy Operator, et le risque de la version
//! Kubernetes elle-même.
//!
//! Sans `needs` dans le rail, comme le `:vuln` du TUI qui s'ouvre toujours : sans Trivy il n'y a
//! pas de scan d'images, mais la ligne Kubernetes — version servie, dernier patch de la mineure,
//! fenêtre de support, feed officiel des CVE — a encore quelque chose à dire.
//!
//! # Rien n'est jugé ici
//!
//! Les lignes et leur ordre, le plancher de sévérité, les comptes, la cible de patch et son ton,
//! le liseré d'une ligne et l'enregistrement de l'analyse viennent de `kdt::vulnerabilities`.
//!
//! # Ce qui ne voyage pas avec la liste
//!
//! Les CVE d'une image. Une vieille image en porte des centaines, et les faire traverser le réseau
//! pour toutes les images à chaque passe coûterait des mégaoctets pour un détail qu'on ouvre une
//! image à la fois. Le détail relit **le seul rapport** de la ligne (`/api/v1/vuln/report`), sous
//! l'identité de la personne, comme le contenu d'un backup Velero.
//!
//! # Le seul cache partagé de kdt-web
//!
//! Le risque de la version Kubernetes ne dépend que de la version et de sources publiques
//! (`dl.k8s.io`, le feed de kubernetes.io) : aucun droit ne s'y prête d'une personne à l'autre, à la
//! différence d'un Secret ou d'un `nodes/proxy`. Le relire pour chaque personne toutes les minutes
//! ferait trois requêtes sortantes par onglet ouvert ; il se garde donc un quart d'heure, par
//! version et par langue. Une réponse dégradée (réseau coupé) ne se garde pas.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::events::LineColor;
use kdt::lang::Strings;
use kdt::vulnerabilities::{
    short_image, vuln_report, vuln_rows, K8sVersionRisk, Sev, VulnComponent, VulnRow,
};
use serde::Deserialize;
use tracing::warn;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

const K8S_RISK_TTL: Duration = Duration::from_secs(15 * 60);

type RiskCache = Mutex<HashMap<(String, &'static str), (Instant, K8sVersionRisk)>>;

fn risk_cache() -> &'static RiskCache {
    static CACHE: OnceLock<RiskCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn k8s_risk(version: &str, st: &'static Strings, lang: &'static str) -> K8sVersionRisk {
    let key = (version.to_string(), lang);
    if let Some((at, risk)) = risk_cache().lock().expect("vuln cache poisoned").get(&key) {
        if at.elapsed() < K8S_RISK_TTL {
            return risk.clone();
        }
    }
    let risk = kdt::vulnerabilities::k8s_version_risk(version, st).await;
    if risk.note.is_none() {
        risk_cache()
            .lock()
            .expect("vuln cache poisoned")
            .insert(key, (Instant::now(), risk.clone()));
    }
    risk
}

#[derive(Deserialize)]
pub struct VulnQuery {
    #[serde(default)]
    ns: String,
    /// Le plancher de sévérité : `unknown` (tout), `high` ou `critical` — le `f` du TUI.
    #[serde(default)]
    min: Sev,
    #[serde(default)]
    lang: String,
}

/// La ligne Kubernetes puis les images de la portée au-dessus du plancher.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VulnQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let lang = if query.lang.eq_ignore_ascii_case("en") { "en" } else { "fr" };
    let ns = Some(query.ns.trim()).filter(|s| !s.is_empty());

    // `/version` est couvert par `system:discovery` : il répond à toute personne connectée.
    let version = client.apiserver_version().await.ok().map(|v| v.git_version);
    let mut inv = kdt::vulnerabilities::vulnerabilities_inventory(&client, None, st).await;
    if let Some(v) = version.as_deref().filter(|v| !v.is_empty()) {
        inv.k8s = Some(k8s_risk(v, st, lang).await);
    }

    axum::Json(payload(inv, ns, query.min, st)).into_response()
}

/// La réponse de la vue, hors HTTP : la sonde de vérification la produit par le même chemin.
fn payload(
    inv: kdt::vulnerabilities::VulnState,
    ns: Option<&str>,
    min: Sev,
    st: &'static Strings,
) -> serde_json::Value {
    let (crit, high, med, low) = inv.counts(ns);
    let scanned = inv.scanned(ns);
    let rows: Vec<serde_json::Value> =
        vuln_rows(&inv, ns, min).iter().map(|row| row_json(row, st)).collect();
    let error = if inv.available { inv.error } else { None };

    serde_json::json!({
        "rows": rows,
        // Trivy absent : la vue n'a que la ligne Kubernetes, et la bande le dit.
        "available": inv.available,
        "error": error,
        "counts": {
            "scanned": scanned,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
        },
    })
}

fn row_json(row: &VulnRow, st: &'static Strings) -> serde_json::Value {
    match row {
        VulnRow::K8s(k) => {
            let (crit, high, med, low) = k.counts();
            serde_json::json!({
                "row": "k8s",
                "uid": format!("vuln|k8s|{}", k.server_version),
                "tone": tone_json(k.tone()),
                "component": k.component_label(),
                "version": k.server_version,
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "target": k.target_label(),
                "target_tone": tone_json(k.target_tone()),
                "target_text": k.target_text(st),
                "eol": k.eol,
                "eol_text": st.vuln_eol.trim(),
                "note": k.note,
                // Une soixantaine au plus, une seule ligne : elles voyagent avec la liste.
                "cves": k.cves,
                "record": record_json(row, st),
            })
        }
        VulnRow::Image(c) => {
            // L'enregistrement de la liste ne porte pas les CVE : le détail en rend un complet,
            // celui que l'analyse reçoit. Même identité, donc le panneau ne le voit pas changer.
            let light = VulnRow::Image(VulnComponent { cves: Vec::new(), ..c.clone() });
            serde_json::json!({
                "row": "image",
                "uid": format!("vuln|{}|{}", c.namespace, c.image),
                "tone": tone_json(c.max_sev.tone()),
                "report_kind": c.report_kind,
                "report": c.report,
                "namespace": c.namespace,
                "workload": c.workload,
                "component": short_image(&c.image),
                "image": c.image,
                "version": c.version,
                "max_sev": c.max_sev,
                "max_label": c.max_sev.label(),
                "max_score": c.max_score,
                "critical": c.critical,
                "high": c.high,
                "medium": c.medium,
                "low": c.low,
                "unknown": c.unknown,
                "total": c.total(),
                "fixable": c.fixable,
                "fixable_text": kdt::lang::fill(st.vuln_fixable, &[("n", &c.fixable.to_string())]),
                "target": c.target_label(st),
                "target_tone": tone_json(if c.fixable > 0 { LineColor::Ok } else { LineColor::Dim }),
                "age": c.age,
                "record": record_json(&light, st),
            })
        }
    }
}

#[derive(Deserialize)]
pub struct ReportQuery {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    lang: String,
}

/// Le détail d'une image : son rapport relu, CVE comprises, et l'enregistrement complet.
pub async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReportQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if query.kind.is_empty() || query.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "kind et name sont requis" })),
        )
            .into_response();
    }
    let st = lang_of(&query.lang);
    match vuln_report(&client, &query.kind, &query.namespace, &query.name).await {
        Ok(c) => {
            let record = record_json(&VulnRow::Image(c.clone()), st);
            axum::Json(serde_json::json!({
                "cves": c.cves,
                "record": record,
                "no_fix": st.vuln_no_fix,
            }))
            .into_response()
        }
        Err(e) => {
            warn!(erreur = %e, "rapport Trivy illisible");
            (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({ "error": e }))).into_response()
        }
    }
}

fn record_json(row: &VulnRow, st: &'static Strings) -> serde_json::Value {
    let record = row.record(st);
    let tone = record.tone();
    let mut value = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("tone".to_string(), serde_json::to_value(tone).unwrap_or(serde_json::Value::Null));
    }
    value
}

fn tone_json(tone: LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}
