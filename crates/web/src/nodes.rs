//! La vue Nodes : les machines du cluster, ce qu'elles portent, et les trois gestes qui les
//! sortent du jeu.
//!
//! Trois questions, comme `:nodes` dans le TUI :
//!
//! - **L'inventaire** — qui est `Ready`, qui est cordonné, quelle condition anormale traîne. Une
//!   ligne rouge y est soit un node malade, soit un node qu'on a délibérément mis de côté : les
//!   deux se ressemblent parce que dans les deux cas ce node ne prend plus ce qu'on croit.
//! - **L'usage** — le détail par container d'un node : ce qui est réservé, ce qui est permis, ce
//!   qui est consommé, et les constats de dimensionnement qui vont avec.
//! - **Le drain** — ce qui partirait, ce qui resterait, et ce qui va refuser.
//!
//! # Rien n'est jugé ici
//!
//! Le ton d'une ligne, la liste des alertes, les constats d'un container, les garde-fous d'un
//! drain : tout vient de `kdt::events` et de `kdt::nodeops`, qui sont ce que le TUI affiche. Ce
//! module joint la lecture et met en forme.
//!
//! # Pas de portée
//!
//! Un node n'a pas de namespace. La barre de portée se désactive et le dit, comme pour les autres
//! vues cluster-scoped.
//!
//! # Les trois écritures, et ce qu'elles ne croient pas
//!
//! `cordon`, `uncordon` et `drain` écrivent sous l'identité de la personne connectée, comme les
//! lectures. Le navigateur nomme le node ; il ne nomme **rien d'autre** :
//!
//! - l'état courant est **relu côté serveur** avant un cordon, pour qu'un node déjà dans l'état
//!   demandé soit répondu sans écriture — et non sur la foi de ce que la page affichait ;
//! - les garde-fous du drain sont **rejoués juste avant d'évincer**, et la confirmation forte est
//!   revérifiée là : un garde-fou qui ne vit que dans la page se contourne en postant la requête à
//!   la main, et entre le préflight et l'écriture l'objet a pu bouger.

use std::convert::Infallible;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use kdt::events::{
    format_cpu_milli, format_memory_bytes, node_usage, nodes_inventory, sort_usage_rows,
    usage_pct, usage_tone, usage_totals, NodeSummary, NodeUsageSort, PodUsageRow, UsageBucket,
};
use kdt::lang::Strings;
use kdt::nodeops::{self, Findings, Reason};
use kube::Client;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct LangQuery {
    #[serde(default)]
    lang: String,
}

/// L'inventaire des nodes du cluster.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let nodes = match nodes_inventory(&client).await {
        Ok(nodes) => nodes,
        // Les nodes sont la matière même de la vue : sans eux il n'y a rien à dire, et une réponse
        // vide se lirait comme un cluster sans machine plutôt que comme un refus.
        Err(e) => {
            warn!(erreur = %e, "lecture des nodes refusée");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };

    axum::Json(serde_json::json!({
        "nodes": nodes.iter().map(|n| node_json(n, st)).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Un node, ses verdicts, et l'enregistrement qu'il représente.
fn node_json(n: &NodeSummary, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(n).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), n.uid().into());
        // La liste des alertes est une règle : c'est elle qui décide que la mise hors service passe
        // en tête, et c'est elle qui décide qu'une ligne est rouge.
        object.insert("alerts".to_string(), n.alerts().into());
        object.insert("tone".to_string(), tone_json(n.tone()));
        object.insert("ready_tone".to_string(), tone_json(n.ready_tone()));
        object.insert("record".to_string(), record_json(n.record(st)));
    }
    value
}

#[derive(Deserialize)]
pub struct UsageQuery {
    node: String,
    /// `mem-req` (défaut), `cpu-req` ou `alpha`. Le tri est une règle de kdt — les containers
    /// système restent en dernier dans les trois — donc il se fait ici et non dans le navigateur.
    #[serde(default)]
    sort: String,
    #[serde(default)]
    lang: String,
}

/// L'usage par container d'un node : ce que `u` ouvre dans le TUI.
pub async fn usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let node = query.node.trim();
    if node.is_empty() {
        return bad_request("node manquant");
    }

    let mut usage = match node_usage(&client, node, st).await {
        Ok(usage) => usage,
        Err(e) => {
            warn!(node = %node, erreur = %e, "lecture de l'usage du node refusée");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };
    sort_usage_rows(&mut usage.rows, NodeUsageSort::parse(&query.sort));

    let totals = usage_totals(&usage.rows);
    let alloc = (usage.alloc_cpu_milli, usage.alloc_mem_bytes);

    axum::Json(serde_json::json!({
        "node": node,
        "rows": usage.rows.iter().map(usage_row_json).collect::<Vec<_>>(),
        // Faux sans metrics-server : toute la colonne « consommé » est alors `null`, et la vue le
        // dit au lieu d'afficher des zéros qui se liraient comme des containers au repos.
        "metrics_available": usage.metrics_available,
        "alloc": {
            "cpu": alloc.0,
            "mem": alloc.1,
            "cpu_text": format_cpu_milli(alloc.0),
            "mem_text": format_memory_bytes(alloc.1),
        },
        "totals": {
            "user": bucket_json(&totals.user, alloc),
            "system": bucket_json(&totals.system, alloc),
            "total": bucket_json(&totals.total, alloc),
            "cpu_waste_text": format_cpu_milli(totals.cpu_waste),
            "mem_waste_text": format_memory_bytes(totals.mem_waste),
            "cpu_waste_pct": totals.cpu_waste_pct,
            "mem_waste_pct": totals.mem_waste_pct,
        },
    }))
    .into_response()
}

/// Une ligne de container : les six quantités écrites comme kdt les écrit, et ses constats.
fn usage_row_json(r: &PodUsageRow) -> serde_json::Value {
    let mut value = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), r.uid().into());
        for (field, v, format) in [
            ("cpu_req_text", r.cpu_req, format_cpu_milli as fn(i64) -> String),
            ("cpu_lim_text", r.cpu_lim, format_cpu_milli),
            ("cpu_use_text", r.cpu_use, format_cpu_milli),
            ("mem_req_text", r.mem_req, format_memory_bytes),
            ("mem_lim_text", r.mem_lim, format_memory_bytes),
            ("mem_use_text", r.mem_use, format_memory_bytes),
        ] {
            object.insert(
                field.to_string(),
                v.map(format).map(Into::into).unwrap_or(serde_json::Value::Null),
            );
        }
        // Les constats de dimensionnement, et leur ton. L'étiquette voyage avec : elle est le mot
        // de la colonne dans les deux interfaces, et le navigateur ne la reconstitue pas.
        object.insert(
            "issues".to_string(),
            r.issues()
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "kind": i,
                        "tag": i.tag(),
                        "severe": i.severe(),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
        object.insert("issues_tone".to_string(), tone_json(r.issues_tone()));
        object.insert("cpu_use_tone".to_string(), tone_json(r.cpu_use_tone()));
        object.insert("mem_use_tone".to_string(), tone_json(r.mem_use_tone()));
        object.insert("restarts_tone".to_string(), tone_json(r.restarts_tone()));
    }
    value
}

/// Un cumul, avec ce qu'il pèse face à l'allocatable du node.
fn bucket_json(b: &UsageBucket, alloc: (i64, i64)) -> serde_json::Value {
    let ratio = |v: i64, whole: i64, format: fn(i64) -> String| {
        let pct = usage_pct(v, whole).unwrap_or(0);
        serde_json::json!({
            "text": format(v),
            "pct": pct,
            "tone": tone_json(usage_tone(pct)),
        })
    };
    serde_json::json!({
        "count": b.count,
        "cpu_req": ratio(b.cpu_req, alloc.0, format_cpu_milli),
        "cpu_lim": ratio(b.cpu_lim, alloc.0, format_cpu_milli),
        "cpu_use": ratio(b.cpu_use, alloc.0, format_cpu_milli),
        "mem_req": ratio(b.mem_req, alloc.1, format_memory_bytes),
        "mem_lim": ratio(b.mem_lim, alloc.1, format_memory_bytes),
        "mem_use": ratio(b.mem_use, alloc.1, format_memory_bytes),
    })
}

#[derive(Deserialize)]
pub struct DrainQuery {
    node: String,
    #[serde(default)]
    lang: String,
}

/// Les garde-fous du drain, sans rien évincer : ce que le panneau du TUI montre avant de demander.
pub async fn drain_preflight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DrainQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let node = query.node.trim();
    if node.is_empty() {
        return bad_request("node manquant");
    }

    match nodeops::preflight_once(&client, node).await {
        Ok(findings) => axum::Json(findings_json(&findings, st, None)).into_response(),
        // Une vérification qui n'a pas conclu n'est pas un feu vert : elle se dit, et elle fait
        // passer la confirmation en mode strict — c'est ce que fait `needs_strict_confirm` dans le
        // TUI, où l'erreur du préflight compte comme un constat grave.
        Err(e) => {
            warn!(node = %node, erreur = %e, "préflight de drain en échec");
            axum::Json(findings_json(&Findings::default(), st, Some(&e))).into_response()
        }
    }
}

fn findings_json(f: &Findings, st: &'static Strings, error: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "reasons": f
            .reasons
            .iter()
            .map(|r| reason_json(r, st))
            .collect::<Vec<_>>(),
        "candidates": f.candidates,
        "to_evict": f.to_evict(),
        "skipped": f.skipped(),
        "strict": error.is_some() || f.needs_strict_confirm(),
        "error": error,
        // Les deux phrases du panneau, rédigées par kdt : ce qui part, et ce qui reste.
        "plan": st.plural(f.to_evict(), st.drain_plan_one, st.drain_plan_many),
        "skipped_label": match f.skipped() {
            0 => String::new(),
            n => st.plural(n, st.drain_plan_skipped_one, st.drain_plan_skipped_many),
        },
        "no_finding": st.drain_no_finding,
    })
}

/// Un constat, avec sa phrase et son niveau. La phrase vient de `kdt` : le TUI et le navigateur
/// disent la même chose du même node.
fn reason_json(r: &Reason, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("text".to_string(), r.text(st).into());
        object.insert(
            "level".to_string(),
            serde_json::to_value(r.level()).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

#[derive(Deserialize)]
pub struct CordonBody {
    node: String,
    /// Vrai pour cordonner, faux pour rendre le node au scheduler.
    unschedulable: bool,
    #[serde(default)]
    lang: String,
}

/// Cordon / uncordon : un champ, réversible, et aucune confirmation — comme dans le TUI.
pub async fn cordon(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CordonBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    let node = body.node.trim().to_string();
    if node.is_empty() {
        return bad_request("node manquant");
    }

    // L'état courant se relit ici et non dans la page : un node déjà cordonné est répondu sans
    // écriture, et c'est le cluster qui le dit — pas la liste que le navigateur avait sous les yeux.
    match current_unschedulable(&client, &node).await {
        Ok(current) if current == body.unschedulable => {
            let already = if body.unschedulable {
                st.node_already_cordoned
            } else {
                st.node_already_schedulable
            };
            return axum::Json(serde_json::json!({ "message": already.replace("{d}", &node) }))
                .into_response();
        }
        Ok(_) => {}
        // Le node n'est pas lisible : on ne devine pas son état, et on n'écrit pas dessus.
        Err(e) => {
            warn!(node = %node, erreur = %e, "lecture du node avant cordon refusée");
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    }

    info!(node = %node, unschedulable = body.unschedulable, "cordon demandé");
    match nodeops::set_cordon(&client, &node, body.unschedulable).await {
        Ok(()) => {
            let ok = if body.unschedulable { st.node_cordon_ok } else { st.node_uncordon_ok };
            axum::Json(serde_json::json!({ "message": ok.replace("{d}", &node) })).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": st.node_cordon_failed.replace("{d}", &node).replace("{e}", &e),
            })),
        )
            .into_response(),
    }
}

async fn current_unschedulable(client: &Client, node: &str) -> Result<bool, String> {
    let api: kube::Api<k8s_openapi::api::core::v1::Node> = kube::Api::all(client.clone());
    let n = api.get(node).await.map_err(kdt::edit::api_error_text)?;
    Ok(n.spec.and_then(|s| s.unschedulable).unwrap_or(false))
}

#[derive(Deserialize)]
pub struct DrainBody {
    node: String,
    /// Le nom retapé, quand les garde-fous exigent la confirmation forte.
    #[serde(default)]
    confirm: String,
    #[serde(default)]
    lang: String,
}

/// Le drain, en flux.
///
/// Un drain dure : chaque pod qu'un budget retient est réessayé vingt-quatre fois à cinq secondes
/// d'intervalle. Rendre une seule réponse à la fin laisserait le navigateur devant deux minutes de
/// silence sans savoir si quelque chose se passe — d'où le SSE, qui porte exactement ce que le
/// panneau du TUI affiche pendant qu'il tourne : évincés, retenus, en échec.
pub async fn drain(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<DrainBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    let node = body.node.trim().to_string();
    if node.is_empty() {
        return bad_request("node manquant");
    }

    // Les garde-fous se rejouent **ici**, juste avant d'écrire, et pas seulement à l'ouverture du
    // panneau : entre les deux requêtes le node a pu se vider, se remplir, ou perdre le budget qui
    // le protégeait. Un préflight en échec vaut constat grave, comme dans le TUI.
    let strict = match nodeops::preflight_once(&client, &node).await {
        Ok(findings) => findings.needs_strict_confirm(),
        Err(e) => {
            warn!(node = %node, erreur = %e, "préflight rejoué avant drain en échec");
            true
        }
    };
    // La confirmation forte est revérifiée côté serveur : celle de la page ne protège que la page.
    if strict && body.confirm.trim() != node {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": st.drain_strict_mismatch.replace("{name}", &node),
            })),
        )
            .into_response();
    }

    info!(node = %node, strict, "drain demandé");

    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    tokio::spawn(async move {
        let key = format!("drain|{node}");
        let shared = nodeops::new_node_op_state();
        {
            let mut s = shared.lock().expect("node op state poisoned");
            s.key = key.clone();
            s.running = true;
        }

        let worker = tokio::spawn({
            let client = client.clone();
            let node = node.clone();
            let key = key.clone();
            let shared = shared.clone();
            async move { nodeops::run_drain(client, node, key, shared).await }
        });

        // Le TUI redessine à chaque tick ; ici on pousse au navigateur ce qui a changé, au même
        // rythme. La progression vit dans l'état partagé de kdt : c'est le même compteur.
        let mut last = String::new();
        loop {
            let (snapshot, finished) = {
                let s = shared.lock().expect("node op state poisoned");
                (
                    serde_json::json!({
                        "evicted": s.evicted,
                        "waiting": s.waiting,
                        "failed": s
                            .failed
                            .iter()
                            .map(|(pod, error)| serde_json::json!({ "pod": pod, "error": error }))
                            .collect::<Vec<_>>(),
                        "to_evict": s.to_evict(),
                        "running": s.running,
                    }),
                    s.done.clone(),
                )
            };
            let text = snapshot.to_string();
            if text != last {
                last = text;
                if tx.send(Ok(sse("progress", snapshot))).await.is_err() {
                    // Navigateur parti. L'éviction déjà envoyée est à l'API, mais rien de neuf ne
                    // part d'ici : le drain lui-même continue, il est à l'apiserver maintenant.
                    break;
                }
            }
            if let Some(done) = finished {
                let payload = match done {
                    Ok(()) => serde_json::json!({ "ok": true, "message": st.drain_ok }),
                    Err(e) => serde_json::json!({
                        "ok": false,
                        "message": st.drain_failed.replace("{e}", &e),
                    }),
                };
                let _ = tx.send(Ok(sse("done", payload))).await;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let _ = worker.await;
    });

    Sse::new(ReceiverStream::new(rx))
        // Une éviction que le budget retient ne dit rien pendant cinq secondes : sans battement, un
        // proxy intermédiaire refermerait la connexion avant le premier pod.
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn sse(name: &str, payload: serde_json::Value) -> Event {
    Event::default().event(name).data(payload.to_string())
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// L'enregistrement que la ligne représente, ton compris : c'est lui qui donne à la vue `y`, `e`,
/// `h`, `Ctrl-D`, l'onglet Related et l'analyse IA.
fn record_json(record: kdt::events::EventRecord) -> serde_json::Value {
    let tone = record.tone();
    let mut value = serde_json::to_value(&record).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "tone".to_string(),
            serde_json::to_value(tone).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(ready: &str, schedulable: bool, abnormal: &[&str]) -> NodeSummary {
        NodeSummary {
            name: "aks-pool-000003".into(),
            ready: ready.into(),
            roles: "agent".into(),
            age: "42d".into(),
            version: "v1.31.2".into(),
            schedulable,
            abnormal: abnormal.iter().map(|s| s.to_string()).collect(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn un_node_sain_porte_ce_que_le_navigateur_lit() {
        let v = node_json(&node("True", true, &[]), lang_of("fr"));
        assert_eq!(v["uid"], "node-aks-pool-000003");
        assert_eq!(v["ready"], "True");
        assert_eq!(v["tone"], "ok");
        assert_eq!(v["ready_tone"], "ok");
        assert_eq!(v["alerts"].as_array().unwrap().len(), 0);
        assert_eq!(v["record"]["kind"], "Node");
        assert_eq!(v["record"]["tone"], "ok");
    }

    // Un cordon est un geste, pas un symptôme : il passe en tête des alertes, et il suffit à
    // rougir la ligne — ce node ne prend plus ce qu'on croit qu'il prend.
    #[test]
    fn un_node_cordonne_nomme_son_cordon_en_premier() {
        let v = node_json(&node("True", false, &["MemoryPressure"]), lang_of("fr"));
        assert_eq!(v["alerts"][0], "Cordoned");
        assert_eq!(v["alerts"][1], "MemoryPressure");
        assert_eq!(v["tone"], "err");
        // La condition `Ready` reste vraie : les deux tons ne disent pas la même chose.
        assert_eq!(v["ready_tone"], "ok");
        assert_eq!(v["record"]["severity"], "warning");
    }

    #[test]
    fn un_node_notready_est_rouge_des_deux_cotes() {
        let v = node_json(&node("False", true, &[]), lang_of("fr"));
        assert_eq!(v["tone"], "err");
        assert_eq!(v["ready_tone"], "err");
    }

    fn row(cpu_req: Option<i64>, cpu_use: Option<i64>, mem_lim: Option<i64>) -> PodUsageRow {
        PodUsageRow {
            namespace: "prod".into(),
            pod: "api-7f".into(),
            container: "api".into(),
            cpu_req,
            cpu_lim: Some(2000),
            cpu_use,
            mem_req: Some(1_000_000_000),
            mem_lim,
            mem_use: Some(500_000_000),
            ready: true,
            restarts: 0,
            is_system: false,
            ..Default::default()
        }
    }

    #[test]
    fn une_ligne_dusage_porte_ses_quantites_et_ses_constats() {
        let v = usage_row_json(&row(Some(1000), Some(100), Some(2_000_000_000)));
        assert_eq!(v["uid"], "usage|prod|api-7f|api");
        assert_eq!(v["cpu_req_text"], "1");
        assert_eq!(v["cpu_use_text"], "100m");
        // 100m consommés sur 1 réservé : dix fois trop, et le tag est celui de la colonne du TUI.
        assert_eq!(v["issues"][0]["kind"], "cpu-oversized");
        assert_eq!(v["issues"][0]["tag"], "cpuOver");
        assert_eq!(v["issues"][0]["severe"], false);
        assert_eq!(v["issues_tone"], "warn");

        // Le palier au-dessus n'est pas un second constat par-dessus le premier : c'est le même
        // en plus grave, et un seul des deux sort.
        let v = usage_row_json(&row(Some(1000), Some(40), Some(2_000_000_000)));
        assert_eq!(v["issues"].as_array().unwrap().len(), 1);
        assert_eq!(v["issues"][0]["tag"], "cpuOver!!");
    }

    // Le cas qui motive tout le `Option` : sans mesure, la consommation n'est pas nulle, elle est
    // inconnue — et un zéro se lirait comme un container au repos.
    #[test]
    fn sans_mesure_la_consommation_est_nulle_et_ne_juge_rien() {
        let v = usage_row_json(&row(Some(1000), None, Some(2_000_000_000)));
        assert!(v["cpu_use_text"].is_null());
        assert_eq!(v["cpu_use_tone"], "dim");
        assert_eq!(v["issues"].as_array().unwrap().len(), 0);
        assert_eq!(v["issues_tone"], "dim");
    }

    // Une limite mémoire absente est ce qui coûte : c'est une ligne rouge, pas un gâchis.
    #[test]
    fn une_limite_memoire_absente_rougit_la_ligne() {
        let v = usage_row_json(&row(Some(1000), Some(900), None));
        let tags: Vec<&str> =
            v["issues"].as_array().unwrap().iter().map(|i| i["tag"].as_str().unwrap()).collect();
        assert!(tags.contains(&"noMemLim"));
        assert_eq!(v["issues_tone"], "err");
    }

    // Un préflight qui n'a pas conclu ne rend pas une liste vide rassurante : il exige la
    // confirmation forte, comme `needs_strict_confirm` dans le TUI.
    #[test]
    fn un_preflight_en_echec_exige_le_nom_retape() {
        let v = findings_json(&Findings::default(), lang_of("fr"), Some("node introuvable"));
        assert_eq!(v["strict"], true);
        assert_eq!(v["error"], "node introuvable");
        assert_eq!(v["to_evict"], 0);
    }

    #[test]
    fn un_constat_grave_exige_le_nom_retape_et_porte_sa_phrase() {
        let findings = Findings {
            reasons: vec![Reason::Unmanaged { pods: vec!["prod/debug".into()] }],
            candidates: Vec::new(),
        };
        let v = findings_json(&findings, lang_of("fr"), None);
        assert_eq!(v["strict"], true);
        assert_eq!(v["reasons"][0]["kind"], "unmanaged");
        assert_eq!(v["reasons"][0]["level"], "danger");
        assert!(v["reasons"][0]["text"].as_str().unwrap().contains("prod/debug"));
    }

    // Un constat qui ne fait qu'avertir laisse la confirmation simple : c'est le partage de kdt,
    // où aucun constat ne bloque et où seul le niveau décide de ce que la confirmation coûte.
    #[test]
    fn un_constat_dinformation_laisse_la_confirmation_simple() {
        let findings = Findings {
            reasons: vec![Reason::DaemonSetPods { count: 6 }],
            candidates: vec![
                nodeops::Candidate {
                    namespace: "prod".into(),
                    name: "api-7f".into(),
                    skip: None,
                },
                nodeops::Candidate {
                    namespace: "kube-system".into(),
                    name: "csi-node".into(),
                    skip: Some(nodeops::Skip::DaemonSet),
                },
            ],
        };
        let v = findings_json(&findings, lang_of("fr"), None);
        assert_eq!(v["strict"], false);
        assert_eq!(v["to_evict"], 1);
        assert_eq!(v["skipped"], 1);
        assert_eq!(v["candidates"][1]["skip"], "daemon-set");
        assert!(!v["skipped_label"].as_str().unwrap().is_empty());
    }

    // Les cumuls sont ce que le bloc de diagnostic affiche : la séparation user/système d'abord,
    // parce qu'un node à 90 % de DaemonSets ne se lit pas comme un node à 90 % d'applicatif.
    #[test]
    fn les_cumuls_separent_lapplicatif_du_systeme() {
        let rows = vec![
            row(Some(1000), Some(800), Some(2_000_000_000)),
            PodUsageRow { is_system: true, ..row(Some(3000), Some(200), Some(1_000_000_000)) },
        ];
        let totals = usage_totals(&rows);
        let v = bucket_json(&totals.user, (4000, 8_000_000_000));
        assert_eq!(v["count"], 1);
        assert_eq!(v["cpu_req"]["text"], "1");
        assert_eq!(v["cpu_req"]["pct"], 25);
        assert_eq!(v["cpu_req"]["tone"], "ok");
        let v = bucket_json(&totals.total, (4000, 8_000_000_000));
        assert_eq!(v["cpu_req"]["pct"], 100);
        assert_eq!(v["cpu_req"]["tone"], "err");
        // 4000 réservés pour 1000 consommés : les trois quarts dorment.
        assert_eq!(totals.cpu_waste_pct, 75);
    }
}
