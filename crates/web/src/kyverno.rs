//! La vue Kyverno : les policies, ce qu'elles appliquent vraiment, et ce qu'elles rejettent.
//!
//! Ce que cette vue apporte n'est pas la liste des ClusterPolicies — `kubectl get cpol` la donne —
//! mais la **jointure** : une policy, ses règles (y compris celles que Kyverno a dérivées
//! lui-même), et les ressources qui échouent dessus. Un `PolicyReport` ne nomme la policy et la
//! règle que par des chaînes ; refaire ce rapprochement à la main coûte une après-midi.
//!
//! # Ce qui est calculé ici, et ce qui ne l'est pas
//!
//! Rien de ce qui juge le cluster. L'arbre, la lisibilité d'une policy, le ton d'une posture, le
//! repli par défaut, les enregistrements synthétiques et le verdict de santé viennent tous de
//! `kdt::kyverno` — le même code que le TUI. Ce module joint deux lectures (l'inventaire Kyverno et
//! les Events d'admission) et rend le résultat.
//!
//! # Pourquoi les Events sont relus ici
//!
//! **Un refus d'admission n'apparaît dans aucun rapport.** La ressource a été refusée, donc elle
//! n'existe pas, donc rien ne la décrit : la seule trace est un Event dont le
//! `reportingComponent` est `kyverno-admission`. Le TUI les trouve dans le tampon qu'il tient déjà ;
//! ici il faut les lire, et c'est la seule raison de cette seconde requête. Une lecture refusée
//! laisse la section **muette** plutôt que d'affirmer qu'il n'y a eu aucun refus.

use std::collections::HashMap;
use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use k8s_openapi::api::core::v1::Event as K8sEvent;
use kdt::events::EventRecord;
use kdt::kyverno::{
    build_ky_rows, is_admission_denial, ky_default_folded, parse_denial_message, record_for_row,
    KyFilter, KyPolicy, KyRow, KyViolation, KyvernoState,
};
use kube::api::ListParams;
use kube::Api;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

/// Combien de refus d'admission on garde par policy.
///
/// Le TUI en montre six dans son panneau ; la page en montre autant, et pour la même raison : ce
/// qu'on cherche est le dernier refus, pas l'historique complet — celui-ci est dans les évènements.
const DENIALS_PER_POLICY: usize = 6;

#[derive(Deserialize)]
pub struct KyvernoQuery {
    /// L'axe de lecture : par policy, ou par ressource. C'est le `t` du TUI.
    ///
    /// Il est au serveur parce que la jointure change de sens : par ressource, l'arbre part des
    /// namespaces et regroupe les constats, ce que le navigateur ne saurait refaire sans les
    /// arêtes que seul kdt a.
    #[serde(default)]
    axis: String,
    /// Le filtre des policies. Il garde toujours l'arbre valide : une policy écartée emporte ses
    /// règles et ses constats, ce qui n'a de sens qu'ici.
    #[serde(default)]
    filter: KyFilter,
    #[serde(default)]
    lang: String,
}

/// L'inventaire Kyverno du cluster : l'arbre, la santé, la file des requests.
///
/// Pas de portée : les policies sont cluster-scoped, et l'axe par ressource groupe **par**
/// namespace — le filtrer par namespace reviendrait à ne garder qu'un de ses regroupements, ce que
/// le champ de recherche fait déjà mieux.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<KyvernoQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let by_resource = query.axis == "resource";

    let shared = kdt::kyverno::new_kyverno_state();
    kdt::kyverno::fetch_kyverno(client.clone(), shared.clone()).await;
    let inventory: KyvernoState = shared.lock().expect("kyverno poisoned").clone();

    let policies: Vec<KyPolicy> = inventory
        .policies
        .iter()
        .filter(|p| query.filter.matches(p))
        .cloned()
        .collect();
    let kept: HashSet<String> = policies.iter().map(|p| p.uid()).collect();
    // Une violation ne se lit que sous sa policy : écarter la policy écarte ses violations. Sauf
    // dans l'axe par ressource, où un constat orphelin — sa policy supprimée, son rapport pas
    // encore ramassé — reste ce qu'il faut voir.
    let violations: Vec<KyViolation> = inventory
        .violations
        .iter()
        .filter(|v| kept.contains(&v.policy_uid) || v.policy_uid.is_empty())
        .cloned()
        .collect();

    // Déplié, comme l'arbre Flux et la chaîne cert-manager : le pliage est un état de la personne
    // qui regarde. Chaque ligne porte en revanche le pli que kdt poserait, pour que le navigateur
    // n'ait pas à redire quelle policy mérite d'être ouverte.
    let rows_model = build_ky_rows(&policies, &violations, by_resource, &HashSet::new());
    let (denials, denials_error) = admission_denials(&client, &policies).await;

    let rows: Vec<serde_json::Value> = rows_model
        .iter()
        .map(|row| row_json(row, &policies, &violations, st))
        .collect();

    let (total, enforce, not_ready, fail, warn_count, error) = inventory.counts();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "policies": total,
            "enforce": enforce,
            "not_ready": not_ready,
            "fail": fail,
            "warn": warn_count,
            "error": error,
            "violations": inventory.violations.len(),
        },
        "health": health_json(&inventory),
        "backlog": backlog_json(&inventory),
        // Les refus d'admission, par nom de policy. Ils n'existent nulle part ailleurs.
        "denials": denials,
        "denials_error": denials_error,
        "installed": inventory.installed,
        // Absent avant Kyverno 1.14 : ce n'est pas une panne, et le dire évite de chercher des
        // ValidatingPolicy qui n'existeront jamais sur ce cluster.
        "cel_installed": inventory.cel_installed,
        "error": inventory.error,
    }))
    .into_response()
}

/// Une ligne de l'arbre : ce qu'elle désigne, sa place, et ce que kdt en dit.
fn row_json(
    row: &KyRow,
    policies: &[KyPolicy],
    violations: &[KyViolation],
    st: &'static kdt::lang::Strings,
) -> serde_json::Value {
    let record: EventRecord = record_for_row(row, policies, violations, st);
    let mut value = match row {
        KyRow::Policy { idx, .. } => {
            let p = &policies[*idx];
            let mut v = serde_json::to_value(p).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "policy".into());
                o.insert("kind_short".into(), p.kind.short().into());
                o.insert("action_label".into(), p.action.label().into());
                o.insert("action_tone".into(), tone_json(p.action.tone()));
                o.insert("ready_label".into(), p.ready.label().into());
                o.insert("ready_glyph".into(), p.ready.glyph().into());
                o.insert("ready_tone".into(), tone_json(p.ready.tone()));
                // Le lit rouge sombre du TUI : une policy qui ne peut pas s'évaluer, ou dont une
                // règle est en erreur, est une policy cassée — pas une ressource non conforme.
                o.insert("alarming".into(), p.alarming().into());
                o.insert("scope".into(), p.scope().into());
                o.insert("summary".into(), p.counts.summary().into());
                o.insert("blocks".into(), p.action.blocks().into());
            }
            v
        }
        KyRow::Rule { policy, rule, .. } => {
            let p = &policies[*policy];
            let r = &p.rules[*rule];
            let mut v = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "rule".into());
                o.insert("policy_uid".into(), p.uid().into());
                o.insert("policy_name".into(), p.name.clone().into());
                o.insert("action_label".into(), r.action.label().into());
                o.insert("action_tone".into(), tone_json(r.action.tone()));
                // Une règle dont la posture diffère de celle de la policy mérite d'être dite : la
                // colonne ACTION de la policy ne vaut alors pas pour elle.
                o.insert("differs".into(), (r.action != p.action).into());
                o.insert("summary".into(), r.counts.summary().into());
            }
            v
        }
        KyRow::Violation { idx, .. } => {
            let vio = &violations[*idx];
            let mut v = serde_json::to_value(vio).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "violation".into());
                o.insert("result_label".into(), vio.result.label().into());
                o.insert("result_glyph".into(), vio.result.glyph().into());
                o.insert("target".into(), vio.target().into());
                o.insert("is_problem".into(), vio.result.is_problem().into());
            }
            v
        }
        KyRow::Exception { policy, exception } => {
            let e = &policies[*policy].exceptions[*exception];
            let mut v = serde_json::to_value(e).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "exception".into());
                o.insert("policy_uid".into(), policies[*policy].uid().into());
            }
            v
        }
        KyRow::Namespace { name, counts, .. } => serde_json::json!({
            "row": "namespace",
            "name": name,
            "counts": counts,
            "summary": counts.summary(),
            "alarming": counts.error + counts.fail > 0,
        }),
        KyRow::Resource { kind, namespace, name, counts, .. } => serde_json::json!({
            "row": "resource",
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "counts": counts,
            "summary": counts.summary(),
        }),
    };

    if let Some(o) = value.as_object_mut() {
        o.insert("uid".into(), row.uid(policies, violations).into());
        o.insert("depth".into(), row.depth().into());
        o.insert("has_children".into(), row.has_children().into());
        // Le pli que kdt poserait sur cette ligne. Le navigateur ne garde que les plis posés à la
        // main, qui gagnent toujours — sinon la branche qu'on vient d'ouvrir se refermerait au
        // rafraîchissement suivant.
        o.insert("fold_default".into(), ky_default_folded(row, policies).into());
        o.insert(
            "record".into(),
            serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn health_json(state: &KyvernoState) -> serde_json::Value {
    let h = &state.health;
    serde_json::json!({
        "state": h.state(),
        "version": h.version,
        "controllers": h
            .controllers
            .iter()
            .map(|(name, ready, desired)| serde_json::json!({
                "name": name,
                "ready": ready,
                "desired": desired,
                "up": ready >= desired && *desired > 0,
            }))
            .collect::<Vec<_>>(),
        "validating_webhooks": h.validating_webhooks,
        "mutating_webhooks": h.mutating_webhooks,
        "webhooks_known": h.webhooks_known,
        "reports": h.reports,
    })
}

fn backlog_json(state: &KyvernoState) -> serde_json::Value {
    let b = &state.backlog;
    let mut value = serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(o) = value.as_object_mut() {
        o.insert("stuck".into(), b.stuck().into());
        // Un empilement, et non un compte : au-delà du seuil de kdt, la file ne se draine plus et
        // les règles `generate` ont silencieusement cessé de produire quoi que ce soit.
        o.insert("pileup".into(), b.has_pileup().into());
    }
    value
}

/// Les refus d'admission du cluster, groupés par policy.
///
/// La cible et la règle sont extraites du message par `kdt` : l'`involvedObject` de l'Event est la
/// **policy**, pas la ressource refusée — celle-ci n'a jamais existé.
async fn admission_denials(
    client: &kube::Client,
    policies: &[KyPolicy],
) -> (serde_json::Value, Option<String>) {
    let names: HashSet<&str> = policies.iter().map(|p| p.name.as_str()).collect();
    let api: Api<K8sEvent> = Api::all(client.clone());
    let list = match api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!(erreur = %e, "évènements illisibles : les refus d'admission resteront muets");
            return (serde_json::json!({}), Some(kdt::edit::api_error_text(e)));
        }
    };

    let mut records: Vec<EventRecord> = list
        .items
        .into_iter()
        .map(EventRecord::from_k8s)
        .filter(|r| names.contains(r.name.as_str()))
        .filter(|r| is_admission_denial(&r.component, &r.message))
        .collect();
    // Le plus récent d'abord : ce qu'on cherche est le dernier refus, pas le premier.
    records.sort_by_key(|r| std::cmp::Reverse(r.time));

    let mut by_policy: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    for r in records {
        let entry = by_policy.entry(r.name.clone()).or_default();
        if entry.len() >= DENIALS_PER_POLICY {
            continue;
        }
        let (target, rule) = parse_denial_message(&r.message)
            .unwrap_or_else(|| (r.message.clone(), String::new()));
        entry.push(serde_json::json!({
            "age": kdt::events::format_age(&r.time),
            "target": target,
            "rule": rule,
            "message": r.message,
        }));
    }

    (
        serde_json::to_value(by_policy).unwrap_or_else(|_| serde_json::json!({})),
        None,
    )
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

#[derive(Deserialize)]
pub struct PurgeBody {
    #[serde(default)]
    lang: String,
}

/// Supprime les UpdateRequest bloquées.
///
/// C'est la coupure manuelle d'une boucle qu'un controller en peine ne peut pas rompre seul : les
/// requests qu'il ne drainera jamais disparaissent, et les règles `synchronize: true` recréent ce
/// qui est encore nécessaire à la réconciliation suivante. Les `Completed` et `Skip` ne sont pas
/// touchées — elles ne sont pas de la file d'attente.
pub async fn purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PurgeBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    info!("purge des UpdateRequest bloquées demandée");
    match kdt::kyverno::purge_stuck_update_requests(client).await {
        Ok(n) => axum::Json(serde_json::json!({
            "message": st.plural(n, st.msg_ky_purged_one, st.msg_ky_purged_many),
            "deleted": n,
        }))
        .into_response(),
        // 409 et non 500 : la demande est arrivée, ce sont les objets qui l'ont repoussée — une
        // purge partielle dit combien sont passées et combien ont résisté.
        Err(e) => {
            warn!(erreur = %e, "purge refusée");
            (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::kyverno::{KyAction, KyCounts, KyKind, KyReady, KyResult, KyRule};

    fn policy() -> KyPolicy {
        KyPolicy {
            kind: KyKind::ClusterPolicy,
            api_version: "kyverno.io/v1".into(),
            namespace: String::new(),
            name: "require-labels".into(),
            title: "les workloads portent une équipe".into(),
            action: KyAction::Enforce,
            background: true,
            admission: true,
            ready: KyReady::Ready,
            ready_message: String::new(),
            rules: vec![KyRule {
                name: "check-team".into(),
                verb: "validate".into(),
                autogen: false,
                action: KyAction::Enforce,
                match_summary: "Pod · ns prod".into(),
                message: "le label team est obligatoire".into(),
                counts: KyCounts { fail: 2, pass: 10, ..Default::default() },
            }],
            exceptions: vec![],
            overrides: vec![],
            counts: KyCounts { fail: 2, pass: 10, ..Default::default() },
            schedule: None,
            age: "3d".into(),
        }
    }

    fn violation(policy_uid: &str) -> KyViolation {
        KyViolation {
            policy_uid: policy_uid.into(),
            policy: "require-labels".into(),
            rule: "check-team".into(),
            result: KyResult::Fail,
            severity: "medium".into(),
            category: "Best Practices".into(),
            message: "le label team est obligatoire".into(),
            api_version: "v1".into(),
            kind: "Pod".into(),
            namespace: "prod".into(),
            name: "api-7f9".into(),
            process: "background scan".into(),
            age: "2h".into(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`. En renommer une côté serveur se
    // verrait ici plutôt qu'à l'écran, sous la forme d'une colonne vide.
    #[test]
    fn une_ligne_de_policy_porte_ce_que_le_navigateur_lit() {
        let policies = vec![policy()];
        let violations = vec![violation(&policies[0].uid())];
        let rows = build_ky_rows(&policies, &violations, false, &HashSet::new());
        let v = row_json(&rows[0], &policies, &violations, lang_of("fr"));

        assert_eq!(v["row"], "policy");
        assert_eq!(v["uid"], "ClusterPolicy|/require-labels");
        assert_eq!(v["depth"], 0);
        assert_eq!(v["has_children"], true);
        assert_eq!(v["kind"], "ClusterPolicy");
        assert_eq!(v["action_label"], "Enforce");
        // Enforce est la seule posture qui casse un déploiement : elle se lit comme une alarme.
        assert_eq!(v["action_tone"], "err");
        assert_eq!(v["ready_label"], "Ready");
        assert_eq!(v["ready_tone"], "ok");
        assert_eq!(v["scope"], "Pod · ns prod");
        assert_eq!(v["summary"], "✗2 ✓10");
        assert_eq!(v["blocks"], true);
        // Elle rejette : kdt ouvre ses règles, et le navigateur n'a pas à redécouvrir pourquoi.
        assert_eq!(v["fold_default"], false);
        assert_eq!(v["record"]["kind"], "ClusterPolicy");
        assert_eq!(v["record"]["uid"], "ky|ClusterPolicy|/require-labels");
    }

    // La feuille vise la ressource fautive, pas la policy : c'est elle qu'on ouvre, qu'on édite ou
    // qu'on supprime depuis cette ligne.
    #[test]
    fn la_feuille_de_constat_adresse_la_ressource() {
        let policies = vec![policy()];
        let violations = vec![violation(&policies[0].uid())];
        let rows = build_ky_rows(&policies, &violations, false, &HashSet::new());
        let leaf = rows
            .iter()
            .find(|r| matches!(r, KyRow::Violation { .. }))
            .expect("un constat sous sa règle");
        let v = row_json(leaf, &policies, &violations, lang_of("fr"));

        assert_eq!(v["row"], "violation");
        assert_eq!(v["depth"], 2);
        assert_eq!(v["result"], "fail");
        assert_eq!(v["result_label"], "fail");
        assert_eq!(v["target"], "prod/api-7f9");
        assert_eq!(v["is_problem"], true);
        assert_eq!(v["record"]["kind"], "Pod");
        assert_eq!(v["record"]["name"], "api-7f9");
        assert_eq!(v["record"]["namespace"], "prod");
    }

    // L'axe par ressource lit la même jointure par l'autre bout : namespace, ressource, puis les
    // policies qu'elle enfreint.
    #[test]
    fn l_axe_par_ressource_groupe_par_namespace() {
        let policies = vec![policy()];
        let violations = vec![violation(&policies[0].uid())];
        let rows = build_ky_rows(&policies, &violations, true, &HashSet::new());
        let ns = row_json(&rows[0], &policies, &violations, lang_of("fr"));
        assert_eq!(ns["row"], "namespace");
        assert_eq!(ns["name"], "prod");
        assert_eq!(ns["summary"], "✗1");
        assert_eq!(ns["alarming"], true);

        let res = row_json(&rows[1], &policies, &violations, lang_of("fr"));
        assert_eq!(res["row"], "resource");
        assert_eq!(res["kind"], "Pod");
        assert_eq!(res["depth"], 1);
        // Le nœud de ressource porte l'enregistrement de l'objet réel : c'est la seule ligne qui
        // connaisse son apiVersion.
        assert_eq!(res["record"]["api_version"], "v1");
    }
}
