//! La vue k8ssandra : sur une base, qu'est-ce qui est restaurable ?
//!
//! Trois mondes sur une seule lecture — le ring (clusters, datacenters, nodes), les sauvegardes
//! Medusa (schedules, runs, catalogue, restaurations), les opérations (Jobs `nodetool`, Reaper,
//! tâches cass-operator et Medusa). Le chiffre qui compte est l'âge de la dernière sauvegarde qui
//! couvre **tous** les nodes : un run partiel se restaure comme s'il était entier, et les trois
//! surfaces qui devraient le dire mentent par omission.
//!
//! # Rien n'est jugé ici
//!
//! Les lignes, leurs états, leurs tons, la couverture d'un run, les actions qu'une ligne offre et
//! l'objet qu'une écriture produit viennent tous de `kdt::k8ssandra` — le même modèle que le TUI
//! parcourt. Ce module lit, sert, et rejoue les garde-fous.
//!
//! # Les écritures ne font pas confiance à la cible nommée
//!
//! Le navigateur envoie l'uid d'une ligne et l'identifiant d'une action. Le serveur relit
//! l'inventaire, retrouve la ligne, vérifie qu'elle offre bien cette action, et c'est **la ligne**
//! qui bâtit l'objet écrit : datacenter, type de backup, nom du backup à restaurer. Un datacenter
//! ou une commande venus du navigateur feraient écrire autre chose que ce que la ligne montre.
//!
//! Une restauration arrête le datacenter pendant toute sa durée : le nom du backup se retape, et se
//! revérifie ici — un garde-fou qui ne vivrait que dans la page se contourne en postant la requête
//! à la main.
//!
//! # Les lectures à la demande
//!
//! Log d'un container, métriques et flux d'un node, snapshots d'un node, réparations Reaper,
//! sortie d'un Job `nodetool` : aucune n'est dans la liste, chacune a sa route, comme dans le TUI
//! où aucune n'est relue par le ticker. Les réparations relisent l'objet Reaper côté serveur : le
//! Secret dont il tire les identifiants et le Service auquel il les envoie ne se prennent que de
//! l'objet lui-même.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::k8ssandra::{
    build_k8c_rows, find_k8c_row, k8c_row_record, K8cAction, K8cRow, K8cState, K8cWorld,
};
use kdt::lang::Strings;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct K8cQuery {
    /// La portée : un namespace, ou vide pour tout le cluster.
    #[serde(default)]
    ns: String,
    #[serde(default)]
    world: K8cWorld,
    /// Ne garder que ce qui a un constat. Un parent reste affiché au-dessus d'un enfant en échec.
    #[serde(default)]
    problems: bool,
    #[serde(default)]
    lang: String,
}

/// L'inventaire de la portée : les lignes du monde demandé, et ce qui vaut pour tout le cluster.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<K8cQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let scope = query.ns.trim().to_string();
    let ns = (!scope.is_empty()).then_some(scope.as_str());

    let inventory = kdt::k8ssandra::k8ssandra_inventory(&client, st).await;
    let now = now_secs();

    // Déplié : le pliage est un état du navigateur, qui part de `fold_default`.
    let rows: Vec<serde_json::Value> =
        build_k8c_rows(&inventory, query.world, query.problems, ns, &HashSet::new(), st)
            .iter()
            .map(|row| row_json(row, &inventory, st, now))
            .collect();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "clusters": inventory.clusters.len(),
            "datacenters": inventory.datacenters.len(),
            "nodes": inventory.nodes.len(),
            "schedules": inventory.schedules.len(),
            "jobs": inventory.jobs.len(),
            "backups": inventory.backups.len(),
            "restores": inventory.restores.len(),
            "ops": inventory.nodetool_jobs.len()
                + inventory.reapers.len()
                + inventory.cass_tasks.len()
                + inventory.tasks.len(),
            "problems": inventory.problems(),
        },
        // Quand s'est terminée la dernière sauvegarde qui couvre tous les nodes. C'est la réponse
        // que la vue doit sans qu'on sélectionne rien.
        "last_restorable": inventory.last_restorable,
        // Faux quand aucune API de management n'a répondu : les colonnes du ring sont inconnues,
        // pas vides.
        "ring_known": inventory.ring_known,
        "cluster_hints": inventory.cluster_hints,
        "installed": inventory.installed,
        "error": inventory.error,
    }))
    .into_response()
}

/// Une ligne : l'objet qu'elle porte, ce que kdt en dit, et son enregistrement.
fn row_json(row: &K8cRow, inventory: &K8cState, st: &'static Strings, now: i64) -> serde_json::Value {
    let (kind, object) = match row {
        K8cRow::Cluster(c) => ("cluster", serde_json::to_value(c)),
        K8cRow::Datacenter(d) => ("datacenter", serde_json::to_value(d)),
        K8cRow::Node(n) => ("node", serde_json::to_value(n)),
        K8cRow::RemoteDc(d) => ("remote_dc", serde_json::to_value(d)),
        K8cRow::RemoteNode(n) => ("remote_node", serde_json::to_value(n)),
        K8cRow::Schedule(s) => ("schedule", serde_json::to_value(s)),
        K8cRow::Job(j) => ("job", serde_json::to_value(j)),
        K8cRow::Backup(b) => ("backup", serde_json::to_value(b)),
        K8cRow::Restore(r) => ("restore", serde_json::to_value(r)),
        K8cRow::Task(t) => ("task", serde_json::to_value(t)),
        K8cRow::CassTask(t) => ("ctask", serde_json::to_value(t)),
        K8cRow::Nodetool(j) => ("nodetool", serde_json::to_value(j)),
        K8cRow::Reaper(r) => ("reaper", serde_json::to_value(r)),
        K8cRow::Group { key, count, .. } => {
            ("group", Ok(serde_json::json!({ "group": key, "count": count })))
        }
    };
    let mut value = object.unwrap_or_else(|_| serde_json::json!({}));
    let (state, tone) = row.state(st);
    let actions: Vec<serde_json::Value> = row
        .actions()
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id(),
                "label": a.label(st),
                "desc": a.desc(row, st),
            })
        })
        .collect();
    if let Some(o) = value.as_object_mut() {
        // Le détail de chaque objet est sérialisé tel quel, sauf ce qui ne doit pas voyager : les
        // `hints` y figurent déjà, et le nom du Secret de Reaper est un fait, pas une valeur.
        o.insert("row".into(), kind.into());
        o.insert("uid".into(), row.uid().into());
        o.insert("name".into(), row.name().into());
        o.insert("namespace".into(), row.namespace().into());
        o.insert("depth".into(), row.depth().into());
        o.insert("foldable".into(), row.fold_key().is_some().into());
        o.insert("fold_default".into(), row.fold_default().into());
        o.insert("has_problem".into(), row.has_problem().into());
        o.insert("kind_label".into(), row.kind_label(st).into());
        o.insert("state".into(), state.into());
        o.insert("state_tone".into(), tone_json(tone));
        o.insert("info".into(), row.info(st, now).into());
        o.insert("span".into(), row.span_text(now).into());
        o.insert("created".into(), row.created().into());
        o.insert("hints".into(), serde_json::to_value(row.hints()).unwrap_or_default());
        o.insert("actions".into(), actions.into());
        o.insert("actions_note".into(), row.actions_note(st).into());
        o.insert(
            "log_target".into(),
            serde_json::to_value(row.log_target()).unwrap_or(serde_json::Value::Null),
        );
        if let K8cRow::Node(n) = row {
            o.insert("load_text".into(), n.load_text().into());
            o.insert(
                "streaming_text".into(),
                n.streaming.as_ref().map(|s| s.expected_text()).into(),
            );
        }
        if let K8cRow::RemoteNode(n) = row {
            o.insert(
                "load_text".into(),
                n.ring.load_bytes.map(kdt::k8ssandra::format_load).unwrap_or_else(|| "—".into()).into(),
            );
        }
        if let K8cRow::CassTask(t) = row {
            o.insert("progress".into(), t.progress_text().into());
        }
        if let K8cRow::Job(j) = row {
            o.insert("coverage".into(), j.coverage_text().into());
            o.insert("running".into(), j.running().into());
            o.insert("complete".into(), serde_json::to_value(j.complete()).unwrap_or_default());
        }
        o.insert("record".into(), record_json(k8c_row_record(row, inventory, st, now)));
    }
    value
}

#[derive(Deserialize)]
pub struct LogQuery {
    namespace: String,
    pod: String,
    container: String,
}

/// Le log d'un container de pod Cassandra. Seuls `cassandra` et `medusa` : ce sont les deux que la
/// vue désigne, et la raison d'un run en échec n'est jamais dans le premier.
pub async fn log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if query.container != "cassandra" && query.container != "medusa" {
        return refused(StatusCode::BAD_REQUEST, "container".to_string());
    }
    lines_json(kdt::k8ssandra::container_log(&client, &query.namespace, &query.pod, &query.container).await)
}

#[derive(Deserialize)]
pub struct OutputQuery {
    namespace: String,
    job: String,
    #[serde(default)]
    lang: String,
}

/// La sortie d'un Job `nodetool` : le log de son pod, et une phrase qui dit quel genre de vide
/// quand il n'a rien écrit.
pub async fn output(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OutputQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    lines_json(kdt::nodetool::output(&client, &query.namespace, &query.job, st).await)
}

#[derive(Deserialize)]
pub struct NodeQuery {
    namespace: String,
    pod: String,
}

/// `tpstats`, `compactionstats` et `netstats` d'un node, par l'API de management.
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NodeQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let (counters, streams) =
        kdt::k8ssandra::node_readings(&client, &query.namespace, &query.pod).await;
    let streams: Vec<Vec<[String; 2]>> = streams
        .into_iter()
        .map(|s| s.into_iter().map(|(k, v)| [k, v]).collect())
        .collect();
    match counters {
        Ok(m) => axum::Json(serde_json::json!({
            // Seuls les pools qui portent quelque chose, ou quelques-uns pour situer un node au
            // repos : c'est la règle du TUI, et elle vit avec les compteurs.
            "pools": m.pools_to_show().iter().map(|p| serde_json::json!({
                "name": p.name,
                "active": p.active,
                "pending": p.pending,
                "blocked": p.blocked,
                "pressured": p.pressured(),
            })).collect::<Vec<_>>(),
            "dropped": m.dropped.iter().map(|(k, n)| serde_json::json!({ "kind": k, "count": n })).collect::<Vec<_>>(),
            "pending_compactions": m.pending_compactions,
            "completed_compactions": m.completed_compactions,
            "bytes_compacted": m.bytes_compacted.map(kdt::k8ssandra::format_load),
            "streams": streams,
            "error": null,
        }))
        .into_response(),
        Err(e) => axum::Json(serde_json::json!({ "error": e, "streams": streams })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SnapshotsQuery {
    namespace: String,
    pod: String,
    #[serde(default)]
    lang: String,
}

/// Les snapshots d'un node, un par tag. Les deux tailles côte à côte : un snapshot est un
/// répertoire de liens durs, et seule `True size` revient quand on l'efface.
pub async fn snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SnapshotsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    match kdt::k8ssandra::node_snapshots(&client, &query.namespace, &query.pod).await {
        Ok(tags) => {
            let (total, partial) = kdt::k8ssandra::snapshot_total(&tags);
            axum::Json(serde_json::json!({
                "tags": tags.iter().map(|t| serde_json::json!({
                    "tag": t.tag,
                    "keyspaces": t.keyspaces,
                    "tables": t.tables,
                    "reclaimable": kdt::k8ssandra::sized_text(t.true_bytes, t.partial),
                    "on_disk": kdt::k8ssandra::sized_text(t.disk_bytes, t.partial),
                    "created": t.created,
                    "origin": kdt::k8ssandra::snapshot_origin_text(t, st),
                })).collect::<Vec<_>>(),
                "total": kdt::k8ssandra::sized_text(total, partial),
                "partial": partial,
                "error": null,
            }))
            .into_response()
        }
        Err(e) => axum::Json(serde_json::json!({ "error": e, "tags": [] })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RepairsQuery {
    namespace: String,
    name: String,
    #[serde(default)]
    lang: String,
}

/// Les réparations planifiées d'un Reaper, par son API REST. L'objet Reaper est relu ici : le
/// Secret d'où sortent les identifiants et le Service qui les reçoit ne se prennent que de lui.
pub async fn repairs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RepairsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let reaper = match kdt::k8ssandra::reaper_by_name(&client, &query.namespace, &query.name).await
    {
        Ok(r) => r,
        Err(e) => return axum::Json(serde_json::json!({ "error": e, "rows": [] })).into_response(),
    };
    match kdt::k8ssandra::reaper_schedules(
        &client,
        &reaper.namespace,
        &reaper.service,
        &reaper.ui_secret,
        st,
    )
    .await
    {
        Ok(rows) => axum::Json(serde_json::json!({
            "rows": rows.into_iter().map(|(keyspace, tables, state, interval)| serde_json::json!({
                "keyspace": keyspace,
                "tables": tables,
                "state": state,
                "interval": interval,
            })).collect::<Vec<_>>(),
            "error": null,
        }))
        .into_response(),
        Err(e) => axum::Json(serde_json::json!({ "error": e, "rows": [] })).into_response(),
    }
}

/// Le corps d'une écriture : quelle ligne, quelle action. Rien d'autre ne décide de l'objet écrit.
#[derive(Deserialize)]
pub struct WriteBody {
    uid: String,
    action: String,
    /// La commande tapée, pour `nodetool` seulement.
    #[serde(default)]
    command: String,
    /// Le nom du backup retapé, pour une restauration seulement.
    #[serde(default)]
    confirm_name: String,
    #[serde(default)]
    lang: String,
}

/// Les écritures de la vue : lancer un run, restaurer, une tâche Medusa ou cass-operator, un
/// `nodetool` sur un node.
pub async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<WriteBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    info!(action = %body.action, ligne = %body.uid, "écriture k8ssandra demandée");

    let Some(action) = K8cAction::from_id(&body.action) else {
        return refused(StatusCode::CONFLICT, st.k8c_no_action.to_string());
    };
    // Relu maintenant : la page affiche ce qu'elle a lu il y a vingt secondes, et une sauvegarde
    // complète alors peut ne plus l'être (catalogue purgé, run relu partiel).
    let inventory = kdt::k8ssandra::k8ssandra_inventory(&client, st).await;
    let Some(row) = find_k8c_row(&inventory, &body.uid, st) else {
        return refused(StatusCode::CONFLICT, st.k8c_no_action.to_string());
    };
    if !row.actions().contains(&action) {
        return refused(StatusCode::CONFLICT, st.k8c_no_action.to_string());
    }

    if action == K8cAction::Nodetool {
        let K8cRow::Node(node) = &row else {
            return refused(StatusCode::CONFLICT, st.k8c_nodetool_no_node.to_string());
        };
        // La liste blanche du TUI, appliquée à la ligne entière : ici rien ne l'a filtrée touche
        // par touche.
        let command = match kdt::nodetool::validate_command(&body.command, st) {
            Ok(c) => c,
            Err(e) => return refused(StatusCode::BAD_REQUEST, e),
        };
        info!(pod = %node.name, commande = %body.command, "nodetool demandé");
        return match kdt::nodetool::run(
            client,
            node.namespace.clone(),
            node.name.clone(),
            node.datacenter.clone(),
            command,
            st,
        )
        .await
        {
            Ok((name, warnings)) => {
                let mut message = kdt::lang::fill(action.started_message(st), &[("name", &name)]);
                // Ce que le plan n'a pas pu lire accompagne la confirmation : le Job tourne déjà,
                // et ce sont les raisons pour lesquelles il pourrait ne rien répondre.
                for w in &warnings {
                    message.push_str(" · ");
                    message.push_str(w);
                }
                axum::Json(serde_json::json!({
                    "message": message,
                    // L'uid que la ligne du Job portera : le navigateur s'y place dès qu'elle
                    // apparaît dans le monde des opérations.
                    "focus": format!("k8c|nodetool|{}/{name}", node.namespace),
                }))
                .into_response()
            }
            Err(e) => refused(
                StatusCode::CONFLICT,
                kdt::lang::fill(st.msg_k8c_write_failed, &[("e", &e)]),
            ),
        };
    }

    // Une restauration arrête le datacenter pendant toute sa durée : le nom se retape, et se
    // revérifie ici.
    if action == K8cAction::Restore && body.confirm_name != row.name() {
        return refused(StatusCode::CONFLICT, st.k8c_restore_confirm_mismatch.to_string());
    }

    let Some(write) = row.write_for(action) else {
        return refused(StatusCode::CONFLICT, st.k8c_no_action.to_string());
    };
    let kind = write.kind().to_string();
    match kdt::k8ssandra::apply_k8c_write(client, write).await {
        Ok(name) => {
            let name = if name.is_empty() { kind } else { name };
            axum::Json(serde_json::json!({
                "message": kdt::lang::fill(action.started_message(st), &[("name", &name)]),
                "focus": null,
            }))
            .into_response()
        }
        Err(e) => refused(
            StatusCode::CONFLICT,
            kdt::lang::fill(st.msg_k8c_write_failed, &[("e", &e)]),
        ),
    }
}

fn lines_json(result: Result<Vec<String>, String>) -> Response {
    match result {
        Ok(lines) => axum::Json(serde_json::json!({ "lines": lines, "error": null })).into_response(),
        Err(e) => axum::Json(serde_json::json!({ "lines": [], "error": e })).into_response(),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est la ligne ou son état qui la repousse.
fn refused(status: StatusCode, e: String) -> Response {
    warn!(erreur = %e, "écriture k8ssandra refusée");
    (status, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// L'enregistrement, ton compris : `EventRecord::tone()` est une méthode, pas un champ, et sans lui
/// le liseré de sévérité de la ligne ne peint rien.
fn record_json(record: kdt::events::EventRecord) -> serde_json::Value {
    let tone = record.tone();
    let mut value = serde_json::to_value(&record).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(o) = value.as_object_mut() {
        o.insert("tone".into(), serde_json::to_value(tone).unwrap_or(serde_json::Value::Null));
    }
    value
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::k8ssandra::{MedBackup, MedJob, MedSchedule};

    fn inventory() -> K8cState {
        K8cState {
            installed: true,
            schedules: vec![MedSchedule {
                uid: "k8c|sched|cass/daily".into(),
                namespace: "cass".into(),
                name: "daily".into(),
                datacenter: "dc1".into(),
                runs: vec!["k8c|job|cass/daily-1758000000".into()],
                ..Default::default()
            }],
            jobs: vec![MedJob {
                uid: "k8c|job|cass/daily-1758000000".into(),
                namespace: "cass".into(),
                name: "daily-1758000000".into(),
                datacenter: "dc1".into(),
                created: 1_758_000_000,
                start: Some(1_758_000_000),
                finish: Some(1_758_000_600),
                finished: vec!["sts-0".into(), "sts-1".into()],
                failed: vec!["sts-2".into()],
                expected: Some(3),
                hints: vec![kdt::k8ssandra::Hint {
                    level: kdt::k8ssandra::HintLevel::Danger,
                    text: "run partiel : 2 nodes réussis, 1 en échec".into(),
                }],
                ..Default::default()
            }],
            backups: vec![MedBackup {
                uid: "k8c|backup|cass/daily-1758000000".into(),
                namespace: "cass".into(),
                name: "daily-1758000000".into(),
                complete: Some(false),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_de_run_porte_ce_que_le_navigateur_lit() {
        let inv = inventory();
        let st = lang_of("fr");
        let rows = build_k8c_rows(&inv, K8cWorld::Backups, false, None, &HashSet::new(), st);
        let run = rows
            .iter()
            .find(|r| matches!(r, K8cRow::Job(_)))
            .expect("le run sous son schedule");
        let v = row_json(run, &inv, st, 1_758_001_000);
        assert_eq!(v["row"], "job");
        assert_eq!(v["uid"], "k8c|job|cass/daily-1758000000");
        assert_eq!(v["depth"], 1);
        assert_eq!(v["coverage"], "2/3");
        // Un run partiel est rouge, pas orange : il se restaure comme s'il était entier.
        assert_eq!(v["state_tone"], "err");
        assert_eq!(v["span"], "10m");
        assert_eq!(v["actions"].as_array().map(Vec::len), Some(0));
        assert_eq!(v["log_target"]["kind"], "container");
        assert_eq!(v["log_target"]["container"], "medusa");
        assert_eq!(v["log_target"]["pod"], "sts-2");
        assert_eq!(v["record"]["kind"], "MedusaBackupJob");
        assert_eq!(v["record"]["tone"], "warn");
    }

    #[test]
    fn un_schedule_s_ouvre_plie_et_offre_un_run() {
        let inv = inventory();
        let st = lang_of("en");
        let rows = build_k8c_rows(&inv, K8cWorld::Backups, false, None, &HashSet::new(), st);
        let v = row_json(&rows[0], &inv, st, 1_758_001_000);
        assert_eq!(v["row"], "schedule");
        assert_eq!(v["fold_default"], true);
        assert_eq!(v["actions"][0]["id"], "backup-now");
        // Le type que la CRD appliquera, nommé, et non un « type de ce schedule ».
        assert!(v["actions"][0]["desc"].as_str().unwrap_or("").contains("differential"));
    }
}
