//! La vue Velero : si le cluster brûle maintenant, qu'est-ce qui revient ?
//!
//! Ce que cette vue apporte n'est pas la liste des backups — `velero get backups` la donne — mais la
//! réponse à cette question-là, qui est éparpillée sur six kinds et **deux silences** :
//!
//! - un backup `PartiallyFailed` est peint comme un succès dans la plupart des tableaux de bord. Il
//!   n'en est pas un : il est allé au bout en ayant échoué à capturer des objets ;
//! - un Schedule qui cesse de se déclencher ne dit **rien du tout** — ni Event, ni condition, ni
//!   compteur de runs manqués. La seule façon de le savoir est de réévaluer le cron soi-même, ce que
//!   `kdt::velero` fait ;
//! - un namespace que personne n'a mis dans un schedule n'est pas sauvegardé, et rien ne le dit.
//!
//! Les règles sont pures et vivent dans `kdt::velero` : ce module ne fait que les servir.
//!
//! # Les écritures ne font pas confiance à la cible nommée
//!
//! Un run manuel doit reproduire le template du Schedule, et une suppression doit porter l'UID de
//! l'objet visé. Ces deux choses sont **relues sur le cluster** à partir du couple
//! namespace/nom : les accepter du navigateur ferait créer un backup avec un spec choisi par
//! l'appelant, ou déposer une demande de suppression contre un UID qui n'est pas celui qu'on croit.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::velero::{
    build_vel_rows, phase_tone, record_for_row, row_child_count, RestoreOptions, VelRow, VelWorld,
    VelWrite, VeleroState,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct VeleroQuery {
    /// La portée : un namespace, ou vide pour tout le cluster.
    #[serde(default)]
    ns: String,
    /// Le monde lu. Les trois partagent une seule lecture du cluster.
    #[serde(default)]
    world: VelWorld,
    /// Grouper les backups sous le Schedule qui les a produits. C'est le `g` du TUI.
    #[serde(default)]
    group: bool,
    /// Ne garder que ce qui a un constat. Un Schedule reste affiché au-dessus d'un backup en
    /// échec : l'écarter isolerait le backup du contexte qu'on vient chercher.
    #[serde(default)]
    problems: bool,
    #[serde(default)]
    lang: String,
}

/// L'inventaire velero de la portée : les lignes du monde demandé, et l'état de l'installation.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VeleroQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let scope = query.ns.trim().to_string();
    let ns = (!scope.is_empty()).then_some(scope.as_str());

    let inventory = read_inventory(&client).await;

    // Déplié : le pliage est un état du navigateur. Le contenu d'un backup n'est pas ici — il se
    // télécharge à la demande, par `/api/v1/velero/contents`, et arrive dans le navigateur qui
    // l'intercale sous sa ligne.
    let rows_model = build_vel_rows(
        &inventory,
        query.world,
        query.group && query.world == VelWorld::Backups,
        query.problems,
        ns,
        &HashSet::new(),
    );
    let rows: Vec<serde_json::Value> = rows_model
        .iter()
        .map(|row| row_json(row, &inventory, st))
        .collect();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "schedules": inventory.schedules.len(),
            "backups": inventory.backups.len(),
            "restores": inventory.restores.len(),
            "problems": inventory.problems(),
        },
        // Quand le dernier backup **réellement restaurable** s'est terminé. C'est le seul chiffre
        // qu'une vue de sauvegarde doit au lecteur dès l'ouverture, et il appartient au cluster
        // plutôt qu'à une ligne.
        "last_success": inventory.last_success,
        "server": server_json(&inventory),
        "cluster_hints": inventory.cluster_hints,
        // Les namespaces qui portent un PVC qu'aucun schedule ne couvre : des données que personne
        // ne protège, et rien d'autre sur le cluster ne le dit.
        "uncovered": inventory.uncovered,
        "installed": inventory.installed,
        "error": inventory.error,
    }))
    .into_response()
}

/// Une lecture complète de l'inventaire velero.
async fn read_inventory(client: &kube::Client) -> VeleroState {
    let shared = kdt::velero::new_velero_state();
    kdt::velero::fetch_velero(client.clone(), shared.clone()).await;
    let inventory = shared.lock().expect("velero poisoned").clone();
    inventory
}

/// Une ligne : ce qu'elle désigne, ce que kdt en dit, et son enregistrement.
fn row_json(
    row: &VelRow,
    inventory: &VeleroState,
    st: &'static kdt::lang::Strings,
) -> serde_json::Value {
    let children = row_child_count(inventory, row);
    let mut value = match row {
        VelRow::Schedule(s) => {
            let mut v = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "schedule".into());
                o.insert("backups".into(), children.into());
                // La prochaine exécution est **calculée** par kdt, pas lue : velero ne la publie
                // nulle part, et c'est précisément ce qui rend un schedule muet quand il s'arrête.
                o.insert(
                    "phase_tone".into(),
                    tone_json(if s.paused {
                        kdt::events::LineColor::Warn
                    } else {
                        phase_tone(if s.phase.is_empty() { "Enabled" } else { &s.phase })
                    }),
                );
            }
            v
        }
        VelRow::Backup(b) => {
            let mut v = serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "backup".into());
                o.insert("phase_tone".into(), tone_json(phase_tone(&b.phase)));
                // Les quatre orthographes d'un échec partiel disent la même chose : ce backup est
                // allé au bout **sans** tout capturer, et on ne restaure pas depuis là.
                o.insert("partially_failed".into(), b.partially_failed().into());
                o.insert("failed".into(), b.failed().into());
                o.insert("running".into(), b.running().into());
                o.insert("usable".into(), b.usable().into());
                o.insert(
                    "volumes".into(),
                    (b.volume_snapshots_attempted + b.pvb_total as i64).into(),
                );
            }
            v
        }
        VelRow::Restore(r) => {
            let mut v = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "restore".into());
                o.insert("phase_tone".into(), tone_json(phase_tone(&r.phase)));
                o.insert("running".into(), r.running().into());
            }
            v
        }
        VelRow::Location(l) => {
            let mut v = serde_json::to_value(l).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "location".into());
                o.insert("phase_tone".into(), tone_json(phase_tone(&l.phase)));
                o.insert("read_only".into(), l.read_only().into());
                o.insert("available".into(), l.available().into());
            }
            v
        }
        VelRow::SnapLocation(l) => {
            let mut v = serde_json::to_value(l).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "snaploc".into());
                o.insert("phase_tone".into(), tone_json(phase_tone(&l.phase)));
            }
            v
        }
        VelRow::Repo(r) => {
            let mut v = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "repo".into());
                o.insert("phase_tone".into(), tone_json(phase_tone(&r.phase)));
            }
            v
        }
        VelRow::Orphans => serde_json::json!({
            "row": "orphans",
            "name": st.vel_orphan_backups,
            "backups": children,
        }),
        // Le contenu d'un backup ne passe pas par ici : il arrive par sa propre route.
        other => serde_json::json!({ "row": "unknown", "name": other.uid() }),
    };

    if let Some(o) = value.as_object_mut() {
        o.insert("uid".into(), row.uid().into());
        o.insert("depth".into(), row.depth(true).into());
        o.insert("has_problem".into(), row.has_problem().into());
        o.insert("hints".into(), serde_json::to_value(row.hints()).unwrap_or_default());
        o.insert(
            "record".into(),
            serde_json::to_value(record_for_row(row, children, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// À quoi ressemble l'installation elle-même.
///
/// Une vue sur les sauvegardes incapable de dire « le controller ne tourne pas » passerait ses
/// constats à accuser les schedules.
fn server_json(inventory: &VeleroState) -> serde_json::Value {
    let s = &inventory.server;
    serde_json::json!({
        "found": s.found,
        "running": s.running(),
        "namespace": s.namespace,
        "ready": s.ready,
        "desired": s.desired,
        "version": s.version,
        // Le DaemonSet qui exécute les sauvegardes de système de fichiers. Absent, `fs-backup` ne
        // capture rien, et aucun backup ne s'en plaint.
        "node_agent": match s.node_agent {
            Some((ready, desired)) => serde_json::json!({ "ready": ready, "desired": desired }),
            None => serde_json::Value::Null,
        },
    })
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

#[derive(Deserialize)]
pub struct ContentsQuery {
    namespace: String,
    name: String,
    /// L'uid de la ligne du backup. Il préfixe l'identité des lignes de contenu, pour que deux
    /// backups tenant le même namespace restent deux lignes distinctes.
    #[serde(default)]
    uid: String,
    #[serde(default)]
    lang: String,
}

/// L'inventaire d'un backup : ce qu'il contient réellement, namespace par namespace.
///
/// Il n'existe que dans le stockage objet, et **il n'y a pas de repli** : un bucket injoignable est
/// rapporté comme tel, jamais rendu comme un backup qui n'aurait rien capturé.
///
/// L'endpoint de la location est résolu **ici** et non fourni par l'appelant : velero signe ses URL
/// contre l'adresse que *le cluster* utilise, et c'est cette adresse-là qui explique un échec de
/// téléchargement depuis l'extérieur.
pub async fn contents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ContentsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inventory = read_inventory(&client).await;
    let backup = inventory
        .backups
        .iter()
        .find(|b| b.namespace == query.namespace && b.name == query.name);
    let Some(backup) = backup else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": st.vel_ct_no_backup })),
        )
            .into_response();
    };
    let s3_url = inventory
        .locations
        .iter()
        .find(|l| l.name == backup.storage_location && l.namespace == backup.namespace)
        .map(|l| l.s3_url.clone())
        .filter(|u| !u.is_empty());

    let uid = if query.uid.is_empty() { backup.uid.clone() } else { query.uid.clone() };
    let store = kdt::velero::new_vel_contents();
    kdt::velero::fetch_contents(
        client,
        query.namespace.clone(),
        query.name.clone(),
        s3_url,
        st,
        store.clone(),
    )
    .await;
    let contents = store.lock().expect("velero contents poisoned").clone();

    axum::Json(serde_json::json!({
        "key": contents.key,
        "namespaces": contents.namespaces,
        "total": contents.total,
        "error": contents.error,
        // Les enregistrements des trois niveaux, sous les mêmes identités que les lignes.
        //
        // Les deux niveaux de regroupement ne désignent aucun objet — ils portent un kind vide, et
        // les gestes génériques n'y trouvent donc rien à ouvrir. Chaque objet capturé, lui, porte
        // son GVK réel : le geste qui l'ouvre vise l'objet **vivant**, ce qui est la question qu'on
        // se pose devant un backup — existe-t-il encore, et ressemble-t-il encore à ce qui a été
        // capturé ?
        "records": contents_records(&uid, &contents, st),
    }))
    .into_response()
}

/// Un enregistrement par ligne de contenu, aux trois niveaux.
fn contents_records(
    uid: &str,
    contents: &kdt::velero::VelContents,
    st: &'static kdt::lang::Strings,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for ns in &contents.namespaces {
        out.push(
            serde_json::to_value(kdt::velero::synthetic_ct_ns_record(uid, ns, st))
                .unwrap_or(serde_json::Value::Null),
        );
        for k in &ns.kinds {
            out.push(
                serde_json::to_value(kdt::velero::synthetic_ct_kind_record(uid, &ns.namespace, k, st))
                    .unwrap_or(serde_json::Value::Null),
            );
            for name in &k.names {
                out.push(
                    serde_json::to_value(kdt::velero::synthetic_ct_object_record(k, &ns.namespace, name))
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    out
}

#[derive(Deserialize)]
pub struct LogsQuery {
    namespace: String,
    name: String,
    /// `Backup` ou `Restore` : seuls ces deux-là ont un run derrière eux.
    kind: String,
    #[serde(default)]
    lang: String,
}

/// Le log d'un run.
///
/// C'est le seul endroit qui dise **quel** objet a produit l'avertissement qu'un backup `Completed`
/// rapporte : l'objet lui-même n'en porte que le compte. Une URL signée injoignable bascule sur le
/// log du controller, et la source est dite — les deux ne contiennent pas la même chose.
pub async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let kind: &'static str = if query.kind == "Restore" { "Restore" } else { "Backup" };

    let store = kdt::velero::new_vel_log();
    kdt::velero::fetch_run_log(
        client,
        query.namespace.clone(),
        kind,
        query.name.clone(),
        st,
        store.clone(),
    )
    .await;
    let log = store.lock().expect("velero log poisoned").clone();

    axum::Json(serde_json::json!({
        "lines": log.lines,
        "source": match log.source {
            kdt::velero::LogSource::Download => "download",
            kdt::velero::LogSource::Server => "server",
            kdt::velero::LogSource::None => "none",
        },
        "error": log.error,
    }))
    .into_response()
}

/// Les options d'une restauration, telles que le formulaire les envoie.
#[derive(Deserialize, Default)]
pub struct RestoreBody {
    #[serde(default)]
    namespaces: Vec<String>,
    /// Les Kinds à garder. Ils sont résolus en noms de ressources **côté serveur** : seul
    /// l'apiserver connaît la correspondance (`Ingress` → `ingresses`, `NetworkPolicy` →
    /// `networkpolicies`), et elle ne se calcule pas.
    #[serde(default)]
    kinds: Vec<KindRef>,
    #[serde(default)]
    target_ns: String,
    #[serde(default)]
    labels: String,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Deserialize)]
pub struct KindRef {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
}

/// Le corps d'une écriture. L'action est nommée dedans, la cible par son namespace et son nom.
#[derive(Deserialize)]
pub struct WriteBody {
    action: String,
    namespace: String,
    name: String,
    #[serde(default)]
    paused: bool,
    #[serde(default)]
    restore: RestoreBody,
    #[serde(default)]
    lang: String,
}

/// Les quatre écritures de la vue.
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
    let target = format!("{}/{}", body.namespace, body.name);
    info!(action = %body.action, cible = %target, "écriture velero demandée");

    let (write, ok_msg) = match body.action.as_str() {
        // Le template du Schedule est relu sur le cluster : un run manuel doit être indiscernable
        // d'un run programmé, y compris pour la rétention qui l'expirera, et un spec venu du
        // navigateur ferait créer autre chose que ce que le schedule décrit.
        "backup-now" => {
            let inventory = read_inventory(&client).await;
            let Some(schedule) = inventory
                .schedules
                .iter()
                .find(|s| s.namespace == body.namespace && s.name == body.name)
            else {
                return refused(st.vel_no_action.to_string());
            };
            (
                VelWrite::BackupNow(Box::new(schedule.clone())),
                st.msg_vel_backup_started,
            )
        }
        "pause" => (
            VelWrite::Pause {
                namespace: body.namespace.clone(),
                name: body.name.clone(),
                paused: body.paused,
            },
            if body.paused { st.msg_vel_paused } else { st.msg_vel_unpaused },
        ),
        "restore" => {
            let mut opts = RestoreOptions::from_selection(
                body.restore.namespaces.clone(),
                &body.restore.target_ns,
                &kdt::velero::parse_labels(&body.restore.labels),
                body.restore.overwrite,
            );
            let kinds: Vec<(String, String)> = body
                .restore
                .kinds
                .iter()
                .map(|k| (k.api_version.clone(), k.kind.clone()))
                .collect();
            let mut unresolved = Vec::new();
            if !kinds.is_empty() {
                let (resolved, missed) = kdt::velero::resolve_resources(&client, &kinds).await;
                opts.resources = resolved;
                unresolved = missed;
            }
            let write = VelWrite::Restore {
                namespace: body.namespace.clone(),
                backup: body.name.clone(),
                opts: Box::new(opts),
            };
            return run(client, write, st.msg_vel_restore_started, target, unresolved, st).await;
        }
        // Supprimer l'objet Backup ne supprime rien : le contrôleur de synchronisation le recrée
        // depuis le bucket une minute plus tard. C'est la demande qui fait disparaître les données,
        // et elle porte l'UID de l'objet — relu ici, jamais reçu du navigateur.
        "delete-backup" => {
            let inventory = read_inventory(&client).await;
            let Some(backup) = inventory
                .backups
                .iter()
                .find(|b| b.namespace == body.namespace && b.name == body.name)
            else {
                return refused(st.vel_ct_no_backup.to_string());
            };
            (
                VelWrite::DeleteBackup {
                    namespace: backup.namespace.clone(),
                    backup: backup.name.clone(),
                    uid: backup.k8s_uid.clone(),
                },
                st.msg_vel_delete_requested,
            )
        }
        _ => return refused(st.vel_no_action.to_string()),
    };

    run(client, write, ok_msg, target, Vec::new(), st).await
}

/// Applique l'écriture et rend la phrase que kdt rédige.
///
/// `unresolved` nomme les Kinds que la discovery n'a pas su placer : une CRD supprimée depuis la
/// prise du backup ne résout plus, et les laisser tomber en silence retirerait de la restauration
/// des objets que quelqu'un avait demandés.
async fn run(
    client: kube::Client,
    write: VelWrite,
    ok: &'static str,
    target: String,
    unresolved: Vec<String>,
    st: &'static kdt::lang::Strings,
) -> Response {
    match kdt::velero::apply_write(client, write).await {
        Ok(name) => {
            let name = if name.is_empty() { target } else { name };
            let mut message = kdt::lang::fill(ok, &[("name", &name)]);
            if !unresolved.is_empty() {
                message.push_str(" · ");
                message.push_str(&kdt::lang::fill(
                    st.vel_ro_unresolved,
                    &[("kinds", &unresolved.join(", "))],
                ));
            }
            axum::Json(serde_json::json!({ "message": message })).into_response()
        }
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou son état qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "écriture velero refusée");
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({ "error": e })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::velero::{VelBackup, VelSchedule};

    fn state() -> VeleroState {
        VeleroState {
            installed: true,
            schedules: vec![VelSchedule {
                namespace: "velero".into(),
                name: "nightly".into(),
                cron: "0 2 * * *".into(),
                uid: "vel|schedule|velero/nightly".into(),
                age: "41d".into(),
                phase: "Enabled".into(),
                ..Default::default()
            }],
            backups: vec![
                VelBackup {
                    namespace: "velero".into(),
                    name: "nightly-20260906020000".into(),
                    phase: "PartiallyFailed".into(),
                    schedule: Some("nightly".into()),
                    items_backed_up: 812,
                    total_items: 820,
                    uid: "vel|backup|velero/nightly-20260906020000".into(),
                    age: "1d".into(),
                    ..Default::default()
                },
                VelBackup {
                    namespace: "velero".into(),
                    name: "manual-fix".into(),
                    phase: "Completed".into(),
                    schedule: None,
                    uid: "vel|backup|velero/manual-fix".into(),
                    age: "3h".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`. En renommer une côté serveur se
    // verrait ici plutôt qu'à l'écran, sous la forme d'une colonne vide.
    #[test]
    fn une_ligne_de_backup_porte_ce_que_le_navigateur_lit() {
        let inv = state();
        let rows = build_vel_rows(&inv, VelWorld::Backups, true, false, None, &HashSet::new());
        let backup = rows
            .iter()
            .find(|r| matches!(r, VelRow::Backup(b) if b.name == "nightly-20260906020000"))
            .expect("le backup sous son schedule");
        let v = row_json(backup, &inv, lang_of("fr"));

        assert_eq!(v["row"], "backup");
        assert_eq!(v["uid"], "vel|backup|velero/nightly-20260906020000");
        assert_eq!(v["depth"], 1);
        assert_eq!(v["phase"], "PartiallyFailed");
        // Un échec partiel n'est pas une nuance de succès : il est rouge, à côté de `Failed`.
        assert_eq!(v["phase_tone"], "err");
        assert_eq!(v["partially_failed"], true);
        assert_eq!(v["usable"], false);
        assert_eq!(v["record"]["kind"], "Backup");
    }

    // Un backup qu'aucun schedule ne réclame — lancé à la main, ou dont le schedule a disparu —
    // n'apparaîtrait dans aucune ligne sans son en-tête.
    #[test]
    fn les_backups_orphelins_ont_leur_en_tete() {
        let inv = state();
        let rows = build_vel_rows(&inv, VelWorld::Backups, true, false, None, &HashSet::new());
        let header = rows
            .iter()
            .find(|r| matches!(r, VelRow::Orphans))
            .expect("l'en-tête des orphelins");
        let v = row_json(header, &inv, lang_of("fr"));
        assert_eq!(v["row"], "orphans");
        assert_eq!(v["backups"], 1);
        // Il ne désigne aucun objet : les gestes génériques ne doivent rien trouver à ouvrir.
        assert_eq!(v["record"]["kind"], "");
    }

    // Le schedule reste affiché au-dessus d'un backup en échec, même quand le filtre ne garde que
    // les problèmes : l'écarter isolerait le backup du contexte qu'on vient chercher.
    #[test]
    fn le_filtre_garde_le_schedule_au_dessus_de_son_backup() {
        let mut inv = state();
        inv.backups[0].hints = vec![kdt::velero::Hint {
            level: kdt::velero::HintLevel::Danger,
            text: "812 objets sur 820".into(),
        }];
        let rows = build_vel_rows(&inv, VelWorld::Backups, true, true, None, &HashSet::new());
        assert!(rows.iter().any(|r| matches!(r, VelRow::Schedule(s) if s.name == "nightly")));
        assert!(rows
            .iter()
            .any(|r| matches!(r, VelRow::Backup(b) if b.name == "nightly-20260906020000")));
    }
}
