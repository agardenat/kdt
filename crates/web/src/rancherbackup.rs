//! La vue rancher-backup : ai-je un backup récent de Rancher, et la restauration marcherait-elle ?
//!
//! L'opérateur répond mal à ces deux questions. Un échec laisse `Ready=True` hérité du dernier
//! succès et ne se lit que sur `Reconciling` ; un run manqué ne laisse aucune trace ; un Backup
//! non chiffré met les Secrets de sa ResourceSet en clair dans l'archive. Trois mondes, comme dans
//! le TUI : les Backups, les Restores, les ResourceSets.
//!
//! # Rien n'est jugé ici
//!
//! Les phases et leurs tons, les constats, les colonnes NEXT et KEEP, les lignes de chaque monde et
//! les enregistrements synthétiques viennent tous de `kdt::rancherbackup`.
//!
//! # L'écriture ne fait pas confiance à la cible nommée
//!
//! Le navigateur nomme un Backup et une action. Le serveur relit ce Backup : c'est **son** spec
//! d'aujourd'hui qui donne la ResourceSet, le stockage et le chiffrement du run ponctuel, et **son**
//! `status.filename` qui désigne l'archive à restaurer — jamais un nom de fichier reçu de la page.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::events::LineColor;
use kdt::lang::Strings;
use kdt::rancherbackup::{
    build_rbk_view, hint_tone, row_record, RbkRow, RbkView, RbkWorld, RbkWrite,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct RbkQuery {
    #[serde(default)]
    world: RbkWorld,
    /// Ne garder que ce qui porte un constat `Warn` ou pire.
    #[serde(default)]
    problems: bool,
    #[serde(default)]
    lang: String,
}

/// Les lignes du monde demandé, et ce qui vaut pour toute l'installation.
///
/// Sans portée de namespace, comme dans le TUI : les trois kinds sont cluster-scoped.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RbkQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inv = match kdt::rancherbackup::rbk_inventory(&client, st).await {
        Ok(inv) => inv,
        Err(e) => {
            return axum::Json(serde_json::json!({ "rows": [], "error": e })).into_response();
        }
    };
    let now = k8s_openapi::jiff::Timestamp::now().as_second();
    axum::Json(payload(&inv, query.world, query.problems, now, st)).into_response()
}

/// La réponse de `list`, sur un inventaire déjà lu.
fn payload(
    inv: &kdt::rancherbackup::RbkState,
    world: RbkWorld,
    problems: bool,
    now: i64,
    st: &'static Strings,
) -> serde_json::Value {
    let view = build_rbk_view(inv, world, problems);
    let rows: Vec<serde_json::Value> =
        view.rows.iter().filter_map(|row| row_json(&view, row, now, st)).collect();

    serde_json::json!({
        "installed": inv.installed,
        "rows": rows,
        "counts": {
            "backups": inv.backups.len(),
            "restores": inv.restores.len(),
            "resource_sets": inv.resource_sets.len(),
            "problems": inv.problems(),
        },
        "last_success": inv.last_success,
        "last_success_age": inv.last_success.map(|t| kdt::velero::age_of(t, now)),
        "operator": inv.operator.as_ref().map(|o| serde_json::json!({
            "namespace": o.namespace,
            "name": o.name,
            "ready": o.ready,
            "desired": o.desired,
            "version": o.version,
            "up": o.up(),
            "default_storage": o.default_storage,
            "storage_label": o.storage_label(),
        })),
        // `false` quand les Deployments n'ont pas pu être lus : « introuvable », pas « absent ».
        "operator_known": inv.operator_known,
        "cluster_hints": inv.cluster_hints,
        "error": serde_json::Value::Null,
    })
}

/// Une ligne : ses champs, ce que kdt en dit, ce qu'on peut y faire, et son enregistrement.
fn row_json(view: &RbkView, row: &RbkRow, now: i64, st: &'static Strings) -> Option<serde_json::Value> {
    let record = record_json(row_record(view, row, st)?);
    let uid = record["uid"].clone();
    let age = |t: Option<i64>| t.map(|t| kdt::velero::age_of(t, now));
    let mut value = match row {
        RbkRow::Backup(_) => {
            let b = view.backup_of(row)?;
            let mut v = serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "backup".into());
                o.insert("recurring".into(), b.recurring().into());
                o.insert("encrypted".into(), b.encrypted().into());
                o.insert("storage_label".into(), b.storage_label().into());
                o.insert("next_text".into(), b.next_text(now).into());
                o.insert("late".into(), b.late(now).into());
                o.insert("keep_text".into(), b.keep_text().into());
                o.insert("last_age".into(), age(b.last).into());
                o.insert("phase_label".into(), b.phase.label().into());
                o.insert("phase_tone".into(), tone_json(b.phase.tone()));
                o.insert("name_tone".into(), hint_tone(b.worst()).map(tone_json).unwrap_or(serde_json::Value::Null));
                // Le menu n'offre que ce qui peut aboutir : pas d'archive réussie, pas de restore.
                o.insert("can_restore".into(), (!b.filename.is_empty()).into());
            }
            v
        }
        RbkRow::Restore(_) => {
            let r = view.restore_of(row)?;
            let mut v = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "restore".into());
                o.insert("age".into(), kdt::velero::age_of(r.created, now).into());
                o.insert("completed_age".into(), age(r.completed).into());
                o.insert("phase_label".into(), r.phase.label().into());
                o.insert("phase_tone".into(), tone_json(r.phase.tone()));
                o.insert("name_tone".into(), hint_tone(r.worst()).map(tone_json).unwrap_or(serde_json::Value::Null));
            }
            v
        }
        RbkRow::ResourceSet(_) => {
            let r = view.resource_set_of(row)?;
            let mut v = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("row".into(), "resource_set".into());
                o.insert("name_tone".into(), hint_tone(r.worst()).map(tone_json).unwrap_or(serde_json::Value::Null));
            }
            v
        }
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), uid);
        object.insert("record".to_string(), record);
    }
    Some(value)
}

/// `EventRecord::tone` est une méthode, pas un champ : sans cette insertion la ligne perdrait son
/// liseré de sévérité, et un Backup en échec se lirait comme une ligne saine.
fn record_json(record: kdt::events::EventRecord) -> serde_json::Value {
    let tone = record.tone();
    let mut value = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "tone".to_string(),
            serde_json::to_value(tone).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn tone_json(tone: LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

#[derive(Deserialize)]
pub struct WriteBody {
    /// `backup-now` ou `restore`.
    action: String,
    /// Le Backup d'où part l'écriture.
    name: String,
    #[serde(default)]
    lang: String,
}

/// Les deux écritures de la vue, sous l'identité de la personne connectée.
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
    let (write, ok) = match body.action.as_str() {
        "backup-now" => (RbkWrite::BackupNow { from: body.name.clone() }, st.msg_rbk_backup_started),
        "restore" => (RbkWrite::Restore { from: body.name.clone() }, st.msg_rbk_restore_started),
        _ => return refused(st.rbk_no_action.to_string()),
    };
    info!(action = %body.action, cible = %body.name, "écriture rancher-backup demandée");
    match kdt::rancherbackup::apply_write(client, write, st).await {
        Ok(name) => axum::Json(serde_json::json!({ "message": kdt::lang::fill(ok, &[("name", &name)]) }))
            .into_response(),
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou le cluster qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "écriture rancher-backup refusée");
    (StatusCode::CONFLICT, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

