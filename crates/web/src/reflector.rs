//! La vue reflector : pourquoi un miroir n'est pas là, ou ne ressemble plus à sa source.
//!
//! Reflector ne dit presque rien quand il décide de ne rien faire — un homonyme qui fait sauter un
//! namespace, un miroir édité à la main dont la version reste « à jour », une liste vide qui vaut
//! « tous les namespaces ». Trois mondes, comme dans le TUI : l'arbre des sources et de leurs
//! destinations, les miroirs à plat pour aligner les versions, les orphelins.
//!
//! # Rien n'est jugé ici
//!
//! L'arithmétique de portée reprise de l'amont, les statuts et leurs tons, les lignes de chaque
//! monde, le filtre « problèmes » qui garde une source au-dessus d'une destination en échec, les
//! enregistrements synthétiques et le plan d'un forçage viennent tous de `kdt::reflector`.
//!
//! # Ce qui ne voyage pas
//!
//! Les valeurs, évidemment : la lecture compare les contenus par une empreinte calculée côté
//! serveur, et cette empreinte non plus ne part pas — seuls les noms de clés voyagent.
//!
//! # L'écriture ne fait pas confiance à la cible nommée
//!
//! Le navigateur envoie l'uid d'une ligne. Le serveur relit l'inventaire, retrouve la ligne, et
//! c'est **elle** qui bâtit le plan : quel miroir vider, et s'il faut horodater la source. Un plan
//! venu de la page écrirait sur ce qu'elle a vu il y a vingt secondes.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::events::LineColor;
use kdt::lang::Strings;
use kdt::reflector::{
    build_refl_view, find_force_row, force_writes, level_tone, mirrors_in, role_label, row_record,
    short_version, ReflOrphan, ReflRow, ReflSource, ReflTarget, ReflView, ReflWorld,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::{auth, AppState};

#[derive(Deserialize)]
pub struct ReflQuery {
    #[serde(default)]
    world: ReflWorld,
    /// Ne garder que ce qui demande un humain. Une source reste au-dessus d'une destination en échec.
    #[serde(default)]
    problems: bool,
    #[serde(default)]
    lang: String,
}

/// Les lignes du monde demandé, et ce qui vaut pour tout le cluster.
///
/// Sans portée de namespace, comme dans le TUI : une source et ses miroirs vivent par définition
/// dans des namespaces différents, et filtrer sur l'un couperait les arêtes que la vue montre.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReflQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inv = match kdt::reflector::reflector_inventory(&client, st).await {
        Ok(inv) => inv,
        Err(e) => {
            return axum::Json(serde_json::json!({ "rows": [], "error": e })).into_response();
        }
    };
    let (sources, mirrors, problems) = inv.summary();

    // Déplié : le pliage est un état du navigateur, qui part de `fold_default`.
    let view = build_refl_view(&inv.sources, &inv.orphans, query.world, query.problems, None);
    let rows: Vec<serde_json::Value> =
        view.rows.iter().filter_map(|row| row_json(&view, row, query.world, st)).collect();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "sources": sources,
            "mirrors": mirrors,
            "orphans": inv.orphans.len(),
            "problems": problems,
        },
        // `null` quand les Deployments n'ont pas pu être lus : « introuvable », pas « absent ».
        "controller_present": inv.controller_present,
        "consumers_known": inv.consumers_known,
        "cluster_hints": inv.cluster_hints,
        "error": serde_json::Value::Null,
    }))
    .into_response()
}

/// Une ligne : les colonnes du TUI, ce que kdt en dit, le plan d'un forçage, et son enregistrement.
fn row_json(
    view: &ReflView,
    row: &ReflRow,
    world: ReflWorld,
    st: &'static Strings,
) -> Option<serde_json::Value> {
    let record = record_json(row_record(view, row, st)?);
    let uid = record["uid"].clone();
    let mut value = match row {
        ReflRow::Source { .. } => {
            let src = view.source_of(row)?;
            let (synced, expected) = src.tally();
            serde_json::json!({
                "row": "source",
                "depth": 0,
                "parent": null,
                "foldable": !src.targets.is_empty(),
                // Replié d'office : une source chargée a des dizaines de miroirs, qui pousseraient
                // toutes les autres sources hors de l'écran.
                "fold_default": true,
                "namespace": src.namespace,
                "name": src.name,
                "kind": src.kind.label(),
                "role": "source",
                // Une source n'a pas d'état à elle : elle a un score.
                "state": if src.scope_known { format!("{synced}/{expected}") } else { "?".to_string() },
                "state_tone": null,
                "version": short_version(&src.resource_version),
                "age": src.age,
                "name_tone": level_tone(src.worst()).map(tone_json).unwrap_or_else(|| tone_json(LineColor::Info)),
                "hints": src.hints,
                "source": source_json(src, st),
            })
        }
        ReflRow::Target { .. } => {
            let src = view.source_of(row)?;
            let t = view.target_of(row)?;
            let nested = world == ReflWorld::Sources;
            serde_json::json!({
                "row": "target",
                "depth": if nested { 1 } else { 0 },
                "parent": if nested { serde_json::json!(format!("refl|src|{}", kdt::reflector::source_key(src))) } else { serde_json::Value::Null },
                "foldable": false,
                "fold_default": false,
                "namespace": t.namespace,
                "name": src.name,
                "kind": src.kind.label(),
                "role": role_label(t, st),
                "state": t.status.label(st),
                "state_tone": tone_json(t.status.tone()),
                "version": t.mirror.as_ref().map(|m| short_version(&m.reflected_version)).unwrap_or_else(|| "—".to_string()),
                "age": t.mirror.as_ref().map(|m| m.age.clone()).unwrap_or_else(|| "—".to_string()),
                "name_tone": level_tone(t.worst()).map(tone_json),
                "hints": t.hints,
                "target": target_json(t, st),
                "source": {
                    "namespace": src.namespace,
                    "name": src.name,
                    "resource_version": src.resource_version,
                },
            })
        }
        ReflRow::Orphan { .. } => {
            let o = view.orphan_of(row)?;
            serde_json::json!({
                "row": "orphan",
                "depth": 0,
                "parent": null,
                "foldable": false,
                "fold_default": false,
                "namespace": o.namespace,
                "name": o.name,
                "kind": o.kind.label(),
                "role": st.refl_role_orphan,
                "state": st.refl_st_orphan,
                "state_tone": tone_json(LineColor::Err),
                "version": short_version(&o.mirror.reflected_version),
                "age": o.age,
                "name_tone": level_tone(o.worst()).map(tone_json),
                "hints": o.hints,
                "orphan": orphan_json(o, st),
            })
        }
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), uid);
        // Le menu n'offre que ce qui changerait quelque chose ; sinon il dit pourquoi.
        let writes = match (view.source_of(row), view.target_of(row)) {
            (Some(src), target) => force_writes(src, target),
            (None, _) => Vec::new(),
        };
        if writes.is_empty() {
            object.insert("force".to_string(), serde_json::Value::Null);
            let why = if matches!(row, ReflRow::Orphan { .. }) {
                st.refl_no_force_orphan
            } else {
                st.refl_no_force
            };
            object.insert("no_force".to_string(), why.into());
        } else {
            object.insert(
                "force".to_string(),
                serde_json::json!({
                    "mirrors": mirrors_in(&writes),
                    // Un miroir auto ne se repousse qu'en voyant sa source : la confirmation le dit.
                    "stamps_source": writes.iter().any(|w| matches!(w, kdt::reflector::ForceWrite::TouchSource { .. })),
                }),
            );
            object.insert("no_force".to_string(), serde_json::Value::Null);
        }
        object.insert("record".to_string(), record);
    }
    Some(value)
}

/// Le détail d'une source : ses faits, ses annotations telles qu'écrites, et sa portée résolue.
fn source_json(src: &ReflSource, st: &'static Strings) -> serde_json::Value {
    let (synced, expected) = src.tally();
    serde_json::json!({
        "type": src.type_,
        "resource_version": src.resource_version,
        "provenance_label": src.provenance.label(),
        "age": src.age,
        "props": src.props,
        "scope_known": src.scope_known,
        "synced": synced,
        "expected": expected,
        // Une ligne par destination : son statut sous le ton de son pire constat, comme le TUI.
        "targets": src.targets.iter().map(|t| serde_json::json!({
            "namespace": t.namespace,
            "auto": t.auto,
            "status_label": t.status.label(st),
            "tone": level_tone(t.worst()).map(tone_json).unwrap_or_else(|| tone_json(LineColor::Ok)),
        })).collect::<Vec<_>>(),
    })
}

fn target_json(t: &ReflTarget, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(t).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("status_label".to_string(), t.status.label(st).into());
        if let (Some(m), Some(mirror)) = (&t.mirror, object.get_mut("mirror").and_then(|v| v.as_object_mut())) {
            mirror.insert("provenance_label".to_string(), m.provenance.label().into());
        }
    }
    value
}

fn orphan_json(o: &ReflOrphan, _st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(o).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("provenance_label".to_string(), o.provenance.label().into());
    }
    value
}

/// `EventRecord::tone` est une méthode, pas un champ : sans cette insertion la ligne perdrait son
/// liseré de sévérité, et un miroir divergent se lirait comme une ligne saine.
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
pub struct ForceBody {
    uid: String,
    #[serde(default)]
    lang: String,
}

/// Forcer une re-réflexion depuis une ligne, sous l'identité de la personne connectée.
pub async fn force(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ForceBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    // L'inventaire est relu : c'est la ligne d'aujourd'hui qui décide du plan, pas celle que la
    // page a affichée — un miroir a pu être rattrapé, ou son nom pris, entre les deux.
    let inv = match kdt::reflector::reflector_inventory(&client, st).await {
        Ok(inv) => inv,
        Err(e) => return refused(e),
    };
    let view = build_refl_view(&inv.sources, &inv.orphans, ReflWorld::Sources, false, None);
    let Some(row) = find_force_row(&view, &body.uid, st) else {
        // Un orphelin n'est jamais dans l'arbre des sources : c'est exactement la raison du refus.
        let why = if body.uid.starts_with("refl|orph|") { st.refl_no_force_orphan } else { st.refl_no_force };
        return refused(why.to_string());
    };
    let Some(src) = view.source_of(row) else {
        return refused(st.refl_no_force.to_string());
    };
    let writes = force_writes(src, view.target_of(row));
    if writes.is_empty() {
        return refused(st.refl_no_force.to_string());
    }

    info!(
        subject = %session.subject,
        cible = %body.uid,
        ecritures = writes.len(),
        "re-réflexion forcée demandée"
    );

    match kdt::reflector::run_force(client, writes, st).await {
        Ok(message) => axum::Json(serde_json::json!({ "message": message })).into_response(),
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou le cluster qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "re-réflexion refusée");
    (StatusCode::CONFLICT, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "aucune session", "reauthenticate": true })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::rbac::Provenance;
    use kdt::reflector::{
        Hint, HintLevel, MirrorFacts, MirroringProps, ReflKind, ReflectorState, TargetStatus,
    };

    fn mirror(auto: bool, version: &str) -> MirrorFacts {
        MirrorFacts {
            auto,
            reflected_version: version.into(),
            reflected_version_set: true,
            reflected_at: String::new(),
            reflected_age: String::new(),
            age: "3d".into(),
            provenance: Provenance::Unmanaged,
            keys: vec![".dockerconfigjson".into()],
        }
    }

    fn state() -> ReflectorState {
        let target = |ns: &str, status: TargetStatus, m: Option<MirrorFacts>, hints: Vec<Hint>| ReflTarget {
            namespace: ns.into(),
            auto: true,
            status,
            mirror: m,
            blocker: None,
            consumers: vec![],
            hints,
        };
        ReflectorState {
            sources: vec![ReflSource {
                kind: ReflKind::Secret,
                namespace: "registry".into(),
                name: "registry-pull".into(),
                type_: "kubernetes.io/dockerconfigjson".into(),
                resource_version: "123456789".into(),
                age: "40d".into(),
                provenance: Provenance::Unmanaged,
                props: MirroringProps { allowed: true, auto_enabled: true, ..MirroringProps::default() },
                scope_known: true,
                targets: vec![
                    target("apps", TargetStatus::Synced, Some(mirror(true, "123456789")), vec![]),
                    target(
                        "blanche",
                        TargetStatus::Blocked,
                        None,
                        vec![Hint { level: HintLevel::Danger, text: "nom déjà pris".into() }],
                    ),
                ],
                hints: vec![],
            }],
            orphans: vec![ReflOrphan {
                kind: ReflKind::ConfigMap,
                namespace: "vieux".into(),
                name: "ca-bundle".into(),
                age: "90d".into(),
                provenance: Provenance::Unmanaged,
                props: MirroringProps {
                    reflects: Some(("certs".into(), "ca-bundle".into())),
                    ..MirroringProps::default()
                },
                mirror: mirror(true, "42"),
                consumers: vec![],
                hints: vec![Hint { level: HintLevel::Warn, text: "source disparue".into() }],
            }],
            ..ReflectorState::default()
        }
    }

    fn rows(world: ReflWorld, problems: bool) -> Vec<serde_json::Value> {
        let s = state();
        let view = build_refl_view(&s.sources, &s.orphans, world, problems, None);
        view.rows.iter().filter_map(|r| row_json(&view, r, world, lang_of("fr"))).collect()
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_source_porte_son_score_et_son_pli() {
        let r = rows(ReflWorld::Sources, false);
        assert_eq!(r.len(), 3);
        let src = &r[0];
        assert_eq!(src["row"], "source");
        assert_eq!(src["state"], "1/2");
        assert_eq!(src["fold_default"], true);
        assert_eq!(src["foldable"], true);
        assert_eq!(src["version"], "…3456789");
        // Une destination bloquée rougit la source : c'est elle qu'on vient chercher.
        assert_eq!(src["name_tone"], "err");
        assert_eq!(src["record"]["kind"], "Secret");
        assert_eq!(src["record"]["tone"], "warn");
        assert_eq!(src["source"]["targets"][1]["tone"], "err");
        // Aucune empreinte de contenu ne part.
        assert!(!src.to_string().contains("fingerprint"));
    }

    #[test]
    fn une_destination_se_range_sous_sa_source() {
        let r = rows(ReflWorld::Sources, false);
        let t = &r[1];
        assert_eq!(t["row"], "target");
        assert_eq!(t["depth"], 1);
        assert_eq!(t["parent"], "refl|src|registry/registry-pull");
        assert_eq!(t["state_tone"], "ok");
        assert_eq!(t["role"], "miroir auto");
        assert_eq!(t["record"]["namespace"], "apps");
        assert_eq!(t["target"]["mirror"]["provenance_label"], Provenance::Unmanaged.label());
        // Un miroir auto ne se repousse qu'en voyant sa source.
        assert_eq!(t["force"]["mirrors"], 1);
        assert_eq!(t["force"]["stamps_source"], true);
    }

    // Le menu n'offre pas ce qui ne changerait rien, et dit pourquoi.
    #[test]
    fn un_nom_pris_ou_un_orphelin_ne_se_force_pas() {
        let r = rows(ReflWorld::Sources, false);
        assert!(r[2]["force"].is_null());
        assert_eq!(r[2]["no_force"], lang_of("fr").refl_no_force);
        let o = rows(ReflWorld::Orphans, false);
        assert_eq!(o[0]["row"], "orphan");
        assert!(o[0]["force"].is_null());
        assert_eq!(o[0]["no_force"], lang_of("fr").refl_no_force_orphan);
        assert_eq!(o[0]["record"]["message"], "reflects certs/ca-bundle · orphelin");
    }

    // Le filtre garde la source au-dessus de la destination en échec, et tait la destination saine.
    #[test]
    fn le_filtre_garde_la_source_au_dessus_du_probleme() {
        let r = rows(ReflWorld::Sources, true);
        let names: Vec<_> = r.iter().map(|x| (x["row"].clone(), x["namespace"].clone())).collect();
        assert_eq!(names.len(), 2);
        assert_eq!(r[0]["row"], "source");
        assert_eq!(r[1]["namespace"], "blanche");
    }

    // À plat, seuls les miroirs qui existent — pas l'emplacement bloqué —, puis les orphelins.
    #[test]
    fn le_monde_miroirs_aligne_ce_qui_existe() {
        let r = rows(ReflWorld::Mirrors, false);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["depth"], 0);
        assert!(r[0]["parent"].is_null());
        assert_eq!(r[1]["row"], "orphan");
    }

    // Le serveur retrouve la ligne par l'uid seul, et c'est elle qui bâtit le plan.
    #[test]
    fn la_ligne_se_retrouve_par_son_uid() {
        let s = state();
        let st = lang_of("fr");
        let view = build_refl_view(&s.sources, &s.orphans, ReflWorld::Sources, false, None);
        let row = find_force_row(&view, "refl|tgt|registry/registry-pull|apps", st).unwrap();
        assert_eq!(force_writes(view.source_of(row).unwrap(), view.target_of(row)).len(), 3);
        assert!(find_force_row(&view, "refl|orph|vieux/ca-bundle", st).is_none());
    }
}
