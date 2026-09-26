//! La vue Argo CD : « le cluster est-il ce que git dit qu'il est », sans ouvrir l'UI d'Argo CD.
//!
//! Quatre mondes, comme dans le TUI, et ils n'ont rien en commun au-delà du cadre : les
//! Applications, les ApplicationSets, les AppProjects, et les dépôts/clusters enregistrés — qui ne
//! sont pas des CRD mais des Secrets étiquetés, et que la ligne désigne donc comme tels.
//!
//! # Ce qui est calculé ici, et ce qui ne l'est pas
//!
//! Rien de ce qui juge le cluster. Le couple sync/health, le health **périmé** d'une comparaison en
//! échec, `automated.enabled: false`, l'Application hors des namespaces honorés : tout vient de
//! `kdt::argocd`. Ce module joint la lecture et la rend.
//!
//! # Ce qui ne voyage pas
//!
//! `status.resources` peut compter des centaines d'entrées par Application. Le panneau ne montre que
//! celles qui ne sont pas dans l'état attendu, vingt au plus — c'est la règle du TUI, et c'est tout
//! ce qui part. Les Secrets de dépôt et de cluster ne sont lus que pour leur adressage : aucun
//! credential n'est décodé, donc aucun ne peut traverser.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::argocd::{
    ArgoApp, ArgoAppSet, ArgoComponent, ArgoEndpoint, ArgoProject, ArgoServer, ArgoWrite,
    EndpointKind,
};
use kdt::events::LineColor;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::{auth, AppState};

/// Le plafond du TUI : au-delà, la liste des resources repousse le reste du panneau hors de vue.
const RESOURCES_SHOWN: usize = 20;

#[derive(Deserialize)]
pub struct ArgoQuery {
    #[serde(default)]
    lang: String,
}

/// Les quatre mondes de la vue, en une lecture.
///
/// Une seule requête et non quatre : les quatre listes viennent du même passage — le compte
/// d'Applications d'un project, d'un set ou d'un dépôt se calcule sur les Applications, quel que
/// soit le monde regardé.
///
/// Sans portée de namespace, comme dans le TUI : les Applications vivent dans le namespace du
/// controller, pas dans celui où elles déploient, et filtrer dessus répondrait à une autre question.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ArgoQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inv = kdt::argocd::argocd_inventory(&client, st).await;

    axum::Json(serde_json::json!({
        "server": server_json(&inv.server, st),
        "error": inv.error,
        "counts": {
            "apps": inv.apps.len(),
            "out_of_sync": inv.out_of_sync(),
            "blind": inv.blind(),
            "unhealthy": inv.unhealthy(),
            "sets": inv.sets.len(),
            "set_apps": inv.sets.iter().map(|x| x.apps.len()).sum::<usize>(),
            "projects": inv.projects.len(),
            "project_apps": inv.projects.iter().map(|p| p.apps).sum::<usize>(),
            "repos": inv.endpoints_of(EndpointKind::Repo),
            "creds": inv.endpoints_of(EndpointKind::RepoCreds),
            "clusters": inv.endpoints_of(EndpointKind::Cluster),
        },
        "apps": inv.apps.iter().map(|a| app_json(a, st)).collect::<Vec<_>>(),
        "sets": inv.sets.iter().map(|x| set_json(x, st)).collect::<Vec<_>>(),
        "projects": inv.projects.iter().map(|p| project_json(p, st)).collect::<Vec<_>>(),
        "endpoints": inv.endpoints.iter().map(|e| endpoint_json(e, st)).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// L'installation elle-même : ce que le TUI montre quand aucune ligne n'est sélectionnée, et la
/// réponse à une liste vide — « rien n'est déclaré » plutôt que « rien n'a été lu ».
fn server_json(s: &ArgoServer, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("install_label".to_string(), kdt::argocd::install_label(s, st).into());
        // Un label qui n'a pas l'air d'une version (le nom de branche d'une image reconstruite)
        // n'entre pas dans le libellé : il se montre à part, sous son vrai nom.
        object.insert(
            "version_in_label".to_string(),
            kdt::argocd::looks_like_a_version(&s.version).into(),
        );
        object.insert(
            "components".to_string(),
            s.components.iter().map(component_json).collect::<Vec<_>>().into(),
        );
    }
    value
}

fn component_json(c: &ArgoComponent) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("tone".to_string(), tone_json(c.tone()));
    }
    value
}

fn app_json(a: &ArgoApp, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(a).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "app".into());
        // La liste entière reste au serveur : seules les resources hors de l'état attendu partent,
        // avec ce qui ne va pas chez chacune, dans les mots d'Argo CD.
        object.remove("resources");
        object.insert("resource_count".to_string(), a.resources.len().into());
        let off: Vec<_> = a.resources_off().collect();
        object.insert("resources_off_count".to_string(), off.len().into());
        object.insert(
            "resources_off".to_string(),
            off.iter()
                .take(RESOURCES_SHOWN)
                .map(|r| serde_json::json!({ "label": r.label(), "marks": r.marks() }))
                .collect::<Vec<_>>()
                .into(),
        );
        object.insert(
            "source_labels".to_string(),
            a.sources.iter().map(|s| s.label()).collect::<Vec<_>>().into(),
        );
        object.insert("sync_tone".to_string(), tone_json(kdt::argocd::sync_tone(&a.sync)));
        object.insert("health_tone".to_string(), tone_json(a.health_tone()));
        object.insert("comparison_broken".to_string(), a.comparison_broken().into());
        object.insert("policy_label".to_string(), a.policy_label().into());
        object.insert("policy_tone".to_string(), tone_json(a.policy_tone()));
        object.insert("destination_label".to_string(), a.destination_label().into());
        object.insert("operation_label".to_string(), a.operation_label().into());
        object.insert("phase_tone".to_string(), tone_json(kdt::argocd::phase_tone(&a.op_phase)));
        object.insert("operation_running".to_string(), a.operation_running().into());
        object.insert("sync_target".to_string(), a.sync_target().into());
        object.insert("record".to_string(), record_json(kdt::argocd::app_record(a, st)));
    }
    value
}

fn set_json(x: &ArgoAppSet, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(x).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "set".into());
        let (state, tone) = x.state();
        object.insert("state_label".to_string(), state.into());
        object.insert("state_tone".to_string(), tone_json(tone));
        object.insert("policy_label".to_string(), x.policy_label().into());
        object.insert("record".to_string(), record_json(kdt::argocd::set_record(x, st)));
    }
    value
}

fn project_json(p: &ArgoProject, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(p).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "project".into());
        cell(object, "repos", p.repos_cell());
        cell(object, "destinations", p.destinations_cell());
        cell(object, "roles", p.roles_cell());
        object.insert("record".to_string(), record_json(kdt::argocd::project_record(p, st)));
    }
    value
}

fn endpoint_json(e: &ArgoEndpoint, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(e).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "endpoint".into());
        object.insert("kind_label".to_string(), e.kind.label().into());
        cell(object, "scope", e.scope_cell());
        object.insert("auth_tone".to_string(), tone_json(e.auth_tone()));
        object.insert("record".to_string(), record_json(kdt::argocd::endpoint_record(e, st)));
    }
    value
}

/// Une cellule dérivée : son texte sous `<nom>_label`, son ton sous `<nom>_tone`.
fn cell(
    object: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    (text, tone): (String, LineColor),
) {
    object.insert(format!("{name}_label"), text.into());
    object.insert(format!("{name}_tone"), tone_json(tone));
}

/// `EventRecord::tone` est une méthode, pas un champ : sans cette insertion la ligne perdrait son
/// liseré de sévérité, et une Application en échec se lirait comme une ligne saine.
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

/// Les trois écritures du TUI, sur une Application. Un set, un project, un Secret de dépôt se
/// changent là où ils sont déclarés : kdt n'écrit rien d'autre.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WriteRequest {
    Refresh { namespace: String, name: String, #[serde(default)] hard: bool },
    Sync { namespace: String, name: String, #[serde(default)] prune: bool },
    Terminate { namespace: String, name: String },
}

#[derive(Deserialize)]
pub struct WriteBody {
    #[serde(flatten)]
    request: WriteRequest,
    #[serde(default)]
    lang: String,
}

/// Applique une écriture, sous l'identité de la personne connectée : c'est son RBAC qui décide si
/// elle peut patcher l'Application, pas un droit du pod.
pub async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<WriteBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    let (write, ok) = match body.request {
        WriteRequest::Refresh { namespace, name, hard } => {
            (ArgoWrite::Refresh { namespace, name, hard }, st.msg_argo_refreshed)
        }
        WriteRequest::Sync { namespace, name, prune } => {
            (ArgoWrite::Sync { namespace, name, prune }, st.msg_argo_synced)
        }
        // La phase est **relue** ici : la page a pu voir une opération qui s'est terminée depuis, et
        // passer `Terminating` sur un `operationState` fini fabriquerait un arrêt de rien.
        WriteRequest::Terminate { namespace, name } => {
            match kdt::argocd::operation_phase(&client, &namespace, &name).await {
                Ok(phase) if matches!(phase.as_str(), "Running" | "Terminating") => {}
                Ok(_) => {
                    let target = format!("{namespace}/{name}");
                    return refused(kdt::lang::fill(st.argo_no_operation, &[("name", &target)]));
                }
                Err(e) => return refused(e),
            }
            (ArgoWrite::Terminate { namespace, name }, st.msg_argo_terminated)
        }
    };
    let target = write.target();

    info!(subject = %session.subject, cible = %target, "écriture argocd demandée");

    match kdt::argocd::apply_argo_write(client, write).await {
        Ok(()) => axum::Json(serde_json::json!({
            "message": kdt::lang::fill(ok, &[("name", &target)]),
        }))
        .into_response(),
        Err(e) => refused(kdt::lang::fill(st.msg_argo_write_failed, &[("name", &target), ("e", &e)])),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou le cluster qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "écriture argocd refusée");
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
    use kdt::argocd::{ArgoCondition, ArgoResource, ArgoSource, Hint, HintLevel};

    fn app() -> ArgoApp {
        ArgoApp {
            namespace: "argocd".into(),
            name: "blanche".into(),
            project: "default".into(),
            sync: "Unknown".into(),
            health: "Healthy".into(),
            auto: true,
            dest_server: "https://kubernetes.default.svc".into(),
            dest_namespace: "blanche".into(),
            dest_label: "in-cluster".into(),
            sources: vec![ArgoSource {
                repo_url: "https://git.example/blanche.git".into(),
                path: "deploy".into(),
                target_revision: "main".into(),
                ..ArgoSource::default()
            }],
            conditions: vec![ArgoCondition {
                kind: "ComparisonError".into(),
                message: "authentication required".into(),
                ..ArgoCondition::default()
            }],
            resources: vec![
                ArgoResource {
                    kind: "Deployment".into(),
                    namespace: "blanche".into(),
                    name: "api".into(),
                    sync: "OutOfSync".into(),
                    health: "Degraded".into(),
                    ..ArgoResource::default()
                },
                ArgoResource {
                    kind: "Service".into(),
                    namespace: "blanche".into(),
                    name: "api".into(),
                    sync: "Synced".into(),
                    health: "Healthy".into(),
                    ..ArgoResource::default()
                },
            ],
            hints: vec![Hint { level: HintLevel::Danger, text: "ComparisonError".into() }],
            uid: "argo|app|argocd/blanche".into(),
            ..ArgoApp::default()
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_application_porte_ce_que_le_navigateur_lit() {
        let v = app_json(&app(), lang_of("fr"));
        assert_eq!(v["row"], "app");
        assert_eq!(v["sync_tone"], "err");
        // Le piège de la vue : un `Healthy` calculé avant l'erreur de comparaison n'est pas vert.
        assert_eq!(v["health_tone"], "dim");
        assert_eq!(v["comparison_broken"], true);
        assert_eq!(v["destination_label"], "in-cluster/blanche");
        assert_eq!(v["sync_target"], "main");
        assert_eq!(v["operation_label"], "—");
        assert_eq!(v["record"]["kind"], "Application");
        assert_eq!(v["record"]["api_version"], "argoproj.io/v1alpha1");
        assert_eq!(v["record"]["tone"], "warn");
        assert!(v["source_labels"][0].as_str().unwrap().contains("//deploy @ main"));
    }

    // Seules les resources hors de l'état attendu voyagent ; la liste complète reste au serveur.
    #[test]
    fn seules_les_resources_hors_etat_voyagent() {
        let v = app_json(&app(), lang_of("fr"));
        assert!(v.get("resources").is_none());
        assert_eq!(v["resource_count"], 2);
        assert_eq!(v["resources_off_count"], 1);
        assert_eq!(v["resources_off"][0]["label"], "Deployment blanche/api");
        assert_eq!(v["resources_off"][0]["marks"][0], "OutOfSync");
        assert_eq!(v["resources_off"][0]["marks"][1], "Degraded");
    }

    // Une ligne de dépôt désigne son Secret : c'est lui que le YAML et la suppression ouvrent.
    #[test]
    fn une_ligne_de_depot_designe_son_secret() {
        let e = ArgoEndpoint {
            kind: EndpointKind::RepoCreds,
            namespace: "argocd".into(),
            secret: "creds-gitlab".into(),
            url: "https://git.example/".into(),
            label: "git.example".into(),
            auth: "none".into(),
            oci: false,
            uid: "argo|ep|argocd/creds-gitlab".into(),
            ..ArgoEndpoint::default()
        };
        let v = endpoint_json(&e, lang_of("fr"));
        assert_eq!(v["kind"], "creds");
        assert_eq!(v["kind_label"], "creds");
        assert_eq!(v["auth_tone"], "warn");
        assert_eq!(v["scope_label"], "·");
        assert_eq!(v["record"]["kind"], "Secret");
        assert_eq!(v["record"]["api_version"], "v1");
        assert_eq!(v["record"]["name"], "creds-gitlab");
    }

    // `*` n'est pas un compte : un project ouvert à tout se lit ouvert à tout.
    #[test]
    fn un_project_ouvert_se_lit_ouvert() {
        let p = ArgoProject {
            namespace: "argocd".into(),
            name: "default".into(),
            source_repos: vec!["*".into()],
            destinations: vec!["*/*".into()],
            open_sources: true,
            open_destinations: true,
            uid: "argo|proj|argocd/default".into(),
            ..ArgoProject::default()
        };
        let v = project_json(&p, lang_of("fr"));
        assert_eq!(v["repos_label"], "*");
        assert_eq!(v["repos_tone"], "warn");
        assert_eq!(v["destinations_label"], "*/*");
        assert_eq!(v["roles_label"], "·");
        assert_eq!(v["record"]["kind"], "AppProject");
    }

    #[test]
    fn un_set_en_erreur_se_signale() {
        let x = ArgoAppSet {
            namespace: "argocd".into(),
            name: "tenants".into(),
            conditions: vec![ArgoCondition {
                kind: "ErrorOccurred".into(),
                status: "True".into(),
                ..ArgoCondition::default()
            }],
            uid: "argo|set|argocd/tenants".into(),
            ..ArgoAppSet::default()
        };
        let v = set_json(&x, lang_of("fr"));
        assert_eq!(v["state_label"], "ErrorOccurred");
        assert_eq!(v["state_tone"], "err");
        assert_eq!(v["policy_label"], "sync");
    }
}
