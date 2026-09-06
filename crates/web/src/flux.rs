//! La vue Flux : l'arbre de dépendances GitOps, son inventaire, et les leviers qui débloquent.
//!
//! Comme pour les évènements, rien n'est jugé ici : l'inventaire, les arêtes de l'arbre et le
//! verdict de chaque ligne viennent de `kdt::flux`, qui est aussi ce que le TUI affiche. Ce module
//! n'est qu'une porte HTTP devant ces fonctions.
//!
//! # Pourquoi l'arbre part déjà construit
//!
//! Le serveur envoie l'arbre **entièrement déplié**, chaque ligne portant sa profondeur. Le
//! navigateur ne replie et ne déplie que ce qu'on lui montre — un état d'affichage, qui n'a pas à
//! faire l'aller-retour. Il ne reconstruit en revanche aucune arête : `dependsOn`,
//! `status.helmChart` et `spec.sourceRef` ne sont pas dans la charge utile, justement pour qu'il
//! n'ait pas de quoi se rebâtir un arbre à lui, qui finirait par différer de celui du TUI.
//!
//! # Portée
//!
//! Il n'y en a pas : l'arbre est celui du cluster entier, comme dans kdt. Un arbre filtré par
//! namespace perd ses arêtes — la GitRepository de `flux-system` est le parent de presque tout —
//! et montrerait des racines qui n'en sont pas. La vue le dit plutôt que de filtrer en silence.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::flux::{FluxResource, InventoryItem, ReconcileScope};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::AppState;

/// L'inventaire Flux du cluster, en lignes d'arbre.
pub async fn tree(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let (resources, error) = kdt::flux::flux_resources(client).await;

    // Déplié : le pliage est un état du navigateur, et le recalculer à chaque requête ferait
    // dépendre la forme de l'arbre de ce que quelqu'un a replié il y a dix minutes.
    let nodes = kdt::flux::build_flux_tree(&resources, &std::collections::HashSet::new());
    let rows: Vec<serde_json::Value> = nodes
        .iter()
        .filter_map(|node| {
            let r = resources.get(node.idx)?;
            Some(row_json(r, node.depth, node.has_children))
        })
        .collect();

    let (ready, failed, unknown, suspended, reconciling) = kdt::flux::counts(&resources);

    // L'erreur voyage avec les lignes plutôt qu'à leur place : un kind refusé par le RBAC laisse
    // les autres lisibles, et rendre 403 ferait disparaître un inventaire partiel mais vrai. Un
    // inventaire silencieusement incomplet est ce qui fait conclure qu'une ressource n'existe pas
    // alors qu'elle était seulement illisible.
    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "total": resources.len(),
            "ready": ready,
            "failed": failed,
            "reconciling": reconciling,
            "unknown": unknown,
            "suspended": suspended,
        },
        "error": error,
    }))
    .into_response()
}

/// La ressource, plus ce que le TUI en peint et où elle se place dans l'arbre.
///
/// Les libellés et les tons sont calculés par `kdt` : un `Suspended` est jaune sur son étiquette
/// et éteint sur sa ligne des deux côtés, et le navigateur n'a pas à redécouvrir pourquoi.
fn row_json(r: &FluxResource, depth: usize, has_children: bool) -> serde_json::Value {
    let mut value = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), kdt::flux::flux_tree_uid(r).into());
        object.insert("depth".to_string(), depth.into());
        object.insert("has_children".to_string(), has_children.into());
        object.insert("ready_label".to_string(), r.ready_label().into());
        object.insert("ready_tone".to_string(), tone_json(r.ready_tone()));
        object.insert("row_tone".to_string(), tone_json(r.row_tone()));
        object.insert("no_prune".to_string(), r.no_prune().into());
        // Ce que le panneau d'inspection ouvrira : le même enregistrement synthétique que le TUI
        // fabrique, pour que Logs, Status et Related s'ouvrent sur la ressource réelle.
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::flux::synthetic_record(r))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// Ce qu'une Kustomization a appliqué, avec l'état vivant de chaque objet.
pub async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TargetQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    match kdt::flux::flux_inventory(
        &client,
        &query.api_version,
        &query.kind,
        &query.namespace,
        &query.name,
    )
    .await
    {
        Ok(inv) => {
            let uid = format!("{}|{}/{}", query.kind, query.namespace, query.name);
            axum::Json(serde_json::json!({
                "items": inv.items.iter().map(|it| item_json(&uid, it)).collect::<Vec<_>>(),
                "prune": inv.prune,
            }))
            .into_response()
        }
        // La Kustomization a pu disparaître, ou sa lecture être refusée : les deux se disent, et
        // ne se confondent pas avec une Kustomization qui n'a rien appliqué.
        Err(e) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "items": [], "error": e })),
        )
            .into_response(),
    }
}

fn item_json(ks_uid: &str, it: &InventoryItem) -> serde_json::Value {
    let mut value = serde_json::to_value(it).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "uid".to_string(),
            format!("inv|{}|{}|{}/{}", ks_uid, it.kind, it.namespace, it.name).into(),
        );
        object.insert("ready_label".to_string(), it.ready_label().into());
        object.insert("tone".to_string(), tone_json(it.tone()));
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::flux::inventory_record(ks_uid, it))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// Une ressource Flux, telle qu'on la désigne dans une requête.
#[derive(Deserialize)]
pub struct TargetQuery {
    #[serde(default, rename = "apiVersion")]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
}

/// Le corps d'une demande de réconciliation : la cible, et jusqu'où elle porte.
#[derive(Deserialize)]
pub struct ReconcileBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    scope: ReconcileScope,
}

/// Demande une réconciliation, dans la portée choisie.
///
/// Le résultat est la phrase que `kdt` rédige, rendue telle quelle. Elle dit ce qui a réellement
/// été demandé — une source suspendue fait échouer la demande plutôt que de laisser croire à une
/// réconciliation qui repartirait sur un artefact périmé — et la reformuler ici ferait dire à
/// l'interface web autre chose que ce que dit le TUI du même geste.
pub async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ReconcileBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    // Tracé : une écriture sur le cluster part sous l'identité de la personne connectée, et c'est
    // la seule trace que kdt-web en garde — les sessions vivent en mémoire et rien n'est journalisé
    // ailleurs.
    info!(
        kind = %body.kind,
        objet = %format!("{}/{}", body.namespace, body.name),
        portee = ?body.scope,
        "réconciliation demandée"
    );

    match kdt::flux::reconcile_once(
        &client,
        body.scope,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
    )
    .await
    {
        Ok(message) => axum::Json(serde_json::json!({ "message": message })).into_response(),
        // 409 et non 500 : la demande est bien arrivée, c'est l'état de l'objet qui la refuse —
        // suspendu, source suspendue, kind qui n'honore pas ce levier. Rien à réessayer tel quel.
        Err(e) => {
            warn!(kind = %body.kind, erreur = %e, "réconciliation refusée");
            (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    }
}

/// Bascule `spec.suspend` sur la ressource visée.
///
/// La direction n'est pas dans la requête : elle se décide sur l'objet vivant, côté `kdt`. Le
/// tableau que le navigateur affiche a jusqu'à un rafraîchissement de retard, et suspendre sur
/// cette lecture-là inverse l'intention — le geste qui devait reprendre suspend à nouveau.
pub async fn suspend(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<TargetBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    info!(
        kind = %body.kind,
        objet = %format!("{}/{}", body.namespace, body.name),
        "bascule de suspend demandée"
    );

    match kdt::flux::toggle_suspend_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
    )
    .await
    {
        Ok(suspended) => axum::Json(serde_json::json!({ "suspended": suspended })).into_response(),
        Err(e) => {
            warn!(kind = %body.kind, erreur = %e, "bascule de suspend refusée");
            (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    }
}

/// Une ressource Flux, telle qu'on la désigne dans un corps posté.
#[derive(Deserialize)]
pub struct TargetBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
}

/// Les logs agrégés de tous les controllers Flux.
///
/// Sans filtre : c'est la vue globale du TUI, celle qu'on ouvre quand on ne sait pas encore quelle
/// ressource regarder. Les logs d'une ressource précise passent par `/api/v1/logs`, qui sait déjà
/// qu'une ligne Flux se lit dans son controller.
pub async fn logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let controllers: Vec<String> = kdt::flux::ALL_CONTROLLERS
        .iter()
        .map(|c| c.to_string())
        .collect();
    // Le même plafond que le TUI applique à la vue globale : six controllers à 200 lignes, c'est
    // déjà de quoi remplir un écran plusieurs fois.
    match kdt::events::flux_logs(client, &controllers, None, 200).await {
        Ok(lines) => axum::Json(serde_json::json!({ "lines": lines })).into_response(),
        Err(e) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "lines": [], "error": e })),
        )
            .into_response(),
    }
}
