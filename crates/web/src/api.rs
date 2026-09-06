//! L'API de données : une route par vue, avec le client de la personne connectée.
//!
//! Premier incrément : les évènements. La règle qui vaut pour toutes les suivantes est posée
//! ici — **les verdicts sont calculés côté serveur**, par le même code que le TUI. Le front
//! reçoit une sévérité et une phrase ; il ne les déduit pas, sinon les deux interfaces finiraient
//! par dire deux choses différentes du même cluster.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use k8s_openapi::api::core::v1::Event as K8sEvent;
use kdt::events::EventRecord;
use kube::api::ListParams;
use kube::Api;
use serde::Deserialize;
use tracing::warn;

use crate::{auth, AppState};

#[derive(Deserialize)]
pub struct EventsQuery {
    /// Portée : un ou plusieurs namespaces séparés par des virgules. Vide, tout le cluster.
    ///
    /// La portée est un paramètre de requête plutôt qu'un mode : dans le TUI elle est un état
    /// qu'une touche change, ici elle est dans l'URL, donc partageable et rechargeable.
    #[serde(default)]
    ns: String,
}

/// Les évènements du cluster, dans la portée demandée.
pub async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };

    let client = match session.client(&state.portal, &state.kube).await {
        Ok(client) => client,
        Err(e) => {
            warn!(subject = %session.subject, erreur = %e, "credential indisponible");
            // Un droit de session révoqué n'est pas une panne : la personne doit repasser par le
            // portail, et le lui dire évite de chercher une erreur ailleurs.
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": "votre accès n'est plus valide, reconnectez-vous",
                    "reauthenticate": true,
                })),
            )
                .into_response();
        }
    };

    let scope: Vec<&str> = query
        .ns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let mut records: Vec<EventRecord> = Vec::new();
    let result = if scope.is_empty() {
        list_into(&mut records, Api::<K8sEvent>::all(client.clone())).await
    } else {
        // Un appel par namespace : l'apiserver ne sait pas filtrer sur une liste, et demander
        // tout le cluster pour jeter ensuite ferait porter à l'utilisateur le coût d'un droit
        // qu'il n'a peut-être pas.
        let mut outcome = Ok(());
        for ns in &scope {
            outcome = list_into(&mut records, Api::<K8sEvent>::namespaced(client.clone(), ns)).await;
            if outcome.is_err() {
                break;
            }
        }
        outcome
    };

    if let Err(e) = result {
        warn!(subject = %session.subject, erreur = %e, "lecture des évènements refusée");
        // C'est très probablement le RBAC : la personne n'a pas le droit de lire les évènements
        // dans cette portée. Le dire tel quel, plutôt que de rendre une liste vide qui ferait
        // croire à un cluster calme.
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    // Le plus récent d'abord : c'est l'ordre dans lequel on lit un flux d'évènements.
    records.sort_by_key(|r| std::cmp::Reverse(r.time));

    axum::Json(serde_json::json!({
        "scope": scope,
        "rows": records,
    }))
    .into_response()
}

async fn list_into(out: &mut Vec<EventRecord>, api: Api<K8sEvent>) -> Result<(), kube::Error> {
    let list = api.list(&ListParams::default()).await?;
    out.extend(list.items.into_iter().map(EventRecord::from_k8s));
    Ok(())
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "aucune session",
            "reauthenticate": true,
        })),
    )
        .into_response()
}
