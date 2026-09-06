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
        // Un droit de session révoqué n'est pas une panne : la personne doit repasser par le
        // portail, et le lui dire évite de chercher une erreur ailleurs.
        Err(e) => return expired(&session.subject, e),
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
            // `to_string` et non le `Debug` de l'erreur : celui-ci déverse la structure `Status`
            // entière, où la phrase de l'apiserver se noie dans des champs vides.
            axum::Json(serde_json::json!({ "error": kdt::edit::api_error_text(e) })),
        )
            .into_response();
    }

    // Chronologique, le plus récent **en bas** : c'est l'ordre du TUI, et c'est celui d'un flux
    // qu'on regarde défiler. L'inverse paraissait plus naturel sur le web, mais faisait dire
    // deux choses différentes aux deux interfaces devant la même liste.
    records.sort_by_key(|r| r.time);

    axum::Json(serde_json::json!({
        "scope": scope,
        "rows": records.iter().map(row_json).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// L'enregistrement, plus le verdict que le TUI peindrait.
///
/// Le ton est calculé ici, par la règle de `kdt`, et non déduit de la sévérité côté navigateur :
/// Kubernetes n'a que Normal et Warning, alors que le troisième niveau — celui qui distingue un
/// `CrashLoopBackOff` d'une sonde qui a hoqueté — est une règle de kdt. Le front peint ce ton,
/// il ne le rejuge pas.
fn row_json(record: &EventRecord) -> serde_json::Value {
    let mut value = serde_json::to_value(record).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "tone".to_string(),
            serde_json::to_value(record.tone()).unwrap_or(serde_json::Value::Null),
        );
    }
    value
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

/// Les logs d'un pod, quand l'objet de l'évènement en est un.
///
/// Réservé au kind `Pod` : remonter d'un Deployment à ses pods demande de choisir lesquels, et ce
/// choix a des règles — le TUI les a — qu'on ne réinvente pas ici en attendant de les réutiliser.
pub async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    if query.namespace.is_empty() || query.pod.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "namespace et pod sont requis" })),
        )
            .into_response();
    }

    let client = match session.client(&state.portal, &state.kube).await {
        Ok(client) => client,
        Err(e) => return expired(&session.subject, e),
    };

    let opts = kdt::events::LogOpts {
        previous: query.previous,
        container: query.container.filter(|c| !c.is_empty()),
    };
    // Le même plafond que le TUI applique par défaut : assez pour comprendre, assez peu pour ne
    // pas rapatrier un fichier de log entier à chaque ouverture d'onglet.
    let logs = kdt::events::pod_logs(client, &query.namespace, &query.pod, 200, &opts).await;

    axum::Json(serde_json::json!({
        "lines": logs.lines,
        "containers": logs.containers,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    pod: String,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    previous: bool,
}

/// Le contexte qui entoure un évènement : RBAC, politiques, stockage, GitOps.
///
/// L'enregistrement est posté plutôt que redemandé au cluster : c'est celui que le serveur a
/// émis, et le relire coûterait une liste complète pour retrouver une ligne. Forger un
/// enregistrement ne donne rien de plus — les sondes partent avec le client de la session, donc
/// le RBAC répond comme il répondrait ailleurs.
pub async fn related(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(record): axum::Json<EventRecord>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };

    let client = match session.client(&state.portal, &state.kube).await {
        Ok(client) => client,
        Err(e) => return expired(&session.subject, e),
    };

    let sections = kdt::enrich::gather_extra_context(&client, &record).await;
    axum::Json(serde_json::json!({
        "sections": sections
            .into_iter()
            .map(|(title, body)| serde_json::json!({ "title": title, "body": body }))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Le droit de session n'est plus valide : le dire, plutôt que de laisser croire à une panne.
fn expired(subject: &str, e: crate::portal::PortalError) -> Response {
    warn!(subject = %subject, erreur = %e, "credential indisponible");
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "votre accès n'est plus valide, reconnectez-vous",
            "reauthenticate": true,
        })),
    )
        .into_response()
}

/// L'état de l'objet visé par l'évènement, mis en forme par kdt.
///
/// Le TUI en fait un onglet du panneau du haut ; c'est le même appel et la même mise en forme,
/// avec le ton de chaque ligne — un `Warn` reste un `Warn` des deux côtés.
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };

    let client = match session.client(&state.portal, &state.kube).await {
        Ok(client) => client,
        Err(e) => return expired(&session.subject, e),
    };

    match kdt::events::object_status(
        client,
        &query.api_version,
        &query.kind,
        &query.namespace,
        &query.name,
    )
    .await
    {
        Ok(lines) => axum::Json(serde_json::json!({
            "lines": lines
                .into_iter()
                .map(|(tone, text)| serde_json::json!({ "tone": tone, "text": text }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        // L'objet a pu disparaître depuis l'évènement, ou la lecture être refusée : les deux se
        // disent, et ne se confondent pas avec un objet sans état.
        Err(e) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "lines": [], "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct StatusQuery {
    #[serde(default, rename = "apiVersion")]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
}
