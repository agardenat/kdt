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

/// Ce que ce cluster sait faire, du point de vue de la personne connectée.
///
/// Le rail des vues s'en sert pour n'afficher que celles qui ont un sujet : une vue Argo CD sur un
/// cluster sans Argo CD ne servirait qu'à faire perdre du temps. La détection est un fait sur le
/// cluster, calculé par `kdt` ; la route ne fait que le rendre.
pub async fn capabilities(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    match kdt::capabilities::detect(&client).await {
        Ok(caps) => axum::Json(caps).into_response(),
        // Un apiserver muet n'est pas un cluster sans add-on. Le dire plutôt que de rendre des
        // `false` : le navigateur préfère alors n'écarter aucune vue, et chaque vue rapportera
        // elle-même ce qu'elle n'a pas pu lire — au lieu qu'une panne réseau se manifeste par un
        // menu amputé que personne ne saurait interpréter.
        Err(e) => {
            warn!(erreur = %e, "sonde des add-ons en échec");
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    }
}

/// Les namespaces que la personne connectée peut voir.
///
/// Le sélecteur de portée s'en sert pour proposer plutôt que faire deviner : un nom de namespace
/// se retient mal, et une faute de frappe rend une vue vide qu'on lit comme un cluster vide.
///
/// **Un refus n'est pas une liste vide**, et c'est tout l'intérêt de rendre l'erreur avec la
/// liste : lister les namespaces demande un droit cluster-scoped que beaucoup de gens n'ont pas,
/// alors qu'ils travaillent dans un namespace qu'ils nomment très bien. La page garde donc la
/// saisie libre, et dit pourquoi elle ne propose rien.
pub async fn namespaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let shared = kdt::events::new_ns_list_state();
    kdt::events::fetch_namespaces(client, shared.clone()).await;
    let list = shared.lock().expect("ns list poisoned").clone();

    axum::Json(serde_json::json!({
        "namespaces": list.namespaces,
        "error": list.error,
    }))
    .into_response()
}

/// Le client de la personne connectée, ou la réponse à lui rendre s'il n'y en a pas.
///
/// Les deux refus ne disent pas la même chose et ne se confondent pas : aucune session du tout,
/// ou une session dont le droit n'est plus valide côté portail. Les manipuler ensemble ici évite
/// que chaque route en oublie un.
pub(crate) async fn session_client(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<kube::Client, Response> {
    let Some(session) = auth::current(state, headers).await else {
        return Err(unauthenticated());
    };
    session
        .client(&state.portal, &state.kube)
        .await
        .map_err(|e| expired(&session.subject, e))
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

/// Les logs de l'objet visé, quels qu'ils soient pour lui.
///
/// « Les logs de cette ligne » ne veut pas dire la même chose selon la ligne, et c'est le serveur
/// qui tranche — comme `maybe_fetch_logs` tranche dans le TUI. Un Pod rend les siens ; une
/// ressource Flux n'en a aucun, ce sont ceux de son controller filtrés sur elle. Laisser le
/// navigateur choisir la route reviendrait à recopier cette règle ailleurs.
///
/// Les autres kinds ne rendent rien : remonter d'un Deployment à ses pods demande de choisir
/// lesquels, et ce choix a des règles — le TUI les a — qu'on ne réinvente pas ici en attendant de
/// les réutiliser.
pub async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if query.namespace.is_empty() || query.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "namespace et name sont requis" })),
        )
            .into_response();
    }

    if query.component == "flux" {
        // Le controller qui réconcilie ce kind, et ses lignes filtrées sur cet objet — la même
        // paire que le TUI compose, plafond compris : les controllers parlent de tout le cluster,
        // et 200 lignes ne suffisent pas à en isoler une ressource.
        let controllers = vec![kdt::flux::controller_for_kind(&query.kind).to_string()];
        let filter = (query.namespace.clone(), query.name.clone());
        return match kdt::events::flux_logs(client, &controllers, Some(&filter), 500).await {
            Ok(lines) => axum::Json(serde_json::json!({
                "lines": lines,
                // Un controller n'a pas de containers à choisir : le sélecteur n'a rien à offrir.
                "containers": Vec::<String>::new(),
            }))
            .into_response(),
            Err(e) => (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "lines": [], "containers": [], "error": e })),
            )
                .into_response(),
        };
    }

    if query.kind != "Pod" {
        return axum::Json(serde_json::json!({
            "lines": Vec::<String>::new(),
            "containers": Vec::<String>::new(),
        }))
        .into_response();
    }

    let opts = kdt::events::LogOpts {
        previous: query.previous,
        container: query.container.filter(|c| !c.is_empty()),
    };
    // Le même plafond que le TUI applique par défaut : assez pour comprendre, assez peu pour ne
    // pas rapatrier un fichier de log entier à chaque ouverture d'onglet.
    let logs = kdt::events::pod_logs(client, &query.namespace, &query.name, 200, &opts).await;

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
    name: String,
    #[serde(default)]
    kind: String,
    /// `flux` pour une ressource Flux, vide pour un objet ordinaire. C'est le champ que
    /// `EventRecord` porte déjà, et il dit d'où viennent les lignes à lire.
    #[serde(default)]
    component: String,
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
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
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
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
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
