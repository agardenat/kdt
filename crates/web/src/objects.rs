//! Les quatre gestes que kdt porte sur **n'importe quel** objet : lire son YAML, l'éditer, le
//! toucher, le supprimer.
//!
//! Dans le TUI ce sont quatre touches — `y`, `e`, `h`, `Ctrl-D` — et elles marchent dans toutes les
//! vues parce qu'elles ne visent pas une ligne de tableau mais l'objet Kubernetes derrière elle. Ici
//! c'est le même partage : ces routes ne connaissent aucune vue, seulement des coordonnées d'objet,
//! et chaque vue leur passe l'enregistrement de sa ligne sélectionnée.
//!
//! # Ce que la suppression vérifie avant de supprimer
//!
//! Rien n'est retiré avant que l'objet ait été lu et inspecté pour les raisons qui font d'une
//! suppression une erreur — au premier rang desquelles être déployé par un moteur GitOps, où le
//! controller remet simplement en place ce qu'on a enlevé. Aucun constat ne bloque : ils décident
//! seulement **combien** la confirmation coûte. Un constat de niveau `danger` — ou une vérification
//! qui n'a pas pu conclure — exige de retaper le nom de l'objet ; le reste se confirme d'un bouton.
//!
//! La sortie par défaut est celle qui ne supprime rien, ici comme dans le TUI.
//!
//! # Ce que l'édition vérifie avant d'écrire
//!
//! Les deux mêmes questions que kdt pose : *ce changement va-t-il survivre ?* — un objet appliqué
//! par Flux, Argo ou Helm est remis en place à la réconciliation suivante — et *l'apiserver
//! l'acceptera-t-il ?* Aucune des deux ne bloque quoi que ce soit : elles se disent, et la personne
//! reste libre. C'est `kdt::edit` qui les répond, et sa phrase est celle du TUI.
//!
//! L'écriture est un PUT, comme `kubectl edit` : le `resourceVersion` que porte le document fait
//! refuser l'écriture si l'objet a bougé entre-temps, plutôt que d'écraser en silence le
//! changement de quelqu'un d'autre.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::{auth, AppState};

/// Les coordonnées d'un objet, telles qu'une vue les tire de l'enregistrement de sa ligne.
#[derive(Deserialize)]
pub struct ObjectQuery {
    #[serde(default, rename = "apiVersion")]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    lang: String,
}

/// Les deux rendus du YAML : brut comme l'apiserver le donne, et net de ce que le runtime a ajouté.
pub async fn yaml(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ObjectQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Some(bad) = missing(&query) {
        return bad;
    }

    match kdt::yaml::object_yaml(
        &client,
        &query.api_version,
        &query.kind,
        &query.namespace,
        &query.name,
    )
    .await
    {
        Ok((raw, neat)) => axum::Json(serde_json::json!({ "raw": raw, "neat": neat })).into_response(),
        // L'objet a pu disparaître depuis l'affichage, ou sa lecture être refusée. Les deux se
        // disent, et ne se confondent pas avec un objet sans contenu.
        Err(e) => refused(e, StatusCode::NOT_FOUND),
    }
}

/// Le document à éditer, et les garde-fous qui s'y appliquent.
pub async fn edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ObjectQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Some(bad) = missing(&query) {
        return bad;
    }
    let st = lang_of(&query.lang);

    match kdt::edit::preflight_once(
        &client,
        &query.api_version,
        &query.kind,
        &query.namespace,
        &query.name,
    )
    .await
    {
        Ok((doc, reasons)) => axum::Json(serde_json::json!({
            "text": kdt::yaml::to_yaml(&doc),
            "reasons": reasons
                .iter()
                .map(|r| serde_json::json!({
                    "level": r.level(),
                    // La phrase est celle de kdt : un garde-fou qui se dirait autrement d'un côté
                    // et de l'autre serait un garde-fou de moins.
                    "text": kdt::edit::reason_text(st, r),
                }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => refused(e, StatusCode::NOT_FOUND),
    }
}

/// Le corps d'une édition : les coordonnées, et le document tel qu'il a été retouché.
#[derive(Deserialize)]
pub struct EditBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    #[serde(default)]
    namespace: String,
    name: String,
    /// Le YAML retouché, dans son entier — c'est un remplacement, pas un patch.
    doc: String,
    #[serde(default)]
    lang: String,
}

/// Ce que ce document changerait, trié comme kdt le trie.
///
/// Trois catégories comptent, et aucune n'est un refus : les champs que l'apiserver possède —
/// écrire dessus ne fait rien —, ceux qu'il fige, et ceux qui feraient pointer le document vers un
/// **autre** objet. Le TUI montre ce tri avant d'écrire, et c'est ce que cette route rend pour que
/// le web pose la même question.
pub async fn diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<EditBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    let after = match kdt::edit::parse_doc(&body.doc, st) {
        Ok(value) => value,
        // Un document illisible est une erreur de saisie, pas une panne : la dire pendant que le
        // texte est encore sous les yeux vaut mieux que la faire dire à l'apiserver.
        Err(e) => return refused(e, StatusCode::BAD_REQUEST),
    };
    let before = match kdt::edit::preflight_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
    )
    .await
    {
        Ok((doc, _)) => doc,
        Err(e) => return refused(e, StatusCode::NOT_FOUND),
    };

    let d = kdt::edit::diff(&before, &after, &body.kind);
    axum::Json(serde_json::json!({
        "paths": d.paths,
        "server_owned": d.server_owned,
        "immutable": d.immutable,
        "identity": d.identity,
        "empty": d.is_empty(),
        // Tout le changement porte sur des champs que l'apiserver possède : écrire laisserait
        // l'objet exactement dans l'état où il est.
        "noop": d.is_noop(),
        "rejected": d.rejected(),
    }))
    .into_response()
}

/// Écrit le document retouché.
pub async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<EditBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    let doc = match kdt::edit::parse_doc(&body.doc, st) {
        Ok(value) => value,
        Err(e) => return refused(e, StatusCode::BAD_REQUEST),
    };

    // Tracé : une écriture part sous l'identité de la personne connectée, et c'est la seule trace
    // que kdt-web en garde.
    info!(
        subject = %session.subject,
        kind = %body.kind,
        objet = %format!("{}/{}", body.namespace, body.name),
        "édition appliquée"
    );

    match kdt::edit::apply_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
        doc,
    )
    .await
    {
        // La phrase de kdt, telle quelle : l'apiserver a accepté la modification.
        Ok(()) => axum::Json(serde_json::json!({ "message": st.edit_ok })).into_response(),
        // 409 : la demande est arrivée, c'est l'apiserver qui la repousse — champ figé, objet qui a
        // bougé entre-temps, webhook d'admission. Sa phrase est ce qui compte.
        Err(e) => refused(e, StatusCode::CONFLICT),
    }
}

/// Le corps d'un touch : les seules coordonnées de l'objet.
#[derive(Deserialize)]
pub struct TouchBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    #[serde(default)]
    namespace: String,
    name: String,
    #[serde(default)]
    lang: String,
}

/// Horodate l'objet pour provoquer une écriture, sans rien lui changer d'autre.
///
/// Ce qui compte n'est pas l'annotation mais l'écriture qu'elle cause : les webhooks d'admission ne
/// tournent que sur un CREATE ou un UPDATE, donc réévaluer une politique contre un objet que
/// personne n'a modifié demande de lui changer quelque chose d'anodin.
///
/// L'auteur écrit dans l'annotation est la **personne connectée**, pas le compte du pod : l'intérêt
/// de la trace est de dire qui a demandé.
pub async fn touch(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<TouchBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    let target = kdt::touch::label(&body.kind, &body.namespace, &body.name);

    info!(subject = %session.subject, objet = %target, "touch demandé");

    match kdt::touch::touch_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
        &kdt::touch::stamp(),
        &session.subject,
    )
    .await
    {
        Ok(()) => axum::Json(serde_json::json!({
            "message": st.touch_ok.replace("{d}", &target),
        }))
        .into_response(),
        Err(e) => {
            warn!(objet = %target, erreur = %e, "touch refusé");
            (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": st.touch_failed.replace("{d}", &target).replace("{e}", &e),
                })),
            )
                .into_response()
        }
    }
}

/// Les garde-fous qui s'appliquent à cet objet, et le coût de la confirmation.
///
/// Une vérification qui n'aboutit pas — objet disparu, lecture refusée — n'est pas un feu vert :
/// elle rend `strict` à vrai et se dit, plutôt que de laisser croire à une suppression anodine.
/// C'est un 200 et non une erreur : la réponse est exploitable, elle porte juste une raison de
/// plus de réfléchir.
pub async fn delete_preflight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ObjectQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Some(bad) = missing(&query) {
        return bad;
    }
    let st = lang_of(&query.lang);

    match kdt::delete::preflight_once(
        &client,
        &query.api_version,
        &query.kind,
        &query.namespace,
        &query.name,
    )
    .await
    {
        Ok(reasons) => axum::Json(serde_json::json!({
            "reasons": reasons
                .iter()
                .map(|r| serde_json::json!({
                    "level": r.level(),
                    // La phrase est celle de kdt : un garde-fou qui se dirait autrement d'un côté et
                    // de l'autre serait un garde-fou de moins.
                    "text": kdt::delete::reason_text(st, r),
                }))
                .collect::<Vec<_>>(),
            "strict": kdt::delete::strict_required(&reasons, false),
            // La phrase qui répond « rien à signaler », pour que le panneau ne soit jamais vide.
            "clear": reasons.is_empty().then_some(st.delete_no_finding),
        }))
        .into_response(),
        Err(e) => axum::Json(serde_json::json!({
            "reasons": Vec::<serde_json::Value>::new(),
            "strict": true,
            "error": st.delete_check_failed.replace("{e}", &e),
        }))
        .into_response(),
    }
}

/// Le corps d'une suppression : les coordonnées, et le nom retapé quand il est exigé.
#[derive(Deserialize)]
pub struct DeleteBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    #[serde(default)]
    namespace: String,
    name: String,
    /// Le nom tel qu'il a été retapé. Vérifié **ici** et pas seulement dans le navigateur : la
    /// confirmation stricte est un garde-fou, et un garde-fou qui ne vit que dans la page se
    /// contourne en postant la requête à la main.
    #[serde(default)]
    confirm_name: String,
    #[serde(default)]
    lang: String,
}

/// Supprime l'objet, avec la politique de propagation de `kubectl delete` (cascade en arrière-plan).
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<DeleteBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    if body.kind.is_empty() || body.name.is_empty() {
        return refused("kind et name sont requis".to_string(), StatusCode::BAD_REQUEST);
    }

    // Les garde-fous sont rejoués avant d'écrire, et non repris de la réponse précédente : entre les
    // deux requêtes l'objet a pu passer sous la main d'un moteur GitOps, ou disparaître.
    let (reasons, failed) = match kdt::delete::preflight_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
    )
    .await
    {
        Ok(reasons) => (reasons, false),
        Err(_) => (Vec::new(), true),
    };
    if kdt::delete::strict_required(&reasons, failed) && body.confirm_name.trim() != body.name {
        return refused(
            st.delete_strict_mismatch.replace("{name}", &body.name),
            StatusCode::BAD_REQUEST,
        );
    }

    // Tracé : une suppression part sous l'identité de la personne connectée, et c'est la seule trace
    // que kdt-web en garde.
    info!(
        subject = %session.subject,
        kind = %body.kind,
        objet = %format!("{}/{}", body.namespace, body.name),
        "suppression demandée"
    );

    match kdt::delete::delete_once(
        &client,
        &body.api_version,
        &body.kind,
        &body.namespace,
        &body.name,
    )
    .await
    {
        Ok(()) => axum::Json(serde_json::json!({ "message": st.delete_ok })).into_response(),
        // 409 : la demande est arrivée, c'est l'apiserver qui la repousse — finalizer, webhook
        // d'admission, droit manquant. Sa phrase est ce qui compte.
        Err(e) => refused(st.delete_failed.replace("{e}", &e), StatusCode::CONFLICT),
    }
}

/// Une coordonnée manquante n'est pas une erreur du cluster : c'est une requête qui ne vise rien.
fn missing(query: &ObjectQuery) -> Option<Response> {
    if query.kind.is_empty() || query.name.is_empty() {
        return Some(refused(
            "kind et name sont requis".to_string(),
            StatusCode::BAD_REQUEST,
        ));
    }
    None
}

fn refused(e: String, code: StatusCode) -> Response {
    warn!(erreur = %e, "geste sur objet refusé");
    (code, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "aucune session", "reauthenticate": true })),
    )
        .into_response()
}
