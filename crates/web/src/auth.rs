//! Les routes d'authentification : ouvrir le flow, en revenir, se déconnecter.
//!
//! kdt-web ne voit jamais de mot de passe. Il envoie le navigateur au portail, et récupère au
//! retour un droit de session — rien de ce que la personne a tapé ne passe par ici.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::{info, warn};

use crate::AppState;

/// Nom du cookie de session.
const COOKIE: &str = "kdt_web_session";

/// Ouvre le flow d'autorisation.
pub async fn login(State(state): State<AppState>) -> Response {
    let (oauth_state, challenge) = state.sessions.begin().await;
    let url = state
        .portal
        .authorize_url(&state.config.redirect_uri(), &oauth_state, &challenge);
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

/// Retour du portail : échange le code, ouvre la session, pose le cookie.
pub async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    // L'état est ce qui rattache ce retour à un départ d'ici : sans lui, n'importe qui pourrait
    // faire aboutir un flow qu'il a ouvert lui-même dans le navigateur de quelqu'un d'autre.
    let Some(verifier) = state.sessions.take_pending(&query.state).await else {
        warn!("retour d'autorisation sans flow correspondant");
        return refused("Cette demande d'accès n'a pas été ouverte ici, ou elle a expiré.");
    };

    let session = match state
        .portal
        .exchange(&query.code, &verifier, &state.config.redirect_uri())
        .await
    {
        Ok(session) => session,
        Err(e) => {
            warn!(erreur = %e, "échange du code refusé");
            return refused("L'accès n'a pas pu être obtenu. Reprenez depuis le début.");
        }
    };

    let subject = session.subject.clone();
    let id = match state.sessions.insert(session).await {
        Ok(id) => id,
        Err(e) => {
            warn!(erreur = %e, "session inutilisable");
            return refused("L'accès obtenu est inutilisable. Prévenez votre administrateur.");
        }
    };

    info!(subject = %subject, "session ouverte");
    (
        [(
            header::SET_COOKIE,
            cookie(&id, state.sessions.ttl().as_secs() as i64),
        )],
        Redirect::to("/"),
    )
        .into_response()
}

/// Ferme la session ici, et le droit de session côté portail.
///
/// Les deux, parce qu'ils ne disent pas la même chose : oublier le cookie laisserait le droit
/// vivre ses sept jours, alors que la personne vient de demander explicitement le contraire.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(id) = session_id(&headers) {
        if let Some(session) = state.sessions.remove(&id).await {
            if let Err(e) = session.close(&state.portal).await {
                // Le portail injoignable ne doit pas empêcher la déconnexion locale : le cookie
                // part quand même, et le droit expirera de lui-même.
                warn!(erreur = %e, "fermeture du droit de session impossible");
            }
            info!(subject = %session.subject, "session fermée");
        }
    }
    (
        [(header::SET_COOKIE, cookie("", 0))],
        Redirect::to("/"),
    )
        .into_response()
}

/// Qui est connecté, pour que le front sache quoi afficher.
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = current(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({
            "authenticated": false
        })))
            .into_response();
    };

    axum::Json(serde_json::json!({
        "authenticated": true,
        "subject": session.subject,
        "groups": session.groups,
        "mode": session.mode.as_str(),
    }))
    .into_response()
}

/// La session en cours, s'il y en a une.
pub async fn current(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<std::sync::Arc<crate::session::Session>> {
    let id = session_id(headers)?;
    state.sessions.get(&id).await
}

fn session_id(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_string())
}

/// Le cookie de session.
///
/// `HttpOnly` le rend invisible au JavaScript de la page, `Secure` interdit le transport en
/// clair, `SameSite=Strict` empêche qu'un autre site déclenche une requête authentifiée. Les
/// mêmes attributs que le portail, pour les mêmes raisons.
fn cookie(id: &str, max_age: i64) -> String {
    format!("{COOKIE}={id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}")
}

fn refused(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_cookie_porte_toutes_ses_protections() {
        let c = cookie("abc", 3600);
        for attribut in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(c.contains(attribut), "{attribut} manquant : {c}");
        }
    }

    #[test]
    fn la_deconnexion_expire_le_cookie() {
        assert!(cookie("", 0).contains("Max-Age=0"));
    }

    #[test]
    fn l_identifiant_se_lit_parmi_d_autres_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; kdt_web_session=abc123; autre=x".parse().unwrap(),
        );
        assert_eq!(session_id(&headers), Some("abc123".to_string()));
    }

    #[test]
    fn sans_cookie_il_n_y_a_pas_de_session() {
        assert_eq!(session_id(&HeaderMap::new()), None);

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "autre=x".parse().unwrap());
        assert_eq!(session_id(&headers), None);
    }
}
