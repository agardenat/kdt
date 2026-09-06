//! Client du portail kdt-identity.
//!
//! kdt-web est le second client du contrat que le plugin `kubectl` utilise déjà : les types
//! viennent de `kdt-identity-api`, jamais d'une redéclaration. Ce qui change du plugin est
//! l'entrée — un flow d'autorisation au lieu d'un mot de passe — et rien d'autre : une fois la
//! session ouverte, les deux demandent leur credential de la même façon.

use anyhow::{anyhow, Context, Result};
use kdt_identity_api::portal::{
    AuthorizeTokenRequest, CredentialRequest, CredentialResponse, SessionRequest, SessionResponse,
    TokenRequest, TokenResponse, AUTHORIZE_PATH, AUTHORIZE_TOKEN_PATH, CREDENTIAL_PATH,
    REVOKE_PATH, SESSION_PATH, TOKEN_PATH, WEB_CLIENT_ID,
};
use kdt_identity_api::portal::RevokeRequest;

/// Un refus du portail : ce n'est pas une panne, et le distinguer évite de réessayer en boucle.
#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    /// Identité refusée : session révoquée, compte désactivé, code invalide. La suite normale est
    /// de repasser par une autorisation, pas de retenter.
    #[error("{0}")]
    Refused(String),
    /// Le portail n'a pas répondu, ou a répondu autre chose que ce qui était attendu.
    #[error(transparent)]
    Unreachable(#[from] anyhow::Error),
}

pub struct Portal {
    http: reqwest::Client,
    root: String,
}

impl Portal {
    pub fn new(root: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            root: root.trim_end_matches('/').to_string(),
        }
    }

    /// L'adresse où envoyer le navigateur pour ouvrir le flow.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, code_challenge: &str) -> String {
        format!(
            "{}{AUTHORIZE_PATH}?client_id={}&redirect_uri={}&state={}&code_challenge={}\
             &code_challenge_method=S256",
            self.root,
            urlencode(WEB_CLIENT_ID),
            urlencode(redirect_uri),
            urlencode(state),
            urlencode(code_challenge),
        )
    }

    /// Échange le code reçu par le navigateur contre un droit de session.
    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<SessionResponse, PortalError> {
        let request = AuthorizeTokenRequest {
            code: code.to_string(),
            code_verifier: code_verifier.to_string(),
            client_id: WEB_CLIENT_ID.to_string(),
            redirect_uri: redirect_uri.to_string(),
        };
        self.post(AUTHORIZE_TOKEN_PATH, &request).await
    }

    /// Rouvre une session contre le droit de renouveler, sans rien redemander à personne.
    pub async fn refresh(
        &self,
        user: &str,
        refresh_token: &str,
    ) -> Result<SessionResponse, PortalError> {
        self.post(SESSION_PATH, &SessionRequest::refresh(user, refresh_token))
            .await
    }

    /// Fait signer une demande de certificat.
    pub async fn certificate(
        &self,
        token: &str,
        csr_pem: &str,
    ) -> Result<CredentialResponse, PortalError> {
        let request = CredentialRequest {
            token: token.to_string(),
            csr: csr_pem.to_string(),
        };
        self.post(CREDENTIAL_PATH, &request).await
    }

    /// Demande un jeton d'identité, en mode OIDC.
    pub async fn token(&self, token: &str) -> Result<TokenResponse, PortalError> {
        let request = TokenRequest {
            token: token.to_string(),
        };
        self.post(TOKEN_PATH, &request).await
    }

    /// Ferme le droit de session. Appelé à la déconnexion : sans cela, le droit vivrait ses sept
    /// jours alors que la personne s'est explicitement déconnectée.
    pub async fn revoke(&self, user: &str, refresh_token: &str) -> Result<()> {
        let request = RevokeRequest {
            user: user.to_string(),
            refresh_token: refresh_token.to_string(),
        };
        self.http
            .post(format!("{}{REVOKE_PATH}", self.root))
            .json(&request)
            .send()
            .await
            .with_context(|| format!("appel du portail {}", self.root))?;
        Ok(())
    }

    async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, PortalError> {
        let url = format!("{}{path}", self.root);
        let response = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::Error::new(e).context(format!("appel du portail {url}")))?;

        // Tout refus du portail ramène à une nouvelle autorisation : session révoquée (401), ou
        // déploiement dont le contrat a changé (400, 404, 409).
        if response.status().is_client_error() {
            let status = response.status();
            let detail = error_detail(response).await;
            return Err(PortalError::Refused(match status.as_u16() {
                401 => "session invalide ou révoquée".to_string(),
                _ => detail,
            }));
        }

        let body = response
            .text()
            .await
            .map_err(|e| anyhow::Error::new(e).context("lecture de la réponse du portail"))?;
        serde_json::from_str(&body)
            .map_err(|e| PortalError::Unreachable(anyhow!("réponse du portail illisible : {e}")))
    }
}

/// Le message d'erreur du portail, s'il en a rendu un.
async fn error_detail(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<kdt_identity_api::portal::ApiError>().await {
        Ok(body) => body.error,
        Err(_) => format!("le portail a répondu {status}"),
    }
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_adresse_d_autorisation_porte_tous_les_parametres() {
        let portal = Portal::new("https://identity.example.com/");
        let url = portal.authorize_url(
            "https://kdt.example.com/auth/callback",
            "etat-1",
            "defi-1",
        );

        assert!(url.starts_with("https://identity.example.com/authorize?"), "{url}");
        assert!(url.contains("client_id=kdt-web"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fkdt.example.com%2Fauth%2Fcallback"),
            "{url}"
        );
        assert!(url.contains("code_challenge_method=S256"), "{url}");
    }

    /// La barre oblique finale de la racine ne doit pas produire une adresse à double barre :
    /// le portail compare l'adresse de retour en entier, et une URL mal formée serait refusée
    /// sans que le message dise pourquoi.
    #[test]
    fn la_racine_est_normalisee() {
        for racine in ["https://identity.example.com", "https://identity.example.com/"] {
            let url = Portal::new(racine).authorize_url("https://kdt.example.com/auth/callback", "s", "d");
            assert!(url.contains("com/authorize?"), "{url}");
            assert!(!url.contains("com//authorize"), "{url}");
        }
    }
}
