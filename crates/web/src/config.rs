//! Configuration du serveur, lue dans l'environnement.
//!
//! Mêmes conventions que kdt-identity, dont kdt-web est le compagnon : une variable vide vaut une
//! variable absente, et ce qui ne peut pas fonctionner est refusé au démarrage plutôt que
//! découvert à la première requête.

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("variable {0} manquante")]
    Missing(&'static str),
    #[error("variable {0} invalide : {1}")]
    Invalid(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Racine publique de kdt-web, telle qu'un navigateur l'atteint.
    ///
    /// Sert à construire l'adresse de retour du flow d'autorisation, qui doit correspondre
    /// **exactement** à celle que le portail a déclarée : `<web_url>/auth/callback`.
    pub web_url: String,
    /// Racine du portail kdt-identity.
    pub portal_url: String,
    /// Adresse d'écoute.
    pub listen: String,
    /// Répertoire du bundle du front, servi à la racine.
    ///
    /// Absent, kdt-web ne sert que son API : c'est ce qu'on veut en développement, où Vite sert
    /// le front et relaie `/api` jusqu'ici.
    pub assets: Option<String>,
    /// Clé de signature des cookies de session, 32 octets en base64.
    ///
    /// Absente, une clé est tirée au démarrage : les sessions ne survivent alors ni à un
    /// redémarrage ni à une seconde réplique. Le serveur le dit au lancement.
    pub session_key: Option<String>,
    /// Durée d'une session de navigateur.
    ///
    /// Distincte du droit de session obtenu du portail, qui dure plus longtemps et que lui seul
    /// peut révoquer. Celle-ci ne fait que borner la validité du cookie.
    pub session_ttl: Duration,
}

impl WebConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self {
            web_url: env("KDT_WEB_URL")
                .ok_or(ConfigError::Missing("KDT_WEB_URL"))?
                .trim_end_matches('/')
                .to_string(),
            portal_url: env("KDT_WEB_PORTAL_URL")
                .ok_or(ConfigError::Missing("KDT_WEB_PORTAL_URL"))?
                .trim_end_matches('/')
                .to_string(),
            listen: env("KDT_WEB_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            assets: env("KDT_WEB_ASSETS"),
            session_key: env("KDT_WEB_SESSION_KEY"),
            session_ttl: duration_from_env("KDT_WEB_SESSION_TTL", Duration::from_secs(12 * 3600))?,
        }
        .validated()
    }

    /// L'adresse de retour, déduite de la racine. Le portail n'en accepte pas d'autre.
    pub fn redirect_uri(&self) -> String {
        format!("{}{}", self.web_url, kdt_identity_api::portal::AUTHORIZE_CALLBACK_PATH)
    }

    fn validated(self) -> Result<Self, ConfigError> {
        // Le cookie de session porte `Secure` : sur http, le navigateur ne le renverrait pas, et
        // l'application serait inutilisable sans que rien ne dise pourquoi. La boucle locale fait
        // exception, c'est le seul chemin praticable derrière un `port-forward`.
        let local = self.web_url.starts_with("http://localhost")
            || self.web_url.starts_with("http://127.0.0.1");
        if !self.web_url.starts_with("https://") && !local {
            return Err(ConfigError::Invalid(
                "KDT_WEB_URL",
                format!(
                    "{:?} : https est exigé, le cookie de session porte Secure et ne \
                     reviendrait jamais",
                    self.web_url
                ),
            ));
        }
        Ok(self)
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Lit une durée avec les suffixes `s`, `m`, `h` et `d`, comme le fait kdt-identity.
fn duration_from_env(key: &'static str, default: Duration) -> Result<Duration, ConfigError> {
    let Some(raw) = env(key) else {
        return Ok(default);
    };
    let (digits, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let value: u64 = digits
        .parse()
        .map_err(|_| ConfigError::Invalid(key, format!("{raw:?} : chiffres attendus")))?;
    let seconds = match unit {
        "s" | "" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86400,
        other => {
            return Err(ConfigError::Invalid(
                key,
                format!("unité {other:?} inconnue, attendu s, m, h ou d"),
            ))
        }
    };
    Ok(Duration::from_secs(seconds))
}
