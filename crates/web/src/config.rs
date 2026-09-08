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
    /// Nom sous lequel ce cluster est connu, affiché dans le bandeau.
    ///
    /// Il n'existe nulle part dans Kubernetes : un cluster ne connaît pas son propre nom, et
    /// l'adresse de son apiserver ne se retient pas. C'est donc un libellé qu'on donne — celui
    /// qui figure dans le kubeconfig des équipes, pour que les deux désignent la même chose.
    ///
    /// Absent, le bandeau retombe sur le contexte visé, puis sur l'hôte de l'apiserver.
    pub cluster_name: Option<String>,
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
    /// Les fournisseurs d'IA que ce déploiement offre, clés comprises.
    ///
    /// Même forme que le tableau `providers` du fichier de configuration de kdt — le type est
    /// littéralement le sien : les deux interfaces se règlent de la même façon, et une passerelle
    /// interne déclarée pour l'une se déclare pareil pour l'autre.
    ///
    /// Ces clés ne sortent jamais du pod. Le navigateur n'apprend d'un fournisseur que son nom,
    /// son modèle et l'hôte qu'il joint — de quoi choisir, et de quoi savoir où part la donnée.
    ///
    /// Vide, il ne reste que les fournisseurs personnels, et rien du tout si ceux-ci sont refusés :
    /// l'interface éteint alors le bouton plutôt que d'ouvrir un réglage qui ne mènerait nulle part.
    pub ai_providers: AiProviders,
    /// Est-ce qu'une personne peut déclarer son propre endpoint depuis son navigateur.
    ///
    /// C'est ce qui rend le réglage possible « depuis l'app » sans que le serveur détienne la clé
    /// de qui que ce soit — comme le fichier de configuration de kdt tient celle du TUI. Le prix
    /// est une requête sortante vers une adresse que le navigateur nomme : `ai.rs` la borne, et
    /// `false` la refuse tout court quand l'exploitant ne veut offrir que la sienne.
    pub ai_allow_custom: bool,
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
            cluster_name: env("KDT_WEB_CLUSTER"),
            assets: env("KDT_WEB_ASSETS"),
            session_key: env("KDT_WEB_SESSION_KEY"),
            session_ttl: duration_from_env("KDT_WEB_SESSION_TTL", Duration::from_secs(12 * 3600))?,
            ai_providers: ai_providers_from_env()?,
            ai_allow_custom: bool_from_env("KDT_WEB_AI_ALLOW_CUSTOM", true)?,
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

/// Les fournisseurs d'IA, lus dans `KDT_WEB_AI_PROVIDERS` : un tableau JSON d'objets
/// `{name, base_url, api_key, model, context_window}`.
///
/// Refusé au démarrage plutôt qu'à la première analyse : une variable mal formée est une erreur de
/// déploiement, et la découvrir au moment où quelqu'un clique fait chercher la panne dans le
/// mauvais endroit. La variable porte des clés, donc son contenu ne figure dans aucun message.
fn ai_providers_from_env() -> Result<AiProviders, ConfigError> {
    let Some(raw) = env("KDT_WEB_AI_PROVIDERS") else {
        return Ok(AiProviders(Vec::new()));
    };
    let providers: Vec<kdt::config::AiProvider> = serde_json::from_str(&raw).map_err(|e| {
        ConfigError::Invalid(
            "KDT_WEB_AI_PROVIDERS",
            format!("tableau JSON attendu : {e}"),
        )
    })?;
    if providers.iter().any(|p| p.name.trim().is_empty()) {
        return Err(ConfigError::Invalid(
            "KDT_WEB_AI_PROVIDERS",
            "chaque fournisseur doit porter un nom".to_string(),
        ));
    }
    Ok(AiProviders(providers))
}

/// La liste des fournisseurs, dont le `Debug` ne dit que les noms.
///
/// `WebConfig` dérive `Debug`, et un `debug!(?config)` écrit un jour par commodité recopierait
/// sinon les clés API dans les journaux du pod. Le type l'interdit, plutôt que la discipline.
#[derive(Clone)]
pub struct AiProviders(Vec<kdt::config::AiProvider>);

impl std::fmt::Debug for AiProviders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|p| &p.name)).finish()
    }
}

impl std::ops::Deref for AiProviders {
    type Target = [kdt::config::AiProvider];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Un booléen d'environnement, aux mêmes mots que partout ailleurs. Ce qui n'est ni vrai ni faux
/// est refusé : `KDT_WEB_AI_ALLOW_CUSTOM=no` doit fermer la porte, pas passer pour un défaut.
fn bool_from_env(key: &'static str, default: bool) -> Result<bool, ConfigError> {
    let Some(raw) = env(key) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(ConfigError::Invalid(
            key,
            format!("{other:?} : attendu true ou false"),
        )),
    }
}
