//! Sessions de navigateur, et le client Kubernetes que chacune porte.
//!
//! C'est ici que tient l'idée de kdt-web : **un client par personne connectée**, construit avec le
//! credential que le portail émet pour elle. L'apiserver voit `kdt:alice` et ses groupes, donc le
//! RBAC du cluster s'applique tel quel — il n'y a rien à réimplémenter, et rien à contourner.
//!
//! Le service account du pod, lui, n'a aucun droit sur les ressources. C'est délibéré : si
//! quelqu'un obtenait l'exécution de code ici, il n'hériterait d'aucun accès.
//!
//! # Ce qui vit en mémoire, et pourquoi
//!
//! Le droit de session — sept jours — ne touche ni le disque ni un `Secret`. Un redémarrage le
//! perd, et tout le monde se reconnecte : c'est le prix, et il est bas devant celui d'un fichier
//! qui contiendrait de quoi agir au nom de chacun.
//!
//! Conséquence à connaître : **une seule réplique**. Une seconde ne reconnaîtrait pas les sessions
//! de la première. Un magasin partagé viendra si le besoin se présente ; il devra alors chiffrer
//! ce qu'il conserve.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use kdt_identity_api::naming::{Subject, SUBJECT_PREFIX};
use kdt_identity_api::portal::{CredentialMode, SessionResponse};
use kube::Client;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::portal::{Portal, PortalError};

/// Marge prise sur l'expiration d'un credential.
///
/// Un credential de dix minutes utilisé à la neuvième minute et demie expirerait au milieu d'une
/// requête. On le renouvelle avant, sur une marge qui couvre largement un aller-retour.
const RENEW_MARGIN: chrono::Duration = chrono::Duration::seconds(60);

/// Ce que le portail a remis, et le client qui en découle.
struct Credential {
    expires_at: DateTime<Utc>,
    client: Client,
}

impl Credential {
    fn usable(&self, now: DateTime<Utc>) -> bool {
        now + RENEW_MARGIN < self.expires_at
    }
}

/// Une session de navigateur.
pub struct Session {
    /// Compte, sans préfixe — tel que le portail l'attend.
    pub user: String,
    /// Identité vue par l'apiserver, préfixe compris.
    pub subject: String,
    /// Groupes, préfixe compris.
    pub groups: Vec<String>,
    pub mode: CredentialMode,
    /// Le droit de renouveler. N'existe qu'ici.
    refresh: Zeroizing<String>,
    /// Fin de validité du droit de session, telle que le portail l'a annoncée.
    refresh_expires_at: DateTime<Utc>,
    /// Le credential courant. Sous `Mutex` : deux requêtes simultanées ne doivent pas en demander
    /// deux au portail, la seconde attend et réutilise ce que la première a obtenu.
    credential: Mutex<Option<Credential>>,
}

impl Session {
    /// Le client à utiliser pour cette personne, renouvelé si besoin.
    ///
    /// Chaque renouvellement repasse par le portail, qui relit l'état du compte et ses groupes
    /// depuis le cluster : une désactivation ou un changement d'appartenance prend effet ici,
    /// au plus tard à l'expiration du credential courant.
    pub async fn client(&self, portal: &Portal, base: &kube::Config) -> Result<Client, PortalError> {
        let now = Utc::now();
        let mut slot = self.credential.lock().await;

        if let Some(current) = slot.as_ref() {
            if current.usable(now) {
                return Ok(current.client.clone());
            }
        }

        if now >= self.refresh_expires_at {
            return Err(PortalError::Refused(
                "le droit de session a expiré".to_string(),
            ));
        }

        let session = portal.refresh(&self.user, &self.refresh).await?;
        let fresh = build_credential(portal, &session, base).await?;
        let client = fresh.client.clone();
        *slot = Some(fresh);
        Ok(client)
    }

    /// Ferme le droit de session côté portail.
    ///
    /// Méthode plutôt qu'accesseur : le droit de renouveler ne sort pas de cette structure, et
    /// la seule chose qu'on ait à en faire depuis l'extérieur est de le fermer.
    pub async fn close(&self, portal: &Portal) -> Result<()> {
        portal.revoke(&self.user, &self.refresh).await
    }
}

/// Construit le credential et le client qui va avec, dans le mode que le déploiement impose.
///
/// Le mode n'est pas un choix de kdt-web : c'est une propriété du cluster, découverte à
/// l'ouverture de session et suivie telle quelle.
async fn build_credential(
    portal: &Portal,
    session: &SessionResponse,
    base: &kube::Config,
) -> Result<Credential, PortalError> {
    let mut config = base.clone();

    let expires_at = match session.mode {
        CredentialMode::Certificate => {
            // La clé est engendrée ici et n'en sort pas ; seule la demande de signature part sur
            // le réseau. C'est ce que fait le plugin sur un poste, pour la même raison.
            let subject = subject_of(&session.subject)?;
            let groups = groups_of(&session.groups)?;
            let generated = kdt_identity_api::csr::generate(&subject, &groups)
                .map_err(|e| anyhow!("demande de signature : {e}"))?;

            let issued = portal.certificate(&session.token, &generated.csr_pem).await?;
            config.auth_info.client_certificate_data = Some(b64(&issued.certificate));
            config.auth_info.client_key_data = Some(secrecy::SecretString::from(b64(
                generated.key_pem.as_str(),
            )));
            parse_time(&issued.expires_at)?
        }
        CredentialMode::Oidc => {
            let issued = portal.token(&session.token).await?;
            config.auth_info.token = Some(secrecy::SecretString::from(issued.id_token));
            parse_time(&issued.expires_at)?
        }
    };

    let client = kdt::connect::build(config)
        .map_err(|e| anyhow!("construction du client : {e}"))?;

    Ok(Credential { expires_at, client })
}

/// Le sujet, tel que le portail l'a annoncé, reconstruit par le constructeur validant.
///
/// Le préfixe est retiré puis remis : ce n'est pas une gymnastique inutile, c'est ce qui fait
/// passer la chaîne par la validation plutôt que de la croire sur parole.
fn subject_of(raw: &str) -> Result<Subject> {
    let name = raw
        .strip_prefix(SUBJECT_PREFIX)
        .ok_or_else(|| anyhow!("sujet {raw:?} sans le préfixe attendu"))?;
    Subject::user(name).with_context(|| format!("sujet {raw:?} invalide"))
}

fn groups_of(raw: &[String]) -> Result<Vec<Subject>> {
    raw.iter()
        .map(|g| {
            let name = g
                .strip_prefix(SUBJECT_PREFIX)
                .ok_or_else(|| anyhow!("groupe {g:?} sans le préfixe attendu"))?;
            Subject::group(name).with_context(|| format!("groupe {g:?} invalide"))
        })
        .collect()
}

fn parse_time(raw: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("horodatage {raw:?}"))?
        .with_timezone(&Utc))
}

fn b64(pem: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(pem.as_bytes())
}

/// Les sessions ouvertes, et les autorisations en cours.
pub struct Sessions {
    open: RwLock<HashMap<String, Arc<Session>>>,
    /// Les flows d'autorisation commencés et pas encore revenus.
    pending: RwLock<HashMap<String, Pending>>,
    ttl: Duration,
}

/// Une autorisation en vol : ce qu'il faut retrouver quand le navigateur revient.
struct Pending {
    verifier: Zeroizing<String>,
    started: Instant,
}

/// Durée pendant laquelle une autorisation commencée peut revenir.
///
/// Le temps de se connecter au portail et de lire l'écran d'accord, pas davantage : au-delà, la
/// personne recommencera, ce qui ne coûte qu'un clic.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Self {
            open: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Ouvre un flow d'autorisation : rend l'état à transmettre et le défi à publier.
    pub async fn begin(&self) -> (String, String) {
        let state = random_token();
        let verifier = Zeroizing::new(random_token());
        let challenge = challenge_of(&verifier);

        let mut pending = self.pending.write().await;
        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
        pending.insert(
            state.clone(),
            Pending {
                verifier,
                started: Instant::now(),
            },
        );
        (state, challenge)
    }

    /// Récupère le vérificateur d'un flow, et le consomme.
    ///
    /// Consommé, donc utilisable une seule fois : un retour rejoué n'ouvrirait pas une seconde
    /// session.
    pub async fn take_pending(&self, state: &str) -> Option<Zeroizing<String>> {
        let mut pending = self.pending.write().await;
        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
        pending.remove(state).map(|p| p.verifier)
    }

    /// Enregistre une session et rend son identifiant, celui que portera le cookie.
    pub async fn insert(&self, session: SessionResponse) -> Result<String> {
        let user = session
            .subject
            .strip_prefix(SUBJECT_PREFIX)
            .ok_or_else(|| anyhow!("sujet {:?} sans le préfixe attendu", session.subject))?
            .to_string();
        let refresh = session
            .refresh_token
            .clone()
            .ok_or_else(|| anyhow!("le portail n'a pas rendu de droit de session"))?;
        let refresh_expires_at = match &session.refresh_expires_at {
            Some(raw) => parse_time(raw)?,
            None => return Err(anyhow!("droit de session sans échéance")),
        };

        let id = random_token();
        let entry = Arc::new(Session {
            user,
            subject: session.subject,
            groups: session.groups,
            mode: session.mode,
            refresh: Zeroizing::new(refresh),
            refresh_expires_at,
            credential: Mutex::new(None),
        });

        self.open.write().await.insert(id.clone(), entry);
        Ok(id)
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.open.read().await.get(id).cloned()
    }

    /// Retire une session et rend ce qu'il faut pour fermer le droit côté portail.
    pub async fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.open.write().await.remove(id)
    }

    /// Durée du cookie.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Un secret de 32 octets, en base64url.
///
/// Sert d'identifiant de session, d'état et de vérificateur PKCE : trois usages qui demandent la
/// même chose — être impossible à deviner.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("CSPRNG du système indisponible");
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Le défi PKCE d'un vérificateur : `BASE64URL(SHA256(verifier))`.
fn challenge_of(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deux_jetons_tires_different() {
        assert_ne!(random_token(), random_token());
    }

    /// Le vérificateur doit rester dans les bornes de la RFC 7636, que le portail vérifie :
    /// 32 octets en base64url font 43 caractères, le minimum exact.
    #[test]
    fn le_verificateur_respecte_les_bornes_du_portail() {
        let v = random_token();
        assert_eq!(v.len(), 43, "{v}");
        assert!(
            v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{v}"
        );
    }

    /// Le défi est le condensé du vérificateur, et rien d'autre : c'est ce que le portail
    /// recalculera.
    #[test]
    fn le_defi_est_le_condense_du_verificateur() {
        let challenge = challenge_of("a".repeat(43).as_str());
        assert_eq!(challenge.len(), 43, "{challenge}");
        assert_ne!(challenge, "a".repeat(43));
        // Déterministe : deux appels sur la même entrée donnent le même défi.
        assert_eq!(challenge, challenge_of("a".repeat(43).as_str()));
    }

    #[tokio::test]
    async fn un_flow_ne_se_reprend_qu_une_fois() {
        let sessions = Sessions::new(Duration::from_secs(3600));
        let (state, _challenge) = sessions.begin().await;

        assert!(sessions.take_pending(&state).await.is_some());
        assert!(
            sessions.take_pending(&state).await.is_none(),
            "un retour rejoué ne doit pas rouvrir de session"
        );
    }

    #[tokio::test]
    async fn un_etat_inconnu_ne_reprend_rien() {
        let sessions = Sessions::new(Duration::from_secs(3600));
        sessions.begin().await;
        assert!(sessions.take_pending("état-inventé").await.is_none());
    }

    #[test]
    fn un_sujet_sans_prefixe_est_refuse() {
        assert!(subject_of("alice").is_err());
        assert!(subject_of("kdt:alice").is_ok());
    }

    #[test]
    fn les_groupes_repassent_par_la_validation() {
        assert!(groups_of(&["kdt:ops".to_string()]).is_ok());
        assert!(groups_of(&["ops".to_string()]).is_err());
        // Un sujet réservé ne doit pas traverser, même annoncé par le portail.
        assert!(groups_of(&["kdt:system:masters".to_string()]).is_err());
    }
}
