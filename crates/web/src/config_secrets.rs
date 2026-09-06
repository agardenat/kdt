//! Les Secrets et les ConfigMaps — deux vues jumelles que tout oppose sur un point.
//!
//! Une ConfigMap est du texte en clair : sa valeur voyage avec la ligne et s'affiche. Un Secret ne
//! montre jamais rien sans qu'on le demande.
//!
//! # Pourquoi la liste des Secrets ne porte pas les valeurs
//!
//! Le TUI garde les octets décodés dans `SecretInfo` : le processus qui dessine les a déjà, et
//! « révéler » n'y est qu'un basculement d'affichage — masqué par défaut, remis à masqué dès que
//! la sélection change, pour que rien ne traîne à l'écran.
//!
//! Sur le web, la même structure de données ne dit plus la même chose. Mettre les valeurs dans la
//! liste, ce serait les faire traverser le réseau **toutes les dix secondes, pour tous les secrets
//! de la portée**, et les laisser dans la mémoire du navigateur et dans l'onglet réseau des
//! devtools, où une capture d'écran les emporte. `SecretInfo` ne sérialise donc ni `data` ni
//! `manifest` — qui les contient aussi — et une valeur se demande secret par secret, par une
//! requête que le RBAC arbitre comme les autres.
//!
//! C'est le même principe que dans kdt, appliqué à un média où « ne pas afficher » ne suffit plus :
//! il faut ne pas envoyer.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use kdt::secrets::SecretInfo;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::AppState;

#[derive(Deserialize)]
pub struct ScopeQuery {
    #[serde(default)]
    ns: String,
}

/// Les Secrets de la portée — **sans leurs valeurs**.
pub async fn secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScopeQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    match kdt::secrets::secrets(client, namespace).await {
        Ok(inv) => {
            let (total, tls, expired, expiring) = summary(&inv.secrets);
            axum::Json(serde_json::json!({
                "secrets": inv.secrets.iter().map(secret_json).collect::<Vec<_>>(),
                // Absent, cert-manager n'a rien à dire sur l'émetteur — ce qui n'est pas la même
                // chose qu'un certificat dont l'émetteur est inconnu.
                "cert_manager_present": inv.cert_manager_present,
                "counts": {
                    "total": total,
                    "tls": tls,
                    "expired": expired,
                    "expiring": expiring,
                },
            }))
            .into_response()
        }
        Err(e) => refused(e),
    }
}

/// Le décompte du bandeau : `(total, tls, expirés, expirant sous 30 j)`.
fn summary(secrets: &[SecretInfo]) -> (usize, usize, usize, usize) {
    kdt::secrets::SecretsState {
        secrets: secrets.to_vec(),
        ..Default::default()
    }
    .summary()
}

fn secret_json(s: &SecretInfo) -> serde_json::Value {
    let mut value = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), format!("{}/{}", s.namespace, s.name).into());
        object.insert("is_tls".to_string(), s.is_tls().into());
        object.insert("provenance_label".to_string(), s.provenance.label().into());
        // Le ton de l'échéance, quand il y en a une. Un secret sans certificat n'a pas de verdict
        // à porter : lui en donner un ferait juger une ligne sur ce qu'elle n'est pas.
        object.insert(
            "expiry_tone".to_string(),
            match &s.tls {
                Some(c) => serde_json::to_value(c.expiry.tone()).unwrap_or(serde_json::Value::Null),
                None => serde_json::Value::Null,
            },
        );
        object.insert(
            "record".to_string(),
            serde_json::to_value(record("Secret", "v1", &s.namespace, &s.name))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

#[derive(Deserialize)]
pub struct RevealQuery {
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
}

/// Les valeurs d'un Secret, sur demande explicite.
///
/// Une requête par secret, jamais en lot : le geste est délibéré, il porte sur un objet nommé, et
/// il laisse une trace dans les logs du serveur — ce que ne ferait pas un champ de plus dans une
/// liste rafraîchie toute seule.
pub async fn reveal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RevealQuery>,
) -> Response {
    let Some(session) = crate::auth::current(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "aucune session", "reauthenticate": true })),
        )
            .into_response();
    };
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

    // Tracé nommément : c'est la seule lecture de kdt-web dont on veut savoir qui l'a faite et sur
    // quoi. Le RBAC l'autorisait déjà — la trace ne restreint rien, elle raconte.
    info!(
        subject = %session.subject,
        secret = %format!("{}/{}", query.namespace, query.name),
        "valeurs de Secret révélées"
    );

    match kdt::secrets::secret_values(client, &query.namespace, &query.name).await {
        Ok(values) => axum::Json(serde_json::json!({
            "values": values
                .into_iter()
                .map(|(key, raw)| {
                    // Les deux formes que le TUI propose sous `b` et `d` : le base64 tel que
                    // l'objet le porte, et le texte quand les octets en sont. Une valeur binaire
                    // n'a pas de forme décodée, et le dire vaut mieux que rendre des remplaçants
                    // Unicode qu'on prendrait pour le contenu.
                    let text = String::from_utf8(raw.clone()).ok();
                    serde_json::json!({
                        "key": key,
                        "base64": base64::engine::general_purpose::STANDARD.encode(&raw),
                        "text": text,
                        "bytes": raw.len(),
                    })
                })
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => refused(e),
    }
}

/// Les ConfigMaps de la portée, valeurs comprises.
pub async fn configmaps(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScopeQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    match kdt::configmaps::configmaps(client, namespace).await {
        Ok(items) => axum::Json(serde_json::json!({
            "configmaps": items
                .iter()
                .map(|cm| {
                    let mut value =
                        serde_json::to_value(cm).unwrap_or_else(|_| serde_json::json!({}));
                    if let Some(object) = value.as_object_mut() {
                        object.insert(
                            "uid".to_string(),
                            format!("{}/{}", cm.namespace, cm.name).into(),
                        );
                        object.insert("keys".to_string(), cm.keys().into());
                        object.insert(
                            "provenance_label".to_string(),
                            cm.provenance.label().into(),
                        );
                        object.insert(
                            "record".to_string(),
                            serde_json::to_value(record("ConfigMap", "v1", &cm.namespace, &cm.name))
                                .unwrap_or(serde_json::Value::Null),
                        );
                    }
                    value
                })
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => refused(e),
    }
}

/// L'enregistrement que le panneau d'inspection ouvre sur cette ligne.
///
/// Ni Secret ni ConfigMap n'ont d'état à juger — ils existent ou non — donc l'enregistrement porte
/// juste l'identité, et ce sont `Status` et `Related` qui ont quelque chose à dire.
fn record(kind: &str, api_version: &str, namespace: &str, name: &str) -> kdt::events::EventRecord {
    kdt::events::EventRecord {
        uid: format!("{}|{}/{}", kind.to_lowercase(), namespace, name),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: kdt::events::Severity::Normal,
        reason: kind.to_string(),
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        message: format!("{} {}/{}", kind, namespace, name),
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

fn refused(e: String) -> Response {
    warn!(erreur = %e, "lecture refusée");
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": e })),
    )
        .into_response()
}
