//! L'analyse par une IA, `i` dans kdt.
//!
//! Le prompt est assemblé ici, par `kdt::ai`, à partir de ce que le cluster répond **au credential
//! de la personne connectée** : son statut, ses logs, ses évènements, et le contexte que
//! `gather_extra_context` va chercher. Une section absente veut souvent dire « pas le droit de la
//! lire », jamais « rien à voir ».
//!
//! # Ce qui part, et où
//!
//! Ce prompt quitte le cluster. Il porte des messages d'évènements, des lignes de log, des objets
//! entiers — donc, potentiellement, des secrets applicatifs qu'un pod a écrits dans ses logs. C'est
//! le même constat que dans kdt, et la même conséquence : l'endpoint doit être un endpoint de
//! confiance, et il n'est jamais choisi par le serveur — il est nommé, soit par l'exploitant dans
//! l'environnement du pod, soit par la personne dans son navigateur.
//!
//! # Deux mondes de fournisseurs, et pourquoi
//!
//! Un **fournisseur du serveur** est déclaré par l'exploitant dans `KDT_WEB_AI_PROVIDERS`. Sa clé
//! ne sort jamais du pod : le navigateur ne connaît que son nom et son modèle.
//!
//! Un **fournisseur personnel** est saisi dans l'interface et vit dans le navigateur, comme la clé
//! vit dans le fichier de configuration de kdt pour le TUI. C'est ce qui rend le réglage possible
//! « depuis l'app » sans que le serveur détienne la clé de qui que ce soit.
//!
//! Un endpoint nommé par un navigateur est une requête sortante que le serveur émet depuis
//! l'intérieur du cluster : c'est la définition d'une SSRF. D'où [`validate_custom_endpoint`], et
//! d'où `KDT_WEB_AI_ALLOW_CUSTOM=false`, qui ferme ce monde-là quand l'exploitant préfère n'offrir
//! que le sien.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use k8s_openapi::api::core::v1::Event as K8sEvent;
use kdt::ai::AiConfig;
use kdt::events::EventRecord;
use kube::api::ListParams;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

use crate::api::session_client;
use crate::lang::{ai_lang_of, lang_of};
use crate::AppState;

/// Ce que le navigateur peut savoir d'un fournisseur du serveur : de quoi le choisir, rien de plus.
///
/// Ni la clé — c'est tout l'intérêt de la déclarer côté serveur — ni l'URL complète, dont le
/// chemin n'apprend rien à qui choisit. L'hôte, lui, est ce qui dit **où part la donnée**, et c'est
/// une question qu'on doit pouvoir se poser avant d'envoyer un log.
#[derive(Serialize)]
pub struct ProviderInfo {
    name: String,
    model: String,
    host: String,
    context_window: Option<usize>,
}

/// Ce que ce serveur offre en matière d'IA, du point de vue du navigateur.
pub async fn config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Une session est exigée bien qu'aucun cluster ne soit lu : la liste des fournisseurs et de
    // leurs hôtes est une information sur le déploiement, pas une page d'accueil.
    if session_client(&state, &headers).await.is_err() {
        return unauthenticated();
    }

    let providers: Vec<ProviderInfo> = state
        .config
        .ai_providers
        .iter()
        .map(|p| ProviderInfo {
            name: p.name.clone(),
            model: p.model.clone().unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            host: host_of(p.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL)),
            context_window: p.context_window,
        })
        .collect();

    axum::Json(serde_json::json!({
        "providers": providers,
        "allow_custom": state.config.ai_allow_custom,
    }))
    .into_response()
}

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-4o-mini";

fn host_of(base_url: &str) -> String {
    reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| base_url.to_string())
}

/// Le fournisseur que le navigateur nomme.
///
/// Étiqueté explicitement : le serveur ne devine pas de quel monde vient un fournisseur en
/// regardant quels champs sont remplis. Un `api_key` oublié dans un `custom` doit être un refus,
/// pas une retombée silencieuse sur un fournisseur du serveur.
#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
enum ProviderChoice {
    /// Déclaré par l'exploitant. Le navigateur n'en donne que le nom ; la clé reste ici.
    Server { name: String },
    /// Saisi dans l'interface, et donc porté par la requête.
    Custom {
        base_url: String,
        model: String,
        api_key: String,
        #[serde(default)]
        context_window: Option<usize>,
    },
}

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    /// La ligne visée, telle que le serveur l'a émise — comme pour `/related`.
    record: EventRecord,
    provider: ProviderChoice,
    #[serde(default)]
    lang: String,
}

/// L'analyse, en SSE.
///
/// En flux parce que kdt l'est : une analyse prend dix secondes à une minute, et regarder la
/// réponse s'écrire dit qu'il se passe quelque chose là où un sablier ne dit rien. Les étapes de
/// l'enrichissement partent dans le même flux, pour la même raison.
///
/// `POST` plutôt qu'un `EventSource` : la cible est un enregistrement entier, pas un identifiant,
/// et le navigateur lit le flux à la main.
pub async fn analyze(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<AnalyzeRequest>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let ai_lang = ai_lang_of(&request.lang);
    let st = lang_of(&request.lang);

    let (config, provider_name) = match resolve(&state, request.provider) {
        Ok(pair) => pair,
        // Un fournisseur inconnu ou un endpoint refusé n'est pas une panne de l'analyse : c'est un
        // refus qui se lit avant qu'aucune donnée du cluster ne parte, donc en JSON, pas en SSE.
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };

    // Le canal borne ce qui peut s'accumuler si le navigateur lit moins vite que le modèle n'écrit.
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    let cluster = state.cluster_label.clone();
    let model = config.model.clone();

    tokio::spawn(async move {
        let _ = tx
            .send(Ok(sse("meta", serde_json::json!({
                "provider": provider_name,
                "model": model,
            }))))
            .await;

        let record = request.record;
        let ns_label = if record.namespace.is_empty() {
            st.vel_all_namespaces.to_string()
        } else {
            record.namespace.clone()
        };

        let stage = |text: String| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Ok(sse("stage", serde_json::json!({ "text": text })))).await;
            }
        };

        stage(st.msg_preparing.to_string()).await;
        let logs = logs_text(&client, &record, st).await;
        let status = status_text(&client, &record, st).await;
        let related = related_text(&client, &record).await;

        // Les mêmes sondes que `/related` et que le TUI, dans le même ordre : ce que l'onglet
        // Related montre est exactement ce que le modèle reçoit.
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<String>();
        let pump = {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(text) = progress_rx.recv().await {
                    let _ = tx.send(Ok(sse("stage", serde_json::json!({ "text": text })))).await;
                }
            })
        };
        let extra = kdt::enrich::gather_extra_context_with_progress(&client, &record, |s, _| {
            let _ = progress_tx.send(s.to_string());
        })
        .await;
        drop(progress_tx);
        let _ = pump.await;

        stage(st.ai_building_prompt.to_string()).await;
        let prompt = kdt::ai::build_ai_prompt(
            &record,
            &cluster,
            &ns_label,
            logs.as_deref(),
            status.as_deref(),
            related.as_deref(),
            &extra,
            kdt::ai::prompt_char_budget(config.context_window),
            st,
        );

        stage(kdt::lang::fill(st.ai_sending, &[("provider", &config.model)])).await;

        // Ce qui a déjà été poussé au navigateur, en octets du texte normalisé. Les deltas partent
        // au fil de l'eau : renvoyer le texte entier à chaque morceau coûterait le carré de sa
        // longueur, sur un canal qui en porte déjà des milliers.
        let mut sent = 0usize;
        let outcome = kdt::ai::stream_completion(
            &config,
            ai_lang,
            &prompt,
            Duration::from_secs(30),
            |raw| {
                let full = kdt::ai::normalize_ai_content(raw);
                // Un `\` en fin de morceau attend son échappement : le caractère qu'il porte peut
                // encore changer au morceau suivant, donc il n'est pas encore stable.
                let stable = if raw.ends_with('\\') {
                    &full[..full.len().saturating_sub(1)]
                } else {
                    full.as_str()
                };
                if stable.len() <= sent {
                    return true;
                }
                let chunk = stable[sent..].to_string();
                sent = stable.len();
                // `try_send` : le canal plein signifie un navigateur parti ou distancé, et attendre
                // ici bloquerait le flux du modèle. `Full` n'est pas fatal — le morceau suivant
                // repartira du même compteur — mais un canal fermé l'est.
                !matches!(
                    tx.try_send(Ok(sse("delta", serde_json::json!({ "text": chunk })))),
                    Err(mpsc::error::TrySendError::Closed(_))
                )
            },
        )
        .await;

        match outcome {
            Ok(_) => {
                let _ = tx.send(Ok(sse("done", serde_json::json!({})))).await;
            }
            Err(e) => {
                let _ = tx.send(Ok(sse("error", serde_json::json!({ "error": e })))).await;
            }
        }
    });

    Sse::new(ReceiverStream::new(rx))
        // Le silence dure le temps de l'enrichissement, puis celui de la réflexion du modèle : sans
        // battement, un proxy intermédiaire refermerait la connexion avant le premier mot.
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn sse(name: &str, payload: serde_json::Value) -> Event {
    Event::default().event(name).data(payload.to_string())
}

/// Le fournisseur nommé, et la clé qui va avec — celle du pod, ou celle du navigateur.
fn resolve(state: &AppState, choice: ProviderChoice) -> Result<(AiConfig, String), String> {
    match choice {
        ProviderChoice::Server { name } => {
            let p = state
                .config
                .ai_providers
                .iter()
                .find(|p| p.name == name)
                .ok_or_else(|| format!("fournisseur {name:?} inconnu de ce serveur"))?;
            let api_key = p
                .api_key
                .clone()
                .ok_or_else(|| format!("le fournisseur {name:?} n'a pas de clé sur ce serveur"))?;
            Ok((
                AiConfig {
                    base_url: p.base_url.clone().unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
                    api_key,
                    model: p.model.clone().unwrap_or_else(|| DEFAULT_MODEL.to_string()),
                    context_window: p.context_window,
                },
                name,
            ))
        }
        ProviderChoice::Custom { base_url, model, api_key, context_window } => {
            if !state.config.ai_allow_custom {
                return Err(
                    "ce serveur n'accepte que ses propres fournisseurs d'IA (KDT_WEB_AI_ALLOW_CUSTOM=false)"
                        .to_string(),
                );
            }
            validate_custom_endpoint(&base_url)?;
            if model.trim().is_empty() {
                return Err("le modèle est requis".to_string());
            }
            if api_key.trim().is_empty() {
                return Err("la clé API est requise".to_string());
            }
            Ok((
                AiConfig {
                    base_url: base_url.trim_end_matches('/').to_string(),
                    api_key,
                    model: model.clone(),
                    context_window,
                },
                model,
            ))
        }
    }
}

/// Ce qu'un navigateur a le droit de faire joindre au serveur.
///
/// La requête part **du pod**, donc de l'intérieur du cluster : un endpoint libre ferait de
/// kdt-web un relais vers tout ce que le réseau du pod atteint. Deux règles suffisent à couvrir ce
/// qui se tente depuis un navigateur :
///
/// * `https` seulement — ce qui écarte du même coup le service de métadonnées du cloud, qui n'écoute
///   qu'en clair, et évite qu'une clé API traverse le cluster en clair ;
/// * aucune adresse IP littérale privée, de bouclage, de lien-local ou non spécifiée.
///
/// Un **nom** qui résout vers une adresse privée passe : le vérifier demanderait de résoudre ici et
/// de rejoindre la même adresse ensuite, ce que ni `reqwest` ni le DNS ne garantissent. C'est le
/// risque résiduel, et c'est ce que `KDT_WEB_AI_ALLOW_CUSTOM=false` retire.
fn validate_custom_endpoint(base_url: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| format!("URL du fournisseur illisible : {e}"))?;
    if url.scheme() != "https" {
        return Err("l'URL du fournisseur doit être en https".to_string());
    }
    let Some(host) = url.host_str() else {
        return Err("l'URL du fournisseur n'a pas d'hôte".to_string());
    };
    // Un nom passe ; une adresse littérale est jugée. `host_str` rend l'IPv6 entre crochets, tels
    // qu'ils figurent dans l'URL.
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    let refused = match literal.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    };
    if refused {
        return Err("une adresse interne ne peut pas être visée depuis le serveur".to_string());
    }
    Ok(())
}

/// Les logs que porte cette ligne, avec la même règle que l'onglet Logs : un Pod rend les siens,
/// une ressource Flux ceux de son controller filtrés sur elle, les autres kinds n'en ont pas.
async fn logs_text(client: &Client, record: &EventRecord, st: &kdt::lang::Strings) -> Option<String> {
    let tail = kdt::ai::PROMPT_LOG_LINES as i64;
    if record.component == "flux" {
        let controllers = vec![kdt::flux::controller_for_kind(&record.kind).to_string()];
        let filter = (record.namespace.clone(), record.name.clone());
        return match kdt::events::flux_logs(client.clone(), &controllers, Some(&filter), 500).await {
            Ok(lines) => kdt::ai::prompt_logs_text(&lines, st),
            // Une lecture refusée est un fait sur le cluster, pas un silence : le dire au modèle
            // vaut mieux que de lui laisser croire qu'un controller n'a rien écrit.
            Err(e) => Some(kdt::lang::fill(st.cap_unavailable, &[("e", &e)])),
        };
    }
    if record.kind != "Pod" || record.namespace.is_empty() {
        return None;
    }
    let logs = kdt::events::pod_logs(
        client.clone(),
        &record.namespace,
        &record.name,
        tail,
        &kdt::events::LogOpts::default(),
    )
    .await;
    kdt::ai::prompt_logs_text(&logs.lines, st)
}

async fn status_text(client: &Client, record: &EventRecord, st: &kdt::lang::Strings) -> Option<String> {
    if record.kind.is_empty() || record.name.is_empty() {
        return None;
    }
    match kdt::events::object_status(
        client.clone(),
        &record.api_version,
        &record.kind,
        &record.namespace,
        &record.name,
    )
    .await
    {
        Ok(lines) => kdt::ai::prompt_status_text(&lines, st),
        Err(e) => Some(kdt::lang::fill(st.cap_unavailable, &[("e", &e)])),
    }
}

/// Les évènements du même objet, agrégés comme le TUI les agrège.
///
/// Le TUI les prend dans son tampon, qu'il tient déjà ; ici il faut les demander. Le sélecteur de
/// champ fait le tri côté apiserver : lister le namespace entier pour n'en garder qu'un objet
/// ferait payer à la personne un droit qu'elle n'a peut-être pas.
async fn related_text(client: &Client, record: &EventRecord) -> Option<String> {
    if record.name.is_empty() {
        return None;
    }
    // Le kind n'entre dans le sélecteur que s'il y en a un : une ligne synthétique peut n'en
    // porter aucun, et `involvedObject.kind=` serait un sélecteur que l'apiserver refuse.
    let mut selector = format!("involvedObject.name={}", record.name);
    if !record.kind.is_empty() {
        selector.push_str(&format!(",involvedObject.kind={}", record.kind));
    }
    let params = ListParams::default().fields(&selector);
    let api: Api<K8sEvent> = if record.namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &record.namespace)
    };
    let list = match api.list(&params).await {
        Ok(list) => list,
        Err(e) => {
            warn!(erreur = %e, "évènements liés illisibles");
            return None;
        }
    };
    let records: Vec<EventRecord> = list.items.into_iter().map(EventRecord::from_k8s).collect();
    kdt::ai::related_events_text(records.iter(), record)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Un endpoint nommé par un navigateur fait émettre une requête sortante **au pod**. Ces refus
    // sont ce qui sépare un fournisseur d'IA d'un relais vers le réseau interne du cluster.
    #[test]
    fn un_endpoint_personnel_ne_vise_ni_le_clair_ni_l_interieur() {
        assert!(validate_custom_endpoint("https://api.openai.com/v1").is_ok());
        assert!(validate_custom_endpoint("https://llm.corp.example/v1").is_ok());

        // Le service de métadonnées du cloud : en clair, et adresse de lien-local. Les deux règles
        // l'écartent, chacune de son côté.
        assert!(validate_custom_endpoint("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_custom_endpoint("https://169.254.169.254/").is_err());

        assert!(validate_custom_endpoint("http://api.openai.com/v1").is_err());
        assert!(validate_custom_endpoint("https://127.0.0.1:11434/v1").is_err());
        assert!(validate_custom_endpoint("https://10.42.0.13:8080/v1").is_err());
        assert!(validate_custom_endpoint("https://[::1]/v1").is_err());
        assert!(validate_custom_endpoint("file:///etc/passwd").is_err());
        assert!(validate_custom_endpoint("pas une url").is_err());
    }

    // Le monde est dit par la requête, jamais deviné : sans `source`, rien ne se lit.
    #[test]
    fn le_monde_du_fournisseur_est_etiquete() {
        let server: ProviderChoice =
            serde_json::from_value(serde_json::json!({ "source": "server", "name": "interne" }))
                .expect("un fournisseur du serveur");
        assert!(matches!(server, ProviderChoice::Server { .. }));

        let untagged = serde_json::from_value::<ProviderChoice>(
            serde_json::json!({ "base_url": "https://x/v1", "model": "m", "api_key": "k" }),
        );
        assert!(untagged.is_err());
    }
}
