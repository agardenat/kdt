use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone)]
pub struct AiState {
    pub current_key: Option<String>,
    pub loading: bool,
    pub content: String,
    pub error: Option<String>,
    pub prompt_preview: String,
    pub stage: String,
    pub started_at: Option<Instant>,
    pub sections_count: usize,
    pub model: String,
    pub export_status: Option<String>,
}

pub fn update_stage(state: &SharedAi, key: &str, stage: impl Into<String>) {
    let mut s = state.lock().expect("ai state poisoned");
    if s.current_key.as_deref() == Some(key) {
        s.stage = stage.into();
    }
}

pub fn update_sections_count(state: &SharedAi, key: &str, count: usize) {
    let mut s = state.lock().expect("ai state poisoned");
    if s.current_key.as_deref() == Some(key) {
        s.sections_count = count;
    }
}

pub type SharedAi = Arc<Mutex<AiState>>;

pub fn new_ai_state() -> SharedAi {
    Arc::new(Mutex::new(AiState::default()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiLanguage { Fr, En }

impl AiLanguage {
    pub fn label(self) -> &'static str {
        match self { Self::Fr => "FR", Self::En => "EN" }
    }
    pub fn toggle(self) -> Self {
        match self { Self::Fr => Self::En, Self::En => Self::Fr }
    }
    fn system_prompt(self) -> &'static str {
        match self {
            Self::Fr => "Tu es un expert Kubernetes. On te fournit un événement Kubernetes ainsi que le statut de l'objet impliqué, ses logs récents, les autres événements liés, et des ressources contextuelles attachées (policies, RBAC, ingress, sources flux/argo, PV/PVC, etc.). Identifie la cause racine la plus probable et propose des actions correctives concrètes. Sois concis et structuré : Diagnostic, Cause probable, Actions recommandées.\n\nRÈGLES STRICTES de format :\n1. CHAQUE action recommandée DOIT être accompagnée de la commande exacte à exécuter (kubectl, helm, etc.) dans un bloc de code triple-backtick avec langage `sh`. Aucune recommandation sans commande associée.\n2. Les commandes longues DOIVENT être formatées sur plusieurs lignes en utilisant `\\` en fin de ligne pour permettre le copier-coller, en gardant chaque ligne sous ~100 caractères.\n3. Pour des inspections, fournis aussi la commande de vérification (kubectl describe, get -o yaml, logs, etc.).\n4. Les commandes inline courtes (noms de ressources, flags) restent en backticks simples.\n\nRéponds en français.",
            Self::En => "You are a Kubernetes expert. You receive a Kubernetes event along with the status of the involved object, recent logs, related events, and attached contextual resources (policies, RBAC, ingress, flux/argo sources, PV/PVC, etc.). Identify the most likely root cause and propose concrete remediation steps. Be concise and structured: Diagnosis, Likely cause, Recommended actions.\n\nSTRICT formatting rules:\n1. EVERY recommended action MUST be accompanied by the exact command to run (kubectl, helm, etc.) in a triple-backtick code block with language `sh`. Never give a recommendation without an associated command.\n2. Long commands MUST be split across multiple lines using `\\` line continuations so they can be copy-pasted, keeping each line under ~100 characters.\n3. For inspections, also provide the verification command (kubectl describe, get -o yaml, logs, etc.).\n4. Short inline commands (resource names, flags) stay in single backticks.\n\nAnswer in English.",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

impl AiConfig {
    pub fn from_env_and_file(file: &crate::config::FileConfig) -> Result<Self, String> {
        let api_key = std::env::var("OPENAI_API_KEY").ok()
            .or_else(|| file.openai_api_key.clone())
            .ok_or_else(|| format!(
                "OPENAI_API_KEY non définie (env OPENAI_API_KEY ou {})",
                crate::config::config_path_display(),
            ))?;
        let base_url = std::env::var("OPENAI_BASE_URL").ok()
            .or_else(|| std::env::var("OPENAI_API_BASE").ok())
            .or_else(|| file.openai_base_url.clone())
            .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
        let model = std::env::var("OPENAI_MODEL").ok()
            .or_else(|| file.openai_model.clone())
            .unwrap_or_else(|| "gpt-4o-mini".to_string());
        Ok(Self { base_url, api_key, model })
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

pub async fn query_ai(config: AiConfig, prompt: String, lang: AiLanguage, key: String, state: SharedAi) {
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let body = ChatRequest {
        model: &config.model,
        messages: vec![
            ChatMessage { role: "system", content: lang.system_prompt() },
            ChatMessage { role: "user", content: &prompt },
        ],
        temperature: 0.2,
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            store_error(&state, &key, format!("client: {}", e));
            return;
        }
    };

    update_stage(&state, &key, format!("Envoi de la requête à {}...", config.model));

    let result = client.post(&url)
        .bearer_auth(&config.api_key)
        .json(&body)
        .send()
        .await;

    update_stage(&state, &key, "Réception et analyse de la réponse...");

    match result {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                let snippet: String = text.chars().take(800).collect();
                store_error(&state, &key, format!("HTTP {}: {}", status, snippet));
                return;
            }
            match resp.json::<ChatResponse>().await {
                Ok(r) => {
                    let content = r.choices.into_iter().next()
                        .map(|c| c.message.content)
                        .unwrap_or_default();
                    let mut s = state.lock().expect("ai state poisoned");
                    if s.current_key.as_deref() != Some(&key) { return; }
                    s.loading = false;
                    s.content = content;
                    s.error = None;
                    s.stage.clear();
                }
                Err(e) => store_error(&state, &key, format!("parse: {}", e)),
            }
        }
        Err(e) => store_error(&state, &key, format!("requête: {}", e)),
    }
}

fn store_error(state: &SharedAi, key: &str, msg: String) {
    let mut s = state.lock().expect("ai state poisoned");
    if s.current_key.as_deref() != Some(key) { return; }
    s.loading = false;
    s.error = Some(msg);
}

pub async fn query_ai_direct(
    config: &AiConfig,
    lang: AiLanguage,
    prompt: &str,
) -> Result<String, String> {
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let body = ChatRequest {
        model: &config.model,
        messages: vec![
            ChatMessage { role: "system", content: lang.system_prompt() },
            ChatMessage { role: "user", content: prompt },
        ],
        temperature: 0.2,
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| format!("client: {}", e))?;
    let resp = client
        .post(&url)
        .bearer_auth(&config.api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("requête: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(800).collect();
        return Err(format!("HTTP {}: {}", status, snippet));
    }
    let r: ChatResponse = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    Ok(r
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default())
}
