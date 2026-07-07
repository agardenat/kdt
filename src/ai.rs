//! OpenAI-compatible chat client used for event/diagnostic analysis.
//!
//! Security note: the prompt sent here is assembled from live cluster data (event messages,
//! pod logs, object status, RBAC/Ingress/PV objects, etc.) and is transmitted to the
//! configured `base_url`. Logs in particular may contain secrets. Use only trusted endpoints;
//! an `http://` base_url sends the bearer key and payload in cleartext.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use serde::{Deserialize, Serialize};

// Shared progress/result state for the AI panel. `current_key` identifies the in-flight request
// so that stale background tasks do not overwrite the state of a newer one.
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

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-4o-mini";

#[derive(Debug, Clone)]
pub struct AiProviderResolved {
    pub name: String,
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub context_window: Option<usize>,
}

// Build the list of selectable providers from the config, then synthesize a "default" provider
// from the legacy `OPENAI_*` env vars / `openai_*` config fields for backward compatibility.
pub fn resolve_providers(file: &crate::config::FileConfig) -> Vec<AiProviderResolved> {
    let mut out: Vec<AiProviderResolved> = file
        .providers
        .iter()
        .map(|p| AiProviderResolved {
            name: p.name.clone(),
            base_url: p.base_url.clone().unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            model: p.model.clone().unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            api_key: p.api_key.clone(),
            context_window: p.context_window,
        })
        .collect();

    let legacy_key = std::env::var("OPENAI_API_KEY").ok().or_else(|| file.openai_api_key.clone());
    let legacy_base = std::env::var("OPENAI_BASE_URL").ok()
        .or_else(|| std::env::var("OPENAI_API_BASE").ok())
        .or_else(|| file.openai_base_url.clone());
    let legacy_model = std::env::var("OPENAI_MODEL").ok().or_else(|| file.openai_model.clone());
    let legacy_ctx = std::env::var("OPENAI_CONTEXT_WINDOW").ok().and_then(|v| v.parse::<usize>().ok());

    let want_default = file.providers.is_empty()
        || legacy_key.is_some()
        || legacy_base.is_some()
        || legacy_model.is_some();
    if want_default && !out.iter().any(|p| p.name == "default") {
        out.push(AiProviderResolved {
            name: "default".to_string(),
            base_url: legacy_base.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            model: legacy_model.unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            api_key: legacy_key,
            context_window: legacy_ctx,
        });
    }

    if out.is_empty() {
        out.push(AiProviderResolved {
            name: "default".to_string(),
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            api_key: None,
            context_window: None,
        });
    }
    out
}

pub fn default_provider_index(
    file: &crate::config::FileConfig,
    providers: &[AiProviderResolved],
) -> usize {
    if let Some(name) = &file.active_provider {
        if let Some(i) = providers.iter().position(|p| &p.name == name) {
            return i;
        }
    }
    0
}

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub context_window: Option<usize>,
}

impl AiConfig {
    pub fn from_resolved(p: &AiProviderResolved) -> Result<Self, String> {
        let api_key = p.api_key.clone().ok_or_else(|| format!(
            "Clé API absente pour le fournisseur '{}' (env OPENAI_API_KEY ou {})",
            p.name,
            crate::config::config_path_display(),
        ))?;
        Ok(Self {
            base_url: p.base_url.clone(),
            api_key,
            model: p.model.clone(),
            context_window: p.context_window,
        })
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
    stream: bool,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

// Streaming (SSE) chunk shape: {"choices":[{"delta":{"content":"..."}}]}
#[derive(Deserialize)]
struct ChatStreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    delta: StreamDelta,
}

#[derive(Deserialize)]
struct StreamDelta {
    #[serde(default)]
    content: Option<String>,
}

// Some models emit literal escape sequences (e.g. "\n") inside the JSON string content.
// Decode the common ones so the markdown renders correctly. Returns input untouched if no '\'.
pub fn normalize_ai_content(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('n') => { chars.next(); out.push('\n'); }
            Some('t') => { chars.next(); out.push('\t'); }
            Some('r') => { chars.next(); }
            Some('"') => { chars.next(); out.push('"'); }
            Some('\\') => { chars.next(); out.push('\\'); }
            _ => out.push('\\'),
        }
    }
    out
}

// Fire a chat completion and stream progress/result into the shared state. Every state write is
// guarded by `current_key` so a superseded request silently drops its result instead of clobbering.
// Fire a streaming (SSE) chat completion, feeding the running accumulated raw content to `on_delta`
// after each chunk. `on_delta` returns false to abort early (e.g. the request was superseded).
// Returns the full raw (un-normalized) content on success.
async fn stream_completion(
    config: &AiConfig,
    lang: AiLanguage,
    prompt: &str,
    connect_timeout: Duration,
    mut on_delta: impl FnMut(&str) -> bool,
) -> Result<String, String> {
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let body = ChatRequest {
        model: &config.model,
        messages: vec![
            ChatMessage { role: "system", content: lang.system_prompt() },
            ChatMessage { role: "user", content: prompt },
        ],
        temperature: 0.2,
        stream: true,
    };

    // No global `.timeout()`: it would cut a legitimately long stream. Bound connect + per-read only.
    let client = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(Duration::from_secs(120))
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

    let mut stream = resp.bytes_stream();
    let mut buf = String::new(); // holds an incomplete trailing SSE line between chunks
    let mut raw = String::new(); // accumulated assistant content

    'outer: while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| format!("flux: {}", e))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));

        // Process complete lines; keep the last (possibly partial) line in `buf`.
        while let Some(nl) = buf.find('\n') {
            let line = buf[..nl].trim_end_matches('\r').to_string();
            buf.drain(..=nl);

            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data.is_empty() { continue; }
            if data == "[DONE]" { break 'outer; }

            if let Ok(parsed) = serde_json::from_str::<ChatStreamChunk>(data) {
                if let Some(delta) = parsed.choices.into_iter().next().and_then(|c| c.delta.content) {
                    if !delta.is_empty() {
                        raw.push_str(&delta);
                        if !on_delta(&raw) { break 'outer; }
                    }
                }
            }
        }
    }

    Ok(raw)
}

// Stream a chat completion into the shared UI state. Every state write is guarded by `current_key`
// so a superseded request silently drops its result instead of clobbering a newer one.
pub async fn query_ai(config: AiConfig, prompt: String, lang: AiLanguage, key: String, state: SharedAi) {
    update_stage(&state, &key, format!("Envoi de la requête à {}...", config.model));

    // Append each delta to the panel content; the render loop (polled every 250ms) shows it live.
    let on_delta = |raw: &str| {
        let mut s = state.lock().expect("ai state poisoned");
        if s.current_key.as_deref() != Some(&key) { return false; }
        if !s.stage.is_empty() { s.stage.clear(); }
        s.content = normalize_ai_content(raw);
        s.error = None;
        true
    };

    match stream_completion(&config, lang, &prompt, Duration::from_secs(30), on_delta).await {
        Ok(raw) => {
            let mut s = state.lock().expect("ai state poisoned");
            if s.current_key.as_deref() != Some(&key) { return; }
            s.loading = false;
            s.content = normalize_ai_content(&raw);
            s.error = None;
            s.stage.clear();
        }
        Err(e) => store_error(&state, &key, e),
    }
}

fn store_error(state: &SharedAi, key: &str, msg: String) {
    let mut s = state.lock().expect("ai state poisoned");
    if s.current_key.as_deref() != Some(key) { return; }
    s.loading = false;
    s.error = Some(msg);
}

// Blocking-style variant used by the batch PDF extraction: returns the content directly
// instead of mutating shared UI state. Streams under the hood for timeout resilience.
pub async fn query_ai_direct(
    config: &AiConfig,
    lang: AiLanguage,
    prompt: &str,
) -> Result<String, String> {
    let raw = stream_completion(config, lang, prompt, Duration::from_secs(30), |_| true).await?;
    Ok(normalize_ai_content(&raw))
}
