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
    // Value written to the config file, and the tag Typst uses for hyphenation.
    pub fn code(self) -> &'static str {
        match self { Self::Fr => "fr", Self::En => "en" }
    }
    fn system_prompt(self) -> &'static str {
        match self {
            Self::Fr => "Expert Kubernetes. On te fournit un événement, le statut de l'objet, ses logs, les événements liés et des ressources contextuelles (policies, RBAC, ingress, sources flux/argo, PV/PVC…).\n\nRÈGLES :\n1. N'invente aucun problème. Ne signale que ce que le contexte montre noir sur blanc ; pas de panne supposée, pas d'erreur extrapolée. Si rien n'indique de souci, dis-le en une phrase — situation saine, rien de spécial à faire — et arrête-toi là, sans action ni commande.\n2. Sinon : cause racine la plus probable puis actions correctives, sous les titres Diagnostic, Cause probable, Actions recommandées. Concis.\n3. Chaque action porte sa commande exacte (kubectl, helm…) dans un bloc ```sh ; aucune reco sans commande. Coupe les commandes longues avec `\\` en fin de ligne, sous ~100 caractères. Pour une inspection, donne aussi la commande de vérification.\n4. Commandes courtes inline en backticks simples.\n\nRéponds en français.",
            Self::En => "Kubernetes expert. You receive an event, the object's status, its logs, related events and contextual resources (policies, RBAC, ingress, flux/argo sources, PV/PVC…).\n\nRULES:\n1. Never invent a problem. Report only what the context shows in black and white; no assumed failure, no extrapolated error. If nothing points to an issue, say so in one sentence — healthy, nothing to do — and stop there, with no action and no command.\n2. Otherwise: most likely root cause then remediation, under the headings Diagnosis, Likely cause, Recommended actions. Concise.\n3. Every action carries its exact command (kubectl, helm…) in a ```sh block; no recommendation without a command. Split long commands with `\\` line continuations, under ~100 characters. For an inspection, also give the verification command.\n4. Short inline commands stay in single backticks.\n\nAnswer in English.",
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
        let api_key = p.api_key.clone().ok_or_else(|| {
            crate::lang::fill(
                crate::lang::active().ai_no_api_key,
                &[
                    ("provider", &p.name),
                    ("env", &crate::config::config_path_display()),
                ],
            )
        })?;
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
// `pub` parce que kdt-web en a besoin : il rend les deltas au navigateur au fil de l'eau, en SSE,
// au lieu de les déposer dans un état partagé qu'un rendu relit.
pub async fn stream_completion(
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
        .map_err(|e| crate::lang::fill(crate::lang::active().ai_request, &[("e", &e.to_string())]))?;

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
    update_stage(
        &state,
        &key,
        crate::lang::fill(crate::lang::t(lang).ai_sending, &[("provider", &config.model)]),
    );

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

// ---------------------------------------------------------------------------
// La construction du prompt.
//
// Elle vivait dans `ui.rs`, donc derrière la feature `tui` : kdt-web ne pouvait pas l'appeler, et
// aurait fini par en écrire une seconde. Deux prompts pour la même question, ce sont deux réponses
// différentes du même cluster — la règle qui vaut pour les verdicts vaut ici.
//
// Rien de ce qui suit ne connaît d'état : des chaînes, un `EventRecord`, et la table de langue
// passée en argument plutôt que lue dans le global — un serveur répond à plusieurs personnes à la
// fois, dont rien ne dit qu'elles lisent la même langue.
// ---------------------------------------------------------------------------

use crate::events::{EventRecord, LineColor, Severity};
use crate::lang::Strings;

// Char budgets for the high-volume free-text prompt sections. Logs and status are kept by their
// tail (most recent/most diagnostic content) once over budget.
pub const MAX_LOGS_CHARS: usize = 12_000;
pub const MAX_STATUS_CHARS: usize = 6_000;
const MAX_RELATED_LINES: usize = 50;
/// Le nombre de lignes de log que le prompt emporte, et que son titre annonce.
pub const PROMPT_LOG_LINES: usize = 200;

// Collapse runs of identical consecutive lines into "<line>  (xN)" so repeated log/status spam does
// not eat the token budget verbatim.
pub fn collapse_repeats<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut run: Option<(&'a str, usize)> = None;
    let flush = |out: &mut Vec<String>, line: &str, n: usize| {
        out.push(if n > 1 { format!("{line}  (x{n})") } else { line.to_string() });
    };
    for line in lines {
        match run {
            Some((prev, n)) if prev == line => run = Some((prev, n + 1)),
            Some((prev, n)) => { flush(&mut out, prev, n); run = Some((line, 1)); }
            None => run = Some((line, 1)),
        }
    }
    if let Some((prev, n)) = run { flush(&mut out, prev, n); }
    out
}

// Keep the last `max` chars of `s` (recent content is the most diagnostic for logs/status),
// aligned to a char boundary and prefixed with an elision marker when truncated.
pub fn cap_chars_tail(s: String, max: usize, st: &Strings) -> String {
    if s.len() <= max { return s; }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) { start += 1; }
    crate::lang::fill(st.prompt_truncated, &[("body", &s[start..])])
}

/// Les dernières lignes de log, repliées et plafonnées, telles que le prompt les porte.
///
/// `None` quand il n'y a rien : une section vide coûte des tokens et se lit comme un trou que le
/// modèle peut chercher à combler. Une erreur de lecture, elle, n'est pas rien — c'est à l'appelant
/// de la dire, parce qu'elle vient de sa propre source.
pub fn prompt_logs_text(lines: &[String], st: &Strings) -> Option<String> {
    if lines.is_empty() { return None; }
    let start = lines.len().saturating_sub(PROMPT_LOG_LINES);
    let collapsed = collapse_repeats(lines[start..].iter().map(|l| l.as_str()));
    Some(cap_chars_tail(collapsed.join("\n"), MAX_LOGS_CHARS, st))
}

/// L'état de l'objet, mis en forme par kdt, replié et plafonné pour le prompt.
///
/// Le ton de chaque ligne est écarté : il peint l'écran, il n'ajoute rien à un texte que le modèle
/// lit — et il coûterait un préfixe par ligne.
pub fn prompt_status_text(lines: &[(LineColor, String)], st: &Strings) -> Option<String> {
    if lines.is_empty() { return None; }
    let collapsed = collapse_repeats(lines.iter().map(|(_, t)| t.as_str()));
    Some(cap_chars_tail(collapsed.join("\n"), MAX_STATUS_CHARS, st))
}

// Aggregate the events of the same object into the prompt's "related events" section. Duplicates
// (same severity/reason/message) collapse into one line, summing their occurrence counts and
// keeping the most recent timestamp, then the 50 most recent lines are kept.
pub fn related_events_text<'a>(
    records: impl IntoIterator<Item = &'a EventRecord>,
    rec: &EventRecord,
) -> Option<String> {
    use k8s_openapi::jiff::Timestamp;
    let mut order: Vec<(Severity, String, String)> = Vec::new();
    let mut agg: std::collections::HashMap<(Severity, String, String), (Timestamp, i64)> =
        std::collections::HashMap::new();
    for r in records
        .into_iter()
        .filter(|r| r.namespace == rec.namespace && r.name == rec.name && r.kind == rec.kind)
    {
        let key = (r.severity, r.reason.clone(), r.message.clone());
        match agg.get_mut(&key) {
            Some((time, count)) => {
                *count += r.count.max(1) as i64;
                if r.time > *time { *time = r.time; }
            }
            None => {
                order.push(key.clone());
                agg.insert(key, (r.time, r.count.max(1) as i64));
            }
        }
    }
    let mut related: Vec<(Timestamp, String)> = order
        .into_iter()
        .map(|key| {
            let (time, count) = agg[&key];
            let (sev, reason, message) = key;
            let line = format!(
                "[{}] {} {} (x{}) — {}",
                time,
                match sev { Severity::Warning => "WARN", Severity::Normal => "OK" },
                reason, count, message,
            );
            (time, line)
        })
        .collect();
    related.sort_by_key(|(t, _)| *t);
    if related.len() > MAX_RELATED_LINES {
        let drop = related.len() - MAX_RELATED_LINES;
        related.drain(0..drop);
    }
    if related.is_empty() {
        None
    } else {
        Some(related.into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n"))
    }
}

// Rough char/token ratio for dense Kubernetes JSON, and tokens held back for the system prompt,
// the model's answer, and a safety margin. Used to derive a char budget from the context window.
const CHARS_PER_TOKEN_EST: usize = 3;
const COMPLETION_RESERVE_TOKENS: usize = 4096;

// Convert a provider context window (tokens) into a char budget for the whole user prompt.
pub fn prompt_char_budget(context_window: Option<usize>) -> Option<usize> {
    context_window
        .map(|toks| toks.saturating_sub(COMPLETION_RESERVE_TOKENS).saturating_mul(CHARS_PER_TOKEN_EST))
}

// Assemble the enrichment sections within `budget` chars, dropping the lowest-priority ones (later
// in the list) when the budget is exhausted and noting how many were omitted. At least the first
// (highest-priority) section is always included even if it alone exceeds the budget.
fn build_extra_block(extra: &[(String, String)], budget: Option<usize>, st: &Strings) -> String {
    if extra.is_empty() { return st.prompt_none.to_string(); }
    let mut out = String::new();
    let mut omitted = 0;
    for (i, (title, body)) in extra.iter().enumerate() {
        let sep = if out.is_empty() { "" } else { "\n\n" };
        let section = format!("{sep}### {title}\n```json\n{body}\n```");
        if let Some(b) = budget {
            if !out.is_empty() && out.len() + section.len() > b {
                omitted = extra.len() - i;
                break;
            }
        }
        out.push_str(&section);
    }
    if omitted > 0 {
        out.push_str(&st.plural(
            omitted,
            st.prompt_sections_omitted_one,
            st.prompt_sections_omitted_many,
        ));
    }
    out
}

// Assemble the full prompt sent to the model: event metadata, object status, recent logs, related
// events, and enrichment sections. This is the complete payload transmitted to the AI endpoint.
//
// Mirrors `build_ai_prompt_inner`'s parameters plus the budget; grouping them would only move the
// same list into a struct used at a single call site.
#[allow(clippy::too_many_arguments)]
pub fn build_ai_prompt(
    rec: &EventRecord,
    ctx_label: &str,
    ns_label: &str,
    logs: Option<&str>,
    status: Option<&str>,
    related: Option<&str>,
    extra: &[(String, String)],
    char_budget: Option<usize>,
    st: &Strings,
) -> String {
    // Two-pass: render the skeleton with a placeholder for the enrichment block, measure the fixed
    // part, then fill the block with whatever fits in the remaining budget. With no enrichment at
    // all there is no placeholder to substitute and the section is dropped along with it.
    const PLACEHOLDER: &str = "\u{0}";
    let has_extra = !extra.is_empty();
    let ph = if has_extra { Some(PLACEHOLDER) } else { None };
    let skeleton = build_ai_prompt_inner(rec, ctx_label, ns_label, logs, status, related, ph);
    if !has_extra { return skeleton; }
    let fixed_len = skeleton.len() - PLACEHOLDER.len();
    let extra_budget = char_budget.map(|b| b.saturating_sub(fixed_len));
    let extra_block = build_extra_block(extra, extra_budget, st);
    skeleton.replace(PLACEHOLDER, &extra_block)
}

// Kept deliberately terse: every heading here is paid for on each analysis, and the model already
// has its instructions from the system prompt — repeating them in the request only costs tokens and
// nudges it towards finding something to say. Sections with nothing in them are not emitted at all.
fn build_ai_prompt_inner(
    rec: &EventRecord,
    ctx_label: &str,
    ns_label: &str,
    logs: Option<&str>,
    status: Option<&str>,
    related: Option<&str>,
    extra_block: Option<&str>,
) -> String {
    let mut out = format!(
"# Événement Kubernetes
cluster {ctx} · ns {ns_label}
{time} {sev} {reason} · {kind} {api} · {ns}/{name} · {comp} · x{count}
{msg}",
        ctx = ctx_label,
        ns_label = ns_label,
        time = rec.time,
        sev = match rec.severity { Severity::Warning => "Warning", Severity::Normal => "Normal" },
        reason = rec.reason,
        kind = rec.kind,
        api = rec.api_version,
        ns = rec.namespace,
        name = rec.name,
        comp = rec.component,
        count = rec.count,
        msg = rec.message,
    );
    for (title, body) in [
        ("## Statut", status),
        ("## Logs (200 dernières lignes)", logs),
        ("## Événements liés", related),
        ("## Contexte attaché", extra_block),
    ] {
        if let Some(body) = body {
            out.push_str(&format!("\n\n{title}\n{body}"));
        }
    }
    out.push_str("\n\n## Demande\nAnalyse ce contexte selon tes règles. Si des policies Kyverno ou des règles RBAC sont fournies, désigne la règle en cause et le patch minimal.");
    out
}
