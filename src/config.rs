//! Optional JSON config file: AI providers (OpenAI-compatible endpoints) and UI language.
//! The file may hold API keys in plaintext, so its filesystem permissions are the user's
//! responsibility.

use std::path::PathBuf;

use serde::Deserialize;

use crate::ai::AiLanguage;

#[derive(Debug, Clone, Deserialize)]
pub struct AiProvider {
    pub name: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    // Model context window in tokens (prompt + completion). When set, the AI prompt is trimmed to
    // fit so the request does not exceed the model's limit. None disables the global budget.
    pub context_window: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub openai_base_url: Option<String>,
    pub openai_api_key: Option<String>,
    pub openai_model: Option<String>,
    pub language: Option<String>,
    pub providers: Vec<AiProvider>,
    pub active_provider: Option<String>,
    // Extra namespaces treated as security-critical in the RBAC view, merged with the built-in list.
    pub critical_namespaces: Vec<String>,
    // Last state of the `²` fold: whether the top panel of a split view starts collapsed.
    pub hide_top_panel: Option<bool>,
}

// Load the config file, falling back to defaults when it is missing or malformed
// (a parse error is logged but never fatal).
pub fn load() -> FileConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str::<FileConfig>(&s) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "invalid config, falling back to defaults");
                FileConfig::default()
            }
        },
        Err(_) => FileConfig::default(),
    }
}

// Resolve the config path: explicit env var, then XDG config dir, then HOME, finally relative.
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("KDT_CONFIG").or_else(|_| std::env::var("KEV_CONFIG")) {
        return PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(home).join("kdt").join("config.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("kdt").join("config.json");
    }
    PathBuf::from(".config/kdt/config.json")
}

pub fn config_path_display() -> String {
    config_path().display().to_string()
}

// These are config values typed by the user, not UI text: they stay untranslated on purpose.
pub fn initial_language(file: &FileConfig) -> Option<AiLanguage> {
    let v = file.language.as_deref()?.to_lowercase();
    match v.as_str() {
        "fr" | "french" | "français" | "francais" => Some(AiLanguage::Fr),
        "en" | "english" | "anglais" => Some(AiLanguage::En),
        _ => None,
    }
}

// Language implied by the POSIX locale, used when the config file says nothing. A locale that is
// neither French nor English resolves to English rather than None: falling through to the French
// default would hand a French UI to someone who asked for neither.
pub fn system_language() -> Option<AiLanguage> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        let Ok(raw) = std::env::var(var) else { continue };
        // `LANGUAGE` holds a colon-separated preference list; the others hold one locale.
        let first = raw.split(':').next().unwrap_or("");
        let tag = first
            .split(['_', '.', '@'])
            .next()
            .unwrap_or("")
            .to_lowercase();
        match tag.as_str() {
            // Not a language: the C locale means "no localization chosen", so keep looking.
            "" | "c" | "posix" => continue,
            "fr" => return Some(AiLanguage::Fr),
            _ => return Some(AiLanguage::En),
        }
    }
    None
}

// Persist the language picked with the `L` key. Best-effort: a failure is logged, never fatal.
pub fn save_language(lang: AiLanguage) {
    save_key("language", serde_json::Value::String(lang.code().to_string()));
}

// Persist the `²` fold, so a panel folded away stays folded in the next session.
pub fn save_hide_top_panel(hidden: bool) {
    save_key("hide_top_panel", serde_json::Value::Bool(hidden));
}

// Write one key into the config file. Best-effort: a failure is logged, never fatal.
//
// The file is edited as raw JSON rather than re-serialized from `FileConfig`, because serializing
// would drop every key this struct does not know about and rewrite the plaintext API keys through
// our own code path. Mutating the single key leaves the rest of the file byte-identical.
fn save_key(key: &str, value: serde_json::Value) {
    let path = config_path();
    let existing = std::fs::read_to_string(&path).ok();
    let mut root = match existing.as_deref() {
        Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(v @ serde_json::Value::Object(_)) => v,
            // A malformed file is left alone: overwriting it would lose the user's API keys.
            _ => {
                tracing::warn!(file = %path.display(), key, "config unreadable, setting not saved");
                return;
            }
        },
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    let Some(obj) = root.as_object_mut() else { return };
    obj.insert(key.to_string(), value);
    let Ok(text) = serde_json::to_string_pretty(&root) else {
        return;
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(dir = %parent.display(), error = %e, "cannot create the config directory");
            return;
        }
    }
    // Capture the current mode before writing so an existing file keeps its permissions, and a new
    // one is created private: this file may hold API keys in plaintext.
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600)
    };
    if let Err(e) = std::fs::write(&path, text) {
        tracing::warn!(file = %path.display(), error = %e, "cannot write the config file");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
    }
}
