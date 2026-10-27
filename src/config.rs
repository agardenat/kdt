//! Optional YAML config file: AI providers (OpenAI-compatible endpoints), UI language, jump hosts.
//! The file may hold API keys in plaintext, so its filesystem permissions are the user's
//! responsibility.
//!
//! It used to be JSON. A `config.json` found where `config.yaml` is expected is converted once, at
//! the first launch of a version that reads YAML, and kept aside as `config.json.bak`. A path given
//! explicitly with a `.json` extension is still read as JSON.

use std::path::{Path, PathBuf};

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
    // Contexts reached through a jump host: see `jump.rs`.
    pub jumps: Vec<crate::jump::JumpConfig>,
}

// Load the config file, falling back to defaults when it is missing or malformed
// (a parse error is logged but never fatal).
pub fn load() -> FileConfig {
    let path = config_path();
    migrate_json(&path);
    // A conversion that could not write leaves the JSON file in place: it is still read.
    let legacy = path.with_extension("json");
    let (path, text) = match std::fs::read_to_string(&path) {
        Ok(s) => (path, s),
        Err(_) => match std::fs::read_to_string(&legacy) {
            Ok(s) if !is_json(&path) => (legacy, s),
            _ => return FileConfig::default(),
        },
    };
    match parse(&path, &text) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(file = %path.display(), error = %e, "invalid config, falling back to defaults");
            FileConfig::default()
        }
    }
}

fn is_json(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "json")
}

fn parse(path: &Path, text: &str) -> Result<FileConfig, String> {
    if is_json(path) {
        return serde_json::from_str(text).map_err(|e| e.to_string());
    }
    // An empty YAML document is not a mapping: it means "nothing configured", not an error.
    if text.trim().is_empty() {
        return Ok(FileConfig::default());
    }
    serde_yaml::from_str(text).map_err(|e| e.to_string())
}

// Keys in the order a person reads them, at every level: what to talk to first, how after. Keys
// not listed follow, alphabetically.
const KEY_ORDER: &[&str] = &[
    "language", "active_provider", "providers", "critical_namespaces", "hide_top_panel", "jumps",
    "name", "contexts", "base_url", "api_key", "model", "context_window", "command", "then", "user",
    "encode", "connect", "ready", "prompt", "escape", "open_timeout", "spare", "max_sessions",
];

fn reorder(value: serde_yaml::Value) -> serde_yaml::Value {
    use serde_yaml::Value;
    match value {
        Value::Mapping(map) => {
            let mut entries: Vec<(Value, Value)> = map.into_iter().map(|(k, v)| (k, reorder(v))).collect();
            entries.sort_by_cached_key(|(k, _)| {
                let key = k.as_str().unwrap_or_default().to_string();
                (KEY_ORDER.iter().position(|o| *o == key).unwrap_or(usize::MAX), key)
            });
            Value::Mapping(entries.into_iter().collect())
        }
        Value::Sequence(items) => Value::Sequence(items.into_iter().map(reorder).collect()),
        other => other,
    }
}

// The JSON file next to the expected YAML one, converted once. Best effort: a failure is logged,
// and the JSON file stays where it is, still read by `load`.
fn migrate_json(path: &Path) {
    if is_json(path) || path.exists() {
        return;
    }
    let legacy = path.with_extension("json");
    let Ok(text) = std::fs::read_to_string(&legacy) else { return };
    let yaml = match to_yaml(&text) {
        Ok(y) => y,
        Err(e) => {
            tracing::warn!(file = %legacy.display(), error = %e, "config not converted to YAML");
            return;
        }
    };
    // The new file keeps the old one's permissions: it holds the same API keys.
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&legacy).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o600)
    };
    if let Err(e) = std::fs::write(path, yaml) {
        tracing::warn!(file = %path.display(), error = %e, "config not converted to YAML");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    let backup = legacy.with_extension("json.bak");
    if let Err(e) = std::fs::rename(&legacy, &backup) {
        tracing::warn!(file = %legacy.display(), error = %e, "converted config left in place");
    }
    tracing::info!(from = %legacy.display(), to = %path.display(), "config converted to YAML");
}

fn to_yaml(json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let yaml = serde_yaml::to_value(&value).map_err(|e| e.to_string())?;
    serde_yaml::to_string(&reorder(yaml)).map_err(|e| e.to_string())
}

// Resolve the config path: explicit env var, then XDG config dir, then HOME, finally relative.
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("KDT_CONFIG").or_else(|_| std::env::var("KEV_CONFIG")) {
        return PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(home).join("kdt").join("config.yaml");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("kdt").join("config.yaml");
    }
    PathBuf::from(".config/kdt/config.yaml")
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
// The file is edited in place rather than re-serialized from `FileConfig`, because serializing
// would drop every key this struct does not know about and rewrite the plaintext API keys through
// our own code path. Changing the single key leaves the rest of the file byte-identical — in YAML
// that includes the comments, which is why the edit is made on the line and not on a parsed tree.
fn save_key(key: &str, value: serde_json::Value) {
    let path = config_path();
    migrate_json(&path);
    let existing = std::fs::read_to_string(&path).ok();
    if !is_json(&path) {
        // Writing a fresh YAML file next to an unconverted JSON one would hide it for good.
        if existing.is_none() && path.with_extension("json").exists() {
            tracing::warn!(file = %path.display(), key, "config not converted yet, setting not saved");
            return;
        }
        let Some(text) = set_yaml_key(existing.as_deref().unwrap_or(""), key, &value) else {
            tracing::warn!(file = %path.display(), key, "config unreadable, setting not saved");
            return;
        };
        write_preserving_mode(&path, text);
        return;
    }
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
    write_preserving_mode(&path, text);
}

// Replace the top-level `key:` line, or append one. None when the file, before or after, is not a
// YAML mapping: a malformed file is left alone, overwriting it would lose the user's API keys.
fn set_yaml_key(text: &str, key: &str, value: &serde_json::Value) -> Option<String> {
    let parsed = |t: &str| t.trim().is_empty() || matches!(serde_yaml::from_str::<serde_yaml::Value>(t), Ok(serde_yaml::Value::Mapping(_)));
    if !parsed(text) {
        return None;
    }
    let rendered = serde_yaml::to_string(value).ok()?;
    let line = format!("{key}: {}", rendered.trim_end());
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    match lines.iter().position(|l| l.strip_prefix(key).is_some_and(|rest| rest.starts_with(':'))) {
        Some(i) => lines[i] = line,
        None => lines.push(line),
    }
    let out = lines.join("\n") + "\n";
    parsed(&out).then_some(out)
}

fn write_preserving_mode(path: &Path, text: String) {
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
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600)
    };
    if let Err(e) = std::fs::write(path, text) {
        tracing::warn!(file = %path.display(), error = %e, "cannot write the config file");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kdt-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_json_config_is_converted_once_and_kept_aside() {
        let dir = scratch("migrate");
        let json = dir.join("config.json");
        std::fs::write(&json, r#"{"providers":[{"model":"m","name":"p"}],"language":"fr","unknown":1}"#).unwrap();
        let yaml = dir.join("config.yaml");
        migrate_json(&yaml);
        let text = std::fs::read_to_string(&yaml).unwrap();
        assert!(!json.exists());
        assert!(dir.join("config.json.bak").exists());
        assert!(text.starts_with("language: fr\n"), "{text}");
        assert!(text.find("name: p").unwrap() < text.find("model: m").unwrap(), "{text}");
        assert!(text.contains("unknown: 1"), "keys kdt does not know survive: {text}");
        let cfg = parse(&yaml, &text).unwrap();
        assert_eq!(cfg.providers[0].name, "p");
        // Already converted: the backup is not touched again.
        std::fs::write(&json, "{}").unwrap();
        migrate_json(&yaml);
        assert!(json.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_yaml_key_is_set_on_its_line_and_comments_stay() {
        let text = "# mine\nlanguage: fr  # comment lost with the value\nproviders: []\n";
        let out = set_yaml_key(text, "language", &serde_json::json!("en")).unwrap();
        assert_eq!(out, "# mine\nlanguage: en\nproviders: []\n");
        let out = set_yaml_key(&out, "hide_top_panel", &serde_json::json!(true)).unwrap();
        assert!(out.ends_with("hide_top_panel: true\n"));
        assert_eq!(set_yaml_key("", "language", &serde_json::json!("fr")).unwrap(), "language: fr\n");
        assert!(set_yaml_key("- a list\n", "language", &serde_json::json!("fr")).is_none());
    }

    #[test]
    fn an_empty_yaml_file_is_an_empty_config() {
        assert!(parse(Path::new("config.yaml"), "\n").unwrap().jumps.is_empty());
    }
}
