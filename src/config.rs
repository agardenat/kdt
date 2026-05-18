use std::path::PathBuf;

use serde::Deserialize;

use crate::ai::AiLanguage;

#[derive(Debug, Clone, Deserialize)]
pub struct AiProvider {
    pub name: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
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
}

pub fn load() -> FileConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str::<FileConfig>(&s) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "config invalide, valeurs par défaut utilisées");
                FileConfig::default()
            }
        },
        Err(_) => FileConfig::default(),
    }
}

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

pub fn initial_language(file: &FileConfig) -> Option<AiLanguage> {
    let v = file.language.as_deref()?.to_lowercase();
    match v.as_str() {
        "fr" | "french" | "français" | "francais" => Some(AiLanguage::Fr),
        "en" | "english" | "anglais" => Some(AiLanguage::En),
        _ => None,
    }
}
