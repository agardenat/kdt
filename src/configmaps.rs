//! ConfigMaps view: lists every ConfigMap in the cluster with its key count and total size, and the
//! detail panel shows each key's value inline (ConfigMap data is plain text, not secret, so it is
//! displayed directly — no reveal toggle, unlike `secrets.rs`).
//!
//! Binary entries (`binaryData`) are surfaced by key name only, since they are not text. Reads follow
//! the same Shared-state pattern as `secrets.rs`/`rbac.rs`.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::format_age;
use crate::rbac::{detect_provenance, Provenance};

#[derive(Debug, Clone)]
pub struct ConfigMapInfo {
    pub namespace: String,
    pub name: String,
    // Text keys with their values, sorted by key.
    pub data: Vec<(String, String)>,
    // Names of `binaryData` keys (values omitted — not text).
    pub binary_keys: Vec<String>,
    pub age: String,
    pub provenance: Provenance,
    // Sum of all text + binary value sizes, for the SIZE column.
    pub total_bytes: usize,
    // Full object serialized to YAML (managedFields stripped), for "copy manifest".
    pub manifest: String,
}

impl ConfigMapInfo {
    // Every key name (text then binary) — drives the copy picker and the DATA count.
    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<String> = self.data.iter().map(|(k, _)| k.clone()).collect();
        k.extend(self.binary_keys.iter().cloned());
        k
    }

    fn sort_key(&self) -> (String, String) {
        (self.namespace.clone(), self.name.clone())
    }
}

#[derive(Default, Debug, Clone)]
pub struct ConfigMapsState {
    pub items: Vec<ConfigMapInfo>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedConfigMaps = Arc<Mutex<ConfigMapsState>>;

pub fn new_configmaps_state() -> SharedConfigMaps {
    Arc::new(Mutex::new(ConfigMapsState::default()))
}

pub async fn fetch_configmaps(client: Client, state: SharedConfigMaps) {
    {
        let mut s = state.lock().expect("configmaps poisoned");
        s.loading = true;
        s.error = None;
    }

    let api: Api<ConfigMap> = Api::all(client.clone());
    let list = match api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };

    let mut out: Vec<ConfigMapInfo> = Vec::with_capacity(list.items.len());
    for cm in &list.items {
        out.push(build_info(cm));
    }
    out.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("configmaps poisoned");
    s.loading = false;
    s.error = None;
    s.items = out;
}

fn build_info(cm: &ConfigMap) -> ConfigMapInfo {
    let mut data: Vec<(String, String)> = cm
        .data
        .as_ref()
        .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    data.sort_by(|a, b| a.0.cmp(&b.0));

    let mut binary_keys: Vec<String> = cm
        .binary_data
        .as_ref()
        .map(|d| d.keys().cloned().collect())
        .unwrap_or_default();
    binary_keys.sort();

    let text_bytes: usize = data.iter().map(|(_, v)| v.len()).sum();
    let bin_bytes: usize = cm
        .binary_data
        .as_ref()
        .map(|d| d.values().map(|b| b.0.len()).sum())
        .unwrap_or(0);

    ConfigMapInfo {
        namespace: cm.metadata.namespace.clone().unwrap_or_default(),
        name: cm.metadata.name.clone().unwrap_or_default(),
        data,
        binary_keys,
        age: cm
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        provenance: detect_provenance(&cm.metadata),
        total_bytes: text_bytes + bin_bytes,
        manifest: manifest_yaml(cm),
    }
}

// Serialize the live object to a kubectl-like YAML manifest, dropping the noisy managedFields.
fn manifest_yaml(cm: &ConfigMap) -> String {
    let mut m = cm.clone();
    m.metadata.managed_fields = None;
    serde_yaml::to_string(&m).unwrap_or_default()
}

fn fail(state: &SharedConfigMaps, msg: String) {
    let mut s = state.lock().expect("configmaps poisoned");
    s.loading = false;
    s.error = Some(msg);
}

// Compact human size for the SIZE column (B / KiB / MiB).
pub fn human_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(512), "512B");
        assert_eq!(human_size(2048), "2.0K");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0M");
    }

    #[test]
    fn keys_lists_text_then_binary() {
        let cm = ConfigMapInfo {
            namespace: "n".into(),
            name: "c".into(),
            data: vec![("a".into(), "x".into()), ("b".into(), "y".into())],
            binary_keys: vec!["bin".into()],
            age: String::new(),
            provenance: Provenance::Unmanaged,
            total_bytes: 0,
            manifest: String::new(),
        };
        assert_eq!(cm.keys(), ["a", "b", "bin"]);
    }
}
