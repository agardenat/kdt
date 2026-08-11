//! Namespaces view: lists every Namespace in the cluster as a first-class object list (like
//! `configmaps.rs`/`secrets.rs`), rather than the modal picker it used to be. Each row carries the
//! phase, age and provenance; the detail panel shows labels and annotations. `Enter` drills into a
//! namespace (scopes the event watcher to it), while `y`/`e`/`h`/`Ctrl-D` act on the object itself.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::format_age;
use crate::rbac::{detect_provenance, Provenance};

#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub name: String,
    // `status.phase`: "Active" or "Terminating" (empty when the API omits it).
    pub phase: String,
    pub age: String,
    pub provenance: Provenance,
    // Labels and annotations, sorted by key, for the detail panel.
    pub labels: Vec<(String, String)>,
    pub annotations: Vec<(String, String)>,
    // Full object serialized to YAML (managedFields stripped), for "copy manifest".
    pub manifest: String,
}

#[derive(Default, Debug, Clone)]
pub struct NamespacesState {
    pub items: Vec<NamespaceInfo>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedNamespaces = Arc<Mutex<NamespacesState>>;

pub fn new_namespaces_state() -> SharedNamespaces {
    Arc::new(Mutex::new(NamespacesState::default()))
}

pub async fn fetch_namespaces_view(client: Client, state: SharedNamespaces) {
    {
        let mut s = state.lock().expect("namespaces poisoned");
        s.loading = true;
        s.error = None;
    }

    let api: Api<Namespace> = Api::all(client.clone());
    let list = match api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };

    let mut out: Vec<NamespaceInfo> = Vec::with_capacity(list.items.len());
    for ns in &list.items {
        out.push(build_info(ns));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));

    let mut s = state.lock().expect("namespaces poisoned");
    s.loading = false;
    s.error = None;
    s.items = out;
}

fn build_info(ns: &Namespace) -> NamespaceInfo {
    let mut labels: Vec<(String, String)> = ns
        .metadata
        .labels
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    labels.sort_by(|a, b| a.0.cmp(&b.0));

    let mut annotations: Vec<(String, String)> = ns
        .metadata
        .annotations
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    annotations.sort_by(|a, b| a.0.cmp(&b.0));

    NamespaceInfo {
        name: ns.metadata.name.clone().unwrap_or_default(),
        phase: ns
            .status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .unwrap_or_default(),
        age: ns
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        provenance: detect_provenance(&ns.metadata),
        labels,
        annotations,
        manifest: manifest_yaml(ns),
    }
}

// Serialize the live object to a kubectl-like YAML manifest, dropping the noisy managedFields.
fn manifest_yaml(ns: &Namespace) -> String {
    let mut m = ns.clone();
    m.metadata.managed_fields = None;
    serde_yaml::to_string(&m).unwrap_or_default()
}

fn fail(state: &SharedNamespaces, msg: String) {
    let mut s = state.lock().expect("namespaces poisoned");
    s.loading = false;
    s.error = Some(msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_reads_phase_and_sorts_labels() {
        let mut ns = Namespace::default();
        ns.metadata.name = Some("prod".into());
        ns.metadata.labels = Some(
            [("b".to_string(), "2".to_string()), ("a".to_string(), "1".to_string())]
                .into_iter()
                .collect(),
        );
        ns.status = Some(k8s_openapi::api::core::v1::NamespaceStatus {
            phase: Some("Active".into()),
            ..Default::default()
        });
        let info = build_info(&ns);
        assert_eq!(info.name, "prod");
        assert_eq!(info.phase, "Active");
        assert_eq!(info.labels, vec![("a".into(), "1".into()), ("b".into(), "2".into())]);
    }
}
