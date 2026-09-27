//! Namespaces view: lists every Namespace in the cluster as a first-class object list (like
//! `configmaps.rs`/`secrets.rs`), rather than the modal picker it used to be. Each row carries the
//! phase, age and provenance; the detail panel shows labels and annotations. `Enter` drills into a
//! namespace (scopes the event watcher to it), while `y`/`e`/`h`/`Ctrl-D` act on the object itself.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::{format_age, EventRecord, LineColor, Severity};
use crate::lang::{fill, Strings};
use crate::rbac::{detect_provenance, Provenance};

// `Serialize` pour kdt-web, sans le manifeste : le YAML se lit par le geste générique `y`, qui le
// relit au moment où on le demande au lieu de le faire voyager avec chaque ligne à chaque passe.
#[derive(Debug, Clone, serde::Serialize)]
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
    #[serde(skip)]
    pub manifest: String,
}

impl NamespaceInfo {
    /// `Active` est la norme, `Terminating` un namespace qui ne finit pas de partir — le plus
    /// souvent un finalizer qu'un controller disparu ne retirera plus.
    pub fn phase_tone(&self) -> LineColor {
        match self.phase.as_str() {
            "Active" => LineColor::Ok,
            "Terminating" => LineColor::Warn,
            _ => LineColor::Dim,
        }
    }

    /// L'enregistrement de la ligne : c'est lui qui donne à la vue `y`, `e`, `h`, `Ctrl-D`,
    /// l'onglet Related et l'analyse IA, sur le Namespace lui-même.
    pub fn record(&self, st: &Strings) -> EventRecord {
        let labels = if self.labels.is_empty() {
            "-".to_string()
        } else {
            self.labels.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
        };
        let message = fill(
            st.rec_namespace,
            &[
                ("name", &self.name),
                ("phase", &self.phase),
                ("origin", &self.provenance.label()),
                ("labels", &labels),
            ],
        );
        EventRecord {
            uid: format!("namespace|{}", self.name),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: if self.phase == "Terminating" { Severity::Warning } else { Severity::Normal },
            reason: "Namespace".to_string(),
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
            namespace: String::new(),
            name: self.name.clone(),
            message,
            component: String::new(),
            host: String::new(),
            count: 1,
        }
    }
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

    let items = match namespaces_inventory(&client).await {
        Ok(items) => items,
        Err(e) => return fail(&state, e),
    };

    let mut s = state.lock().expect("namespaces poisoned");
    s.loading = false;
    s.error = None;
    s.items = items;
}

/// Les namespaces du cluster, triés par nom — rendus au lieu d'être déposés, pour kdt-web.
pub async fn namespaces_inventory(client: &Client) -> Result<Vec<NamespaceInfo>, String> {
    let api: Api<Namespace> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let mut out: Vec<NamespaceInfo> = list.items.iter().map(build_info).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
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
