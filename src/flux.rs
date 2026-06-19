use std::sync::{Arc, Mutex};

use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxReady {
    Ready,
    Failed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FluxResource {
    pub kind: String,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub ready: FluxReady,
    pub suspended: bool,
    pub message: String,
    pub revision: String,
    pub age: String,
}

impl FluxResource {
    fn sort_key(&self) -> (u8, &str, &str, &str) {
        let bucket = match (self.suspended, self.ready) {
            (false, FluxReady::Failed) => 0,
            (false, FluxReady::Unknown) => 1,
            (true, _) => 2,
            (false, FluxReady::Ready) => 3,
        };
        (bucket, self.kind.as_str(), self.namespace.as_str(), self.name.as_str())
    }
}

#[derive(Default, Debug, Clone)]
pub struct FluxState {
    pub resources: Vec<FluxResource>,
    pub error: Option<String>,
    pub loading: bool,
}

impl FluxState {
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut ready = 0;
        let mut failed = 0;
        let mut unknown = 0;
        let mut suspended = 0;
        for r in &self.resources {
            if r.suspended {
                suspended += 1;
            }
            match r.ready {
                FluxReady::Ready => ready += 1,
                FluxReady::Failed => failed += 1,
                FluxReady::Unknown => unknown += 1,
            }
        }
        (ready, failed, unknown, suspended)
    }
}

pub type SharedFlux = Arc<Mutex<FluxState>>;

pub fn new_flux_state() -> SharedFlux {
    Arc::new(Mutex::new(FluxState::default()))
}

const CANDIDATES: &[(&str, &[&str], &str)] = &[
    ("kustomize.toolkit.fluxcd.io", &["v1", "v1beta2", "v1beta1"], "Kustomization"),
    ("helm.toolkit.fluxcd.io", &["v2", "v2beta2", "v2beta1"], "HelmRelease"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "GitRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "OCIRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "HelmRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "HelmChart"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "Bucket"),
];

pub async fn fetch_flux(client: Client, state: SharedFlux) {
    {
        let mut s = state.lock().expect("flux poisoned");
        s.loading = true;
        s.error = None;
    }

    let mut resources: Vec<FluxResource> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut found_crd = false;

    for (group, versions, kind) in CANDIDATES {
        let mut resolved = None;
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(&client, &gvk).await {
                resolved = Some((ar, *v));
                break;
            }
        }
        let Some((ar, version)) = resolved else { continue };
        found_crd = true;
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                let api_version = format!("{}/{}", group, version);
                for obj in &list.items {
                    resources.push(parse_flux(obj, kind, &api_version));
                }
            }
            Err(e) => errors.push(format!("{}: {}", kind, e)),
        }
    }

    resources.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("flux poisoned");
    s.loading = false;
    s.resources = resources;
    s.error = if !found_crd {
        Some("Flux CRDs introuvables (Flux n'est pas installé sur ce cluster ?)".into())
    } else if s.resources.is_empty() && !errors.is_empty() {
        Some(errors.join(" · "))
    } else {
        None
    };
}

fn parse_flux(obj: &DynamicObject, kind: &str, api_version: &str) -> FluxResource {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let suspended = obj
        .data
        .get("spec")
        .and_then(|s| s.get("suspend"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let status = obj.data.get("status");
    let ready_cond = status
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Ready"))
        });

    let (ready, message) = match ready_cond {
        Some(c) => {
            let st = c.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let msg = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let r = match st {
                "True" => FluxReady::Ready,
                "False" => FluxReady::Failed,
                _ => FluxReady::Unknown,
            };
            let combined = if r == FluxReady::Ready {
                collapse_ws(msg)
            } else {
                let mut m = String::new();
                if !reason.is_empty() {
                    m.push_str(reason);
                }
                if !msg.is_empty() {
                    if !m.is_empty() {
                        m.push_str(": ");
                    }
                    m.push_str(&collapse_ws(msg));
                }
                m
            };
            (r, combined)
        }
        None => (FluxReady::Unknown, "(pas de condition Ready)".to_string()),
    };

    let revision = flux_revision(status);
    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    FluxResource {
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        namespace,
        name,
        ready,
        suspended,
        message,
        revision,
        age,
    }
}

fn flux_revision(status: Option<&serde_json::Value>) -> String {
    let Some(status) = status else { return String::new() };
    let str_at = |path: &[&str]| -> Option<String> {
        let mut cur = status;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_str().map(|s| s.to_string())
    };
    let raw = str_at(&["lastAppliedRevision"])
        .or_else(|| str_at(&["lastAttemptedRevision"]))
        .or_else(|| str_at(&["artifact", "revision"]))
        .or_else(|| {
            status
                .get("history")
                .and_then(|h| h.as_array())
                .and_then(|a| a.first())
                .and_then(|h| h.get("chartVersion"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    shorten_revision(&raw)
}

fn shorten_revision(raw: &str) -> String {
    let (branch, digest) = match raw.split_once('@') {
        Some((b, d)) => (Some(b), d),
        None => (None, raw),
    };
    let short_digest = digest
        .rsplit_once(':')
        .map(|(_, h)| h)
        .unwrap_or(digest);
    let short_digest = if short_digest.len() > 12 {
        &short_digest[..12]
    } else {
        short_digest
    };
    match branch {
        Some(b) => format!("{}@{}", b, short_digest),
        None => short_digest.to_string(),
    }
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
