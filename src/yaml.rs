//! Live YAML view of an arbitrary Kubernetes object.
//!
//! The object is fetched by GVK through API discovery (so CRDs work the same as built-in kinds) and
//! rendered twice: `raw`, exactly as the API server returns it (`kubectl get -o yaml`), and `neat`,
//! stripped of the attributes added at runtime — bookkeeping metadata, the whole `status` block and
//! the fields the apiserver/kubelet default into pod specs — the way `kubectl neat` does.

use std::sync::{Arc, Mutex};

use kube::api::DynamicObject;
use kube::core::GroupVersionKind;
use kube::discovery::{self, Scope};
use kube::{Api, Client};
use serde_json::{json, Map, Value};

#[derive(Default, Debug, Clone)]
pub struct YamlState {
    // Identity ("apiVersion|kind|ns/name") of the object this content belongs to: a result whose key
    // no longer matches the current selection is dropped instead of overwriting the view.
    pub key: String,
    pub loading: bool,
    pub error: Option<String>,
    pub raw: String,
    pub neat: String,
}

pub type SharedYaml = Arc<Mutex<YamlState>>;

pub fn new_yaml_state() -> SharedYaml {
    Arc::new(Mutex::new(YamlState::default()))
}

// Fetch the object and render both forms into the shared state, keyed against the selection that
// asked for it.
pub async fn fetch_yaml(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    state: SharedYaml,
) {
    let result = load_object(&client, &api_version, &kind, &namespace, &name).await;
    let mut s = state.lock().expect("yaml state poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(value) => {
            s.raw = to_yaml(&value);
            s.neat = to_yaml(&neat(value));
            s.error = None;
        }
        Err(e) => {
            s.raw.clear();
            s.neat.clear();
            s.error = Some(e);
        }
    }
}

async fn load_object(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<Value, String> {
    if kind.is_empty() || name.is_empty() {
        return Err("objet sans kind/name".to_string());
    }
    let gvk = if let Some((g, v)) = api_version.split_once('/') {
        GroupVersionKind::gvk(g, v, kind)
    } else {
        GroupVersionKind::gvk("", api_version, kind)
    };
    let (ar, caps) = discovery::pinned_kind(client, &gvk)
        .await
        .map_err(|e| format!("discovery {}/{} : {}", api_version, kind, e))?;
    let api: Api<DynamicObject> = if caps.scope == Scope::Cluster {
        Api::all_with(client.clone(), &ar)
    } else {
        Api::namespaced_with(client.clone(), namespace, &ar)
    };
    let obj = api.get(name).await.map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(&obj).map_err(|e| e.to_string())?;
    // A GET normally echoes apiVersion/kind; re-add them if the server omitted them so the YAML
    // stays a valid, appliable manifest.
    if let Value::Object(map) = &mut value {
        map.entry("apiVersion").or_insert_with(|| json!(api_version));
        map.entry("kind").or_insert_with(|| json!(kind));
    }
    Ok(value)
}

fn to_yaml(value: &Value) -> String {
    serde_yaml::to_string(value).unwrap_or_else(|e| format!("sérialisation YAML impossible : {e}"))
}

// Metadata fields the apiserver owns: none of them survive a re-apply.
const META_NOISE: &[&str] = &[
    "creationTimestamp",
    "resourceVersion",
    "selfLink",
    "uid",
    "generation",
    "managedFields",
];

// Annotations written by controllers, not by the author of the manifest.
const ANNOTATION_NOISE: &[&str] = &[
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
];

// Keys whose contents are user payload with arbitrary key names — never walked, so a ConfigMap key
// literally named `uid` or `status` is left untouched.
const OPAQUE_KEYS: &[&str] = &["data", "stringData", "binaryData"];

// Drop the runtime attributes, keeping what a human actually authored.
pub fn neat(mut value: Value) -> Value {
    if let Value::Object(map) = &mut value {
        map.remove("status");
    }
    clean(&mut value);
    value
}

fn clean(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(meta)) = map.get_mut("metadata") {
                clean_metadata(meta);
            }
            // Any object carrying `containers` is a PodSpec, wherever it sits (Pod, Deployment
            // template, CronJob job template…), so defaults are stripped without listing kinds.
            if map.contains_key("containers") {
                clean_pod_spec(map);
            }
            for (k, child) in map.iter_mut() {
                if OPAQUE_KEYS.contains(&k.as_str()) {
                    continue;
                }
                clean(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(clean),
        _ => {}
    }
}

fn clean_metadata(meta: &mut Map<String, Value>) {
    for k in META_NOISE {
        meta.remove(*k);
    }
    if let Some(Value::Object(ann)) = meta.get_mut("annotations") {
        for k in ANNOTATION_NOISE {
            ann.remove(*k);
        }
        if ann.is_empty() {
            meta.remove("annotations");
        }
    }
}

// Fields the apiserver defaults into every pod spec, plus the service-account plumbing it injects.
fn clean_pod_spec(spec: &mut Map<String, Value>) {
    remove_default(spec, "dnsPolicy", json!("ClusterFirst"));
    remove_default(spec, "restartPolicy", json!("Always"));
    remove_default(spec, "schedulerName", json!("default-scheduler"));
    remove_default(spec, "terminationGracePeriodSeconds", json!(30));
    remove_default(spec, "enableServiceLinks", json!(true));
    remove_default(spec, "preemptionPolicy", json!("PreemptLowerPriority"));
    remove_default(spec, "priority", json!(0));
    remove_default(spec, "securityContext", json!({}));
    // `serviceAccount` is the deprecated mirror of `serviceAccountName`.
    if spec.get("serviceAccount") == spec.get("serviceAccountName") {
        spec.remove("serviceAccount");
    }

    retain_array(spec, "tolerations", |t| !is_default_toleration(t));
    retain_array(spec, "volumes", |v| {
        !v.get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .starts_with("kube-api-access-")
    });

    for key in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(Value::Array(containers)) = spec.get_mut(key) else { continue };
        for c in containers.iter_mut() {
            let Value::Object(c) = c else { continue };
            clean_container(c);
        }
    }
}

fn clean_container(c: &mut Map<String, Value>) {
    remove_default(c, "terminationMessagePath", json!("/dev/termination-log"));
    remove_default(c, "terminationMessagePolicy", json!("File"));
    remove_default(c, "resources", json!({}));
    retain_array(c, "volumeMounts", |m| {
        m.get("mountPath").and_then(Value::as_str)
            != Some("/var/run/secrets/kubernetes.io/serviceaccount")
    });
    if let Some(Value::Array(ports)) = c.get_mut("ports") {
        for p in ports.iter_mut() {
            if let Value::Object(p) = p {
                remove_default(p, "protocol", json!("TCP"));
            }
        }
    }
}

// The two tolerations the node-lifecycle controller adds to every pod.
fn is_default_toleration(t: &Value) -> bool {
    let key = t.get("key").and_then(Value::as_str).unwrap_or_default();
    matches!(key, "node.kubernetes.io/not-ready" | "node.kubernetes.io/unreachable")
        && t.get("effect").and_then(Value::as_str) == Some("NoExecute")
        && t.get("operator").and_then(Value::as_str) == Some("Exists")
}

fn remove_default(map: &mut Map<String, Value>, key: &str, default: Value) {
    if map.get(key) == Some(&default) {
        map.remove(key);
    }
}

// Filter an array field in place, dropping the field entirely once nothing is left.
fn retain_array(map: &mut Map<String, Value>, key: &str, keep: impl Fn(&Value) -> bool) {
    let Some(Value::Array(items)) = map.get_mut(key) else { return };
    items.retain(keep);
    if items.is_empty() {
        map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neat_strips_runtime_metadata_and_status() {
        let out = neat(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "web",
                "uid": "abc",
                "resourceVersion": "42",
                "managedFields": [{"manager": "kubectl"}],
                "creationTimestamp": "2026-01-01T00:00:00Z",
                "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
            },
            "status": {"phase": "Running"},
        }));
        let meta = out["metadata"].as_object().unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta["name"], json!("web"));
        assert!(out.get("status").is_none());
    }

    #[test]
    fn neat_strips_pod_spec_defaults_and_injected_plumbing() {
        let out = neat(json!({
            "kind": "Pod",
            "spec": {
                "dnsPolicy": "ClusterFirst",
                "restartPolicy": "Always",
                "schedulerName": "default-scheduler",
                "terminationGracePeriodSeconds": 30,
                "nodeName": "node-1",
                "serviceAccount": "app",
                "serviceAccountName": "app",
                "volumes": [{"name": "kube-api-access-x1y2"}],
                "tolerations": [
                    {"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute"},
                    {"key": "dedicated", "operator": "Equal", "value": "gpu"},
                ],
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "terminationMessagePath": "/dev/termination-log",
                    "terminationMessagePolicy": "File",
                    "ports": [{"containerPort": 80, "protocol": "TCP"}],
                    "volumeMounts": [
                        {"name": "kube-api-access-x1y2", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"},
                        {"name": "cfg", "mountPath": "/etc/app"},
                    ],
                }],
            },
        }));
        let spec = out["spec"].as_object().unwrap();
        assert!(spec.get("dnsPolicy").is_none());
        assert!(spec.get("volumes").is_none());
        assert!(spec.get("serviceAccount").is_none());
        assert_eq!(spec["nodeName"], json!("node-1"));
        assert_eq!(spec["serviceAccountName"], json!("app"));
        assert_eq!(spec["tolerations"].as_array().unwrap().len(), 1);
        let c = spec["containers"][0].as_object().unwrap();
        assert!(c.get("terminationMessagePath").is_none());
        assert!(c["ports"][0].get("protocol").is_none());
        assert_eq!(c["volumeMounts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn neat_leaves_user_payload_alone() {
        let out = neat(json!({
            "kind": "ConfigMap",
            "data": {"uid": "keep-me", "status": "keep-me-too", "creationTimestamp": "x"},
        }));
        assert_eq!(out["data"].as_object().unwrap().len(), 3);
    }
}
