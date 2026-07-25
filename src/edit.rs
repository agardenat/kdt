//! Guarded edit of an arbitrary Kubernetes object, round-tripped through the user's `$EDITOR`.
//!
//! Two questions are answered before anything is written back, because most failed edits fail for
//! one of them: *will this change survive?* and *will the API server even take it?* The first is
//! ownership — an object applied by Flux, Argo or Helm is put back at the next reconciliation, and
//! a pod owned by a ReplicaSet loses the change the moment it is recreated. The second is
//! mutability — a running pod only accepts a new image, a Job or a PVC only a handful of fields,
//! and everything under `status` belongs to the controller whatever the user typed.
//!
//! Both are reported structured ([`Reason`] before the editor opens, [`Diff`] once it closes) so the
//! UI localises them and colours them. As with [`crate::delete`], none of them blocks anything: the
//! user is told what will happen and remains free to go ahead.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::{DynamicObject, PostParams};
use kube::{Api, Client};
use serde_json::Value;

use crate::delete::{controller_owner_of, gitops_owner_of, GitOpsTool, Level};
use crate::yaml::{dynamic_api, dynamic_resource, to_yaml};

// One reason an edit is likely to be pointless or refused, as data: the UI turns it into a
// localised sentence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reason {
    // Applied by a GitOps engine: the change is overwritten at the next reconciliation, and the
    // repository — not the cluster — is where it belongs.
    GitOps { tool: GitOpsTool, detail: String },
    // Owned by a controller, which owns the spec: the change lasts until the object is recreated.
    OwnedBy { kind: String, name: String },
    // Already being deleted: whatever is written now goes away with the object.
    Terminating,
    // A pod that has run to completion: nothing about it is live any more.
    Completed { phase: String },
    // The API server answered `no` to a `can-i update`.
    Forbidden,
    // ConfigMap/Secret marked `immutable: true`: the payload can no longer be changed at all.
    Immutable,
    // A running pod: of the whole spec, only container images can be updated in place.
    RunningPod,
    // Kinds whose spec is mostly frozen once created (Job, PVC, StatefulSet…).
    PartialSpec { kind: String },
}

impl Reason {
    pub fn level(&self) -> Level {
        match self {
            Reason::GitOps { .. }
            | Reason::Terminating
            | Reason::Completed { .. }
            | Reason::Forbidden => Level::Danger,
            Reason::OwnedBy { .. }
            | Reason::Immutable
            | Reason::RunningPod
            | Reason::PartialSpec { .. } => Level::Warn,
        }
    }
}

// Everything worth warning about before handing `obj` to the editor, most severe first. The
// `can-i update` answer is not decided here — it needs the API server — and is appended by
// [`preflight`].
pub fn assess(obj: &Value) -> Vec<Reason> {
    let kind = obj.get("kind").and_then(Value::as_str).unwrap_or_default();
    let mut out = Vec::new();

    if let Some((tool, detail)) = gitops_owner_of(obj) {
        out.push(Reason::GitOps { tool, detail });
    }
    if obj
        .get("metadata")
        .and_then(|m| m.get("deletionTimestamp"))
        .is_some_and(|v| !v.is_null())
    {
        out.push(Reason::Terminating);
    }
    if let Some((kind, name)) = controller_owner_of(obj) {
        out.push(Reason::OwnedBy { kind, name });
    }
    match kind {
        "Pod" => {
            let phase = obj
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            match phase {
                "Succeeded" | "Failed" => {
                    out.push(Reason::Completed { phase: phase.to_string() })
                }
                _ => out.push(Reason::RunningPod),
            }
        }
        "Job" | "PersistentVolumeClaim" | "StatefulSet" => {
            out.push(Reason::PartialSpec { kind: kind.to_string() })
        }
        "ConfigMap" | "Secret" if obj.get("immutable") == Some(&Value::Bool(true)) => {
            out.push(Reason::Immutable)
        }
        _ => {}
    }

    out.sort_by_key(|r| std::cmp::Reverse(r.level()));
    out
}

// What the user actually changed, sorted into the buckets that decide whether applying is worth
// doing: `paths` is every difference, the other three are the subsets that will be ignored,
// rejected, or that make the document a different object altogether.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Diff {
    pub paths: Vec<String>,
    pub server_owned: Vec<String>,
    pub immutable: Vec<String>,
    pub identity: Vec<String>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    // Every single change lands on a field the API server owns: applying would leave the object
    // exactly as it is now.
    pub fn is_noop(&self) -> bool {
        !self.paths.is_empty() && self.paths.iter().all(|p| self.server_owned.contains(p))
    }

    // At least one change the API server will refuse outright.
    pub fn rejected(&self) -> bool {
        !self.immutable.is_empty() || !self.identity.is_empty()
    }
}

// Beyond this many differing paths the list stops being readable — and an edit that rewrites forty
// fields is not one the panel can usefully summarise anyway.
const MAX_PATHS: usize = 40;

// The fields that make the document point at a *different* object: changing one is never an edit.
const IDENTITY: &[&str] =
    &["apiVersion", "kind", "metadata.name", "metadata.namespace", "metadata.uid"];

// Metadata the API server writes and re-writes: editing it is either ignored or a source of
// conflict, never a change to the object.
const SERVER_METADATA: &[&str] = &[
    "metadata.resourceVersion",
    "metadata.uid",
    "metadata.creationTimestamp",
    "metadata.generation",
    "metadata.managedFields",
    "metadata.selfLink",
    "metadata.deletionTimestamp",
    "metadata.deletionGracePeriodSeconds",
];

// Compare the fetched object with the edited one and classify every difference.
pub fn diff(before: &Value, after: &Value, kind: &str) -> Diff {
    let mut paths = Vec::new();
    walk("", before, after, &mut paths);
    paths.truncate(MAX_PATHS);

    let identity: Vec<String> =
        paths.iter().filter(|p| IDENTITY.contains(&p.as_str())).cloned().collect();
    let server_owned: Vec<String> = paths.iter().filter(|p| is_server_owned(p)).cloned().collect();
    let immutable: Vec<String> = paths
        .iter()
        .filter(|p| !identity.contains(p) && is_immutable(kind, p, before))
        .cloned()
        .collect();
    Diff { paths, server_owned, immutable, identity }
}

// Collect the dotted path of every leaf that differs. Arrays are compared element by element when
// they are the same length, and reported whole otherwise: a reordered or resized list is one change
// to a human, not one per index.
fn walk(prefix: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    if a == b || out.len() >= MAX_PATHS {
        return;
    }
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys = x.keys().chain(y.keys().filter(|k| !x.contains_key(k.as_str())));
            for k in keys {
                let child =
                    if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                walk(&child, x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null), out);
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (xa, ya)) in x.iter().zip(y).enumerate() {
                walk(&format!("{}[{}]", prefix, i), xa, ya, out);
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

fn is_server_owned(path: &str) -> bool {
    under(path, "status") || SERVER_METADATA.contains(&path)
}

// Whether `path` names a field Kubernetes freezes once the object exists. Deliberately conservative:
// only rules that hold for every cluster are encoded, so a warning here is a warning the API server
// will confirm.
fn is_immutable(kind: &str, path: &str, before: &Value) -> bool {
    match kind {
        // A running pod takes a new image and little else; the rest of the spec is sealed.
        "Pod" => under(path, "spec") && !pod_mutable(path),
        "Job" => {
            under(path, "spec")
                && !under_any(
                    path,
                    &[
                        "spec.parallelism",
                        "spec.activeDeadlineSeconds",
                        "spec.ttlSecondsAfterFinished",
                        "spec.suspend",
                    ],
                )
        }
        // A PVC can only grow, and only through its storage request.
        "PersistentVolumeClaim" => under(path, "spec") && !under(path, "spec.resources"),
        "StatefulSet" => {
            under(path, "spec")
                && !under_any(
                    path,
                    &[
                        "spec.replicas",
                        "spec.template",
                        "spec.updateStrategy",
                        "spec.persistentVolumeClaimRetentionPolicy",
                        "spec.minReadySeconds",
                        "spec.ordinals",
                    ],
                )
        }
        "Service" => under_any(
            path,
            &["spec.clusterIP", "spec.clusterIPs", "spec.ipFamilies", "spec.ipFamilyPolicy"],
        ),
        "Deployment" | "ReplicaSet" | "DaemonSet" => under(path, "spec.selector"),
        "ConfigMap" | "Secret" => {
            before.get("immutable") == Some(&Value::Bool(true))
                && under_any(path, &["data", "binaryData", "stringData", "immutable"])
        }
        "CustomResourceDefinition" => {
            under_any(path, &["spec.group", "spec.names.kind", "spec.names.plural", "spec.scope"])
        }
        _ => false,
    }
}

// The parts of a pod spec that can still be changed on a live pod.
fn pod_mutable(path: &str) -> bool {
    if under_any(
        path,
        &[
            "spec.activeDeadlineSeconds",
            "spec.tolerations",
            "spec.terminationGracePeriodSeconds",
            "spec.ephemeralContainers",
        ],
    ) {
        return true;
    }
    ["spec.containers[", "spec.initContainers["].iter().any(|p| {
        path.strip_prefix(p)
            .and_then(|rest| rest.split_once("]."))
            .is_some_and(|(_, field)| field == "image")
    })
}

// `path` is `root` itself or something nested under it.
fn under(path: &str, root: &str) -> bool {
    path == root
        || (path.len() > root.len()
            && path.starts_with(root)
            && matches!(path.as_bytes()[root.len()], b'.' | b'['))
}

fn under_any(path: &str, roots: &[&str]) -> bool {
    roots.iter().any(|r| under(path, r))
}

#[derive(Default, Debug, Clone)]
pub struct EditState {
    // Identity ("apiVersion|kind|ns/name") of the object the content belongs to: a result whose key
    // no longer matches the open panel is dropped instead of overwriting it.
    pub key: String,
    pub loading: bool,
    // Preflight failure (object gone, RBAC…). Nothing can be edited without the document, so unlike
    // the delete flow this one is terminal: the panel shows the error and closes.
    pub error: Option<String>,
    pub reasons: Vec<Reason>,
    // The object as fetched, and the very same document rendered as YAML for the editor.
    pub doc: Value,
    pub text: String,
    pub applying: bool,
    pub done: Option<Result<(), String>>,
}

pub type SharedEdit = Arc<Mutex<EditState>>;

pub fn new_edit_state() -> SharedEdit {
    Arc::new(Mutex::new(EditState::default()))
}

// Fetch the object, publish it and the guard-rails that apply to editing it.
pub async fn preflight(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    state: SharedEdit,
) {
    let result = load(&client, &api_version, &kind, &namespace, &name).await;
    let mut s = state.lock().expect("edit state poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok((doc, reasons)) => {
            s.text = to_yaml(&doc);
            s.doc = doc;
            s.reasons = reasons;
            s.error = None;
        }
        Err(e) => {
            s.reasons.clear();
            s.doc = Value::Null;
            s.text.clear();
            s.error = Some(e);
        }
    }
}

// Write the edited document back with a plain PUT, the way `kubectl edit` does: the resourceVersion
// carried by the document makes the API server reject the write if the object moved underneath,
// rather than silently clobbering someone else's change.
// One more argument than the delete flow, for the same flat list of object coordinates: grouping
// them into a struct here alone would just make this call read differently from its neighbours.
#[allow(clippy::too_many_arguments)]
pub async fn apply(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    doc: Value,
    state: SharedEdit,
) {
    let result = replace(&client, &api_version, &kind, &namespace, &name, doc).await;
    let mut s = state.lock().expect("edit state poisoned");
    if s.key != key {
        return;
    }
    s.applying = false;
    s.done = Some(result);
}

async fn replace(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    doc: Value,
) -> Result<(), String> {
    let api = dynamic_api(client, api_version, kind, namespace).await?;
    let obj: DynamicObject =
        serde_json::from_value(doc).map_err(|e| format!("document inexploitable : {e}"))?;
    api.replace(name, &PostParams::default(), &obj).await.map(|_| ()).map_err(api_error_text)
}

// kube renders an API failure by dumping the whole response — the message, an escaped second copy
// of it, and the diff the server computed — which is unreadable in a panel. The server's own
// `message` is the part that tells the user what to fix.
fn api_error_text(e: kube::Error) -> String {
    match e {
        kube::Error::Api(resp) if !resp.message.is_empty() => resp.message,
        other => other.to_string(),
    }
}

async fn load(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<(Value, Vec<Reason>), String> {
    if kind.is_empty() || name.is_empty() {
        return Err("objet sans kind/name".to_string());
    }
    let (api, ar) = dynamic_resource(client, api_version, kind, namespace).await?;
    let obj = api.get(name).await.map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(&obj).map_err(|e| e.to_string())?;
    // A GET normally echoes apiVersion/kind, but a DynamicObject round-trip can drop them: put the
    // requested ones back so the document stays a valid manifest and the PUT keeps its identity.
    if let Value::Object(map) = &mut value {
        map.entry("apiVersion").or_insert_with(|| Value::String(api_version.to_string()));
        map.entry("kind").or_insert_with(|| Value::String(kind.to_string()));
        // Field ownership bookkeeping: unreadable, enormous, and never meant to be typed by hand.
        if let Some(Value::Object(meta)) = map.get_mut("metadata") {
            meta.remove("managedFields");
        }
    }

    let mut reasons = assess(&value);
    if !can_update(client, &ar, namespace, name).await {
        reasons.insert(0, Reason::Forbidden);
    }
    Ok((value, reasons))
}

// Ask the API server whether this user may update this object. A failure to ask is not an answer:
// the check stays silent rather than claiming a permission problem it could not establish.
async fn can_update(client: &Client, ar: &kube::api::ApiResource, namespace: &str, name: &str) -> bool {
    let review = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                group: Some(ar.group.clone()),
                resource: Some(ar.plural.clone()),
                namespace: (!namespace.is_empty()).then(|| namespace.to_string()),
                name: Some(name.to_string()),
                verb: Some("update".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let api: Api<SelfSubjectAccessReview> = Api::all(client.clone());
    match api.create(&PostParams::default(), &review).await {
        Ok(r) => r.status.map(|s| s.allowed).unwrap_or(true),
        Err(_) => true,
    }
}

// The editor to hand the file to: `$KDT_EDITOR` first for a kdt-specific choice, then the
// conventional variables, and `vi` as the last resort every POSIX system has. The value may carry
// arguments ("code -w", "nvim -u NONE"), split on whitespace the way `kubectl edit` does.
pub fn editor_command() -> (String, Vec<String>) {
    let raw = ["KDT_EDITOR", "KUBE_EDITOR", "VISUAL", "EDITOR"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "vi".to_string());
    let mut parts = raw.split_whitespace().map(str::to_string);
    let program = parts.next().unwrap_or_else(|| "vi".to_string());
    (program, parts.collect())
}

// Where the document is dropped for the editor. The pid keeps concurrent kdt sessions apart, and
// the object coordinates make the file recognisable in the editor's title bar.
pub fn temp_path(kind: &str, namespace: &str, name: &str) -> PathBuf {
    let slug = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
            .collect()
    };
    let stem = if namespace.is_empty() {
        format!("{}-{}", slug(kind), slug(name))
    } else {
        format!("{}-{}-{}", slug(kind), slug(namespace), slug(name))
    };
    std::env::temp_dir().join(format!("kdt-edit-{}-{}.yaml", stem, std::process::id()))
}

// Written 0600 and never world-readable: a Secret's data goes through this file.
pub fn write_temp(path: &Path, content: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{} : {e}", path.display()))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("{} : {e}", path.display()))
}

pub fn read_temp(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))
}

pub fn remove_temp(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// Parse what came back from the editor. Anything that is not a single YAML mapping is refused here
// rather than by the API server, so the user gets the error while the buffer is still at hand.
pub fn parse(text: &str) -> Result<Value, String> {
    let value: Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("le document n'est pas un objet YAML".to_string());
    }
    Ok(value)
}

// Run the editor on `path`, inheriting the terminal — the caller is responsible for having handed
// it over first.
pub async fn run_editor(path: &Path) -> Result<(), String> {
    let (program, args) = editor_command();
    let status = tokio::process::Command::new(&program)
        .args(args)
        .arg(path)
        .status()
        .await
        .map_err(|e| format!("{program} : {e}"))?;
    if !status.success() {
        return Err(format!("{program} : {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_flux_managed_object_warns_that_the_edit_will_not_survive() {
        let reasons = assess(&json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "namespace": "apps",
                "labels": {
                    "kustomize.toolkit.fluxcd.io/name": "apps",
                    "kustomize.toolkit.fluxcd.io/namespace": "flux-system",
                },
            },
        }));
        assert_eq!(
            reasons,
            vec![Reason::GitOps {
                tool: GitOpsTool::FluxKustomize,
                detail: "flux-system/apps".to_string()
            }]
        );
    }

    #[test]
    fn a_running_pod_owned_by_a_replicaset_warns_twice() {
        let reasons = assess(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "web-1",
                "namespace": "apps",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc", "controller": true}],
            },
            "status": {"phase": "Running"},
        }));
        assert_eq!(
            reasons,
            vec![
                Reason::OwnedBy { kind: "ReplicaSet".to_string(), name: "web-abc".to_string() },
                Reason::RunningPod,
            ]
        );
    }

    #[test]
    fn a_finished_pod_and_a_terminating_object_are_dangers() {
        let done = assess(&json!({
            "kind": "Pod",
            "metadata": {"name": "job-1"},
            "status": {"phase": "Succeeded"},
        }));
        assert_eq!(done, vec![Reason::Completed { phase: "Succeeded".to_string() }]);

        let going = assess(&json!({
            "kind": "ConfigMap",
            "metadata": {"name": "cfg", "deletionTimestamp": "2026-01-01T00:00:00Z"},
        }));
        assert_eq!(going, vec![Reason::Terminating]);
        assert_eq!(going[0].level(), Level::Danger);
    }

    #[test]
    fn an_immutable_configmap_is_flagged_and_its_data_is_rejected() {
        let cm = json!({
            "kind": "ConfigMap",
            "metadata": {"name": "cfg"},
            "immutable": true,
            "data": {"a": "1"},
        });
        assert_eq!(assess(&cm), vec![Reason::Immutable]);

        let mut edited = cm.clone();
        edited["data"]["a"] = json!("2");
        let d = diff(&cm, &edited, "ConfigMap");
        assert_eq!(d.paths, vec!["data.a".to_string()]);
        assert_eq!(d.immutable, vec!["data.a".to_string()]);
        assert!(d.rejected());
    }

    #[test]
    fn a_plain_deployment_triggers_nothing() {
        assert!(assess(&json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "apps"},
        }))
        .is_empty());
    }

    #[test]
    fn an_unchanged_document_diffs_to_nothing() {
        let obj = json!({"kind": "ConfigMap", "data": {"a": "1"}});
        let d = diff(&obj, &obj, "ConfigMap");
        assert!(d.is_empty());
        assert!(!d.is_noop());
    }

    #[test]
    fn changing_only_status_and_server_metadata_is_a_no_op() {
        let before = json!({
            "kind": "Deployment",
            "metadata": {"name": "web", "resourceVersion": "42"},
            "spec": {"replicas": 2},
            "status": {"readyReplicas": 2},
        });
        let mut after = before.clone();
        after["status"]["readyReplicas"] = json!(9);
        after["metadata"]["resourceVersion"] = json!("43");

        let d = diff(&before, &after, "Deployment");
        assert_eq!(d.paths, vec!["metadata.resourceVersion", "status.readyReplicas"]);
        assert!(d.is_noop());
        assert!(!d.rejected());
    }

    #[test]
    fn a_pod_accepts_a_new_image_but_not_a_new_node() {
        let before = json!({
            "kind": "Pod",
            "metadata": {"name": "web"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx:1.25"}],
            },
        });

        let mut image = before.clone();
        image["spec"]["containers"][0]["image"] = json!("nginx:1.27");
        let d = diff(&before, &image, "Pod");
        assert_eq!(d.paths, vec!["spec.containers[0].image".to_string()]);
        assert!(d.immutable.is_empty());

        let mut node = before.clone();
        node["spec"]["nodeName"] = json!("node-2");
        let d = diff(&before, &node, "Pod");
        assert_eq!(d.immutable, vec!["spec.nodeName".to_string()]);
        assert!(d.rejected());
    }

    #[test]
    fn a_statefulset_takes_replicas_but_not_its_service_name() {
        let before = json!({
            "kind": "StatefulSet",
            "spec": {"replicas": 1, "serviceName": "db", "selector": {"matchLabels": {"a": "b"}}},
        });

        let mut scaled = before.clone();
        scaled["spec"]["replicas"] = json!(3);
        assert!(diff(&before, &scaled, "StatefulSet").immutable.is_empty());

        let mut renamed = before.clone();
        renamed["spec"]["serviceName"] = json!("db2");
        assert_eq!(
            diff(&before, &renamed, "StatefulSet").immutable,
            vec!["spec.serviceName".to_string()]
        );
    }

    #[test]
    fn renaming_the_object_is_reported_as_identity_not_as_an_edit() {
        let before = json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a"}});
        let after = json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "b"}});
        let d = diff(&before, &after, "ConfigMap");
        assert_eq!(d.identity, vec!["metadata.name".to_string()]);
        assert!(d.immutable.is_empty());
        assert!(d.rejected());
    }

    #[test]
    fn a_resized_list_is_one_change_not_one_per_element() {
        let before = json!({"kind": "Service", "spec": {"ports": [{"port": 80}]}});
        let after = json!({"kind": "Service", "spec": {"ports": [{"port": 80}, {"port": 443}]}});
        assert_eq!(diff(&before, &after, "Service").paths, vec!["spec.ports".to_string()]);
    }

    #[test]
    fn added_and_removed_keys_are_both_seen() {
        let before = json!({"kind": "ConfigMap", "data": {"a": "1"}});
        let after = json!({"kind": "ConfigMap", "data": {"b": "2"}});
        let mut paths = diff(&before, &after, "ConfigMap").paths;
        paths.sort();
        assert_eq!(paths, vec!["data.a".to_string(), "data.b".to_string()]);
    }

    #[test]
    fn under_matches_the_field_and_its_children_only() {
        assert!(under("spec", "spec"));
        assert!(under("spec.replicas", "spec"));
        assert!(under("spec[0]", "spec"));
        assert!(!under("specialField", "spec"));
        assert!(!under("status.spec", "spec"));
    }

    #[test]
    fn the_editor_falls_back_to_vi_and_keeps_arguments() {
        std::env::set_var("KDT_EDITOR", "nvim -u NONE");
        let (program, args) = editor_command();
        assert_eq!(program, "nvim");
        assert_eq!(args, vec!["-u".to_string(), "NONE".to_string()]);

        std::env::set_var("KDT_EDITOR", "   ");
        std::env::remove_var("KUBE_EDITOR");
        std::env::remove_var("VISUAL");
        std::env::remove_var("EDITOR");
        assert_eq!(editor_command().0, "vi");
        std::env::remove_var("KDT_EDITOR");
    }

    #[test]
    fn parse_refuses_anything_that_is_not_a_mapping() {
        assert!(parse("- a\n- b\n").is_err());
        assert!(parse("kind: ConfigMap\n").is_ok());
        assert!(parse("kind: [\n").is_err());
    }
}
