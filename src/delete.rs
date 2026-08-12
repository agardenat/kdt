//! Guarded deletion of an arbitrary Kubernetes object.
//!
//! Nothing is removed before the object has been fetched and inspected for the reasons deleting it
//! is usually a mistake — first among them being managed by a GitOps engine, where the controller
//! simply puts back whatever was deleted. The findings are returned structured ([`Reason`]) rather
//! than as sentences, so the UI localises them and decides how hard to make the confirmation. None
//! of them blocks anything: the user can always confirm through a warning.

use std::sync::{Arc, Mutex};

use kube::api::DeleteParams;
use kube::Client;
use serde_json::{Map, Value};

use crate::yaml::dynamic_api;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Info,
    Warn,
    Danger,
}

// The GitOps engine a resource was deployed by, identified from the labels/annotations its
// controller stamps on everything it applies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GitOpsTool {
    FluxKustomize,
    FluxHelm,
    Argo,
    Helm,
}

// One reason to think twice, as data: the UI turns it into a localised sentence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reason {
    // Deployed by a GitOps engine: deleting it desynchronises the cluster from the repository, and
    // the object comes back at the next reconciliation.
    GitOps { tool: GitOpsTool, detail: String },
    // The object *is* a GitOps entry point: deleting it takes everything it deploys with it.
    GitOpsRoot { kind: String },
    NamespaceCascade,
    CrdCascade,
    // Owned by a controller, which recreates the object right away.
    OwnedBy { kind: String, name: String },
    SystemNamespace { namespace: String },
    NodeDrain,
    PersistentData,
    // A velero Backup: deleting the object is not deleting the backup. The data stays in object
    // storage, and velero's backup-sync controller reads the bucket back and re-creates the object
    // within the minute (`backup_sync_controller.go`). The only deletion that removes anything is a
    // `DeleteBackupRequest`, which the `:velero` view files under `o`.
    VeleroBackup,
    // The same Backup, but one that velero has actually started running. Deleting it cancels the run
    // mid-flight, and because a forced deletion does not reliably release velero's single backup
    // slot, the 1.18 backup queue can stay stuck (`queuePosition` never advancing) until the server
    // is restarted. A `Queued`/`New` backup has not started and is the safe one to clear, so it does
    // not raise this.
    VeleroBackupRunning,
    // A CassandraDatacenter or K8ssandraCluster: deleting it takes the StatefulSet and, with it, the
    // PersistentVolumeClaims holding the database. There is no undo short of a Medusa restore, and
    // the whole point of the `:k8ssandra` view is that the restore may not exist.
    CassandraData,
    // A MedusaBackup: the same trap as `VeleroBackup`, one API group over. Deleting the object does
    // not delete the backup — the files stay in the bucket, and the `sync` MedusaTask recreates the
    // object from the bucket index at the next run. Removing the data takes a `purge` MedusaTask.
    MedusaBackup,
    // A Medusa run still in flight. Deleting it abandons the operation mid-transfer, leaving partial
    // files in the bucket that the next differential backup will build on.
    MedusaRunning,
    Finalizers,
}

impl Reason {
    pub fn level(&self) -> Level {
        match self {
            Reason::GitOps { .. }
            | Reason::GitOpsRoot { .. }
            | Reason::NamespaceCascade
            | Reason::VeleroBackupRunning
            | Reason::CassandraData
            | Reason::CrdCascade => Level::Danger,
            Reason::OwnedBy { .. }
            | Reason::SystemNamespace { .. }
            | Reason::NodeDrain
            | Reason::PersistentData
            | Reason::VeleroBackup
            | Reason::MedusaBackup
            | Reason::MedusaRunning => Level::Warn,
            Reason::Finalizers => Level::Info,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct DeleteState {
    // Identity ("apiVersion|kind|ns/name") of the object the content belongs to: a result whose key
    // no longer matches the open panel is dropped instead of overwriting it.
    pub key: String,
    pub loading: bool,
    // Preflight failure (object gone, RBAC…). Treated as a reason to demand the strict confirmation:
    // when the checks could not run, nothing says the deletion is harmless.
    pub error: Option<String>,
    pub reasons: Vec<Reason>,
    pub deleting: bool,
    pub done: Option<Result<(), String>>,
}

impl DeleteState {
    // The strict, type-the-name confirmation is required as soon as something dangerous shows up —
    // or as soon as the preflight itself could not conclude.
    pub fn needs_strict_confirm(&self) -> bool {
        self.error.is_some() || self.reasons.iter().any(|r| r.level() == Level::Danger)
    }
}

pub type SharedDelete = Arc<Mutex<DeleteState>>;

pub fn new_delete_state() -> SharedDelete {
    Arc::new(Mutex::new(DeleteState::default()))
}

// Fetch the object and publish the guard-rails that apply to it.
pub async fn preflight(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    state: SharedDelete,
) {
    let result = load(&client, &api_version, &kind, &namespace, &name).await;
    let mut s = state.lock().expect("delete state poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(value) => {
            s.reasons = assess(&value);
            s.error = None;
        }
        Err(e) => {
            s.reasons.clear();
            s.error = Some(e);
        }
    }
}

// Actually delete, with the propagation policy `kubectl delete` uses (background cascade).
pub async fn run_delete(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    state: SharedDelete,
) {
    let result = match dynamic_api(&client, &api_version, &kind, &namespace).await {
        Ok(api) => api
            .delete(&name, &DeleteParams::background())
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    let mut s = state.lock().expect("delete state poisoned");
    if s.key != key {
        return;
    }
    s.deleting = false;
    s.done = Some(result);
}

async fn load(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<Value, String> {
    if kind.is_empty() || name.is_empty() {
        return Err("objet sans kind/name".to_string());
    }
    let api = dynamic_api(client, api_version, kind, namespace).await?;
    let obj = api.get(name).await.map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(&obj).map_err(|e| e.to_string())?;
    // A GET normally echoes apiVersion/kind, but a DynamicObject round-trip can drop them: put the
    // requested ones back so the checks below always see the identity of what is being deleted.
    if let Value::Object(map) = &mut value {
        map.entry("apiVersion")
            .or_insert_with(|| Value::String(api_version.to_string()));
        map.entry("kind")
            .or_insert_with(|| Value::String(kind.to_string()));
    }
    Ok(value)
}

// Labels the Flux controllers stamp on every object they apply.
const FLUX_KS: (&str, &str) = (
    "kustomize.toolkit.fluxcd.io/name",
    "kustomize.toolkit.fluxcd.io/namespace",
);
const FLUX_HR: (&str, &str) = (
    "helm.toolkit.fluxcd.io/name",
    "helm.toolkit.fluxcd.io/namespace",
);
// Argo CD tracks ownership either by annotation (`<app>:<group>/<Kind>:<ns>/<name>`) or, in label
// mode, by stamping the application name.
const ARGO_TRACKING: &str = "argocd.argoproj.io/tracking-id";
const ARGO_INSTANCE: &str = "argocd.argoproj.io/instance";
// Helm 3 records the owning release in annotations.
const HELM_RELEASE: (&str, &str) = ("meta.helm.sh/release-name", "meta.helm.sh/release-namespace");

// Namespaces where a deletion breaks the cluster itself rather than an application.
const SYSTEM_NAMESPACES: &[&str] = &[
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "flux-system",
    "argocd",
];

// Everything worth warning about before removing `obj`, most severe first.
pub fn assess(obj: &Value) -> Vec<Reason> {
    let kind = str_at(obj, "kind");
    let api_version = str_at(obj, "apiVersion");
    let meta = obj.get("metadata");
    let name = meta.map(|m| str_at(m, "name")).unwrap_or_default();
    let namespace = meta.map(|m| str_at(m, "namespace")).unwrap_or_default();
    let labels = sub_map(meta, "labels");
    let annotations = sub_map(meta, "annotations");

    let mut out = Vec::new();
    if let Some((tool, detail)) = gitops_owner(labels, annotations) {
        out.push(Reason::GitOps { tool, detail });
    }
    if is_gitops_root(api_version, kind) {
        out.push(Reason::GitOpsRoot { kind: kind.to_string() });
    }
    match kind {
        "Namespace" => out.push(Reason::NamespaceCascade),
        "CustomResourceDefinition" => out.push(Reason::CrdCascade),
        "Node" => out.push(Reason::NodeDrain),
        "PersistentVolumeClaim" | "PersistentVolume" => out.push(Reason::PersistentData),
        "Backup" if api_version.starts_with("velero.io/") => {
            out.push(Reason::VeleroBackup);
            if velero_backup_running(obj) {
                out.push(Reason::VeleroBackupRunning);
            }
        }
        "CassandraDatacenter" | "K8ssandraCluster" => out.push(Reason::CassandraData),
        "MedusaBackup" if api_version.starts_with("medusa.k8ssandra.io/") => {
            out.push(Reason::MedusaBackup);
        }
        "MedusaBackupJob" | "MedusaRestoreJob" | "MedusaTask"
            if api_version.starts_with("medusa.k8ssandra.io/") && medusa_in_progress(obj) =>
        {
            out.push(Reason::MedusaRunning);
        }
        _ => {}
    }
    if let Some((kind, name)) = controller_owner(meta) {
        out.push(Reason::OwnedBy { kind, name });
    }
    // A system namespace counts whether the object sits in one or *is* one.
    let ns = if kind == "Namespace" { name } else { namespace };
    if SYSTEM_NAMESPACES.contains(&ns) {
        out.push(Reason::SystemNamespace { namespace: ns.to_string() });
    }
    if meta
        .and_then(|m| m.get("finalizers"))
        .and_then(Value::as_array)
        .is_some_and(|f| !f.is_empty())
    {
        out.push(Reason::Finalizers);
    }

    out.sort_by_key(|r| std::cmp::Reverse(r.level()));
    out
}

// Whether a Medusa run has nodes still working. `status.inProgress` is the only field that says so:
// there is no phase, and a finish time is absent both while it runs and when it never started.
fn medusa_in_progress(obj: &Value) -> bool {
    obj.get("status")
        .and_then(|s| s.get("inProgress"))
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

// Object-level entry points for the two ownership checks, shared with the edit guard-rails
// ([`crate::edit`]), which ask the same questions of an object for the opposite reason: what is
// deployed by a controller cannot be deleted *or* edited durably.
pub fn gitops_owner_of(obj: &Value) -> Option<(GitOpsTool, String)> {
    let meta = obj.get("metadata");
    gitops_owner(sub_map(meta, "labels"), sub_map(meta, "annotations"))
}

pub fn controller_owner_of(obj: &Value) -> Option<(String, String)> {
    controller_owner(obj.get("metadata"))
}

// Flux/Argo/Helm ownership, read off the labels and annotations their controllers write. Flux keys
// are looked up in both maps: some setups propagate them as annotations.
fn gitops_owner(
    labels: Option<&Map<String, Value>>,
    annotations: Option<&Map<String, Value>>,
) -> Option<(GitOpsTool, String)> {
    let stamped = |key: &str| -> Option<&str> {
        lookup(labels, key).or_else(|| lookup(annotations, key))
    };

    for (tool, (name_key, ns_key)) in
        [(GitOpsTool::FluxKustomize, FLUX_KS), (GitOpsTool::FluxHelm, FLUX_HR)]
    {
        if let Some(name) = stamped(name_key) {
            let detail = match stamped(ns_key) {
                Some(ns) => format!("{}/{}", ns, name),
                None => name.to_string(),
            };
            return Some((tool, detail));
        }
    }
    // `<app>:<group>/<Kind>:<ns>/<name>` — only the application name is interesting here.
    if let Some(id) = lookup(annotations, ARGO_TRACKING) {
        let app = id.split(':').next().unwrap_or(id);
        return Some((GitOpsTool::Argo, app.to_string()));
    }
    if let Some(app) = lookup(labels, ARGO_INSTANCE) {
        return Some((GitOpsTool::Argo, app.to_string()));
    }
    if let Some(release) = lookup(annotations, HELM_RELEASE.0) {
        let detail = match lookup(annotations, HELM_RELEASE.1) {
            Some(ns) => format!("{}/{}", ns, release),
            None => release.to_string(),
        };
        return Some((GitOpsTool::Helm, detail));
    }
    None
}

// The GitOps entry points: deleting one of these prunes everything it deployed.
fn is_gitops_root(api_version: &str, kind: &str) -> bool {
    (api_version.contains("kustomize.toolkit.fluxcd.io") && kind == "Kustomization")
        || (api_version.contains("helm.toolkit.fluxcd.io") && kind == "HelmRelease")
        || (api_version.contains("argoproj.io") && matches!(kind, "Application" | "ApplicationSet"))
}

// The controlling owner reference, falling back to the first one when none is marked as controller.
fn controller_owner(meta: Option<&Value>) -> Option<(String, String)> {
    let refs = meta?.get("ownerReferences")?.as_array()?;
    let owner = refs
        .iter()
        .find(|o| o.get("controller").and_then(Value::as_bool) == Some(true))
        .or_else(|| refs.first())?;
    let kind = str_at(owner, "kind");
    let name = str_at(owner, "name");
    if kind.is_empty() || name.is_empty() {
        return None;
    }
    Some((kind.to_string(), name.to_string()))
}

// The backup phases where velero has started the run and holds the single backup slot. `Queued`,
// `New` and `ReadyToStart` are excluded on purpose: they never held the slot, so clearing them is
// the safe cleanup, not the hazard.
fn velero_backup_running(obj: &Value) -> bool {
    let phase = obj.get("status").map(|s| str_at(s, "phase")).unwrap_or_default();
    matches!(
        phase,
        "InProgress"
            | "WaitingForPluginOperations"
            | "WaitingForPluginOperationsPartiallyFailed"
            | "Finalizing"
            | "FinalizingPartiallyFailed"
    )
}

fn str_at<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn sub_map<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Map<String, Value>> {
    value?.get(key)?.as_object()
}

fn lookup<'a>(map: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a str> {
    let v = map?.get(key)?.as_str()?;
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Deleting a velero Backup object is the one deletion in this list that does not delete
    // anything: the bucket keeps the data and the sync controller re-creates the object. The rule
    // has to be scoped to the velero group — plenty of CRDs are called `Backup`.
    #[test]
    fn a_velero_backup_warns_that_the_object_is_not_the_backup() {
        let reasons = assess(&json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "daily-20260730", "namespace": "velero" },
        }));
        assert!(reasons.contains(&Reason::VeleroBackup));
        let other = assess(&json!({
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "Backup",
            "metadata": { "name": "pg", "namespace": "db" },
        }));
        assert!(!other.contains(&Reason::VeleroBackup));
    }

    #[test]
    fn deleting_a_running_velero_backup_is_a_danger_a_queued_one_is_not() {
        // In progress: cancels the run and can wedge velero's backup queue, so it earns the strict
        // confirmation on top of the plain "the object is not the backup" warning.
        let running = assess(&json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "daily-1", "namespace": "velero" },
            "status": { "phase": "InProgress" },
        }));
        assert!(running.contains(&Reason::VeleroBackupRunning));
        assert_eq!(running[0].level(), Level::Danger);
        let s = DeleteState { reasons: running, ..Default::default() };
        assert!(s.needs_strict_confirm());

        // Queued has not started: it is exactly the backup the operator clears to unblock things,
        // so only the ordinary warning shows and no strict confirmation is forced.
        let queued = assess(&json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "daily-2", "namespace": "velero" },
            "status": { "phase": "Queued" },
        }));
        assert!(!queued.contains(&Reason::VeleroBackupRunning));
        assert!(queued.contains(&Reason::VeleroBackup));
        let s = DeleteState { reasons: queued, ..Default::default() };
        assert!(!s.needs_strict_confirm());
    }

    #[test]
    fn flux_kustomize_labels_are_a_danger() {
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
        assert!(reasons[0].level() == Level::Danger);
    }

    #[test]
    fn argo_tracking_id_keeps_only_the_application_name() {
        let reasons = assess(&json!({
            "kind": "Service",
            "metadata": {
                "name": "web",
                "annotations": { ARGO_TRACKING: "guestbook:/Service:default/web" },
            },
        }));
        assert_eq!(
            reasons,
            vec![Reason::GitOps { tool: GitOpsTool::Argo, detail: "guestbook".to_string() }]
        );
    }

    #[test]
    fn helm_release_annotations_are_reported() {
        let reasons = assess(&json!({
            "kind": "ConfigMap",
            "metadata": {
                "name": "cfg",
                "annotations": {
                    "meta.helm.sh/release-name": "kube-prom",
                    "meta.helm.sh/release-namespace": "monitoring",
                },
            },
        }));
        assert_eq!(
            reasons,
            vec![Reason::GitOps {
                tool: GitOpsTool::Helm,
                detail: "monitoring/kube-prom".to_string()
            }]
        );
    }

    #[test]
    fn owned_pod_in_a_system_namespace_warns_twice_without_danger() {
        let reasons = assess(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "coredns-abc",
                "namespace": "kube-system",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "coredns-1", "controller": true}],
            },
        }));
        assert_eq!(
            reasons,
            vec![
                Reason::OwnedBy { kind: "ReplicaSet".to_string(), name: "coredns-1".to_string() },
                Reason::SystemNamespace { namespace: "kube-system".to_string() },
            ]
        );
        let s = DeleteState { reasons, ..Default::default() };
        assert!(!s.needs_strict_confirm());
    }

    #[test]
    fn a_flux_kustomization_is_a_gitops_root_and_sorts_dangers_first() {
        let reasons = assess(&json!({
            "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
            "kind": "Kustomization",
            "metadata": {
                "name": "apps",
                "namespace": "flux-system",
                "finalizers": ["finalizers.fluxcd.io"],
            },
        }));
        assert_eq!(
            reasons,
            vec![
                Reason::GitOpsRoot { kind: "Kustomization".to_string() },
                Reason::SystemNamespace { namespace: "flux-system".to_string() },
                Reason::Finalizers,
            ]
        );
        let s = DeleteState { reasons, ..Default::default() };
        assert!(s.needs_strict_confirm());
    }

    #[test]
    fn deleting_a_namespace_cascades() {
        let reasons = assess(&json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "staging"},
        }));
        assert_eq!(reasons, vec![Reason::NamespaceCascade]);
    }

    #[test]
    fn a_plain_object_triggers_nothing() {
        let reasons = assess(&json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "cfg", "namespace": "default"},
        }));
        assert!(reasons.is_empty());
        let s = DeleteState::default();
        assert!(!s.needs_strict_confirm());
    }

    #[test]
    fn a_failed_preflight_forces_the_strict_confirmation() {
        let s = DeleteState { error: Some("forbidden".to_string()), ..Default::default() };
        assert!(s.needs_strict_confirm());
    }
}
