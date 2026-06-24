//! Pod inventory plus the workload (Deployment/StatefulSet/DaemonSet/Job/ReplicaSet) a pod
//! originates from, with scale and rollout-restart actions. Owners are resolved by walking
//! ownerReferences (Pod → ReplicaSet → Deployment), so the UI can switch from a pod to a
//! hierarchical view of its workload and all sibling pods. Each pod also carries its IP and live
//! CPU/memory usage (metrics-server) against summed container requests/limits, for a k9s-style view.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::{
    fetch_pod_usage, format_age, parse_quantity_cpu_milli, parse_quantity_memory_bytes,
};
use crate::flux::SharedReconcile;

// Live usage per pod, keyed by (namespace, name): CPU millicores and memory bytes.
type UsageMap = HashMap<(String, String), (i64, i64)>;

// The workload a pod ultimately belongs to, after resolving ReplicaSet → Deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRef {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub api_version: String,
}

#[derive(Debug, Clone)]
pub struct PodResource {
    pub namespace: String,
    pub name: String,
    pub ready: String,
    pub status: String,
    pub restarts: i32,
    pub age: String,
    pub node: String,
    pub ip: String,
    pub owner: Option<OwnerRef>,
    pub uid: String,
    // Live usage from metrics-server (None when unavailable), and summed container requests/limits.
    pub cpu_milli: Option<i64>,
    pub mem_bytes: Option<i64>,
    pub cpu_req: Option<i64>,
    pub cpu_lim: Option<i64>,
    pub mem_req: Option<i64>,
    pub mem_lim: Option<i64>,
}

impl PodResource {
    // Surface problems first (not-ready/failed), then by namespace/name.
    fn sort_key(&self) -> (u8, &str, &str) {
        let bucket = match self.status.as_str() {
            "Running" | "Succeeded" | "Completed" => 2,
            "Pending" | "ContainerCreating" | "PodInitializing" | "Terminating" => 1,
            _ => 0,
        };
        (bucket, self.namespace.as_str(), self.name.as_str())
    }
}

// The "object" row shown at the top of the hierarchical view.
#[derive(Debug, Clone)]
pub struct WorkloadResource {
    pub kind: String,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub replicas: Option<i32>,
    pub ready_replicas: i32,
    pub age: String,
    pub uid: String,
}

impl WorkloadResource {
    pub fn uid(kind: &str, ns: &str, name: &str) -> String {
        format!("{}|{}/{}", kind, ns, name)
    }

    pub fn as_owner(&self) -> OwnerRef {
        OwnerRef {
            kind: self.kind.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            api_version: self.api_version.clone(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PodsState {
    pub pods: Vec<PodResource>,
    pub workloads: Vec<WorkloadResource>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedPods = Arc<Mutex<PodsState>>;

pub fn new_pods_state() -> SharedPods {
    Arc::new(Mutex::new(PodsState::default()))
}

// (group, version, kind) of the top-level workloads listed as parent rows. ReplicaSets are left out
// on purpose: a pod owned by a Deployment's ReplicaSet is resolved up to the Deployment, and naked
// ReplicaSets/bare pods surface as their own orphan group in the UI.
const WORKLOAD_KINDS: &[(&str, &str, &str)] = &[
    ("apps", "v1", "Deployment"),
    ("apps", "v1", "StatefulSet"),
    ("apps", "v1", "DaemonSet"),
    ("batch", "v1", "Job"),
];

// List every pod plus every top-level workload in `namespace` (None = all namespaces). Pods carry
// their resolved owner so the UI can group each pod under its workload row. Workloads are listed
// directly (not derived from pods) so a scaled-to-zero Deployment still shows up for scale/restart.
pub async fn fetch_workloads(client: Client, namespace: Option<String>, state: SharedPods) {
    {
        let mut s = state.lock().expect("pods poisoned");
        s.loading = true;
        s.error = None;
    }
    let api: Api<Pod> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = match api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(e) => {
            let mut s = state.lock().expect("pods poisoned");
            s.loading = false;
            s.error = Some(e.to_string());
            return;
        }
    };

    let usage = fetch_pod_usage(&client).await;
    let mut rs_cache: HashMap<String, Option<OwnerRef>> = HashMap::new();
    let mut pods: Vec<PodResource> = Vec::with_capacity(list.items.len());
    for p in &list.items {
        let owner = resolve_owner(&client, p, &mut rs_cache).await;
        pods.push(pod_resource(p, owner, &usage));
    }
    pods.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut workloads = list_workloads(&client, &namespace).await;
    workloads.sort_by(|a, b| {
        (a.namespace.as_str(), a.kind.as_str(), a.name.as_str())
            .cmp(&(b.namespace.as_str(), b.kind.as_str(), b.name.as_str()))
    });

    let mut s = state.lock().expect("pods poisoned");
    s.loading = false;
    s.workloads = workloads;
    s.pods = pods;
    s.error = None;
}

async fn list_workloads(client: &Client, namespace: &Option<String>) -> Vec<WorkloadResource> {
    let mut out = Vec::new();
    for (group, version, kind) in WORKLOAD_KINDS {
        let gvk = GroupVersionKind::gvk(group, version, kind);
        let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await else { continue };
        let api: Api<DynamicObject> = match namespace {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
            None => Api::all_with(client.clone(), &ar),
        };
        let Ok(list) = api.list(&ListParams::default()).await else { continue };
        let api_version = format!("{}/{}", group, version);
        for obj in &list.items {
            out.push(workload_from_obj(obj, kind, &api_version));
        }
    }
    out
}

fn workload_from_obj(obj: &DynamicObject, kind: &str, api_version: &str) -> WorkloadResource {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let replicas = obj
        .data
        .get("spec")
        .and_then(|s| s.get("replicas"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let ready_replicas = obj
        .data
        .get("status")
        .and_then(|s| {
            s.get("readyReplicas")
                .or_else(|| s.get("numberReady"))
                .or_else(|| s.get("ready"))
        })
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;
    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();
    WorkloadResource {
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        namespace: namespace.clone(),
        name: name.clone(),
        replicas,
        ready_replicas,
        age,
        uid: WorkloadResource::uid(kind, &namespace, &name),
    }
}

// Walk a pod's ownerReferences to the top-level workload. A ReplicaSet is resolved one step further
// to its owning Deployment (cached by namespace/name to avoid repeated API calls within one list).
async fn resolve_owner(
    client: &Client,
    pod: &Pod,
    rs_cache: &mut HashMap<String, Option<OwnerRef>>,
) -> Option<OwnerRef> {
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let refs = pod.metadata.owner_references.as_ref()?;
    let owner = refs.iter().find(|r| r.controller == Some(true)).or_else(|| refs.first())?;

    if owner.kind == "ReplicaSet" {
        let key = format!("{}/{}", ns, owner.name);
        if let Some(cached) = rs_cache.get(&key) {
            return cached.clone();
        }
        let resolved = replicaset_owner(client, &ns, &owner.name).await.or_else(|| {
            Some(OwnerRef {
                kind: "ReplicaSet".to_string(),
                name: owner.name.clone(),
                namespace: ns.clone(),
                api_version: owner.api_version.clone(),
            })
        });
        rs_cache.insert(key, resolved.clone());
        return resolved;
    }

    Some(OwnerRef {
        kind: owner.kind.clone(),
        name: owner.name.clone(),
        namespace: ns,
        api_version: owner.api_version.clone(),
    })
}

async fn replicaset_owner(client: &Client, ns: &str, name: &str) -> Option<OwnerRef> {
    let api: Api<ReplicaSet> = Api::namespaced(client.clone(), ns);
    let rs = api.get(name).await.ok()?;
    let refs = rs.metadata.owner_references.as_ref()?;
    let owner = refs.iter().find(|r| r.controller == Some(true)).or_else(|| refs.first())?;
    Some(OwnerRef {
        kind: owner.kind.clone(),
        name: owner.name.clone(),
        namespace: ns.to_string(),
        api_version: owner.api_version.clone(),
    })
}

fn pod_resource(p: &Pod, owner: Option<OwnerRef>, usage: &UsageMap) -> PodResource {
    let namespace = p.metadata.namespace.clone().unwrap_or_default();
    let name = p.metadata.name.clone().unwrap_or_default();
    let node = p.spec.as_ref().and_then(|s| s.node_name.clone()).unwrap_or_default();
    let ip = p.status.as_ref().and_then(|s| s.pod_ip.clone()).unwrap_or_default();
    let age = p
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    let statuses = p.status.as_ref().and_then(|s| s.container_statuses.as_ref());
    let total = statuses.map(|c| c.len()).unwrap_or(0);
    let ready_n = statuses
        .map(|c| c.iter().filter(|cs| cs.ready).count())
        .unwrap_or(0);
    let ready = format!("{}/{}", ready_n, total);
    let restarts = statuses
        .map(|c| c.iter().map(|cs| cs.restart_count).sum())
        .unwrap_or(0);

    let (cpu_req, cpu_lim, mem_req, mem_lim) = sum_resources(p);
    let (cpu_milli, mem_bytes) = match usage.get(&(namespace.clone(), name.clone())) {
        Some((c, m)) => (Some(*c), Some(*m)),
        None => (None, None),
    };

    PodResource {
        uid: format!("pod|{}/{}", namespace, name),
        status: pod_status(p),
        restarts,
        ready,
        age,
        node,
        ip,
        owner,
        cpu_milli,
        mem_bytes,
        cpu_req,
        cpu_lim,
        mem_req,
        mem_lim,
        namespace,
        name,
    }
}

// Sum CPU (millicores) and memory (bytes) requests/limits across a pod's regular containers.
// Returns (cpu_req, cpu_lim, mem_req, mem_lim); a component is None when no container declares it.
fn sum_resources(p: &Pod) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    let Some(spec) = p.spec.as_ref() else { return (None, None, None, None) };
    let mut cpu_req = None;
    let mut cpu_lim = None;
    let mut mem_req = None;
    let mut mem_lim = None;
    let add = |acc: &mut Option<i64>, v: Option<i64>| {
        if let Some(v) = v {
            *acc = Some(acc.unwrap_or(0) + v);
        }
    };
    for c in &spec.containers {
        let Some(res) = c.resources.as_ref() else { continue };
        add(&mut cpu_req, res.requests.as_ref().and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)));
        add(&mut cpu_lim, res.limits.as_ref().and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)));
        add(&mut mem_req, res.requests.as_ref().and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)));
        add(&mut mem_lim, res.limits.as_ref().and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)));
    }
    (cpu_req, cpu_lim, mem_req, mem_lim)
}

// Best-effort STATUS column matching kubectl: a waiting/terminated container reason takes precedence
// over the phase, and a deletion timestamp shows as "Terminating".
fn pod_status(p: &Pod) -> String {
    if p.metadata.deletion_timestamp.is_some() {
        return "Terminating".to_string();
    }
    let status = p.status.as_ref();
    if let Some(containers) = status.and_then(|s| s.container_statuses.as_ref()) {
        for cs in containers {
            if let Some(state) = &cs.state {
                if let Some(waiting) = &state.waiting {
                    if let Some(reason) = &waiting.reason {
                        if reason != "ContainerCreating" || containers.len() == 1 {
                            return reason.clone();
                        }
                    }
                }
                if let Some(term) = &state.terminated {
                    if let Some(reason) = &term.reason {
                        if reason != "Completed" {
                            return reason.clone();
                        }
                    }
                }
            }
        }
    }
    match status.and_then(|s| s.phase.as_deref()) {
        // Match kubectl/k9s wording: a successfully finished pod reads "Completed", not "Succeeded".
        Some("Succeeded") => "Completed".to_string(),
        Some(p) => p.to_string(),
        None => "Unknown".to_string(),
    }
}

// (group, candidate versions) for the workload kinds we act on.
fn workload_group(kind: &str) -> Option<(&'static str, &'static [&'static str])> {
    match kind {
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" => Some(("apps", &["v1"])),
        "Job" => Some(("batch", &["v1"])),
        _ => None,
    }
}

async fn resolve_ar(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
) -> Result<ApiResource, String> {
    for v in versions {
        let gvk = GroupVersionKind::gvk(group, v, kind);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            return Ok(ar);
        }
    }
    Err(format!("{} introuvable sur le cluster", kind))
}

async fn workload_api(client: &Client, owner: &OwnerRef) -> Result<Api<DynamicObject>, String> {
    let (group, versions) = workload_group(&owner.kind)
        .ok_or_else(|| format!("type non géré : {}", owner.kind))?;
    let ar = resolve_ar(client, group, versions, &owner.kind).await?;
    Ok(Api::namespaced_with(client.clone(), &owner.namespace, &ar))
}

async fn patch_replicas(client: &Client, owner: &OwnerRef, replicas: i32) -> Result<(), String> {
    if matches!(owner.kind.as_str(), "DaemonSet" | "Job") {
        return Err(format!("scale non supporté pour {}", owner.kind));
    }
    let api = workload_api(client, owner).await?;
    let patch = serde_json::json!({ "spec": { "replicas": replicas } });
    api.patch(&owner.name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map(|_| ())
        .map_err(|e| format!("{}/{} : {}", owner.kind, owner.name, e))
}

// Scale to an absolute replica count.
pub async fn run_scale(client: Client, owner: OwnerRef, replicas: i32, status: SharedReconcile) {
    let msg = match patch_replicas(&client, &owner, replicas).await {
        Ok(()) => format!("⇅ scale {}/{} → {}", owner.kind, owner.name, replicas),
        Err(e) => format!("✗ scale : {}", e),
    };
    publish(&status, msg);
}

// Hard recycle that bypasses a rolling update: scale to 0, wait briefly, then back to `replicas`.
pub async fn run_force_recycle(client: Client, owner: OwnerRef, replicas: i32, status: SharedReconcile) {
    let msg = match patch_replicas(&client, &owner, 0).await {
        Ok(()) => {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match patch_replicas(&client, &owner, replicas).await {
                Ok(()) => format!("♻ recycle {}/{} (0 → {})", owner.kind, owner.name, replicas),
                Err(e) => format!("✗ recycle (remontée) : {}", e),
            }
        }
        Err(e) => format!("✗ recycle (descente) : {}", e),
    };
    publish(&status, msg);
}

// Rollout restart via the standard restartedAt template annotation.
pub async fn run_restart(client: Client, owner: OwnerRef, status: SharedReconcile) {
    let msg = match patch_restart(&client, &owner).await {
        Ok(()) => format!("↻ restart {}/{}", owner.kind, owner.name),
        Err(e) => format!("✗ restart : {}", e),
    };
    publish(&status, msg);
}

async fn patch_restart(client: &Client, owner: &OwnerRef) -> Result<(), String> {
    if !matches!(owner.kind.as_str(), "Deployment" | "StatefulSet" | "DaemonSet") {
        return Err(format!("restart non supporté pour {}", owner.kind));
    }
    let api = workload_api(client, owner).await?;
    let now = chrono::Utc::now().to_rfc3339();
    let patch = serde_json::json!({
        "spec": { "template": { "metadata": { "annotations": {
            "kubectl.kubernetes.io/restartedAt": now
        } } } }
    });
    api.patch(&owner.name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map(|_| ())
        .map_err(|e| format!("{}/{} : {}", owner.kind, owner.name, e))
}

fn publish(status: &SharedReconcile, msg: String) {
    if let Ok(mut s) = status.lock() {
        *s = Some((std::time::Instant::now(), msg));
    }
}
