//! Pod inventory plus the workload (Deployment/StatefulSet/DaemonSet/Job/ReplicaSet) a pod
//! originates from, with scale and rollout-restart actions. Owners are resolved by walking
//! ownerReferences (Pod → ReplicaSet → Deployment), so the UI can switch from a pod to a
//! hierarchical view of its workload and all sibling pods. Each pod also carries its IP and live
//! CPU/memory usage (metrics-server) against summed container requests/limits, for a k9s-style view.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod, ResourceRequirements};
use crate::lang::{active, fill};
use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::{
    fetch_container_usage, format_age, parse_quantity_cpu_milli, parse_quantity_memory_bytes,
    ContainerUsageMap,
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

// Where a container sits in the pod's lifecycle. It decides how a row reads more than how it is
// fetched: an init container that says "Completed" did its job, a regular one that says the same is
// gone, and only a running one can be exec'd into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind { Init, Regular, Ephemeral }

impl ContainerKind {
    // Prefix shown in front of the container name, so the three families never read alike.
    pub fn tag(self) -> &'static str {
        match self {
            ContainerKind::Init => "init:",
            ContainerKind::Ephemeral => "eph:",
            ContainerKind::Regular => "",
        }
    }
}

// One container of a pod, as the pods view shows it: the spec side (name, image, requests/limits)
// joined with the status side (ready, state, restarts) and its own slice of the metrics-server read.
// It is a display row, not an API object — a container has no manifest of its own, so `y`/`e`/delete
// on such a row keep acting on the owning pod.
#[derive(Debug, Clone)]
pub struct ContainerResource {
    pub namespace: String,
    pub pod: String,
    pub name: String,
    pub image: String,
    pub kind: ContainerKind,
    pub ready: bool,
    // Running / a waiting reason (CrashLoopBackOff…) / a terminated reason (Completed, OOMKilled…).
    pub state: String,
    pub restarts: i32,
    // Time since this container last started (or finished), not since the pod was created.
    pub age: String,
    pub cpu_milli: Option<i64>,
    pub mem_bytes: Option<i64>,
    pub cpu_req: Option<i64>,
    pub cpu_lim: Option<i64>,
    pub mem_req: Option<i64>,
    pub mem_lim: Option<i64>,
    pub uid: String,
}

impl ContainerResource {
    pub fn uid(ns: &str, pod: &str, name: &str) -> String {
        format!("ctr|{}/{}/{}", ns, pod, name)
    }

    // The only state `kubectl exec` can land in. Checked before the terminal is handed over, since
    // afterwards the failure scrolls past on a screen kdt is about to repaint.
    pub fn is_running(&self) -> bool {
        self.state == "Running"
    }

    pub fn display_name(&self) -> String {
        format!("{}{}", self.kind.tag(), self.name)
    }
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
    // Init, regular and ephemeral containers in spec order, shown when the pod row is expanded.
    pub containers: Vec<ContainerResource>,
}

impl PodResource {
    // Stable order by namespace/name so pods keep their natural place (problems are not hoisted up).
    fn sort_key(&self) -> (&str, &str) {
        (self.namespace.as_str(), self.name.as_str())
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
    // Kinds the API server refused (RBAC) or could not serve for this listing, with the reason.
    // Skipping them silently would let the view claim "no Job" when the truth is "not allowed to
    // look", so the caller shows what is missing rather than an empty gap.
    pub missing_kinds: Vec<String>,
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

    // One metrics read serves both levels: the container rows use it as it comes, the pod rows use
    // the sum of it, so expanding a pod costs no extra API call.
    let cusage = fetch_container_usage(&client).await;
    let mut usage: UsageMap = HashMap::new();
    for ((ns, pod, _c), (cpu, mem)) in &cusage {
        let e = usage.entry((ns.clone(), pod.clone())).or_insert((0, 0));
        e.0 += cpu;
        e.1 += mem;
    }
    let mut rs_cache: HashMap<String, Option<OwnerRef>> = HashMap::new();
    let mut pods: Vec<PodResource> = Vec::with_capacity(list.items.len());
    for p in &list.items {
        let owner = resolve_owner(&client, p, &mut rs_cache).await;
        pods.push(pod_resource(p, owner, &usage, &cusage));
    }
    pods.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let (mut workloads, missing_kinds) = list_workloads(&client, &namespace).await;
    workloads.sort_by(|a, b| {
        (a.namespace.as_str(), a.kind.as_str(), a.name.as_str())
            .cmp(&(b.namespace.as_str(), b.kind.as_str(), b.name.as_str()))
    });

    let mut s = state.lock().expect("pods poisoned");
    s.loading = false;
    s.workloads = workloads;
    s.missing_kinds = missing_kinds;
    s.pods = pods;
    s.error = None;
}

// Returns the workloads found, and the kinds that could not be listed at all (discovery or list
// refused) with their reason — a Job the caller is not allowed to list must not look like a cluster
// without Jobs.
async fn list_workloads(
    client: &Client,
    namespace: &Option<String>,
) -> (Vec<WorkloadResource>, Vec<String>) {
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for (group, version, kind) in WORKLOAD_KINDS {
        let gvk = GroupVersionKind::gvk(group, version, kind);
        let ar = match discovery::pinned_kind(client, &gvk).await {
            Ok((ar, _caps)) => ar,
            Err(e) => {
                missing.push(format!("{}: {}", kind, short_reason(&e.to_string())));
                continue;
            }
        };
        let api: Api<DynamicObject> = match namespace {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
            None => Api::all_with(client.clone(), &ar),
        };
        let list = match api.list(&ListParams::default()).await {
            Ok(l) => l,
            Err(e) => {
                missing.push(format!("{}: {}", kind, short_reason(&e.to_string())));
                continue;
            }
        };
        let api_version = format!("{}/{}", group, version);
        for obj in &list.items {
            out.push(workload_from_obj(obj, kind, &api_version));
        }
    }
    (out, missing)
}

// Keep a listing failure to one readable clause: the title line has room for a cause, not for a
// serialised API error.
fn short_reason(e: &str) -> String {
    let first = e.split(':').next_back().unwrap_or(e).trim();
    let first = if first.is_empty() { e.trim() } else { first };
    if first.chars().count() > 60 {
        format!("{}…", first.chars().take(59).collect::<String>())
    } else {
        first.to_string()
    }
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

fn pod_resource(
    p: &Pod,
    owner: Option<OwnerRef>,
    usage: &UsageMap,
    cusage: &ContainerUsageMap,
) -> PodResource {
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

    let containers = pod_containers(p, &namespace, &name, cusage);

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
        containers,
        namespace,
        name,
    }
}

// The pod's containers in the order they run: init first, then the regular ones, then any ephemeral
// debug container. Spec and status are joined by name — a container declared but not yet started has
// no status at all, and reads "Pending" rather than being dropped from the list.
fn pod_containers(
    p: &Pod,
    namespace: &str,
    pod: &str,
    cusage: &ContainerUsageMap,
) -> Vec<ContainerResource> {
    let Some(spec) = p.spec.as_ref() else { return Vec::new() };
    let status = p.status.as_ref();
    let find = |statuses: Option<&Vec<ContainerStatus>>, name: &str| {
        statuses.and_then(|v| v.iter().find(|s| s.name == name)).cloned()
    };

    let mut out = Vec::new();
    for c in spec.init_containers.iter().flatten() {
        let st = find(status.and_then(|s| s.init_container_statuses.as_ref()), &c.name);
        out.push(container_resource(
            namespace, pod, ContainerKind::Init, &c.name, &c.image, c.resources.as_ref(), st.as_ref(), cusage,
        ));
    }
    for c in &spec.containers {
        let st = find(status.and_then(|s| s.container_statuses.as_ref()), &c.name);
        out.push(container_resource(
            namespace, pod, ContainerKind::Regular, &c.name, &c.image, c.resources.as_ref(), st.as_ref(), cusage,
        ));
    }
    for c in spec.ephemeral_containers.iter().flatten() {
        let st = find(status.and_then(|s| s.ephemeral_container_statuses.as_ref()), &c.name);
        out.push(container_resource(
            namespace, pod, ContainerKind::Ephemeral, &c.name, &c.image, c.resources.as_ref(), st.as_ref(), cusage,
        ));
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn container_resource(
    namespace: &str,
    pod: &str,
    kind: ContainerKind,
    name: &str,
    spec_image: &Option<String>,
    resources: Option<&ResourceRequirements>,
    st: Option<&ContainerStatus>,
    cusage: &ContainerUsageMap,
) -> ContainerResource {
    let (state, age) = container_state(st);
    // What actually runs beats what was asked for: status.image is the image the kubelet resolved,
    // which is the whole question when a rollout is half-done. Falls back to the spec before it is.
    let image = st
        .map(|s| s.image.clone())
        .filter(|i| !i.is_empty())
        .or_else(|| spec_image.clone())
        .unwrap_or_default();
    let q = |m: Option<&std::collections::BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>>, key: &str, cpu: bool| {
        m.and_then(|m| m.get(key)).and_then(|v| {
            if cpu { parse_quantity_cpu_milli(&v.0) } else { parse_quantity_memory_bytes(&v.0) }
        })
    };
    let (req, lim) = match resources {
        Some(r) => (r.requests.as_ref(), r.limits.as_ref()),
        None => (None, None),
    };
    let (cpu_milli, mem_bytes) = match cusage.get(&(namespace.to_string(), pod.to_string(), name.to_string())) {
        Some((c, m)) => (Some(*c), Some(*m)),
        None => (None, None),
    };
    ContainerResource {
        namespace: namespace.to_string(),
        pod: pod.to_string(),
        name: name.to_string(),
        image,
        kind,
        ready: st.map(|s| s.ready).unwrap_or(false),
        state,
        restarts: st.map(|s| s.restart_count).unwrap_or(0),
        age,
        cpu_milli,
        mem_bytes,
        cpu_req: q(req, "cpu", true),
        cpu_lim: q(lim, "cpu", true),
        mem_req: q(req, "memory", false),
        mem_lim: q(lim, "memory", false),
        uid: ContainerResource::uid(namespace, pod, name),
    }
}

// The container's state and the age that goes with it. The age is deliberately not the pod's: on a
// restarting container the only figure that answers "when did this last blow up" is its own
// startedAt (or, once it is dead, its finishedAt).
fn container_state(st: Option<&ContainerStatus>) -> (String, String) {
    let Some(state) = st.and_then(|s| s.state.as_ref()) else {
        return ("Pending".to_string(), String::new());
    };
    if let Some(r) = &state.running {
        let age = r.started_at.as_ref().map(|t| format_age(&t.0)).unwrap_or_default();
        return ("Running".to_string(), age);
    }
    if let Some(w) = &state.waiting {
        return (w.reason.clone().unwrap_or_else(|| "Waiting".to_string()), String::new());
    }
    if let Some(t) = &state.terminated {
        let age = t.finished_at.as_ref().map(|x| format_age(&x.0)).unwrap_or_default();
        // A reasonless exit still says something: the code is the only thing left to report.
        let reason = t
            .reason
            .clone()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| format!("Exit {}", t.exit_code));
        return (reason, age);
    }
    ("Unknown".to_string(), String::new())
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
    Err(fill(active().pods_kind_not_found, &[("kind", kind)]))
}

async fn workload_api(client: &Client, owner: &OwnerRef) -> Result<Api<DynamicObject>, String> {
    let (group, versions) = workload_group(&owner.kind)
        .ok_or_else(|| fill(active().pods_kind_unsupported, &[("kind", &owner.kind)]))?;
    let ar = resolve_ar(client, group, versions, &owner.kind).await?;
    Ok(Api::namespaced_with(client.clone(), &owner.namespace, &ar))
}

async fn patch_replicas(client: &Client, owner: &OwnerRef, replicas: i32) -> Result<(), String> {
    if matches!(owner.kind.as_str(), "DaemonSet" | "Job") {
        return Err(fill(active().pods_scale_unsupported, &[("kind", &owner.kind)]));
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
                Ok(()) => format!("↻ recycle {}/{} (0 → {})", owner.kind, owner.name, replicas),
                Err(e) => fill(active().pods_recycle_failed, &[("e", &e)]),
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
        return Err(fill(active().pods_restart_unsupported, &[("kind", &owner.kind)]));
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

#[cfg(test)]
mod container_tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        Container, ContainerState, ContainerStateRunning, ContainerStateTerminated,
        ContainerStateWaiting, PodSpec, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    fn now() -> Time {
        Time(k8s_openapi::jiff::Timestamp::now() - std::time::Duration::from_secs(4 * 3600))
    }

    fn status_of(name: &str, state: ContainerState, ready: bool, restarts: i32) -> ContainerStatus {
        ContainerStatus {
            name: name.to_string(),
            image: format!("registry.example.com/{}:v2", name),
            ready,
            restart_count: restarts,
            state: Some(state),
            ..Default::default()
        }
    }

    fn pod_with(spec: PodSpec, status: PodStatus) -> Pod {
        Pod { spec: Some(spec), status: Some(status), ..Default::default() }
    }

    #[test]
    fn init_regular_and_ephemeral_containers_come_back_in_running_order() {
        let p = pod_with(
            PodSpec {
                init_containers: Some(vec![Container {
                    name: "wait-db".to_string(),
                    image: Some("busybox:1.36".to_string()),
                    ..Default::default()
                }]),
                containers: vec![Container {
                    name: "app".to_string(),
                    image: Some("app:1.0".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            PodStatus::default(),
        );
        let out = pod_containers(&p, "apps", "web-0", &ContainerUsageMap::new());
        let names: Vec<String> = out.iter().map(|c| c.display_name()).collect();
        assert_eq!(names, vec!["init:wait-db", "app"]);
        // No status yet is not "gone": the container is declared and waiting for the kubelet.
        assert!(out.iter().all(|c| c.state == "Pending" && !c.is_running()));
    }

    #[test]
    fn a_container_is_judged_on_its_own_state_not_the_pods() {
        let p = pod_with(
            PodSpec {
                init_containers: Some(vec![Container {
                    name: "wait-db".to_string(),
                    image: Some("busybox:1.36".to_string()),
                    ..Default::default()
                }]),
                containers: vec![
                    Container { name: "app".to_string(), image: Some("app:1.0".to_string()), ..Default::default() },
                    Container { name: "sidecar".to_string(), image: Some("proxy:2.0".to_string()), ..Default::default() },
                ],
                ..Default::default()
            },
            PodStatus {
                init_container_statuses: Some(vec![status_of(
                    "wait-db",
                    ContainerState {
                        terminated: Some(ContainerStateTerminated {
                            exit_code: 0,
                            reason: Some("Completed".to_string()),
                            finished_at: Some(now()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    false,
                    0,
                )]),
                container_statuses: Some(vec![
                    status_of(
                        "app",
                        ContainerState {
                            running: Some(ContainerStateRunning { started_at: Some(now()) }),
                            ..Default::default()
                        },
                        true,
                        0,
                    ),
                    status_of(
                        "sidecar",
                        ContainerState {
                            waiting: Some(ContainerStateWaiting {
                                reason: Some("CrashLoopBackOff".to_string()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        false,
                        7,
                    ),
                ]),
                ..Default::default()
            },
        );
        let out = pod_containers(&p, "apps", "web-0", &ContainerUsageMap::new());
        let by = |n: &str| out.iter().find(|c| c.name == n).expect("container").clone();

        // A finished init container is not a failure, and it is not exec'able either.
        let init = by("wait-db");
        assert_eq!(init.state, "Completed");
        assert!(!init.is_running());
        // Its age is its own finishedAt, not the pod's creation.
        assert_eq!(init.age, "4h");

        assert!(by("app").is_running());
        assert_eq!(by("sidecar").state, "CrashLoopBackOff");
        assert_eq!(by("sidecar").restarts, 7);
        // What actually runs beats what was asked for.
        assert_eq!(by("app").image, "registry.example.com/app:v2");
    }

    #[test]
    fn a_reasonless_exit_still_reports_its_code() {
        let p = pod_with(
            PodSpec {
                containers: vec![Container {
                    name: "job".to_string(),
                    image: Some("runner:1".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            PodStatus {
                container_statuses: Some(vec![status_of(
                    "job",
                    ContainerState {
                        terminated: Some(ContainerStateTerminated {
                            exit_code: 137,
                            reason: None,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    false,
                    0,
                )]),
                ..Default::default()
            },
        );
        let out = pod_containers(&p, "apps", "job-0", &ContainerUsageMap::new());
        assert_eq!(out[0].state, "Exit 137");
    }

    #[test]
    fn each_container_takes_its_own_slice_of_the_metrics_read() {
        let mut usage = ContainerUsageMap::new();
        usage.insert(("apps".to_string(), "web-0".to_string(), "app".to_string()), (250, 1024));
        let p = pod_with(
            PodSpec {
                containers: vec![
                    Container { name: "app".to_string(), image: Some("app:1".to_string()), ..Default::default() },
                    Container { name: "sidecar".to_string(), image: Some("proxy:1".to_string()), ..Default::default() },
                ],
                ..Default::default()
            },
            PodStatus::default(),
        );
        let out = pod_containers(&p, "apps", "web-0", &usage);
        assert_eq!(out[0].cpu_milli, Some(250));
        assert_eq!(out[0].mem_bytes, Some(1024));
        // Nothing is invented for the container metrics-server did not report.
        assert_eq!(out[1].cpu_milli, None);
        assert_eq!(out[1].mem_bytes, None);
    }
}
