//! Cordon / uncordon / drain of a node.
//!
//! Draining is the one gesture in kdt that moves someone else's workloads around, so nothing is
//! evicted before the node has been looked at: which pods would be deleted for good, which
//! PodDisruptionBudget is going to refuse the eviction, and whether what is left of the cluster can
//! even take what is being pushed off. The findings come back structured ([`Reason`]) the way
//! [`crate::delete`] does them — the UI localises them and decides how hard to make the
//! confirmation. None of them blocks anything: the operator can always confirm through a warning.
//!
//! Everything that decides ([`plan`], [`assess`], [`room_left`]) is pure and takes the whole
//! snapshot, so it is testable without a cluster; only [`preflight`], [`set_cordon`] and
//! [`run_drain`] talk to the API.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::{Node, Pod};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{Api, EvictParams, ListParams, Patch, PatchParams};
use kube::Client;

pub use crate::delete::Level;
use crate::events::{parse_quantity_cpu_milli, parse_quantity_memory_bytes};

// Why a pod on the node is left alone rather than evicted, matching what `kubectl drain` skips.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Skip {
    // Owned by a DaemonSet: the controller would put it straight back on the same node.
    DaemonSet,
    // A static pod: the kubelet owns it from a file on disk, the API cannot evict it.
    Mirror,
    // Already Succeeded/Failed — nothing is running to move.
    Finished,
    // Already on its way out.
    Terminating,
}

// One pod of the node, and what the drain intends to do with it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Candidate {
    pub namespace: String,
    pub name: String,
    pub skip: Option<Skip>,
}

// One reason to think twice before draining, as data: the UI turns it into a localised sentence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reason {
    // No controller behind these pods: an eviction deletes them, and nothing recreates them.
    Unmanaged { pods: Vec<String> },
    // A PodDisruptionBudget that allows no disruption at all: the eviction is refused outright.
    PdbBlocked { pdbs: Vec<String> },
    // The last node that could take anything: everything evicted stays Pending.
    OnlySchedulable,
    // The budget allows fewer disruptions than there are pods to move: the drain proceeds one pod
    // at a time as the workloads recover, which can take a while.
    PdbTight { pdbs: Vec<String> },
    // What the other nodes have left does not fit what is being pushed off them.
    NoRoom { cpu_short: bool, mem_short: bool },
    // A single pod bigger than the free room on any remaining node: it has nowhere to land.
    PodTooBig { pods: Vec<String> },
    // emptyDir data goes away with the pod.
    LocalStorage { pods: Vec<String> },
    // Static pods cannot be evicted through the API: the drain leaves them running.
    StaticPods { pods: Vec<String> },
    ControlPlane,
    // Already unschedulable: the drain skips the cordon step and goes straight to the eviction.
    AlreadyCordoned,
    NotReady,
    // Pods the drain deliberately leaves in place.
    DaemonSetPods { count: usize },
}

impl Reason {
    pub fn level(&self) -> Level {
        match self {
            Reason::Unmanaged { .. } | Reason::PdbBlocked { .. } | Reason::OnlySchedulable => {
                Level::Danger
            }
            Reason::PdbTight { .. }
            | Reason::NoRoom { .. }
            | Reason::PodTooBig { .. }
            | Reason::LocalStorage { .. }
            | Reason::StaticPods { .. }
            | Reason::ControlPlane => Level::Warn,
            Reason::AlreadyCordoned | Reason::NotReady | Reason::DaemonSetPods { .. } => Level::Info,
        }
    }
}

// What one of the remaining nodes has left, requests-wise. Nothing here is measured usage: the
// scheduler packs on requests, so that is what says whether an evicted pod can land.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Room {
    pub node: String,
    pub cpu_milli: i64,
    pub mem_bytes: i64,
}

#[derive(Default, Debug, Clone)]
pub struct NodeOpState {
    // Identity ("<op>|<node>") of the operation the content belongs to: a result whose key no longer
    // matches the open panel is dropped instead of overwriting it.
    pub key: String,
    pub loading: bool,
    // Preflight failure (node gone, RBAC…). Treated as a reason to demand the strict confirmation:
    // when the checks could not run, nothing says the drain is harmless.
    pub error: Option<String>,
    pub reasons: Vec<Reason>,
    pub candidates: Vec<Candidate>,
    pub running: bool,
    // Progress, as it comes: pods gone, pods a budget is still holding back, pods that failed.
    pub evicted: Vec<String>,
    pub waiting: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub done: Option<Result<(), String>>,
}

impl NodeOpState {
    // The strict, type-the-name confirmation is required as soon as something dangerous shows up —
    // or as soon as the preflight itself could not conclude.
    pub fn needs_strict_confirm(&self) -> bool {
        self.error.is_some() || self.reasons.iter().any(|r| r.level() == Level::Danger)
    }

    pub fn to_evict(&self) -> usize {
        self.candidates.iter().filter(|c| c.skip.is_none()).count()
    }
}

pub type SharedNodeOp = Arc<Mutex<NodeOpState>>;

pub fn new_node_op_state() -> SharedNodeOp {
    Arc::new(Mutex::new(NodeOpState::default()))
}

// Fetch what the guard-rails need and publish their findings: the node, every pod in the cluster
// (the ones on the node are what gets evicted, the others are what fills the nodes they would land
// on), the other nodes, and the disruption budgets.
pub async fn preflight(client: Client, node: String, key: String, state: SharedNodeOp) {
    let result = collect(&client, &node).await;
    let mut s = state.lock().expect("node op state poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok((reasons, candidates)) => {
            s.reasons = reasons;
            s.candidates = candidates;
            s.error = None;
        }
        Err(e) => {
            s.reasons.clear();
            s.candidates.clear();
            s.error = Some(e);
        }
    }
}

async fn collect(client: &Client, node: &str) -> Result<(Vec<Reason>, Vec<Candidate>), String> {
    let nodes: Api<Node> = Api::all(client.clone());
    let target = nodes.get(node).await.map_err(|e| e.to_string())?;
    let all_nodes = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?
        .items;
    let pods: Api<Pod> = Api::all(client.clone());
    let all_pods = pods
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?
        .items;
    // Budgets are best-effort: a cluster where `policy/v1` is not readable still gets every other
    // finding, and a rule that has no data to work from says nothing rather than guessing.
    let pdbs: Api<PodDisruptionBudget> = Api::all(client.clone());
    let all_pdbs = pdbs
        .list(&ListParams::default())
        .await
        .map(|l| l.items)
        .unwrap_or_default();

    let candidates = plan(node, &all_pods);
    let rooms = room_left(node, &all_nodes, &all_pods);
    let reasons = assess(node, &target, &all_pods, &all_pdbs, &rooms);
    Ok((reasons, candidates))
}

// Who the drain would move, and who it deliberately leaves behind. Same rules as `kubectl drain`
// with `--ignore-daemonsets`, which is the only sane default: without it every drain on a real
// cluster refuses to start.
pub fn plan(node: &str, pods: &[Pod]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = pods
        .iter()
        .filter(|p| p.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node))
        .map(|p| Candidate {
            namespace: p.metadata.namespace.clone().unwrap_or_default(),
            name: p.metadata.name.clone().unwrap_or_default(),
            skip: skip_reason(p),
        })
        .collect();
    out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    out
}

fn skip_reason(p: &Pod) -> Option<Skip> {
    if p.metadata.deletion_timestamp.is_some() {
        return Some(Skip::Terminating);
    }
    let phase = p.status.as_ref().and_then(|s| s.phase.as_deref()).unwrap_or("");
    if matches!(phase, "Succeeded" | "Failed") {
        return Some(Skip::Finished);
    }
    if is_mirror(p) {
        return Some(Skip::Mirror);
    }
    if owner_kind(p).as_deref() == Some("DaemonSet") {
        return Some(Skip::DaemonSet);
    }
    None
}

// Everything worth warning about before draining `node`, most severe first.
pub fn assess(
    node: &str,
    target: &Node,
    pods: &[Pod],
    pdbs: &[PodDisruptionBudget],
    rooms: &[Room],
) -> Vec<Reason> {
    let on_node: Vec<&Pod> = pods
        .iter()
        .filter(|p| p.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node))
        .collect();
    let evictable: Vec<&Pod> = on_node
        .iter()
        .copied()
        .filter(|p| skip_reason(p).is_none())
        .collect();

    let mut out = Vec::new();

    let unmanaged: Vec<String> = evictable
        .iter()
        .filter(|p| owner_kind(p).is_none())
        .map(|p| pod_label(p))
        .collect();
    if !unmanaged.is_empty() {
        out.push(Reason::Unmanaged { pods: unmanaged });
    }

    let (blocked, tight) = pdb_findings(&evictable, pdbs);
    if !blocked.is_empty() {
        out.push(Reason::PdbBlocked { pdbs: blocked });
    }
    if !tight.is_empty() {
        out.push(Reason::PdbTight { pdbs: tight });
    }

    // Capacity is only worth talking about when there is something to place. An empty node that is
    // the last one standing is a cordon with extra steps, not a problem.
    if !evictable.is_empty() {
        if rooms.is_empty() {
            out.push(Reason::OnlySchedulable);
        } else {
            let (need_cpu, need_mem) = evictable
                .iter()
                .map(|p| pod_requests(p))
                .fold((0, 0), |(c, m), (pc, pm)| (c + pc, m + pm));
            let free_cpu: i64 = rooms.iter().map(|r| r.cpu_milli).sum();
            let free_mem: i64 = rooms.iter().map(|r| r.mem_bytes).sum();
            let cpu_short = need_cpu > free_cpu;
            let mem_short = need_mem > free_mem;
            if cpu_short || mem_short {
                out.push(Reason::NoRoom { cpu_short, mem_short });
            }
            // Even when the totals fit, a pod only ever lands on *one* node.
            let too_big: Vec<String> = evictable
                .iter()
                .filter(|p| {
                    let (c, m) = pod_requests(p);
                    (c > 0 || m > 0)
                        && !rooms.iter().any(|r| r.cpu_milli >= c && r.mem_bytes >= m)
                })
                .map(|p| pod_label(p))
                .collect();
            if !too_big.is_empty() {
                out.push(Reason::PodTooBig { pods: too_big });
            }
        }
    }

    let local: Vec<String> = evictable
        .iter()
        .filter(|p| has_empty_dir(p))
        .map(|p| pod_label(p))
        .collect();
    if !local.is_empty() {
        out.push(Reason::LocalStorage { pods: local });
    }

    let statics: Vec<String> = on_node
        .iter()
        .filter(|p| skip_reason(p) == Some(Skip::Mirror))
        .map(|p| pod_label(p))
        .collect();
    if !statics.is_empty() {
        out.push(Reason::StaticPods { pods: statics });
    }

    if is_control_plane(target) {
        out.push(Reason::ControlPlane);
    }
    if target.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false) {
        out.push(Reason::AlreadyCordoned);
    }
    if !is_ready(target) {
        out.push(Reason::NotReady);
    }
    let daemons = on_node
        .iter()
        .filter(|p| skip_reason(p) == Some(Skip::DaemonSet))
        .count();
    if daemons > 0 {
        out.push(Reason::DaemonSetPods { count: daemons });
    }

    out.sort_by_key(|r| std::cmp::Reverse(r.level()));
    out
}

// What each *other* node has left over its pods' requests. Only nodes that could actually take a
// pod count: a node that is NotReady or already cordoned is not somewhere to land.
pub fn room_left(draining: &str, nodes: &[Node], pods: &[Pod]) -> Vec<Room> {
    let mut used: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for p in pods {
        let Some(host) = p.spec.as_ref().and_then(|s| s.node_name.as_deref()) else { continue };
        if host == draining {
            continue;
        }
        // A finished pod holds nothing: the scheduler does not count it either.
        let phase = p.status.as_ref().and_then(|s| s.phase.as_deref()).unwrap_or("");
        if matches!(phase, "Succeeded" | "Failed") {
            continue;
        }
        let (c, m) = pod_requests(p);
        let e = used.entry(host.to_string()).or_insert((0, 0));
        e.0 += c;
        e.1 += m;
    }
    nodes
        .iter()
        .filter(|n| n.metadata.name.as_deref() != Some(draining))
        .filter(|n| is_ready(n) && !n.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false))
        .map(|n| {
            let name = n.metadata.name.clone().unwrap_or_default();
            let (cpu, mem) = allocatable(n);
            let (uc, um) = used.get(&name).copied().unwrap_or((0, 0));
            Room {
                node: name,
                cpu_milli: (cpu - uc).max(0),
                mem_bytes: (mem - um).max(0),
            }
        })
        .collect()
}

// Budgets standing between the drain and the pods it wants to move. `disruptionsAllowed` is the
// live figure the eviction API itself checks, so it answers the question directly: at zero the
// eviction comes back refused, below the number of pods to move it comes back refused *part way*.
fn pdb_findings(evictable: &[&Pod], pdbs: &[PodDisruptionBudget]) -> (Vec<String>, Vec<String>) {
    let mut blocked = Vec::new();
    let mut tight = Vec::new();
    for pdb in pdbs {
        let ns = pdb.metadata.namespace.clone().unwrap_or_default();
        let selector = pdb.spec.as_ref().and_then(|s| s.selector.as_ref());
        let matched = evictable
            .iter()
            .filter(|p| p.metadata.namespace.as_deref().unwrap_or("") == ns)
            .filter(|p| selector_matches(selector, p.metadata.labels.as_ref()))
            .count();
        if matched == 0 {
            continue;
        }
        // A budget whose status has not been computed yet says nothing: an absent figure is not a
        // zero, and reporting it as one would cry wolf on every freshly created PDB.
        let Some(allowed) = pdb.status.as_ref().map(|s| s.disruptions_allowed) else { continue };
        let label = format!("{}/{}", ns, pdb.metadata.name.clone().unwrap_or_default());
        if allowed <= 0 {
            blocked.push(label);
        } else if (allowed as usize) < matched {
            tight.push(label);
        }
    }
    (blocked, tight)
}

// `matchLabels` + `matchExpressions`, with the policy/v1 semantics for the two empty cases: a null
// selector matches no pod at all, an empty one matches every pod of the namespace.
fn selector_matches(
    selector: Option<&LabelSelector>,
    labels: Option<&BTreeMap<String, String>>,
) -> bool {
    let Some(sel) = selector else { return false };
    let empty = BTreeMap::new();
    let labels = labels.unwrap_or(&empty);
    if let Some(m) = &sel.match_labels {
        if !m.iter().all(|(k, v)| labels.get(k) == Some(v)) {
            return false;
        }
    }
    if let Some(exprs) = &sel.match_expressions {
        for e in exprs {
            let value = labels.get(&e.key);
            let ok = match e.operator.as_str() {
                "In" => value.is_some_and(|v| {
                    e.values.as_ref().is_some_and(|vs| vs.contains(v))
                }),
                "NotIn" => match value {
                    None => true,
                    Some(v) => !e.values.as_ref().is_some_and(|vs| vs.contains(v)),
                },
                "Exists" => value.is_some(),
                "DoesNotExist" => value.is_none(),
                // An operator we do not know is not something to guess at: treat the selector as
                // matching so the budget is at least reported rather than silently dropped.
                _ => true,
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

// The pod's effective requests, the way the scheduler computes them: the sum over the containers,
// floored by the largest init container, which runs alone before them.
fn pod_requests(p: &Pod) -> (i64, i64) {
    let Some(spec) = &p.spec else { return (0, 0) };
    let sum = spec.containers.iter().fold((0, 0), |(c, m), ct| {
        let (cc, cm) = container_requests(ct.resources.as_ref());
        (c + cc, m + cm)
    });
    let init = spec
        .init_containers
        .iter()
        .flatten()
        .fold((0, 0), |(c, m), ct| {
            let (cc, cm) = container_requests(ct.resources.as_ref());
            (c.max(cc), m.max(cm))
        });
    (sum.0.max(init.0), sum.1.max(init.1))
}

fn container_requests(
    res: Option<&k8s_openapi::api::core::v1::ResourceRequirements>,
) -> (i64, i64) {
    let Some(req) = res.and_then(|r| r.requests.as_ref()) else { return (0, 0) };
    let cpu = req.get("cpu").and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0);
    let mem = req
        .get("memory")
        .and_then(|q| parse_quantity_memory_bytes(&q.0))
        .unwrap_or(0);
    (cpu, mem)
}

fn allocatable(n: &Node) -> (i64, i64) {
    let Some(alloc) = n.status.as_ref().and_then(|s| s.allocatable.as_ref()) else {
        return (0, 0);
    };
    let cpu = alloc.get("cpu").and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0);
    let mem = alloc
        .get("memory")
        .and_then(|q| parse_quantity_memory_bytes(&q.0))
        .unwrap_or(0);
    (cpu, mem)
}

fn is_ready(n: &Node) -> bool {
    n.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .is_some_and(|c| c.status == "True")
}

fn is_control_plane(n: &Node) -> bool {
    n.metadata.labels.as_ref().is_some_and(|l| {
        l.contains_key("node-role.kubernetes.io/control-plane")
            || l.contains_key("node-role.kubernetes.io/master")
    })
}

fn is_mirror(p: &Pod) -> bool {
    p.metadata
        .annotations
        .as_ref()
        .is_some_and(|a| a.contains_key("kubernetes.io/config.mirror"))
}

fn owner_kind(p: &Pod) -> Option<String> {
    let refs = p.metadata.owner_references.as_ref()?;
    let owner = refs
        .iter()
        .find(|o| o.controller == Some(true))
        .or_else(|| refs.first())?;
    Some(owner.kind.clone())
}

fn has_empty_dir(p: &Pod) -> bool {
    p.spec
        .as_ref()
        .and_then(|s| s.volumes.as_ref())
        .is_some_and(|vs| vs.iter().any(|v| v.empty_dir.is_some()))
}

fn pod_label(p: &Pod) -> String {
    format!(
        "{}/{}",
        p.metadata.namespace.clone().unwrap_or_default(),
        p.metadata.name.clone().unwrap_or_default()
    )
}

// How long a pod a budget keeps refusing is retried before the drain gives up on it. `kubectl`
// retries forever; a TUI panel cannot, so it stops at something an operator will wait through and
// says which pods it left behind.
const EVICT_RETRIES: usize = 24;
const EVICT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

// Drain the node: cordon first — so nothing is scheduled back onto it behind the eviction — then
// evict, retrying the pods a budget holds back and publishing progress as it goes.
pub async fn run_drain(client: Client, node: String, key: String, state: SharedNodeOp) {
    let result = drain(&client, &node, &key, &state).await;
    let mut s = state.lock().expect("node op state poisoned");
    if s.key != key {
        return;
    }
    s.running = false;
    s.done = Some(result);
}

// Cordon/uncordon: a one-field patch, reversible, and the only node operation with no panel — it
// goes straight through and reports in the footer toast.
pub async fn set_cordon(client: &Client, node: &str, value: bool) -> Result<(), String> {
    let api: Api<Node> = Api::all(client.clone());
    let patch = serde_json::json!({ "spec": { "unschedulable": value } });
    api.patch(node, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map(|_| ())
        .map_err(crate::edit::api_error_text)
}

async fn drain(
    client: &Client,
    node: &str,
    key: &str,
    state: &SharedNodeOp,
) -> Result<(), String> {
    set_cordon(client, node, true).await?;

    let pods: Api<Pod> = Api::all(client.clone());
    let listed = pods
        .list(&ListParams::default().fields(&format!("spec.nodeName={}", node)))
        .await
        .map_err(|e| e.to_string())?
        .items;
    let mut todo: Vec<(String, String)> = listed
        .iter()
        .filter(|p| skip_reason(p).is_none())
        .map(|p| {
            (
                p.metadata.namespace.clone().unwrap_or_default(),
                p.metadata.name.clone().unwrap_or_default(),
            )
        })
        .collect();
    todo.sort();

    let ep = EvictParams::default();
    for attempt in 0..=EVICT_RETRIES {
        if todo.is_empty() {
            break;
        }
        if attempt > 0 {
            tokio::time::sleep(EVICT_RETRY_DELAY).await;
        }
        let mut still = Vec::new();
        for (ns, name) in todo {
            let api: Api<Pod> = Api::namespaced(client.clone(), &ns);
            let label = format!("{}/{}", ns, name);
            match api.evict(&name, &ep).await {
                Ok(_) => publish(state, key, |s| s.evicted.push(label.clone())),
                // A budget refusing the disruption is the normal way this goes: the pod is put back
                // in the queue rather than counted as a failure.
                Err(kube::Error::Api(e)) if e.code == 429 => {
                    still.push((ns.clone(), name.clone()));
                    publish(state, key, |s| {
                        if !s.waiting.contains(&label) {
                            s.waiting.push(label.clone());
                        }
                    });
                }
                // Gone already (finished, or evicted by something else) — nothing to do.
                Err(kube::Error::Api(e)) if e.code == 404 => {
                    publish(state, key, |s| s.evicted.push(label.clone()));
                }
                Err(e) => {
                    let text = crate::edit::api_error_text(e);
                    publish(state, key, |s| s.failed.push((label.clone(), text.clone())));
                }
            }
        }
        // Only the ones a budget is still holding back come round again.
        publish(state, key, |s| {
            s.waiting.retain(|w| still.iter().any(|(ns, n)| &format!("{}/{}", ns, n) == w));
        });
        todo = still;
    }

    let (left, failed) = {
        let s = state.lock().expect("node op state poisoned");
        (s.waiting.len(), s.failed.len())
    };
    if failed > 0 {
        return Err(format!("{} pod(s) en échec", failed));
    }
    if left > 0 {
        return Err(format!("{} pod(s) retenus par un PDB", left));
    }
    Ok(())
}

// Publish progress mid-run, dropping it if the panel has moved on to another operation.
fn publish(state: &SharedNodeOp, key: &str, f: impl FnOnce(&mut NodeOpState)) {
    let mut s = state.lock().expect("node op state poisoned");
    if s.key != key {
        return;
    }
    f(&mut s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(v: serde_json::Value) -> Pod {
        serde_json::from_value(v).expect("pod fixture")
    }

    fn node(v: serde_json::Value) -> Node {
        serde_json::from_value(v).expect("node fixture")
    }

    fn plain_node(name: &str, cpu: &str, mem: &str) -> Node {
        node(json!({
            "metadata": {"name": name},
            "spec": {},
            "status": {
                "allocatable": {"cpu": cpu, "memory": mem},
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }))
    }

    fn owned_pod(ns: &str, name: &str, host: &str, kind: &str) -> Pod {
        pod(json!({
            "metadata": {
                "name": name, "namespace": ns,
                "ownerReferences": [{"kind": kind, "name": "owner", "controller": true}],
            },
            "spec": {"nodeName": host, "containers": [{"name": "c"}]},
            "status": {"phase": "Running"},
        }))
    }

    #[test]
    fn daemonset_and_static_pods_are_left_where_they_are() {
        let pods = vec![
            owned_pod("apps", "web", "n1", "ReplicaSet"),
            owned_pod("kube-system", "cni", "n1", "DaemonSet"),
            pod(json!({
                "metadata": {
                    "name": "apiserver-n1", "namespace": "kube-system",
                    "annotations": {"kubernetes.io/config.mirror": "abc"},
                },
                "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
                "status": {"phase": "Running"},
            })),
            owned_pod("apps", "elsewhere", "n2", "ReplicaSet"),
        ];
        let plan = plan("n1", &pods);
        assert_eq!(plan.len(), 3, "only the pods of n1");
        assert_eq!(plan.iter().filter(|c| c.skip.is_none()).count(), 1);
        assert_eq!(
            plan.iter().find(|c| c.name == "cni").and_then(|c| c.skip),
            Some(Skip::DaemonSet)
        );
        assert_eq!(
            plan.iter().find(|c| c.name == "apiserver-n1").and_then(|c| c.skip),
            Some(Skip::Mirror)
        );
    }

    #[test]
    fn a_pod_with_no_controller_is_a_danger() {
        let bare = pod(json!({
            "metadata": {"name": "debug", "namespace": "default"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
            "status": {"phase": "Running"},
        }));
        let target = plain_node("n1", "4", "8Gi");
        let others = vec![plain_node("n2", "4", "8Gi")];
        let pods = vec![bare];
        let rooms = room_left("n1", &others, &pods);
        let reasons = assess("n1", &target, &pods, &[], &rooms);
        assert_eq!(
            reasons.first(),
            Some(&Reason::Unmanaged { pods: vec!["default/debug".to_string()] })
        );
        let s = NodeOpState { reasons, ..Default::default() };
        assert!(s.needs_strict_confirm());
    }

    #[test]
    fn a_budget_at_zero_blocks_and_a_tight_one_only_warns() {
        let pods = vec![
            pod(json!({
                "metadata": {
                    "name": "web-1", "namespace": "apps", "labels": {"app": "web"},
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "web", "controller": true}],
                },
                "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
                "status": {"phase": "Running"},
            })),
            pod(json!({
                "metadata": {
                    "name": "web-2", "namespace": "apps", "labels": {"app": "web"},
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "web", "controller": true}],
                },
                "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
                "status": {"phase": "Running"},
            })),
        ];
        let blocking: PodDisruptionBudget = serde_json::from_value(json!({
            "metadata": {"name": "web", "namespace": "apps"},
            "spec": {"selector": {"matchLabels": {"app": "web"}}},
            "status": {"disruptionsAllowed": 0, "currentHealthy": 2, "desiredHealthy": 2,
                       "expectedPods": 2, "disruptedPods": {}, "observedGeneration": 1},
        }))
        .expect("pdb fixture");
        let target = plain_node("n1", "4", "8Gi");
        let others = vec![plain_node("n2", "4", "8Gi")];
        let rooms = room_left("n1", &others, &pods);

        let reasons = assess("n1", &target, &pods, std::slice::from_ref(&blocking), &rooms);
        assert!(reasons.contains(&Reason::PdbBlocked { pdbs: vec!["apps/web".to_string()] }));

        let mut tight = blocking.clone();
        tight.status.as_mut().expect("status").disruptions_allowed = 1;
        let reasons = assess("n1", &target, &pods, &[tight], &rooms);
        assert!(reasons.contains(&Reason::PdbTight { pdbs: vec!["apps/web".to_string()] }));
        assert!(!reasons.iter().any(|r| r.level() == Level::Danger));
    }

    #[test]
    fn a_budget_without_a_computed_status_says_nothing() {
        let pods = vec![owned_pod("apps", "web-1", "n1", "ReplicaSet")];
        let pdb: PodDisruptionBudget = serde_json::from_value(json!({
            "metadata": {"name": "web", "namespace": "apps"},
            "spec": {"selector": {}},
        }))
        .expect("pdb fixture");
        let target = plain_node("n1", "4", "8Gi");
        let rooms = room_left("n1", &[plain_node("n2", "4", "8Gi")], &pods);
        let reasons = assess("n1", &target, &pods, &[pdb], &rooms);
        assert!(!reasons
            .iter()
            .any(|r| matches!(r, Reason::PdbBlocked { .. } | Reason::PdbTight { .. })));
    }

    #[test]
    fn room_is_counted_on_requests_and_only_on_nodes_that_could_take_a_pod() {
        let pods = vec![
            pod(json!({
                "metadata": {"name": "big", "namespace": "apps"},
                "spec": {"nodeName": "n2", "containers": [
                    {"name": "c", "resources": {"requests": {"cpu": "1500m", "memory": "2Gi"}}}
                ]},
                "status": {"phase": "Running"},
            })),
            // A finished pod holds nothing.
            pod(json!({
                "metadata": {"name": "done", "namespace": "apps"},
                "spec": {"nodeName": "n2", "containers": [
                    {"name": "c", "resources": {"requests": {"cpu": "2", "memory": "4Gi"}}}
                ]},
                "status": {"phase": "Succeeded"},
            })),
        ];
        let mut cordoned = plain_node("n3", "8", "16Gi");
        cordoned.spec.as_mut().expect("spec").unschedulable = Some(true);
        let nodes = vec![plain_node("n1", "4", "8Gi"), plain_node("n2", "4", "8Gi"), cordoned];
        let rooms = room_left("n1", &nodes, &pods);
        assert_eq!(
            rooms,
            vec![Room {
                node: "n2".to_string(),
                cpu_milli: 4000 - 1500,
                mem_bytes: 8 * 1024 * 1024 * 1024 - 2 * 1024 * 1024 * 1024,
            }]
        );
    }

    #[test]
    fn a_pod_larger_than_every_remaining_node_has_nowhere_to_land() {
        let heavy = pod(json!({
            "metadata": {
                "name": "db-0", "namespace": "data",
                "ownerReferences": [{"kind": "StatefulSet", "name": "db", "controller": true}],
            },
            "spec": {"nodeName": "n1", "containers": [
                {"name": "c", "resources": {"requests": {"cpu": "1", "memory": "12Gi"}}}
            ]},
            "status": {"phase": "Running"},
        }));
        let pods = vec![heavy];
        let target = plain_node("n1", "16", "32Gi");
        let rooms = room_left("n1", &[plain_node("n2", "16", "8Gi")], &pods);
        let reasons = assess("n1", &target, &pods, &[], &rooms);
        assert!(reasons.contains(&Reason::PodTooBig { pods: vec!["data/db-0".to_string()] }));
        assert!(reasons.contains(&Reason::NoRoom { cpu_short: false, mem_short: true }));
    }

    #[test]
    fn the_last_schedulable_node_is_a_danger_only_when_it_carries_something() {
        let pods = vec![owned_pod("apps", "web", "n1", "ReplicaSet")];
        let target = plain_node("n1", "4", "8Gi");
        let reasons = assess("n1", &target, &pods, &[], &[]);
        assert!(reasons.contains(&Reason::OnlySchedulable));

        let reasons = assess("n1", &target, &[], &[], &[]);
        assert!(!reasons.contains(&Reason::OnlySchedulable));
        assert!(reasons.is_empty());
    }

    #[test]
    fn emptydir_and_control_plane_warn_without_blocking() {
        let with_dir = pod(json!({
            "metadata": {
                "name": "cache", "namespace": "apps",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "cache", "controller": true}],
            },
            "spec": {
                "nodeName": "n1",
                "containers": [{"name": "c"}],
                "volumes": [{"name": "scratch", "emptyDir": {}}],
            },
            "status": {"phase": "Running"},
        }));
        let target = node(json!({
            "metadata": {"name": "n1", "labels": {"node-role.kubernetes.io/control-plane": ""}},
            "spec": {"unschedulable": true},
            "status": {
                "allocatable": {"cpu": "4", "memory": "8Gi"},
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }));
        let pods = vec![with_dir];
        let rooms = room_left("n1", &[plain_node("n2", "4", "8Gi")], &pods);
        let reasons = assess("n1", &target, &pods, &[], &rooms);
        assert!(reasons.contains(&Reason::LocalStorage { pods: vec!["apps/cache".to_string()] }));
        assert!(reasons.contains(&Reason::ControlPlane));
        assert!(reasons.contains(&Reason::AlreadyCordoned));
        let s = NodeOpState { reasons, ..Default::default() };
        assert!(!s.needs_strict_confirm());
    }

    #[test]
    fn init_containers_floor_the_request_rather_than_adding_to_it() {
        let p = pod(json!({
            "metadata": {"name": "p", "namespace": "apps"},
            "spec": {
                "nodeName": "n1",
                "initContainers": [
                    {"name": "i", "resources": {"requests": {"cpu": "2", "memory": "1Gi"}}}
                ],
                "containers": [
                    {"name": "a", "resources": {"requests": {"cpu": "500m", "memory": "2Gi"}}},
                    {"name": "b", "resources": {"requests": {"cpu": "500m", "memory": "1Gi"}}},
                ],
            },
        }));
        assert_eq!(pod_requests(&p), (2000, 3 * 1024 * 1024 * 1024));
    }

    #[test]
    fn a_null_selector_matches_nothing_and_an_empty_one_matches_everything() {
        let labels: BTreeMap<String, String> =
            [("app".to_string(), "web".to_string())].into_iter().collect();
        assert!(!selector_matches(None, Some(&labels)));
        assert!(selector_matches(Some(&LabelSelector::default()), Some(&labels)));

        let sel: LabelSelector = serde_json::from_value(json!({
            "matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]
        }))
        .expect("selector fixture");
        assert!(selector_matches(Some(&sel), Some(&labels)));

        let sel: LabelSelector = serde_json::from_value(json!({
            "matchExpressions": [{"key": "tier", "operator": "DoesNotExist"}]
        }))
        .expect("selector fixture");
        assert!(selector_matches(Some(&sel), Some(&labels)));
    }
}
