//! Headroom for the `:capacity` view: not "here is the usage" but "here is what will break".
//!
//! Three questions, three worlds, one fetch:
//!
//! - **Nodes** — what is reserved against what exists, and above all: *if this node goes, do its
//!   pods have anywhere to land?* That is the question `kubectl top` cannot answer, because it
//!   needs requests, remaining room, taints and selectors at the same time.
//! - **Workloads** — the pods the scheduler cannot see (no requests), the ones asking for far more
//!   than they use (capacity asleep), and the ones about to hit their own limit.
//! - **Quotas** — the `ResourceQuota` about to refuse the next deployment.
//!
//! Every rule is a pure function over the snapshot ([`analyse`]): no client, no I/O, testable. The
//! placement simulation is an honest first-fit — it says so rather than pretending to be the
//! scheduler — and it stays silent when metrics-server is absent instead of guessing.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::ReplicaSet;
use crate::lang::{Strings, fill};
use k8s_openapi::api::core::v1::{Node, Pod, ResourceQuota, Taint, Toleration};
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::{
    fetch_pod_usage, format_cpu_milli, format_memory_bytes, parse_quantity_cpu_milli,
    parse_quantity_memory_bytes,
};
use crate::nodeops::{pod_requests, skip_reason};
pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint {
    Hint { level: HintLevel::Info, text }
}
fn warn(text: String) -> Hint {
    Hint { level: HintLevel::Warn, text }
}
fn danger(text: String) -> Hint {
    Hint { level: HintLevel::Danger, text }
}

// Where "nearly full" starts. Reservation is what the scheduler looks at, so it gets the tighter
// threshold: at 90% reserved, a normal pod no longer fits even though the node looks idle.
const RESERVED_WARN_PCT: i64 = 90;
const USED_WARN_PCT: i64 = 90;
const QUOTA_WARN_PCT: i64 = 90;
// Below this, "the totals fit" is not the same as "there is room": one more pod and it does not.
const TIGHT_SPARE_PCT: i64 = 10;
// A pod asking for this many times what it uses is oversized — but only past an absolute floor,
// or every 10m sidecar in the cluster gets flagged for asking 50m.
const OVERSIZED_FACTOR: i64 = 4;
const OVERSIZED_MIN_CPU: i64 = 200;
const OVERSIZED_MIN_MEM: i64 = 512 * 1024 * 1024;
// Sitting this close to your own limit means throttling (CPU) or the OOM killer (memory).
const NEAR_LIMIT_PCT: i64 = 90;

// --- Rows ---------------------------------------------------------------------------------------

// Why a pod has nowhere to go. The distinction matters: no room is fixed by adding capacity, a
// selector or a taint is fixed by changing the pod — and no amount of new nodes will help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Homeless {
    NoRoom,
    Taints,
    Selector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomelessPod {
    pub namespace: String,
    pub name: String,
    pub why: Homeless,
    pub cpu: i64,
    pub mem: i64,
}

// What losing the node would do, once its pods have been placed elsewhere on paper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loss {
    // The only node that could take anything: there is no simulation to run.
    Alone,
    // Everything lands, with room to spare.
    Fits,
    // Everything lands, and then there is almost nothing left.
    Tight,
    // These pods have nowhere to go.
    Homeless(Vec<HomelessPod>),
}

impl Loss {
    pub fn homeless(&self) -> usize {
        match self {
            Loss::Homeless(v) => v.len(),
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeRoom {
    pub name: String,
    pub ready: bool,
    pub schedulable: bool,
    pub alloc_cpu: i64,
    pub alloc_mem: i64,
    // Reserved by the pods that are actually running there — what the scheduler packs against.
    pub req_cpu: i64,
    pub req_mem: i64,
    pub lim_cpu: i64,
    pub lim_mem: i64,
    // Measured, when metrics-server is there to measure it.
    pub use_cpu: Option<i64>,
    pub use_mem: Option<i64>,
    pub pods: usize,
    pub pod_capacity: i64,
    pub loss: Loss,
    pub hints: Vec<Hint>,
}

impl NodeRoom {
    pub fn uid(&self) -> String {
        format!("cap-node-{}", self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qos {
    Guaranteed,
    Burstable,
    BestEffort,
}

impl Qos {
    pub fn label(self) -> &'static str {
        match self {
            Qos::Guaranteed => "Guaranteed",
            Qos::Burstable => "Burstable",
            Qos::BestEffort => "BestEffort",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkloadSizing {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub pods: usize,
    pub cpu_req: i64,
    pub mem_req: i64,
    pub cpu_lim: i64,
    pub mem_lim: i64,
    pub cpu_use: Option<i64>,
    pub mem_use: Option<i64>,
    pub qos: Qos,
    pub no_cpu_request: bool,
    pub no_mem_request: bool,
    pub no_mem_limit: bool,
    pub hints: Vec<Hint>,
}

impl WorkloadSizing {
    pub fn uid(&self) -> String {
        format!("cap-wl-{}-{}-{}", self.kind, self.namespace, self.name)
    }
}

#[derive(Debug, Clone)]
pub struct QuotaItem {
    pub resource: String,
    pub used: i64,
    pub hard: i64,
    // Kept as written, because a quota counts objects as readily as it counts CPU and the two do
    // not format the same way.
    pub used_text: String,
    pub hard_text: String,
}

impl QuotaItem {
    pub fn pct(&self) -> i64 {
        pct(self.used, self.hard)
    }
}

#[derive(Debug, Clone)]
pub struct QuotaPressure {
    pub namespace: String,
    pub name: String,
    pub items: Vec<QuotaItem>,
    pub hints: Vec<Hint>,
}

impl QuotaPressure {
    pub fn uid(&self) -> String {
        format!("cap-quota-{}-{}", self.namespace, self.name)
    }

    pub fn worst_pct(&self) -> i64 {
        self.items.iter().map(QuotaItem::pct).max().unwrap_or(0)
    }
}

#[derive(Default, Debug, Clone)]
pub struct CapacityState {
    pub nodes: Vec<NodeRoom>,
    pub workloads: Vec<WorkloadSizing>,
    pub quotas: Vec<QuotaPressure>,
    // Findings that belong to no single row: the cluster-wide ones.
    pub cluster_hints: Vec<Hint>,
    // False when metrics-server is absent: every rule that compares against measured usage then
    // stays quiet rather than reading an absent figure as a zero.
    pub metrics_available: bool,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedCapacity = Arc<Mutex<CapacityState>>;

pub fn new_capacity_state() -> SharedCapacity {
    Arc::new(Mutex::new(CapacityState::default()))
}

// --- Fetch --------------------------------------------------------------------------------------

// One pass over everything the rules cross-reference. Nodes and pods are mandatory; quotas,
// ReplicaSets (to name a Deployment rather than its hash) and metrics degrade to "absent" so a
// cluster that refuses one of them still gets every other finding.
pub async fn fetch_capacity(client: Client, state: SharedCapacity) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("capacity poisoned");
        s.loading = true;
        s.error = None;
    }

    let nodes_api: Api<Node> = Api::all(client.clone());
    let pods_api: Api<Pod> = Api::all(client.clone());
    let quotas_api: Api<ResourceQuota> = Api::all(client.clone());
    let rs_api: Api<ReplicaSet> = Api::all(client.clone());

    let lp = ListParams::default();
    let (nodes, pods, quotas, replicasets, usage) = tokio::join!(
        nodes_api.list(&lp),
        pods_api.list(&lp),
        quotas_api.list(&lp),
        rs_api.list(&lp),
        fetch_pod_usage(&client),
    );

    let nodes = match nodes {
        Ok(l) => l.items,
        Err(e) => return publish_error(&state, format!("nodes: {}", e)),
    };
    let pods = match pods {
        Ok(l) => l.items,
        Err(e) => return publish_error(&state, format!("pods: {}", e)),
    };
    let quotas = quotas.map(|l| l.items).unwrap_or_default();
    let owners = replicaset_owners(replicasets.map(|l| l.items).unwrap_or_default());

    let metrics_available = !usage.is_empty();
    let computed = analyse(&nodes, &pods, &quotas, &owners, &usage, metrics_available, st);

    let mut s = state.lock().expect("capacity poisoned");
    s.loading = false;
    s.error = None;
    s.nodes = computed.nodes;
    s.workloads = computed.workloads;
    s.quotas = computed.quotas;
    s.cluster_hints = computed.cluster_hints;
    s.metrics_available = metrics_available;
}

fn publish_error(state: &SharedCapacity, msg: String) {
    let mut s = state.lock().expect("capacity poisoned");
    s.loading = false;
    s.error = Some(msg);
}

// "ns/replicaset" → the Deployment above it, so a workload row is named after what a human deploys
// rather than after a hash nobody typed.
fn replicaset_owners(sets: Vec<ReplicaSet>) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    for rs in sets {
        let ns = rs.metadata.namespace.clone().unwrap_or_default();
        let name = rs.metadata.name.clone().unwrap_or_default();
        let Some(refs) = rs.metadata.owner_references.as_ref() else { continue };
        let Some(owner) = refs.iter().find(|o| o.controller == Some(true)).or_else(|| refs.first())
        else {
            continue;
        };
        out.insert(format!("{}/{}", ns, name), (owner.kind.clone(), owner.name.clone()));
    }
    out
}

// --- Rules --------------------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
pub struct Analysis {
    pub nodes: Vec<NodeRoom>,
    pub workloads: Vec<WorkloadSizing>,
    pub quotas: Vec<QuotaPressure>,
    pub cluster_hints: Vec<Hint>,
}

pub fn analyse(
    nodes: &[Node],
    pods: &[Pod],
    quotas: &[ResourceQuota],
    rs_owners: &HashMap<String, (String, String)>,
    usage: &HashMap<(String, String), (i64, i64)>,
    metrics_available: bool,
    st: &'static Strings,
) -> Analysis {
    let mut rooms = node_rooms(nodes, pods, usage, metrics_available);
    for room in &mut rooms {
        room.loss = simulate_loss(&room.name, nodes, pods);
        room.hints = node_hints(room, st);
    }
    rooms.sort_by(|a, b| {
        b.loss.homeless().cmp(&a.loss.homeless()).then(a.name.cmp(&b.name))
    });

    let workloads = workload_sizing(pods, rs_owners, usage, metrics_available, st);
    let quotas = quota_pressure(quotas, st);
    let cluster_hints = cluster_hints(&rooms, &workloads, metrics_available, st);

    Analysis { nodes: rooms, workloads, quotas, cluster_hints }
}

fn node_rooms(
    nodes: &[Node],
    pods: &[Pod],
    usage: &HashMap<(String, String), (i64, i64)>,
    metrics_available: bool,
) -> Vec<NodeRoom> {
    nodes
        .iter()
        .map(|n| {
            let name = n.metadata.name.clone().unwrap_or_default();
            let on_node: Vec<&Pod> = pods.iter().filter(|p| hosted_by(p, &name)).collect();
            let (mut req_cpu, mut req_mem, mut lim_cpu, mut lim_mem) = (0, 0, 0, 0);
            let (mut use_cpu, mut use_mem) = (0, 0);
            for p in &on_node {
                let (c, m) = pod_requests(p);
                req_cpu += c;
                req_mem += m;
                let (lc, lm) = pod_limits(p);
                lim_cpu += lc;
                lim_mem += lm;
                if let Some((uc, um)) = usage.get(&pod_key(p)) {
                    use_cpu += uc;
                    use_mem += um;
                }
            }
            let (alloc_cpu, alloc_mem) = allocatable(n);
            NodeRoom {
                name,
                ready: is_ready(n),
                schedulable: !unschedulable(n),
                alloc_cpu,
                alloc_mem,
                req_cpu,
                req_mem,
                lim_cpu,
                lim_mem,
                // Summed pod usage, not node usage: it leaves out the kubelet and the container
                // runtime, and saying so is better than a second metrics API to reconcile.
                use_cpu: metrics_available.then_some(use_cpu),
                use_mem: metrics_available.then_some(use_mem),
                pods: on_node.len(),
                pod_capacity: pod_capacity(n),
                loss: Loss::Alone,
                hints: Vec::new(),
            }
        })
        .collect()
}

fn node_hints(room: &NodeRoom, st: &'static Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    match &room.loss {
        Loss::Homeless(pods) => {
            let names: Vec<String> = pods
                .iter()
                .take(4)
                .map(|p| format!("{}/{}", p.namespace, p.name))
                .collect();
            out.push(danger(fill(
                &st.plural(pods.len(), st.cap_loss_homeless_one, st.cap_loss_homeless_many),
                &[("pods", &names.join(", "))],
            )));
        }
        Loss::Tight => out.push(warn(st.cap_loss_tight.to_string())),
        Loss::Fits | Loss::Alone => {}
    }
    let cpu_pct = pct(room.req_cpu, room.alloc_cpu);
    let mem_pct = pct(room.req_mem, room.alloc_mem);
    if cpu_pct >= RESERVED_WARN_PCT {
        out.push(warn(fill(
            st.cap_cpu_reserved,
            &[
                ("pct", &cpu_pct.to_string()),
                ("used", &cpu_text(room.req_cpu)),
                ("total", &cpu_text(room.alloc_cpu)),
            ],
        )));
    }
    if mem_pct >= RESERVED_WARN_PCT {
        out.push(warn(fill(
            st.cap_mem_reserved,
            &[
                ("pct", &mem_pct.to_string()),
                ("used", &mem_text(room.req_mem)),
                ("total", &mem_text(room.alloc_mem)),
            ],
        )));
    }
    if let (Some(c), Some(m)) = (room.use_cpu, room.use_mem) {
        let uc = pct(c, room.alloc_cpu);
        let um = pct(m, room.alloc_mem);
        if uc >= USED_WARN_PCT {
            out.push(warn(fill(st.cap_cpu_used, &[("pct", &uc.to_string())])));
        }
        if um >= USED_WARN_PCT {
            out.push(warn(fill(st.cap_mem_used, &[("pct", &um.to_string())])));
        }
    }
    // Over-commit is not a fault — it is how clusters are run — but the ratio is worth knowing
    // when the node is also close to full on the measured side.
    if room.alloc_cpu > 0 && room.lim_cpu > room.alloc_cpu {
        out.push(info(fill(
            st.cap_cpu_overcommit,
            &[("pct", &pct(room.lim_cpu, room.alloc_cpu).to_string())],
        )));
    }
    if room.alloc_mem > 0 && room.lim_mem > room.alloc_mem {
        out.push(info(fill(
            st.cap_mem_overcommit,
            &[("pct", &pct(room.lim_mem, room.alloc_mem).to_string())],
        )));
    }
    if room.pod_capacity > 0 {
        let p = pct(room.pods as i64, room.pod_capacity);
        if p >= RESERVED_WARN_PCT {
            out.push(warn(fill(
                st.cap_pod_slots,
                &[
                    ("used", &room.pods.to_string()),
                    ("total", &room.pod_capacity.to_string()),
                ],
            )));
        }
    }
    if !room.schedulable {
        out.push(info(st.cap_node_cordoned.to_string()));
    }
    if !room.ready {
        out.push(warn(st.cap_node_not_ready.to_string()));
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.level));
    out
}

// Can the rest of the cluster take this node's pods? First-fit, biggest first, decrementing the
// room as it places — the same heuristic `kubectl` users run in their heads, made explicit.
//
// It is deliberately *not* a scheduler: it weighs requests, taints and the hard placement rules
// (nodeSelector, required node affinity), and ignores the soft ones (preferred affinity, spread
// constraints, inter-pod affinity), which can only make the real answer worse, never better. So a
// verdict of "it fits" is the optimistic bound, and that is the honest way round.
pub fn simulate_loss(target: &str, nodes: &[Node], pods: &[Pod]) -> Loss {
    let others: Vec<&Node> = nodes
        .iter()
        .filter(|n| n.metadata.name.as_deref() != Some(target))
        .filter(|n| is_ready(n) && !unschedulable(n))
        .collect();
    if others.is_empty() {
        return Loss::Alone;
    }

    let mut free: Vec<(usize, i64, i64)> = others
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let name = n.metadata.name.clone().unwrap_or_default();
            let (alloc_cpu, alloc_mem) = allocatable(n);
            let (used_cpu, used_mem) = pods
                .iter()
                .filter(|p| hosted_by(p, &name))
                .map(pod_requests)
                .fold((0, 0), |(c, m), (pc, pm)| (c + pc, m + pm));
            (i, (alloc_cpu - used_cpu).max(0), (alloc_mem - used_mem).max(0))
        })
        .collect();
    let total_free_cpu: i64 = free.iter().map(|(_, c, _)| *c).sum();
    let total_free_mem: i64 = free.iter().map(|(_, _, m)| *m).sum();

    let mut movers: Vec<(&Pod, i64, i64)> = pods
        .iter()
        .filter(|p| hosted_by(p, target))
        .filter(|p| skip_reason(p).is_none())
        .map(|p| {
            let (c, m) = pod_requests(p);
            (p, c, m)
        })
        .collect();
    // Biggest first: placing the small ones first is how a first-fit strands the large one.
    movers.sort_by_key(|m| std::cmp::Reverse((m.2, m.1)));

    let mut stranded = Vec::new();
    for (pod, cpu, mem) in movers {
        // Which nodes would even accept it, before any question of room.
        let eligible: Vec<usize> = free
            .iter()
            .filter(|(i, _, _)| accepts(others[*i], pod))
            .map(|(i, _, _)| *i)
            .collect();
        if eligible.is_empty() {
            stranded.push(HomelessPod {
                namespace: pod.metadata.namespace.clone().unwrap_or_default(),
                name: pod.metadata.name.clone().unwrap_or_default(),
                why: if others.iter().any(|n| tolerated(n, pod)) {
                    Homeless::Selector
                } else {
                    Homeless::Taints
                },
                cpu,
                mem,
            });
            continue;
        }
        match free
            .iter_mut()
            .find(|(i, c, m)| eligible.contains(i) && *c >= cpu && *m >= mem)
        {
            Some((_, c, m)) => {
                *c -= cpu;
                *m -= mem;
            }
            None => stranded.push(HomelessPod {
                namespace: pod.metadata.namespace.clone().unwrap_or_default(),
                name: pod.metadata.name.clone().unwrap_or_default(),
                why: Homeless::NoRoom,
                cpu,
                mem,
            }),
        }
    }

    if !stranded.is_empty() {
        return Loss::Homeless(stranded);
    }
    let left_cpu: i64 = free.iter().map(|(_, c, _)| *c).sum();
    let left_mem: i64 = free.iter().map(|(_, _, m)| *m).sum();
    let tight = pct(left_cpu, total_free_cpu.max(1)) < TIGHT_SPARE_PCT
        || pct(left_mem, total_free_mem.max(1)) < TIGHT_SPARE_PCT;
    if tight {
        Loss::Tight
    } else {
        Loss::Fits
    }
}

// Would this node take this pod at all: taints it does not tolerate, a nodeSelector it does not
// satisfy, a required node affinity it does not match.
fn accepts(node: &Node, pod: &Pod) -> bool {
    tolerated(node, pod) && selected(node, pod)
}

fn tolerated(node: &Node, pod: &Pod) -> bool {
    let taints: &[Taint] = node
        .spec
        .as_ref()
        .and_then(|s| s.taints.as_deref())
        .unwrap_or(&[]);
    let empty: Vec<Toleration> = Vec::new();
    let tolerations = pod
        .spec
        .as_ref()
        .and_then(|s| s.tolerations.as_ref())
        .unwrap_or(&empty);
    taints
        .iter()
        // `PreferNoSchedule` is a preference, not a rule: it never keeps a pod out.
        .filter(|t| t.effect != "PreferNoSchedule")
        .all(|t| tolerations.iter().any(|tol| tolerates(tol, t)))
}

fn tolerates(tol: &Toleration, taint: &Taint) -> bool {
    // An effect on the toleration narrows it to that effect; absent, it covers them all.
    match tol.effect.as_deref() {
        Some(e) if !e.is_empty() && e != taint.effect => return false,
        _ => {}
    }
    // The empty key with `Exists` is the wildcard: it tolerates everything.
    match tol.key.as_deref() {
        None | Some("") => return tol.operator.as_deref() == Some("Exists"),
        Some(k) if k != taint.key => return false,
        _ => {}
    }
    match tol.operator.as_deref() {
        Some("Exists") => true,
        // `Equal` is the default when the operator is omitted.
        _ => tol.value.as_deref().unwrap_or("") == taint.value.as_deref().unwrap_or(""),
    }
}

fn selected(node: &Node, pod: &Pod) -> bool {
    let empty = BTreeMap::new();
    let labels = node.metadata.labels.as_ref().unwrap_or(&empty);
    let Some(spec) = &pod.spec else { return true };
    if let Some(sel) = &spec.node_selector {
        if !sel.iter().all(|(k, v)| labels.get(k) == Some(v)) {
            return false;
        }
    }
    let Some(terms) = spec
        .affinity
        .as_ref()
        .and_then(|a| a.node_affinity.as_ref())
        .and_then(|na| na.required_during_scheduling_ignored_during_execution.as_ref())
    else {
        return true;
    };
    if terms.node_selector_terms.is_empty() {
        return true;
    }
    // The terms are ORed, the expressions inside one term are ANDed.
    terms.node_selector_terms.iter().any(|term| {
        term.match_expressions
            .iter()
            .flatten()
            .all(|e| match_expression(labels, &e.key, &e.operator, e.values.as_deref()))
            && term
                .match_fields
                .iter()
                .flatten()
                // Field selectors address `metadata.name` and little else; only that one is worth
                // answering, and anything else is left alone rather than guessed at.
                .all(|e| match e.key.as_str() {
                    "metadata.name" => e
                        .values
                        .as_ref()
                        .is_some_and(|v| v.iter().any(|n| Some(n.as_str()) == node.metadata.name.as_deref())),
                    _ => true,
                })
    })
}

fn match_expression(
    labels: &BTreeMap<String, String>,
    key: &str,
    op: &str,
    values: Option<&[String]>,
) -> bool {
    let value = labels.get(key);
    match op {
        "In" => value.is_some_and(|v| values.is_some_and(|vs| vs.contains(v))),
        "NotIn" => match value {
            None => true,
            Some(v) => !values.is_some_and(|vs| vs.contains(v)),
        },
        "Exists" => value.is_some(),
        "DoesNotExist" => value.is_none(),
        "Gt" | "Lt" => {
            let Some(v) = value.and_then(|v| v.parse::<i64>().ok()) else { return false };
            let Some(bound) = values.and_then(|vs| vs.first()).and_then(|s| s.parse::<i64>().ok())
            else {
                return false;
            };
            if op == "Gt" { v > bound } else { v < bound }
        }
        // An operator we do not know is not a reason to declare the pod unplaceable.
        _ => true,
    }
}

// One row per workload, summed over its pods — the level at which requests are actually decided,
// since every pod of a Deployment carries the same spec.
fn workload_sizing(
    pods: &[Pod],
    rs_owners: &HashMap<String, (String, String)>,
    usage: &HashMap<(String, String), (i64, i64)>,
    metrics_available: bool,
    st: &'static Strings,
) -> Vec<WorkloadSizing> {
    let mut by_owner: BTreeMap<(String, String, String), WorkloadSizing> = BTreeMap::new();
    for p in pods {
        // A finished pod holds nothing and asks for nothing worth reviewing.
        if matches!(
            p.status.as_ref().and_then(|s| s.phase.as_deref()).unwrap_or(""),
            "Succeeded" | "Failed"
        ) {
            continue;
        }
        let ns = p.metadata.namespace.clone().unwrap_or_default();
        let (kind, name) = workload_of(p, rs_owners);
        let (cpu_req, mem_req) = pod_requests(p);
        let (cpu_lim, mem_lim) = pod_limits(p);
        let (uc, um) = usage.get(&pod_key(p)).copied().unwrap_or((0, 0));
        let e = by_owner
            .entry((ns.clone(), kind.clone(), name.clone()))
            .or_insert_with(|| WorkloadSizing {
                namespace: ns.clone(),
                kind: kind.clone(),
                name: name.clone(),
                pods: 0,
                cpu_req: 0,
                mem_req: 0,
                cpu_lim: 0,
                mem_lim: 0,
                cpu_use: metrics_available.then_some(0),
                mem_use: metrics_available.then_some(0),
                qos: qos_of(p),
                no_cpu_request: false,
                no_mem_request: false,
                no_mem_limit: false,
                hints: Vec::new(),
            });
        e.pods += 1;
        e.cpu_req += cpu_req;
        e.mem_req += mem_req;
        e.cpu_lim += cpu_lim;
        e.mem_lim += mem_lim;
        if let (Some(c), Some(m)) = (e.cpu_use.as_mut(), e.mem_use.as_mut()) {
            *c += uc;
            *m += um;
        }
        // One pod without a request is enough for the workload to have the problem.
        let (missing_cpu, missing_mem, missing_mem_limit) = missing_resources(p);
        e.no_cpu_request |= missing_cpu;
        e.no_mem_request |= missing_mem;
        e.no_mem_limit |= missing_mem_limit;
        if qos_rank(qos_of(p)) < qos_rank(e.qos) {
            e.qos = qos_of(p);
        }
    }

    let mut out: Vec<WorkloadSizing> = by_owner.into_values().collect();
    for w in &mut out {
        w.hints = sizing_hints(w, st);
    }
    // Most to answer for first: the rows with findings, worst level first.
    out.sort_by(|a, b| {
        worst(&b.hints)
            .cmp(&worst(&a.hints))
            .then(a.namespace.cmp(&b.namespace))
            .then(a.name.cmp(&b.name))
    });
    out
}

fn sizing_hints(w: &WorkloadSizing, st: &'static Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    if w.no_cpu_request || w.no_mem_request {
        // Spelled out once per case rather than pasted together from a fragment: which resource is
        // missing changes the article and the elision in French, and the word order in English.
        //
        // No request means the scheduler places the pod as if it were free, and the kubelet evicts
        // it first when the node runs short. Both halves matter, hence Warn and not Info.
        out.push(warn(
            match (w.no_cpu_request, w.no_mem_request) {
                (true, true) => st.cap_no_request_both,
                (true, false) => st.cap_no_request_cpu,
                _ => st.cap_no_request_mem,
            }
            .to_string(),
        ));
    }
    if w.qos == Qos::BestEffort {
        out.push(warn(st.cap_besteffort.to_string()));
    }
    if let (Some(cu), Some(mu)) = (w.cpu_use, w.mem_use) {
        if oversized(w.cpu_req, cu, OVERSIZED_MIN_CPU) {
            out.push(info(fill(
                st.cap_oversized_cpu,
                &[
                    ("req", &cpu_text(w.cpu_req)),
                    ("used", &cpu_text(cu)),
                    ("idle", &cpu_text(w.cpu_req - cu)),
                ],
            )));
        }
        if oversized(w.mem_req, mu, OVERSIZED_MIN_MEM) {
            out.push(info(fill(
                st.cap_oversized_mem,
                &[
                    ("req", &mem_text(w.mem_req)),
                    ("used", &mem_text(mu)),
                    ("idle", &mem_text(w.mem_req - mu)),
                ],
            )));
        }
        if w.cpu_lim > 0 && pct(cu, w.cpu_lim) >= NEAR_LIMIT_PCT {
            out.push(warn(fill(
                st.cap_near_cpu_limit,
                &[("pct", &pct(cu, w.cpu_lim).to_string())],
            )));
        }
        if w.mem_lim > 0 && pct(mu, w.mem_lim) >= NEAR_LIMIT_PCT {
            out.push(danger(fill(
                st.cap_near_mem_limit,
                &[("pct", &pct(mu, w.mem_lim).to_string())],
            )));
        }
    }
    if w.no_mem_limit {
        out.push(info(st.cap_no_mem_limit.to_string()));
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.level));
    out
}

fn oversized(req: i64, used: i64, floor: i64) -> bool {
    req > floor && used * OVERSIZED_FACTOR < req
}

fn quota_pressure(quotas: &[ResourceQuota], st: &'static Strings) -> Vec<QuotaPressure> {
    let mut out: Vec<QuotaPressure> = quotas
        .iter()
        .map(|q| {
            let namespace = q.metadata.namespace.clone().unwrap_or_default();
            let name = q.metadata.name.clone().unwrap_or_default();
            let status = q.status.as_ref();
            let hard = status.and_then(|s| s.hard.as_ref());
            let used = status.and_then(|s| s.used.as_ref());
            let mut items: Vec<QuotaItem> = Vec::new();
            if let Some(hard) = hard {
                for (resource, h) in hard {
                    let u = used.and_then(|m| m.get(resource)).map(|q| q.0.clone());
                    let used_text = u.clone().unwrap_or_else(|| "0".to_string());
                    items.push(QuotaItem {
                        resource: resource.clone(),
                        used: quantity(&used_text, resource),
                        hard: quantity(&h.0, resource),
                        used_text,
                        hard_text: h.0.clone(),
                    });
                }
            }
            items.sort_by(|a, b| b.pct().cmp(&a.pct()).then(a.resource.cmp(&b.resource)));
            let mut hints = Vec::new();
            for i in &items {
                if i.pct() >= 100 {
                    hints.push(danger(fill(
                        st.cap_quota_full,
                        &[
                            ("resource", &i.resource),
                            ("used", &i.used_text),
                            ("hard", &i.hard_text),
                        ],
                    )));
                } else if i.pct() >= QUOTA_WARN_PCT {
                    hints.push(warn(fill(
                        st.cap_quota_near,
                        &[
                            ("resource", &i.resource),
                            ("pct", &i.pct().to_string()),
                            ("used", &i.used_text),
                            ("hard", &i.hard_text),
                        ],
                    )));
                }
            }
            QuotaPressure { namespace, name, items, hints }
        })
        .collect();
    out.sort_by(|a, b| b.worst_pct().cmp(&a.worst_pct()).then(a.namespace.cmp(&b.namespace)));
    out
}

fn cluster_hints(
    nodes: &[NodeRoom],
    workloads: &[WorkloadSizing],
    metrics_available: bool,
    st: &'static Strings,
) -> Vec<Hint> {
    let mut out = Vec::new();
    if !metrics_available {
        // Said once, at the top: without it, half this view is requests-only, and a reader has to
        // know that rather than wonder why the usage columns are empty.
        out.push(info(st.cap_no_metrics.to_string()));
    }
    let worst = nodes.iter().max_by_key(|n| n.loss.homeless());
    if let Some(n) = worst {
        if n.loss.homeless() > 0 {
            out.push(danger(fill(
                &st.plural(
                    n.loss.homeless(),
                    st.cap_worst_loss_one,
                    st.cap_worst_loss_many,
                ),
                &[("name", &n.name)],
            )));
        }
    }
    let no_request = workloads
        .iter()
        .filter(|w| w.no_cpu_request || w.no_mem_request)
        .count();
    if no_request > 0 {
        out.push(warn(st.plural(
            no_request,
            st.cap_no_request_total_one,
            st.cap_no_request_total_many,
        )));
    }
    let schedulable = nodes.iter().filter(|n| n.ready && n.schedulable).count();
    if schedulable <= 1 {
        out.push(info(st.plural(
            schedulable,
            st.cap_few_schedulable_one,
            st.cap_few_schedulable_many,
        )));
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.level));
    out
}

// --- Helpers ------------------------------------------------------------------------------------

fn worst(hints: &[Hint]) -> Option<HintLevel> {
    hints.iter().map(|h| h.level).max()
}

pub fn pct(part: i64, whole: i64) -> i64 {
    if whole <= 0 {
        return 0;
    }
    (part as f64 / whole as f64 * 100.0).round() as i64
}

fn hosted_by(p: &Pod, node: &str) -> bool {
    p.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node)
        && !matches!(
            p.status.as_ref().and_then(|s| s.phase.as_deref()).unwrap_or(""),
            "Succeeded" | "Failed"
        )
}

fn pod_key(p: &Pod) -> (String, String) {
    (
        p.metadata.namespace.clone().unwrap_or_default(),
        p.metadata.name.clone().unwrap_or_default(),
    )
}

// Limits do not have the init-container floor that requests do: an init container's limit does not
// constrain the running phase, so only the containers are summed.
fn pod_limits(p: &Pod) -> (i64, i64) {
    let Some(spec) = &p.spec else { return (0, 0) };
    spec.containers.iter().fold((0, 0), |(c, m), ct| {
        let lim = ct.resources.as_ref().and_then(|r| r.limits.as_ref());
        let cpu = lim
            .and_then(|l| l.get("cpu"))
            .and_then(|q| parse_quantity_cpu_milli(&q.0))
            .unwrap_or(0);
        let mem = lim
            .and_then(|l| l.get("memory"))
            .and_then(|q| parse_quantity_memory_bytes(&q.0))
            .unwrap_or(0);
        (c + cpu, m + mem)
    })
}

// (no cpu request, no memory request, no memory limit) — true as soon as one container is missing
// it, since that container is the one that will misbehave.
fn missing_resources(p: &Pod) -> (bool, bool, bool) {
    let Some(spec) = &p.spec else { return (false, false, false) };
    let mut out = (false, false, false);
    for c in &spec.containers {
        let req = c.resources.as_ref().and_then(|r| r.requests.as_ref());
        let lim = c.resources.as_ref().and_then(|r| r.limits.as_ref());
        out.0 |= req.and_then(|m| m.get("cpu")).is_none();
        out.1 |= req.and_then(|m| m.get("memory")).is_none();
        out.2 |= lim.and_then(|m| m.get("memory")).is_none();
    }
    out
}

fn qos_of(p: &Pod) -> Qos {
    // The kubelet publishes it; recomputing it would only be a second opinion on the same spec.
    if let Some(q) = p.status.as_ref().and_then(|s| s.qos_class.as_deref()) {
        return match q {
            "Guaranteed" => Qos::Guaranteed,
            "BestEffort" => Qos::BestEffort,
            _ => Qos::Burstable,
        };
    }
    let (cpu_missing, mem_missing, _) = missing_resources(p);
    let (req_cpu, req_mem) = pod_requests(p);
    let (lim_cpu, lim_mem) = pod_limits(p);
    if cpu_missing && mem_missing && lim_cpu == 0 && lim_mem == 0 {
        Qos::BestEffort
    } else if req_cpu == lim_cpu && req_mem == lim_mem && req_cpu > 0 && req_mem > 0 {
        Qos::Guaranteed
    } else {
        Qos::Burstable
    }
}

fn qos_rank(q: Qos) -> u8 {
    match q {
        Qos::BestEffort => 0,
        Qos::Burstable => 1,
        Qos::Guaranteed => 2,
    }
}

fn workload_of(p: &Pod, rs_owners: &HashMap<String, (String, String)>) -> (String, String) {
    let ns = p.metadata.namespace.clone().unwrap_or_default();
    let Some(refs) = p.metadata.owner_references.as_ref() else {
        return ("Pod".to_string(), p.metadata.name.clone().unwrap_or_default());
    };
    let Some(owner) = refs.iter().find(|o| o.controller == Some(true)).or_else(|| refs.first())
    else {
        return ("Pod".to_string(), p.metadata.name.clone().unwrap_or_default());
    };
    if owner.kind == "ReplicaSet" {
        if let Some((kind, name)) = rs_owners.get(&format!("{}/{}", ns, owner.name)) {
            return (kind.clone(), name.clone());
        }
    }
    (owner.kind.clone(), owner.name.clone())
}

fn allocatable(n: &Node) -> (i64, i64) {
    let Some(alloc) = n.status.as_ref().and_then(|s| s.allocatable.as_ref()) else {
        return (0, 0);
    };
    (
        alloc.get("cpu").and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0),
        alloc
            .get("memory")
            .and_then(|q| parse_quantity_memory_bytes(&q.0))
            .unwrap_or(0),
    )
}

fn pod_capacity(n: &Node) -> i64 {
    n.status
        .as_ref()
        .and_then(|s| s.allocatable.as_ref())
        .and_then(|a| a.get("pods"))
        .and_then(|q| q.0.parse::<i64>().ok())
        .unwrap_or(0)
}

fn is_ready(n: &Node) -> bool {
    n.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .is_some_and(|c| c.status == "True")
}

fn unschedulable(n: &Node) -> bool {
    n.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false)
}

// A quota counts CPU, memory *and* plain objects ("pods: 10"), so the unit follows the key. Counts
// go through the memory parser rather than a bare `parse`: a quota writes a thousand pods as `1k`,
// and reading that as zero would print a reassuring 0% on a quota that is actually full.
fn quantity(text: &str, resource: &str) -> i64 {
    if resource.contains("cpu") {
        parse_quantity_cpu_milli(text).unwrap_or(0)
    } else {
        parse_quantity_memory_bytes(text).unwrap_or(0)
    }
}

// Rendering helpers shared with the view, so a CPU figure reads the same everywhere.
pub fn cpu_text(v: i64) -> String {
    format_cpu_milli(v)
}

pub fn mem_text(v: i64) -> String {
    format_memory_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{FR, reads_as};
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
                "allocatable": {"cpu": cpu, "memory": mem, "pods": "110"},
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }))
    }

    fn sized_pod(ns: &str, name: &str, host: &str, cpu: &str, mem: &str) -> Pod {
        pod(json!({
            "metadata": {
                "name": name, "namespace": ns,
                "ownerReferences": [{"kind": "StatefulSet", "name": "db", "controller": true}],
            },
            "spec": {"nodeName": host, "containers": [
                {"name": "c", "resources": {"requests": {"cpu": cpu, "memory": mem}}}
            ]},
            "status": {"phase": "Running"},
        }))
    }

    #[test]
    fn losing_a_node_strands_what_does_not_fit_anywhere() {
        let nodes = vec![plain_node("n1", "4", "8Gi"), plain_node("n2", "4", "8Gi")];
        // n2 already carries 7Gi, so the 4Gi pod on n1 has nowhere to land.
        let pods = vec![
            sized_pod("data", "big", "n1", "500m", "4Gi"),
            sized_pod("data", "resident", "n2", "500m", "7Gi"),
        ];
        let loss = simulate_loss("n1", &nodes, &pods);
        match loss {
            Loss::Homeless(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].name, "big");
                assert_eq!(v[0].why, Homeless::NoRoom);
            }
            other => panic!("attendu Homeless, obtenu {:?}", other),
        }
    }

    #[test]
    fn the_biggest_pod_is_placed_first_so_first_fit_does_not_strand_it() {
        // 6Gi free on n2, two pods to move: 4Gi and 2Gi. Smallest-first would still fit here, so
        // the case that discriminates is one where a naive order fragments the room.
        let nodes = vec![
            plain_node("n1", "4", "8Gi"),
            plain_node("n2", "4", "4Gi"),
            plain_node("n3", "4", "4Gi"),
        ];
        let pods = vec![
            sized_pod("apps", "small", "n1", "100m", "1Gi"),
            sized_pod("apps", "large", "n1", "100m", "4Gi"),
        ];
        // Largest first: 4Gi → n2 (full), 1Gi → n3. Everything lands.
        assert!(matches!(simulate_loss("n1", &nodes, &pods), Loss::Fits | Loss::Tight));
    }

    #[test]
    fn a_taint_and_a_selector_are_told_apart() {
        let mut tainted = plain_node("n2", "8", "16Gi");
        tainted.spec.as_mut().expect("spec").taints = Some(vec![serde_json::from_value(json!({
            "key": "gpu", "value": "true", "effect": "NoSchedule"
        }))
        .expect("taint")]);
        let nodes = vec![plain_node("n1", "8", "16Gi"), tainted];
        let picky = pod(json!({
            "metadata": {"name": "picky", "namespace": "apps"},
            "spec": {
                "nodeName": "n1",
                "nodeSelector": {"disk": "ssd"},
                "containers": [{"name": "c"}],
            },
            "status": {"phase": "Running"},
        }));
        let untolerating = pod(json!({
            "metadata": {"name": "plain", "namespace": "apps"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
            "status": {"phase": "Running"},
        }));

        let loss = simulate_loss("n1", &nodes, &[picky, untolerating]);
        let Loss::Homeless(v) = loss else { panic!("attendu Homeless") };
        let picky = v.iter().find(|p| p.name == "picky").expect("picky");
        let plain = v.iter().find(|p| p.name == "plain").expect("plain");
        // The only other node is tainted, so nothing gets through — but the picky pod's own
        // selector is reported, because that is what its owner has to fix.
        assert_eq!(plain.why, Homeless::Taints);
        assert_eq!(picky.why, Homeless::Taints);

        // Untaint it: now the selector is the only thing left standing in the way.
        let nodes = vec![plain_node("n1", "8", "16Gi"), plain_node("n2", "8", "16Gi")];
        let picky = pod(json!({
            "metadata": {"name": "picky", "namespace": "apps"},
            "spec": {"nodeName": "n1", "nodeSelector": {"disk": "ssd"}, "containers": [{"name": "c"}]},
            "status": {"phase": "Running"},
        }));
        let Loss::Homeless(v) = simulate_loss("n1", &nodes, &[picky]) else {
            panic!("attendu Homeless")
        };
        assert_eq!(v[0].why, Homeless::Selector);
    }

    #[test]
    fn a_tolerated_taint_does_not_keep_a_pod_out() {
        let mut tainted = plain_node("n2", "8", "16Gi");
        tainted.spec.as_mut().expect("spec").taints = Some(vec![
            serde_json::from_value(json!({"key": "gpu", "value": "true", "effect": "NoSchedule"}))
                .expect("taint"),
        ]);
        let nodes = vec![plain_node("n1", "8", "16Gi"), tainted];
        let tolerant = pod(json!({
            "metadata": {"name": "gpu-job", "namespace": "apps"},
            "spec": {
                "nodeName": "n1",
                "tolerations": [{"key": "gpu", "operator": "Equal", "value": "true", "effect": "NoSchedule"}],
                "containers": [{"name": "c"}],
            },
            "status": {"phase": "Running"},
        }));
        assert!(matches!(simulate_loss("n1", &nodes, &[tolerant]), Loss::Fits | Loss::Tight));
    }

    #[test]
    fn preferred_taints_and_the_wildcard_toleration_are_handled() {
        let taint: Taint =
            serde_json::from_value(json!({"key": "spot", "effect": "NoSchedule"})).expect("taint");
        let wildcard: Toleration =
            serde_json::from_value(json!({"operator": "Exists"})).expect("tol");
        assert!(tolerates(&wildcard, &taint));

        let wrong_effect: Toleration =
            serde_json::from_value(json!({"key": "spot", "operator": "Exists", "effect": "NoExecute"}))
                .expect("tol");
        assert!(!tolerates(&wrong_effect, &taint));

        // A PreferNoSchedule taint never keeps anyone out, tolerated or not.
        let mut n = plain_node("n1", "1", "1Gi");
        n.spec.as_mut().expect("spec").taints = Some(vec![serde_json::from_value(
            json!({"key": "soft", "effect": "PreferNoSchedule"}),
        )
        .expect("taint")]);
        let bare = pod(json!({
            "metadata": {"name": "p", "namespace": "d"},
            "spec": {"containers": [{"name": "c"}]},
        }));
        assert!(tolerated(&n, &bare));
    }

    #[test]
    fn a_single_node_cluster_has_no_simulation_to_run() {
        let nodes = vec![plain_node("n1", "4", "8Gi")];
        let pods = vec![sized_pod("apps", "web", "n1", "1", "1Gi")];
        assert_eq!(simulate_loss("n1", &nodes, &pods), Loss::Alone);
    }

    #[test]
    fn daemonset_and_finished_pods_are_not_re_placed() {
        let nodes = vec![plain_node("n1", "1", "1Gi"), plain_node("n2", "1", "1Gi")];
        let ds = pod(json!({
            "metadata": {
                "name": "cni", "namespace": "kube-system",
                "ownerReferences": [{"kind": "DaemonSet", "name": "cni", "controller": true}],
            },
            "spec": {"nodeName": "n1", "containers": [
                {"name": "c", "resources": {"requests": {"cpu": "4", "memory": "8Gi"}}}
            ]},
            "status": {"phase": "Running"},
        }));
        let done = pod(json!({
            "metadata": {"name": "job", "namespace": "apps"},
            "spec": {"nodeName": "n1", "containers": [
                {"name": "c", "resources": {"requests": {"cpu": "4", "memory": "8Gi"}}}
            ]},
            "status": {"phase": "Succeeded"},
        }));
        // Both are far bigger than n2, and neither should be counted as stranded.
        assert!(matches!(simulate_loss("n1", &nodes, &[ds, done]), Loss::Fits | Loss::Tight));
    }

    #[test]
    fn a_workload_without_requests_is_flagged_and_named_after_its_deployment() {
        let p = pod(json!({
            "metadata": {
                "name": "web-6d9c-abc", "namespace": "apps",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-6d9c", "controller": true}],
            },
            "spec": {"nodeName": "n1", "containers": [{"name": "c"}]},
            "status": {"phase": "Running", "qosClass": "BestEffort"},
        }));
        let mut owners = HashMap::new();
        owners.insert(
            "apps/web-6d9c".to_string(),
            ("Deployment".to_string(), "web".to_string()),
        );
        let rows = workload_sizing(&[p], &owners, &HashMap::new(), false, &FR);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].kind.as_str(), rows[0].name.as_str()), ("Deployment", "web"));
        assert_eq!(rows[0].qos, Qos::BestEffort);
        assert!(rows[0].hints.iter().any(|h| h.text == FR.cap_no_request_both));
        assert!(rows[0].hints.iter().any(|h| h.text == FR.cap_besteffort));
    }

    #[test]
    fn oversizing_needs_both_a_ratio_and_an_absolute_floor() {
        // 2 CPU asked, 100m used: 20x over, well past the floor.
        let big = sized_pod("apps", "hog", "n1", "2", "4Gi");
        let mut usage = HashMap::new();
        usage.insert(("apps".to_string(), "hog".to_string()), (100, 100 * 1024 * 1024));
        let rows = workload_sizing(&[big], &HashMap::new(), &usage, true, &FR);
        assert!(rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_oversized_cpu)));
        assert!(rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_oversized_mem)));

        // A 50m sidecar using 1m is 50x over and nobody cares: below the floor, nothing is said.
        let small = sized_pod("apps", "sidecar", "n1", "50m", "16Mi");
        let mut usage = HashMap::new();
        usage.insert(("apps".to_string(), "sidecar".to_string()), (1, 1024 * 1024));
        let rows = workload_sizing(&[small], &HashMap::new(), &usage, true, &FR);
        assert!(!rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_oversized_cpu)));
    }

    #[test]
    fn without_metrics_no_rule_reads_an_absent_figure_as_a_zero() {
        let p = sized_pod("apps", "web", "n1", "2", "4Gi");
        let rows = workload_sizing(&[p], &HashMap::new(), &HashMap::new(), false, &FR);
        assert_eq!(rows[0].cpu_use, None);
        assert!(!rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_oversized_cpu)));
        assert!(!rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_near_cpu_limit)));
    }

    #[test]
    fn memory_against_its_own_limit_is_a_danger_and_cpu_only_a_warning() {
        let p = pod(json!({
            "metadata": {"name": "tight", "namespace": "apps"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c", "resources": {
                "requests": {"cpu": "1", "memory": "1Gi"},
                "limits": {"cpu": "1", "memory": "1Gi"},
            }}]},
            "status": {"phase": "Running", "qosClass": "Guaranteed"},
        }));
        let mut usage = HashMap::new();
        usage.insert(
            ("apps".to_string(), "tight".to_string()),
            (980, 1000 * 1024 * 1024),
        );
        let rows = workload_sizing(&[p], &HashMap::new(), &usage, true, &FR);
        let mem = rows[0]
            .hints
            .iter()
            .find(|h| reads_as(&h.text, FR.cap_near_mem_limit))
            .expect("near-limit-mem");
        assert_eq!(mem.level, HintLevel::Danger);
        let cpu = rows[0]
            .hints
            .iter()
            .find(|h| reads_as(&h.text, FR.cap_near_cpu_limit))
            .expect("near-limit-cpu");
        assert_eq!(cpu.level, HintLevel::Warn);
    }

    #[test]
    fn a_saturated_quota_is_a_danger_and_object_counts_parse_as_counts() {
        let q: ResourceQuota = serde_json::from_value(json!({
            "metadata": {"name": "compute", "namespace": "apps"},
            "spec": {},
            "status": {
                "hard": {"requests.cpu": "10", "requests.memory": "20Gi", "pods": "10"},
                "used": {"requests.cpu": "9500m", "requests.memory": "4Gi", "pods": "10"},
            },
        }))
        .expect("quota fixture");
        let rows = quota_pressure(&[q], &FR);
        assert_eq!(rows.len(), 1);
        let pods = rows[0].items.iter().find(|i| i.resource == "pods").expect("pods");
        assert_eq!((pods.used, pods.hard, pods.pct()), (10, 10, 100));
        // `1k` is how a quota writes a thousand: read as zero it would print a reassuring 0%.
        assert_eq!(quantity("1k", "pods"), 1000);
        let cpu = rows[0]
            .items
            .iter()
            .find(|i| i.resource == "requests.cpu")
            .expect("cpu");
        assert_eq!(cpu.pct(), 95);
        assert!(rows[0].hints.iter().any(|h| h.level == HintLevel::Danger));
        assert!(rows[0].hints.iter().any(|h| reads_as(&h.text, FR.cap_quota_near)));
    }

    #[test]
    fn a_nearly_full_node_says_so_on_the_axis_that_is_full() {
        let n = plain_node("n1", "4", "8Gi");
        let pods = vec![sized_pod("apps", "hog", "n1", "3800m", "1Gi")];
        let rooms = node_rooms(&[n], &pods, &HashMap::new(), false);
        assert_eq!(pct(rooms[0].req_cpu, rooms[0].alloc_cpu), 95);
        let hints = node_hints(&rooms[0], &FR);
        assert!(hints.iter().any(|h| reads_as(&h.text, FR.cap_cpu_reserved)));
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cap_mem_reserved)));
    }
}
