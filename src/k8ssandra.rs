//! K8ssandra / Cassandra inventory for the `:k8ssandra` view.
//!
//! `kubectl get medusabackupjobs` lists objects. It does not say whether anything is restorable,
//! and on a k8ssandra cluster that is the only question that matters. The three surfaces an operator
//! would normally check all lie by omission:
//!
//! * `MedusaBackupSchedule.status` keeps a fresh `lastExecution` and a clean `nextSchedule` whether
//!   the run it fired succeeded or failed — it records that the schedule fired, nothing more.
//! * the nightly purge CronJob completes green while purging nothing, because it purges what the
//!   catalogue knows about and the catalogue is exactly what stops being written when backups break.
//! * `MedusaBackup` objects, the catalogue itself, simply stop appearing. An absence produces no
//!   event, no condition, and no status field anywhere.
//!
//! So a cluster can run for months with a green schedule, a green CronJob, and not one restorable
//! backup. This view exists to say that out loud: the headline is the age of the last backup that
//! covers *every* node of the datacenter, and a schedule whose runs all fail is a `Danger`, not a
//! detail two screens down.
//!
//! Two shapes of the API have to be survived rather than assumed. `MedusaBackup.status` carries only
//! `startTime`/`finishTime` on k8ssandra-operator up to 1.9; `totalNodes`, `finishedNodes`,
//! `nodes[]` and `status` appear later. Where they are missing the per-node coverage is recovered
//! from the `MedusaBackupJob` of the same name, and where that is missing too the verdict abstains
//! instead of guessing. And a `finishTime` of `1970-01-01T00:00:00Z` is a serialised zero value, not
//! a date in 1970 — see [`real_ts`], without which the view would report an age of half a century.
//!
//! The ring itself (up/down, schema agreement, load) comes from [`crate::mgmtapi`], not from any
//! CRD. When the management API does not answer, `ring_known` goes false and every rule that needs
//! it goes quiet.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures::future::join_all;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::{json, Value};

use crate::lang::{fill, Strings};
use crate::mgmtapi::{self, Endpoint};

// The severity vocabulary is the cluster-wide one, deliberately not a local copy: reflector defined
// its own and that is why the diagnostic carries a second, near-identical hint-pushing helper.
pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- API surface ---------------------------------------------------------------------------------

const G_K8SSANDRA: &str = "k8ssandra.io";
const G_CASSANDRA: &str = "cassandra.datastax.com";
const G_MEDUSA: &str = "medusa.k8ssandra.io";
const G_CONTROL: &str = "control.k8ssandra.io";
const G_REAPER: &str = "reaper.k8ssandra.io";
const G_STARGATE: &str = "stargate.k8ssandra.io";

// The label cass-operator stamps on every pod it owns, used to list the Cassandra pods of the whole
// cluster in one call instead of one call per namespace.
const L_DATACENTER: &str = "cassandra.datastax.com/datacenter";
const L_CLUSTER: &str = "cassandra.datastax.com/cluster";
const L_RACK: &str = "cassandra.datastax.com/rack";
const L_NODE_STATE: &str = "cassandra.datastax.com/node-state";

// Every kind the view reads, newest API version first. Twelve kinds is twelve discovery round-trips;
// in sequence on a remote cluster that is ten seconds of blank screen, so they are probed as one
// wave and listed as a second — the shape velero and kyverno already use.
const KINDS: &[(&str, &[&str], &str)] = &[
    (G_K8SSANDRA, &["v1alpha1"], "K8ssandraCluster"),
    (G_CASSANDRA, &["v1beta1"], "CassandraDatacenter"),
    (G_MEDUSA, &["v1alpha1"], "MedusaBackupSchedule"),
    (G_MEDUSA, &["v1alpha1"], "MedusaBackupJob"),
    (G_MEDUSA, &["v1alpha1"], "MedusaBackup"),
    (G_MEDUSA, &["v1alpha1"], "MedusaRestoreJob"),
    (G_MEDUSA, &["v1alpha1"], "MedusaTask"),
    (G_CONTROL, &["v1alpha1"], "CassandraTask"),
    (G_CONTROL, &["v1alpha1"], "K8ssandraTask"),
    (G_REAPER, &["v1alpha1"], "Reaper"),
    (G_STARGATE, &["v1alpha1"], "Stargate"),
];

// A `finishTime` that Go never set marshals as the epoch rather than as an absent field. Anything
// inside the first day of 1970 is that zero value: no Cassandra cluster has a real backup there, and
// treating it as a date turns "never finished" into "finished 56 years ago", which is the difference
// between a red RPO and a green one.
const EPOCH_GUARD: i64 = 86_400;

/// What `MedusaBackupJob.spec.backupType` falls back to when nobody sets one.
///
/// The CRD defaults the field to `differential` and constrains it to an enum of exactly
/// `differential` and `full` — the empty string is **not** in that enum. So "unset" has to be
/// expressed by leaving the key out of the payload entirely: sending `backupType: ""` is not an
/// absent field, it is an invalid value, and the apiserver rejects the whole create.
pub const DEFAULT_BACKUP_TYPE: &str = "differential";

/// The backup type a run started from this schedule will really carry, and whether that is the CRD's
/// default rather than something the schedule asked for.
pub fn effective_backup_type(raw: &str) -> (&str, bool) {
    match raw.trim() {
        "" => (DEFAULT_BACKUP_TYPE, true),
        set => (set, false),
    }
}

/// A timestamp that is actually a timestamp — see [`EPOCH_GUARD`].
pub fn real_ts(t: Option<i64>) -> Option<i64> {
    t.filter(|v| *v > EPOCH_GUARD)
}

// --- Records -------------------------------------------------------------------------------------

/// How Medusa is configured on a cluster. Read from the K8ssandraCluster, which is the only place it
/// exists: the MedusaBackupJob objects carry no storage information at all.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MedusaConfig {
    pub provider: String,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    pub secret: String,
    pub max_backup_age: Option<i64>,
    pub max_backup_count: Option<i64>,
    pub concurrent_transfers: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct K8cCluster {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub created: i64,
    pub server_type: String,
    pub server_version: String,
    pub auth: Option<bool>,
    pub medusa: Option<MedusaConfig>,
    pub reaper_enabled: bool,
    pub stargate_enabled: bool,
    pub datacenters: Vec<String>,
    pub conditions: Vec<(String, String)>,
    // `status.error` is a free string the operator sets to the literal "None" when all is well.
    pub error: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct K8cDatacenter {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    /// The Cassandra cluster name (`spec.clusterName`), which is also Medusa's prefix in the bucket.
    pub cluster_name: String,
    pub created: i64,
    pub server_type: String,
    pub server_version: String,
    pub size: i64,
    pub racks: Vec<String>,
    pub stopped: bool,
    /// `status.cassandraOperatorProgress`: `Ready`, or `Updating` while the operator reconciles.
    pub progress: String,
    pub conditions: Vec<(String, String)>,
    /// Pod name to host id, as the operator recorded it. Its length is how many nodes ever joined.
    pub node_statuses: Vec<(String, String)>,
    pub declared_storage: String,
    pub storage_class: String,
    pub hints: Vec<Hint>,
}

impl K8cDatacenter {
    pub fn condition(&self, kind: &str) -> Option<&str> {
        self.conditions.iter().find(|(k, _)| k == kind).map(|(_, v)| v.as_str())
    }
    pub fn ready(&self) -> bool {
        self.condition("Ready") == Some("True")
    }
    /// The operations cass-operator reports as in flight. A datacenter in one of these states is
    /// mid-change, and that is the context every other reading has to be understood in.
    pub fn in_flight(&self) -> Vec<&str> {
        ["Updating", "RollingRestart", "ReplacingNodes", "ScalingDown", "Resuming"]
            .into_iter()
            .filter(|k| self.condition(k) == Some("True"))
            .collect()
    }
}

/// What the ring says about a node, when the management API answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RingFacts {
    pub state: String,
    pub alive: bool,
    pub status_code: String,
    pub load_bytes: Option<f64>,
    pub tokens: usize,
    pub schema: String,
    pub ip: String,
}

#[derive(Debug, Clone, Default)]
pub struct K8cNode {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub cluster: String,
    pub datacenter: String,
    pub rack: String,
    pub created: i64,
    pub phase: String,
    pub ready: bool,
    pub restarts: i32,
    pub node_name: String,
    pub pod_ip: String,
    pub host_id: String,
    /// Set when the datacenter status claims a host id the ring does not know for this pod: the
    /// operator's record has gone stale, and every join that trusts it silently finds nothing.
    pub host_id_stale: bool,
    /// cass-operator's own view (`cassandra.datastax.com/node-state`), e.g. `Started`.
    pub node_state: String,
    /// None when the management API did not answer: unknown, not down.
    pub ring: Option<RingFacts>,
    pub claims: Vec<(String, String)>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct MedSchedule {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub backup_type: String,
    pub cron: String,
    pub disabled: bool,
    pub last_execution: Option<i64>,
    pub next_schedule: Option<i64>,
    /// Runs fired by this schedule, newest first, as uids into [`K8cState::jobs`].
    pub runs: Vec<String>,
    pub hints: Vec<Hint>,
}

/// One run of Medusa. The outcome is per node: `finished` and `failed` are pod name lists, and a run
/// that finished on some nodes and failed on others produced a backup that cannot be restored whole.
#[derive(Debug, Clone, Default)]
pub struct MedJob {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub backup_type: String,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    pub finished: Vec<String>,
    pub failed: Vec<String>,
    pub in_progress: Vec<String>,
    /// Nodes the datacenter had when this run happened, when it could be established.
    pub expected: Option<usize>,
    /// Whether a `MedusaBackup` of the same name exists — the catalogue entry that makes it
    /// restorable through the operator.
    pub in_catalogue: bool,
    pub hints: Vec<Hint>,
}

impl MedJob {
    pub fn running(&self) -> bool {
        !self.in_progress.is_empty() || (self.finish.is_none() && self.start.is_some())
    }
    /// Complete on every node the datacenter has. `None` when the node count is unknown, which is an
    /// abstention: the run is not declared whole and not declared partial.
    pub fn complete(&self) -> Option<bool> {
        if !self.failed.is_empty() || self.running() {
            return Some(false);
        }
        self.expected.map(|n| n > 0 && self.finished.len() >= n)
    }
    pub fn partial(&self) -> bool {
        !self.finished.is_empty() && !self.failed.is_empty()
    }
}

/// A catalogue entry: what Medusa considers restorable.
#[derive(Debug, Clone, Default)]
pub struct MedBackup {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub backup_type: String,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    // Present only from the operator versions that added them; None means "this API does not say".
    pub total_nodes: Option<i64>,
    pub finished_nodes: Option<i64>,
    pub total_size: Option<i64>,
    pub status: String,
    /// Coverage recovered from the run of the same name when the object itself does not carry it.
    pub complete: Option<bool>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct MedRestore {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub backup: String,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    pub datacenter_stopped: Option<i64>,
    pub restore_key: String,
    pub restore_prepared: bool,
    pub failed: Vec<String>,
    pub in_progress: Vec<String>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct MedTask {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    /// `purge`, `sync`, or `prepare_restore`.
    pub operation: String,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    pub finished: Vec<String>,
    pub failed: Vec<String>,
    pub in_progress: Vec<String>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct CassTask {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub commands: Vec<String>,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    pub active: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct ReaperRec {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub datacenter: String,
    pub created: i64,
    pub progress: String,
    pub ready: bool,
    /// Secret holding the UI credentials, as the object names it — never a name derived by hand.
    pub ui_secret: String,
    /// Service the REST API is reached through, derived from the object name the operator uses.
    pub service: String,
    pub hints: Vec<Hint>,
}

// --- State ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct K8cState {
    pub installed: bool,
    pub clusters: Vec<K8cCluster>,
    pub datacenters: Vec<K8cDatacenter>,
    pub nodes: Vec<K8cNode>,
    pub schedules: Vec<MedSchedule>,
    pub jobs: Vec<MedJob>,
    pub backups: Vec<MedBackup>,
    pub restores: Vec<MedRestore>,
    pub tasks: Vec<MedTask>,
    pub cass_tasks: Vec<CassTask>,
    pub reapers: Vec<ReaperRec>,
    /// The `nodetool` Jobs kdt has started, which are Jobs rather than CRDs and so are listed on
    /// their own rather than going through `analyse`.
    pub nodetool_jobs: Vec<crate::nodetool::NtJob>,
    pub cluster_hints: Vec<Hint>,
    /// When the newest backup that covers every node finished. The one number the view owes on sight.
    pub last_restorable: Option<i64>,
    /// False when no management API answered: the ring columns are unknown, not empty.
    pub ring_known: bool,
    pub error: Option<String>,
    pub loading: bool,
}

impl K8cState {
    pub fn problems(&self) -> usize {
        let count = |hints: &[Hint]| usize::from(hints.iter().any(|h| h.level >= HintLevel::Warn));
        self.clusters.iter().map(|c| count(&c.hints)).sum::<usize>()
            + self.datacenters.iter().map(|d| count(&d.hints)).sum::<usize>()
            + self.nodes.iter().map(|n| count(&n.hints)).sum::<usize>()
            + self.schedules.iter().map(|s| count(&s.hints)).sum::<usize>()
            + self.jobs.iter().map(|j| count(&j.hints)).sum::<usize>()
            + self.backups.iter().map(|b| count(&b.hints)).sum::<usize>()
            + self.restores.iter().map(|r| count(&r.hints)).sum::<usize>()
            + self.tasks.iter().map(|t| count(&t.hints)).sum::<usize>()
            + self.cass_tasks.iter().map(|t| count(&t.hints)).sum::<usize>()
            + self.reapers.iter().map(|r| count(&r.hints)).sum::<usize>()
    }
}

pub type SharedK8c = Arc<Mutex<K8cState>>;

pub fn new_k8c_state() -> SharedK8c {
    Arc::new(Mutex::new(K8cState::default()))
}

// --- Fetch ---------------------------------------------------------------------------------------

struct Listed {
    by_kind: HashMap<&'static str, Vec<DynamicObject>>,
    installed: bool,
}

pub async fn fetch_k8ssandra(client: Client, state: SharedK8c) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("k8ssandra poisoned");
        s.loading = true;
        s.error = None;
    }

    let (objects, pods, claims, nodetool_jobs) = futures::join!(
        list_kinds(&client),
        list_cassandra_pods(&client),
        list_claims(&client),
        crate::nodetool::list_jobs(&client, st),
    );

    let Listed { mut by_kind, installed } = objects;
    if !installed {
        let mut s = state.lock().expect("k8ssandra poisoned");
        *s = K8cState {
            loading: false,
            installed: false,
            error: Some(st.k8c_crds_missing.to_string()),
            ..K8cState::default()
        };
        return;
    }

    let take = |k: &str, by: &mut HashMap<&'static str, Vec<DynamicObject>>| {
        by.remove(k).unwrap_or_default()
    };
    let clusters_raw = take("K8ssandraCluster", &mut by_kind);
    let dcs_raw = take("CassandraDatacenter", &mut by_kind);
    let scheds_raw = take("MedusaBackupSchedule", &mut by_kind);
    let jobs_raw = take("MedusaBackupJob", &mut by_kind);
    let backups_raw = take("MedusaBackup", &mut by_kind);
    let restores_raw = take("MedusaRestoreJob", &mut by_kind);
    let tasks_raw = take("MedusaTask", &mut by_kind);
    let ctasks_raw = take("CassandraTask", &mut by_kind);
    let k8ctasks_raw = take("K8ssandraTask", &mut by_kind);
    let reapers_raw = take("Reaper", &mut by_kind);
    let stargates_raw = take("Stargate", &mut by_kind);

    let mut clusters: Vec<K8cCluster> = clusters_raw.iter().map(parse_cluster).collect();
    clusters.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut datacenters: Vec<K8cDatacenter> = dcs_raw.iter().map(parse_datacenter).collect();
    datacenters.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut schedules: Vec<MedSchedule> = scheds_raw.iter().map(parse_schedule).collect();
    schedules.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    // Runs, catalogue and restores newest first: on a schedule keeping a fortnight of history, the
    // one worth looking at is the last one that ran.
    let mut jobs: Vec<MedJob> = jobs_raw.iter().map(parse_job).collect();
    jobs.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut backups: Vec<MedBackup> = backups_raw.iter().map(parse_backup).collect();
    backups.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut restores: Vec<MedRestore> = restores_raw.iter().map(parse_restore).collect();
    restores.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut tasks: Vec<MedTask> = tasks_raw.iter().map(parse_med_task).collect();
    tasks.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut cass_tasks: Vec<CassTask> = ctasks_raw
        .iter()
        .chain(k8ctasks_raw.iter())
        .map(parse_cass_task)
        .collect();
    cass_tasks.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut reapers: Vec<ReaperRec> = reapers_raw.iter().map(parse_reaper).collect();
    reapers.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    for c in &mut clusters {
        c.stargate_enabled = c.stargate_enabled
            || stargates_raw.iter().any(|s| {
                s.metadata.namespace.as_deref() == Some(c.namespace.as_str())
            });
    }

    // The ring is one HTTP call per datacenter, against a pod that is Ready. A datacenter with no
    // Ready pod is skipped rather than retried: there is nothing to ask.
    let pods = pods.unwrap_or_default();
    let nodes = build_nodes(&pods, claims.as_deref().unwrap_or_default());
    // The ring is joined to the pods inside `analyse`, once the host ids have been copied out of the
    // datacenter status: nothing here knows a pod's host id yet.
    let (ring, ring_known) = fetch_rings(&client, &datacenters, &nodes).await;

    let inv = Inventory {
        clusters,
        datacenters,
        nodes,
        schedules,
        jobs,
        backups,
        restores,
        tasks,
        cass_tasks,
        reapers,
        ring,
        ring_known,
        pods_known: !pods.is_empty(),
        claims_known: claims.is_some(),
    };
    let analysed = analyse(inv, now_ts(), st);

    let mut s = state.lock().expect("k8ssandra poisoned");
    *s = K8cState {
        installed: true,
        loading: false,
        error: None,
        clusters: analysed.clusters,
        datacenters: analysed.datacenters,
        nodes: analysed.nodes,
        schedules: analysed.schedules,
        jobs: analysed.jobs,
        backups: analysed.backups,
        restores: analysed.restores,
        tasks: analysed.tasks,
        cass_tasks: analysed.cass_tasks,
        reapers: analysed.reapers,
        nodetool_jobs: nodetool_jobs.unwrap_or_default(),
        cluster_hints: analysed.cluster_hints,
        last_restorable: analysed.last_restorable,
        ring_known: analysed.ring_known,
    };
}

// Two waves: resolve every kind through discovery, then list the ones that resolved. A kind that
// does not resolve is not an error — Stargate and K8ssandraTask are simply absent on most clusters,
// and an older operator does not serve them at all.
async fn list_kinds(client: &Client) -> Listed {
    let probes = KINDS.iter().map(|(group, versions, kind)| async move {
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
                return Some((*group, *kind, ar));
            }
        }
        None
    });
    let resolved: Vec<_> = join_all(probes).await.into_iter().flatten().collect();
    let installed = resolved.iter().any(|(group, _, _)| *group == G_K8SSANDRA);

    let lists = resolved.into_iter().map(|(_, kind, ar)| {
        let client = client.clone();
        async move {
            let api: Api<DynamicObject> = Api::all_with(client, &ar);
            match api.list(&ListParams::default()).await {
                Ok(list) => Some((kind, list.items)),
                Err(_) => None,
            }
        }
    });
    let by_kind = join_all(lists).await.into_iter().flatten().collect();
    Listed { by_kind, installed }
}

// Only the pods cass-operator owns, in one call. `None` means the list could not be read at all,
// which the rules treat as "unknown" rather than "no pods".
async fn list_cassandra_pods(client: &Client) -> Option<Vec<Pod>> {
    let api: Api<Pod> = Api::all(client.clone());
    api.list(&ListParams::default().labels(L_DATACENTER))
        .await
        .ok()
        .map(|l| l.items)
}

async fn list_claims(client: &Client) -> Option<Vec<PersistentVolumeClaim>> {
    let api: Api<PersistentVolumeClaim> = Api::all(client.clone());
    api.list(&ListParams::default()).await.ok().map(|l| l.items)
}

// One ring read per datacenter, in parallel, from the first Ready pod of each. The management API is
// on the pod itself, so any Ready pod gives the same view of the ring.
async fn fetch_rings(
    client: &Client,
    datacenters: &[K8cDatacenter],
    nodes: &[K8cNode],
) -> (Vec<Endpoint>, bool) {
    let calls = datacenters.iter().filter_map(|dc| {
        let pod = nodes
            .iter()
            .find(|n| n.namespace == dc.namespace && n.datacenter == dc.name && n.ready)?;
        let (ns, name) = (pod.namespace.clone(), pod.name.clone());
        let client = client.clone();
        Some(async move { mgmtapi::endpoints(&client, &ns, &name).await.ok() })
    });
    let results: Vec<Option<Vec<Endpoint>>> = join_all(calls).await;
    let known = results.iter().any(Option::is_some);
    let mut all: Vec<Endpoint> = results.into_iter().flatten().flatten().collect();
    // The same endpoint is reported by every datacenter that gossips with it; keep one entry each.
    let mut seen = HashSet::new();
    all.retain(|e| seen.insert(e.host_id.clone()));
    (all, known)
}

// Join the pods to their ring entries.
//
// The obvious key is the host id out of `status.nodeStatuses`, and it is the wrong one: that map is
// the operator's memory of the datacenter, and it goes stale. On one of the clusters this was built
// against, not a single host id in `nodeStatuses` still existed in the ring — the pods had been
// re-bootstrapped and cass-operator never rewrote them — while every pod IP matched exactly.
//
// So the address is tried first, since it is read from the live pod and from the live ring on both
// sides, and the host id is only the fallback for the case where the IP is not known yet. When both
// are available and they disagree, the ring wins and the pod is marked: an operator reading a stale
// host id would go looking for a node that no longer exists under that name.
fn attach_ring(nodes: &mut [K8cNode], ring: &[Endpoint]) {
    for n in nodes.iter_mut() {
        let by_ip = ring
            .iter()
            .find(|e| !n.pod_ip.is_empty() && e.ip == n.pod_ip);
        let by_host = ring
            .iter()
            .find(|e| !n.host_id.is_empty() && e.host_id == n.host_id);
        let Some(e) = by_ip.or(by_host) else { continue };
        if !n.host_id.is_empty() && n.host_id != e.host_id {
            n.host_id_stale = true;
            n.host_id = e.host_id.clone();
        } else if n.host_id.is_empty() {
            n.host_id = e.host_id.clone();
        }
        n.ring = Some(RingFacts {
            state: e.state.clone(),
            alive: e.alive,
            status_code: e.status_code(),
            load_bytes: e.load_bytes,
            tokens: e.tokens,
            schema: e.schema.clone(),
            ip: e.ip.clone(),
        });
    }
}

fn build_nodes(pods: &[Pod], claims: &[PersistentVolumeClaim]) -> Vec<K8cNode> {
    let mut by_pod: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for c in claims {
        let Some(ns) = c.metadata.namespace.clone() else { continue };
        let Some(name) = c.metadata.name.clone() else { continue };
        // A StatefulSet claim is `<template>-<pod name>`; that suffix is the only link back to the
        // pod without reading the StatefulSet itself.
        let size = c
            .spec
            .as_ref()
            .and_then(|s| s.resources.as_ref())
            .and_then(|r| r.requests.as_ref())
            .and_then(|r| r.get("storage"))
            .map(|q| q.0.clone())
            .unwrap_or_default();
        by_pod.entry((ns, name.clone())).or_default().push((name, size));
    }

    let mut out: Vec<K8cNode> = pods
        .iter()
        .map(|p| {
            let namespace = p.metadata.namespace.clone().unwrap_or_default();
            let name = p.metadata.name.clone().unwrap_or_default();
            let label = |k: &str| {
                p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(k))
                    .cloned()
                    .unwrap_or_default()
            };
            let status = p.status.as_ref();
            let ready = status
                .and_then(|s| s.conditions.as_ref())
                .map(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                .unwrap_or(false);
            let restarts = status
                .and_then(|s| s.container_statuses.as_ref())
                .map(|cs| cs.iter().map(|c| c.restart_count).max().unwrap_or(0))
                .unwrap_or(0);
            let claims = by_pod
                .iter()
                .filter(|((ns, claim), _)| *ns == namespace && claim.ends_with(&format!("-{name}")))
                .flat_map(|(_, v)| v.clone())
                .collect();
            K8cNode {
                uid: format!("k8c|node|{namespace}/{name}"),
                namespace,
                name,
                cluster: label(L_CLUSTER),
                datacenter: label(L_DATACENTER),
                rack: label(L_RACK),
                node_state: label(L_NODE_STATE),
                created: p
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| t.0.as_second())
                    .unwrap_or(0),
                phase: status.and_then(|s| s.phase.clone()).unwrap_or_default(),
                ready,
                restarts,
                node_name: p.spec.as_ref().and_then(|s| s.node_name.clone()).unwrap_or_default(),
                pod_ip: status.and_then(|s| s.pod_ip.clone()).unwrap_or_default(),
                host_id: String::new(),
                host_id_stale: false,
                ring: None,
                claims,
                hints: Vec::new(),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (&a.namespace, &a.datacenter, &a.rack, &a.name)
            .cmp(&(&b.namespace, &b.datacenter, &b.rack, &b.name))
    });
    out
}

// --- Parsing --------------------------------------------------------------------------------------

fn parse_cluster(obj: &DynamicObject) -> K8cCluster {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);

    let datacenters = spec
        .get("cassandra")
        .and_then(|c| c.get("datacenters"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|d| str_at(d, &["metadata", "name"]))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let medusa = spec.get("medusa").filter(|m| !m.is_null()).map(|m| {
        let sp = m.get("storageProperties").cloned().unwrap_or(Value::Null);
        MedusaConfig {
            provider: str_at(&sp, &["storageProvider"]),
            bucket: str_at(&sp, &["bucketName"]),
            prefix: str_at(&sp, &["prefix"]),
            region: str_at(&sp, &["region"]),
            secret: str_at(&sp, &["storageSecretRef", "name"]),
            max_backup_age: int_opt(&sp, &["maxBackupAge"]),
            max_backup_count: int_opt(&sp, &["maxBackupCount"]),
            concurrent_transfers: int_opt(&sp, &["concurrentTransfers"]),
        }
    });

    K8cCluster {
        uid: format!("k8c|cluster|{namespace}/{name}"),
        namespace,
        name,
        created: meta_ts(obj),
        server_type: str_at(&spec, &["cassandra", "serverType"]),
        server_version: str_at(&spec, &["cassandra", "serverVersion"]),
        auth: spec.get("auth").and_then(Value::as_bool),
        medusa,
        reaper_enabled: spec.get("reaper").map(|r| !r.is_null()).unwrap_or(false),
        stargate_enabled: spec.get("stargate").map(|s| !s.is_null()).unwrap_or(false),
        datacenters,
        conditions: conditions_of(&status),
        error: str_at(&status, &["error"]),
        hints: Vec::new(),
    }
}

fn parse_datacenter(obj: &DynamicObject) -> K8cDatacenter {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);

    let racks = spec
        .get("racks")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|r| str_at(r, &["name"])).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    // `status.nodeStatuses` is a map of pod name to host id, not a list.
    let node_statuses = status
        .get("nodeStatuses")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), str_at(v, &["hostID"])))
                .collect()
        })
        .unwrap_or_default();

    let claim = spec
        .get("storageConfig")
        .and_then(|s| s.get("cassandraDataVolumeClaimSpec"))
        .cloned()
        .unwrap_or(Value::Null);

    K8cDatacenter {
        uid: format!("k8c|dc|{namespace}/{name}"),
        namespace,
        name,
        cluster_name: str_at(&spec, &["clusterName"]),
        created: meta_ts(obj),
        server_type: str_at(&spec, &["serverType"]),
        server_version: str_at(&spec, &["serverVersion"]),
        size: int_at(&spec, &["size"]),
        racks,
        stopped: spec.get("stopped").and_then(Value::as_bool).unwrap_or(false),
        progress: str_at(&status, &["cassandraOperatorProgress"]),
        conditions: conditions_of(&status),
        node_statuses,
        declared_storage: str_at(&claim, &["resources", "requests", "storage"]),
        storage_class: str_at(&claim, &["storageClassName"]),
        hints: Vec::new(),
    }
}

fn parse_schedule(obj: &DynamicObject) -> MedSchedule {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    MedSchedule {
        uid: format!("k8c|sched|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["backupSpec", "cassandraDatacenter"]),
        backup_type: str_at(&spec, &["backupSpec", "backupType"]),
        cron: str_at(&spec, &["cronSchedule"]),
        disabled: spec.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        last_execution: real_ts(ts_at(&status, &["lastExecution"])),
        next_schedule: real_ts(ts_at(&status, &["nextSchedule"])),
        runs: Vec::new(),
        hints: Vec::new(),
    }
}

fn parse_job(obj: &DynamicObject) -> MedJob {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    MedJob {
        uid: format!("k8c|job|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["cassandraDatacenter"]),
        backup_type: str_at(&spec, &["backupType"]),
        created: meta_ts(obj),
        start: real_ts(ts_at(&status, &["startTime"])),
        finish: real_ts(ts_at(&status, &["finishTime"])),
        finished: strings_at(&status, &["finished"]),
        failed: strings_at(&status, &["failed"]),
        in_progress: strings_at(&status, &["inProgress"]),
        expected: None,
        in_catalogue: false,
        hints: Vec::new(),
    }
}

fn parse_backup(obj: &DynamicObject) -> MedBackup {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    MedBackup {
        uid: format!("k8c|backup|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["cassandraDatacenter"]),
        backup_type: str_at(&spec, &["backupType"]),
        created: meta_ts(obj),
        start: real_ts(ts_at(&status, &["startTime"])),
        finish: real_ts(ts_at(&status, &["finishTime"])),
        total_nodes: int_opt(&status, &["totalNodes"]),
        finished_nodes: int_opt(&status, &["finishedNodes"]),
        total_size: int_opt(&status, &["totalSize"]),
        status: str_at(&status, &["status"]),
        complete: None,
        hints: Vec::new(),
    }
}

fn parse_restore(obj: &DynamicObject) -> MedRestore {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    MedRestore {
        uid: format!("k8c|restore|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["cassandraDatacenter"]),
        backup: str_at(&spec, &["backup"]),
        created: meta_ts(obj),
        start: real_ts(ts_at(&status, &["startTime"])),
        finish: real_ts(ts_at(&status, &["finishTime"])),
        datacenter_stopped: real_ts(ts_at(&status, &["datacenterStopped"])),
        restore_key: str_at(&status, &["restoreKey"]),
        restore_prepared: status
            .get("restorePrepared")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        failed: strings_at(&status, &["failed"]),
        in_progress: strings_at(&status, &["inProgress"]),
        hints: Vec::new(),
    }
}

fn parse_med_task(obj: &DynamicObject) -> MedTask {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    // `status.finished` of a MedusaTask is a list of objects (`{podName, ...}`), not of strings as
    // it is on a MedusaBackupJob. Same field name, different shape, in the same API group.
    let finished = status
        .get("finished")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|e| match e.as_str() {
                    Some(s) => s.to_string(),
                    None => str_at(e, &["podName"]),
                })
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    MedTask {
        uid: format!("k8c|task|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["cassandraDatacenter"]),
        operation: str_at(&spec, &["operation"]),
        created: meta_ts(obj),
        start: real_ts(ts_at(&status, &["startTime"])),
        finish: real_ts(ts_at(&status, &["finishTime"])),
        finished,
        failed: strings_at(&status, &["failed"]),
        in_progress: strings_at(&status, &["inProgress"]),
        hints: Vec::new(),
    }
}

fn parse_cass_task(obj: &DynamicObject) -> CassTask {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    // A K8ssandraTask wraps the same job list one level down, under `spec.template`.
    let jobs = spec
        .get("jobs")
        .or_else(|| spec.get("template").and_then(|t| t.get("jobs")))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|j| str_at(j, &["command"]))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    CassTask {
        uid: format!("k8c|ctask|{namespace}/{name}"),
        namespace,
        name,
        datacenter: str_at(&spec, &["datacenter", "name"]),
        commands: jobs,
        created: meta_ts(obj),
        start: real_ts(ts_at(&status, &["startTime"])),
        finish: real_ts(ts_at(&status, &["completionTime"])),
        active: int_at(&status, &["active"]),
        succeeded: int_at(&status, &["succeeded"]),
        failed: int_at(&status, &["failed"]),
        hints: Vec::new(),
    }
}

fn parse_reaper(obj: &DynamicObject) -> ReaperRec {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec").cloned().unwrap_or(Value::Null);
    let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
    let conditions = conditions_of(&status);
    ReaperRec {
        uid: format!("k8c|reaper|{namespace}/{name}"),
        namespace,
        name: name.clone(),
        datacenter: str_at(&spec, &["datacenterRef", "name"]),
        created: meta_ts(obj),
        progress: str_at(&status, &["progress"]),
        ready: conditions.iter().any(|(k, v)| k == "Ready" && v == "True"),
        ui_secret: str_at(&spec, &["uiUserSecretRef", "name"]),
        // The operator names the Service after the object: `<reaper name>-service`.
        service: format!("{name}-service"),
        hints: Vec::new(),
    }
}

fn conditions_of(status: &Value) -> Vec<(String, String)> {
    status
        .get("conditions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|c| (str_at(c, &["type"]), str_at(c, &["status"])))
                .filter(|(k, _)| !k.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

// --- Rules ----------------------------------------------------------------------------------------

pub struct Inventory {
    pub clusters: Vec<K8cCluster>,
    pub datacenters: Vec<K8cDatacenter>,
    pub nodes: Vec<K8cNode>,
    pub schedules: Vec<MedSchedule>,
    pub jobs: Vec<MedJob>,
    pub backups: Vec<MedBackup>,
    pub restores: Vec<MedRestore>,
    pub tasks: Vec<MedTask>,
    pub cass_tasks: Vec<CassTask>,
    pub reapers: Vec<ReaperRec>,
    pub ring: Vec<Endpoint>,
    pub ring_known: bool,
    pub pods_known: bool,
    pub claims_known: bool,
}

pub struct Analysed {
    pub clusters: Vec<K8cCluster>,
    pub datacenters: Vec<K8cDatacenter>,
    pub nodes: Vec<K8cNode>,
    pub schedules: Vec<MedSchedule>,
    pub jobs: Vec<MedJob>,
    pub backups: Vec<MedBackup>,
    pub restores: Vec<MedRestore>,
    pub tasks: Vec<MedTask>,
    pub cass_tasks: Vec<CassTask>,
    pub reapers: Vec<ReaperRec>,
    pub cluster_hints: Vec<Hint>,
    pub last_restorable: Option<i64>,
    pub ring_known: bool,
}

/// Every verdict of the view, as a pure function of one consistent snapshot. No client, no clock of
/// its own, no I/O — so both language tables can be exercised against the same fixtures.
pub fn analyse(inv: Inventory, now: i64, st: &'static Strings) -> Analysed {
    let Inventory {
        mut clusters,
        mut datacenters,
        mut nodes,
        mut schedules,
        mut jobs,
        mut backups,
        mut restores,
        mut tasks,
        mut cass_tasks,
        mut reapers,
        ring,
        ring_known,
        pods_known,
        claims_known,
    } = inv;
    let mut cluster_hints: Vec<Hint> = Vec::new();

    // How many nodes a run had to cover, per (namespace, datacenter). `spec.size` is the intent;
    // `status.nodeStatuses` is what actually joined. The larger of the two is what a whole backup
    // has to span, so a run is never called complete on the strength of a shrunken ring.
    let expected: HashMap<(String, String), usize> = datacenters
        .iter()
        .map(|d| {
            let joined = d.node_statuses.len();
            let size = d.size.max(0) as usize;
            ((d.namespace.clone(), d.name.clone()), size.max(joined))
        })
        .collect();

    let catalogue: HashSet<(String, String)> = backups
        .iter()
        .map(|b| (b.namespace.clone(), b.name.clone()))
        .collect();

    // --- Runs -------------------------------------------------------------------------------------
    for j in &mut jobs {
        j.expected = expected.get(&(j.namespace.clone(), j.datacenter.clone())).copied();
        j.in_catalogue = catalogue.contains(&(j.namespace.clone(), j.name.clone()));

        if j.running() {
            j.hints.push(info(st.k8c_job_running.to_string()));
            continue;
        }
        if !j.failed.is_empty() && j.finished.is_empty() {
            j.hints.push(danger(fill(
                st.k8c_job_all_failed,
                &[("n", &j.failed.len().to_string())],
            )));
        } else if j.partial() {
            // The dangerous case, and the quiet one: Medusa reports a finish time and some nodes
            // succeeded, so the run looks like it produced something. It did — a capture missing
            // whole replicas, which restores as if it were whole.
            j.hints.push(danger(fill(
                st.k8c_job_partial,
                &[
                    ("ok", &j.finished.len().to_string()),
                    ("ko", &j.failed.len().to_string()),
                ],
            )));
        } else if j.complete() == Some(false) && j.failed.is_empty() {
            if let Some(n) = j.expected {
                j.hints.push(warn(fill(
                    st.k8c_job_short,
                    &[("ok", &j.finished.len().to_string()), ("n", &n.to_string())],
                )));
            }
        }
        if j.complete() == Some(true) && !j.in_catalogue {
            // Medusa's own catalogue is written by the `sync` task. A run that succeeded without a
            // catalogue entry is restorable from the bucket but invisible to the operator.
            j.hints.push(warn(st.k8c_job_uncatalogued.to_string()));
        }
    }

    // --- Catalogue --------------------------------------------------------------------------------
    let job_by_name: HashMap<(String, String), &MedJob> = jobs
        .iter()
        .map(|j| ((j.namespace.clone(), j.name.clone()), j))
        .collect();
    for b in &mut backups {
        // Newer operators state the coverage on the object; older ones say nothing and the run of
        // the same name is the only witness. Neither available means the verdict abstains.
        b.complete = match (b.total_nodes, b.finished_nodes) {
            (Some(total), Some(done)) if total > 0 => Some(done >= total),
            _ => job_by_name
                .get(&(b.namespace.clone(), b.name.clone()))
                .and_then(|j| j.complete()),
        };
        if real_ts(b.finish).is_none() {
            b.hints.push(danger(st.k8c_backup_unfinished.to_string()));
        }
        match b.complete {
            Some(false) => b.hints.push(danger(st.k8c_backup_partial.to_string())),
            None => b.hints.push(info(st.k8c_backup_coverage_unknown.to_string())),
            Some(true) => {}
        }
    }

    // --- Schedules --------------------------------------------------------------------------------
    for s in &mut schedules {
        let mut runs: Vec<&MedJob> = jobs
            .iter()
            .filter(|j| j.namespace == s.namespace && run_of(&s.name, &j.name))
            .collect();
        runs.sort_by_key(|j| std::cmp::Reverse(j.created));
        s.runs = runs.iter().map(|j| j.uid.clone()).collect();

        if s.disabled {
            s.hints.push(info(st.k8c_sched_disabled.to_string()));
        }
        if runs.is_empty() {
            if s.last_execution.is_some() {
                // The schedule says it fired and nothing it fired is left: either the runs were
                // pruned, or they never got created.
                s.hints.push(warn(st.k8c_sched_no_runs.to_string()));
            }
            continue;
        }

        let last_ok = runs.iter().find(|j| j.complete() == Some(true));
        let consecutive_failures = runs
            .iter()
            .take_while(|j| !j.running() && j.complete() == Some(false))
            .count();
        if consecutive_failures > 0 {
            let last_seen = last_ok
                .and_then(|j| real_ts(j.finish).or(Some(j.created)))
                .map(|t| age_of(t, now))
                .unwrap_or_else(|| st.k8c_never.to_string());
            // The headline failure of this view: `lastExecution` is fresh, `nextSchedule` is clean,
            // and not one of those runs produced anything restorable.
            s.hints.push(danger(fill(
                st.k8c_sched_all_failing,
                &[("n", &consecutive_failures.to_string()), ("age", &last_seen)],
            )));
        }
        if let (Some(next), false) = (s.next_schedule, s.disabled) {
            if next < now {
                s.hints.push(warn(fill(
                    st.k8c_sched_overdue,
                    &[("age", &age_of(next, now))],
                )));
            }
        }
    }

    // --- Restores ---------------------------------------------------------------------------------
    for r in &mut restores {
        if !r.failed.is_empty() {
            r.hints.push(danger(fill(
                st.k8c_restore_failed,
                &[("n", &r.failed.len().to_string())],
            )));
        }
        if r.finish.is_none() && r.start.is_some() {
            r.hints.push(warn(st.k8c_restore_running.to_string()));
            if r.datacenter_stopped.is_some() {
                // Not a side effect worth discovering afterwards: the datacenter is down for the
                // duration, which is what makes a restore an outage rather than an operation.
                r.hints.push(danger(st.k8c_restore_dc_down.to_string()));
            }
        }
    }

    // --- Medusa tasks -----------------------------------------------------------------------------
    for t in &mut tasks {
        if !t.failed.is_empty() {
            t.hints.push(warn(fill(
                st.k8c_task_failed,
                &[("n", &t.failed.len().to_string())],
            )));
        }
    }

    // --- Cassandra tasks --------------------------------------------------------------------------
    for t in &mut cass_tasks {
        if t.failed > 0 {
            t.hints.push(warn(fill(
                st.k8c_ctask_failed,
                &[("n", &t.failed.to_string())],
            )));
        }
        if t.active > 0 {
            t.hints.push(info(fill(
                st.k8c_ctask_running,
                &[("n", &t.active.to_string())],
            )));
        }
    }

    // --- Datacenters and nodes --------------------------------------------------------------------
    for d in &mut datacenters {
        if d.stopped {
            d.hints.push(danger(st.k8c_dc_stopped.to_string()));
        }
        if !d.ready() && !d.stopped {
            d.hints.push(danger(st.k8c_dc_not_ready.to_string()));
        }
        if d.condition("Healthy") == Some("False") {
            d.hints.push(warn(st.k8c_dc_unhealthy.to_string()));
        }
        let in_flight = d.in_flight();
        if !in_flight.is_empty() {
            d.hints.push(info(fill(
                st.k8c_dc_in_flight,
                &[("ops", &in_flight.join(", "))],
            )));
        }
        if !d.progress.is_empty() && d.progress != "Ready" {
            d.hints.push(info(fill(
                st.k8c_dc_progress,
                &[("state", &d.progress)],
            )));
        }
        let joined = d.node_statuses.len() as i64;
        if d.size > 0 && joined < d.size {
            d.hints.push(danger(fill(
                st.k8c_dc_missing_nodes,
                &[("joined", &joined.to_string()), ("size", &d.size.to_string())],
            )));
        }
        // The declared claim size and the real one diverge whenever a volume was expanded in place:
        // the field is immutable, so this is a fact to know, not a fault to fix.
        if claims_known && !d.declared_storage.is_empty() {
            let real: HashSet<&str> = nodes
                .iter()
                .filter(|n| n.namespace == d.namespace && n.datacenter == d.name)
                .flat_map(|n| n.claims.iter().map(|(_, size)| size.as_str()))
                .collect();
            if !real.is_empty() && !real.contains(d.declared_storage.as_str()) {
                let mut sizes: Vec<&str> = real.into_iter().collect();
                sizes.sort_unstable();
                d.hints.push(info(fill(
                    st.k8c_dc_storage_drift,
                    &[("declared", &d.declared_storage), ("real", &sizes.join(", "))],
                )));
            }
        }
    }

    // Host ids come from the datacenter status, which is the only place a pod name is tied to one.
    let host_by_pod: HashMap<(String, String), String> = datacenters
        .iter()
        .flat_map(|d| {
            d.node_statuses
                .iter()
                .map(|(pod, id)| ((d.namespace.clone(), pod.clone()), id.clone()))
        })
        .collect();
    for n in &mut nodes {
        if n.host_id.is_empty() {
            if let Some(id) = host_by_pod.get(&(n.namespace.clone(), n.name.clone())) {
                n.host_id = id.clone();
            }
        }
    }
    // The ring is joined on the host id, which only exists once the loop above has copied it out of
    // the datacenter status — so this has to happen before any rule reads `n.ring`, or a node the
    // ring reports DOWN raises nothing at all.
    attach_ring(&mut nodes, &ring);

    for n in &mut nodes {
        if !n.ready {
            n.hints.push(danger(fill(
                st.k8c_node_not_ready,
                &[("phase", if n.phase.is_empty() { "?" } else { &n.phase })],
            )));
        }
        if n.restarts > 0 {
            n.hints.push(info(fill(
                st.k8c_node_restarts,
                &[("n", &n.restarts.to_string())],
            )));
        }
        if n.host_id_stale {
            n.hints.push(info(st.k8c_node_host_id_stale.to_string()));
        }
        match &n.ring {
            Some(r) if !r.alive => n.hints.push(danger(st.k8c_node_down.to_string())),
            Some(r) if r.state != "NORMAL" => n.hints.push(warn(fill(
                st.k8c_node_state,
                &[("state", &r.state)],
            ))),
            _ => {}
        }
    }

    // --- Reaper -----------------------------------------------------------------------------------
    for r in &mut reapers {
        if !r.ready {
            r.hints.push(warn(fill(
                st.k8c_reaper_not_ready,
                &[("progress", if r.progress.is_empty() { "?" } else { &r.progress })],
            )));
        }
    }

    // --- Clusters and the cluster-wide reading ----------------------------------------------------
    for c in &mut clusters {
        if !c.error.is_empty() && c.error != "None" {
            c.hints.push(danger(fill(st.k8c_cluster_error, &[("msg", &c.error)])));
        }
        if c.medusa.is_none() {
            // No Medusa block means no backups at all, which is worth saying on a database.
            c.hints.push(warn(st.k8c_cluster_no_medusa.to_string()));
        }
        if !c.reaper_enabled {
            c.hints.push(info(st.k8c_cluster_no_reaper.to_string()));
        }
    }

    if ring_known {
        for (cluster, versions) in mgmtapi::schema_versions_by_cluster(&ring) {
            if versions.len() > 1 {
                cluster_hints.push(danger(fill(
                    st.k8c_schema_disagreement,
                    &[("cluster", &cluster), ("n", &versions.len().to_string())],
                )));
            }
        }
    } else if pods_known {
        cluster_hints.push(info(st.k8c_ring_unknown.to_string()));
    }

    // The headline: the newest run that covered every node, and the age the reader came for.
    let last_restorable = jobs
        .iter()
        .filter(|j| j.complete() == Some(true))
        .filter_map(|j| real_ts(j.finish).or(real_ts(Some(j.created))))
        .chain(
            backups
                .iter()
                .filter(|b| b.complete == Some(true))
                .filter_map(|b| real_ts(b.finish)),
        )
        .max();

    if !schedules.is_empty() {
        match last_restorable {
            None => cluster_hints.push(danger(st.k8c_no_restorable.to_string())),
            Some(t) => {
                let stale = schedules
                    .iter()
                    .filter(|s| !s.disabled)
                    .filter_map(|s| s.last_execution)
                    .max()
                    .map(|last| last > t)
                    .unwrap_or(false);
                if stale {
                    // A schedule that fired more recently than the last usable backup is the exact
                    // shape of the silent failure this view exists for.
                    cluster_hints.push(danger(fill(
                        st.k8c_backup_stale,
                        &[("age", &age_of(t, now))],
                    )));
                }
            }
        }
    }

    Analysed {
        clusters,
        datacenters,
        nodes,
        schedules,
        jobs,
        backups,
        restores,
        tasks,
        cass_tasks,
        reapers,
        cluster_hints,
        last_restorable,
        ring_known,
    }
}

/// Whether `job` is a run fired by `schedule`. The operator names runs `<schedule>-<epoch>`, so the
/// test is the exact prefix plus an all-digit suffix — a plain `starts_with` would attribute
/// `medusa-daily-full-2` to `medusa-daily`.
pub fn run_of(schedule: &str, job: &str) -> bool {
    let Some(rest) = job.strip_prefix(schedule) else { return false };
    let Some(suffix) = rest.strip_prefix('-') else { return false };
    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
}

// --- Writes ----------------------------------------------------------------------------------------

/// The writes the view offers, as data. Each one creates an object; nothing here patches or deletes,
/// which is what keeps the blast radius of the whole module readable.
#[derive(Debug, Clone, PartialEq)]
pub enum K8cWrite {
    /// Run a schedule now: a MedusaBackupJob with the same datacenter and backup type.
    BackupNow {
        namespace: String,
        datacenter: String,
        backup_type: String,
        prefix: String,
    },
    /// Restore a catalogue entry. This stops the datacenter for the duration.
    Restore {
        namespace: String,
        datacenter: String,
        backup: String,
    },
    /// A Medusa maintenance task: `purge` or `sync`.
    Task {
        namespace: String,
        datacenter: String,
        operation: String,
    },
    /// A cass-operator task on the datacenter.
    CassandraTask {
        namespace: String,
        datacenter: String,
        command: String,
    },
}

impl K8cWrite {
    pub fn namespace(&self) -> &str {
        match self {
            K8cWrite::BackupNow { namespace, .. }
            | K8cWrite::Restore { namespace, .. }
            | K8cWrite::Task { namespace, .. }
            | K8cWrite::CassandraTask { namespace, .. } => namespace,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            K8cWrite::BackupNow { .. } => "MedusaBackupJob",
            K8cWrite::Restore { .. } => "MedusaRestoreJob",
            K8cWrite::Task { .. } => "MedusaTask",
            K8cWrite::CassandraTask { .. } => "CassandraTask",
        }
    }

    fn api_version(&self) -> &'static str {
        match self {
            K8cWrite::CassandraTask { .. } => "control.k8ssandra.io/v1alpha1",
            _ => "medusa.k8ssandra.io/v1alpha1",
        }
    }
}

/// The object a write produces. Pure, so the payload can be asserted in a test rather than tried
/// against a cluster.
pub fn write_payload(write: &K8cWrite) -> Value {
    let meta = |prefix: &str| {
        json!({
            // `generateName` rather than a name built from a clock: two operators pressing the same
            // key in the same second get two objects instead of one conflict.
            "generateName": format!("{prefix}-"),
            "namespace": write.namespace(),
        })
    };
    match write {
        K8cWrite::BackupNow { datacenter, backup_type, prefix, .. } => {
            let mut spec = json!({ "cassandraDatacenter": datacenter });
            // Omitted rather than sent empty when the schedule names no type — see
            // [`DEFAULT_BACKUP_TYPE`]: an empty string is outside the CRD's enum and costs the whole
            // create, where an absent key gets defaulted to `differential`.
            if !backup_type.trim().is_empty() {
                spec["backupType"] = json!(backup_type);
            }
            json!({
                "apiVersion": write.api_version(),
                "kind": write.kind(),
                "metadata": meta(prefix),
                "spec": spec,
            })
        }
        K8cWrite::Restore { datacenter, backup, .. } => json!({
            "apiVersion": write.api_version(),
            "kind": write.kind(),
            "metadata": meta("kdt-restore"),
            "spec": { "cassandraDatacenter": datacenter, "backup": backup },
        }),
        K8cWrite::Task { datacenter, operation, .. } => json!({
            "apiVersion": write.api_version(),
            "kind": write.kind(),
            "metadata": meta(&format!("kdt-{operation}")),
            "spec": { "cassandraDatacenter": datacenter, "operation": operation },
        }),
        K8cWrite::CassandraTask { namespace, datacenter, command } => json!({
            "apiVersion": write.api_version(),
            "kind": write.kind(),
            "metadata": meta(&format!("kdt-{command}")),
            "spec": {
                "datacenter": { "name": datacenter, "namespace": namespace },
                "jobs": [ { "name": command, "command": command } ],
            },
        }),
    }
}

pub async fn apply_k8c_write(client: Client, write: K8cWrite) -> Result<String, String> {
    let payload = write_payload(&write);
    let obj: DynamicObject = serde_json::from_value(payload).map_err(|e| e.to_string())?;
    let (api, _ar) = crate::yaml::dynamic_resource(
        &client,
        write.api_version(),
        write.kind(),
        write.namespace(),
    )
    .await?;
    let created = api
        .create(&PostParams::default(), &obj)
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(created.metadata.name.unwrap_or_default())
}

// --- Helpers ---------------------------------------------------------------------------------------

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn age_of(then: i64, now: i64) -> String {
    crate::velero::age_of(then, now)
}

/// A byte count as Cassandra reports it, which is a Java double.
pub fn format_load(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn meta_ts(obj: &DynamicObject) -> i64 {
    obj.metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0)
}

fn str_at(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or_default().to_string()
}

fn int_at(v: &Value, path: &[&str]) -> i64 {
    int_opt(v, path).unwrap_or(0)
}

fn int_opt(v: &Value, path: &[&str]) -> Option<i64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_i64()
}

fn strings_at(v: &Value, path: &[&str]) -> Vec<String> {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    cur.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn ts_at(v: &Value, path: &[&str]) -> Option<i64> {
    let raw = str_at(v, path);
    if raw.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(&raw).ok().map(|t| t.timestamp())
}

// --- Bottom panel: container logs and node metrics ------------------------------------------------

/// Which of the two on-demand readings the bottom of the detail panel is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelKind {
    Logs,
    Metrics,
    Repairs,
    Snapshots,
    /// The output of a `nodetool` Job, which is the log of its pod — see [`crate::nodetool`].
    Nodetool,
}

/// The panel appended under the detail of the selected row, on `l` or `m`.
///
/// Both readings are expensive in their own way — a log tail is a streamed request, the metrics
/// exposition is ~29 000 lines — so neither is ever fetched by the refresh ticker. `key` is what the
/// panel is currently about; a second press on the same row closes it.
#[derive(Debug, Clone, Default)]
pub struct K8cPanel {
    pub key: String,
    pub kind: Option<PanelKind>,
    pub title: String,
    pub lines: Vec<String>,
    pub metrics: Option<mgmtapi::NodeMetrics>,
    /// Active streaming sessions (`nodetool netstats`), as the flat pairs the node reports.
    pub streams: Vec<Vec<(String, String)>>,
    /// Reaper's repair schedules, as (keyspace, tables, state, interval) read from its REST API.
    pub repairs: Vec<(String, String, String, String)>,
    /// The node's snapshots (`nodetool listsnapshots`), one row per tag.
    pub snapshots: Vec<SnapshotTag>,
    pub loading: bool,
    pub error: Option<String>,
}

pub type SharedK8cPanel = Arc<Mutex<K8cPanel>>;

pub fn new_k8c_panel() -> SharedK8cPanel {
    Arc::new(Mutex::new(K8cPanel::default()))
}

// How many lines of a container log to keep. Enough to hold a Medusa run's stack trace, short enough
// that the panel stays scrollable.
const LOG_TAIL: i64 = 200;

/// Tail one container of one pod. The container matters: the reason a backup failed is in `medusa`,
/// never in `cassandra`, and the two sit in the same pod.
pub async fn fetch_k8c_logs(
    client: Client,
    namespace: String,
    pod: String,
    container: String,
    key: String,
    state: SharedK8cPanel,
) {
    {
        let mut s = state.lock().expect("k8ssandra panel poisoned");
        *s = K8cPanel {
            key: key.clone(),
            kind: Some(PanelKind::Logs),
            title: format!("{pod} · {container}"),
            loading: true,
            ..K8cPanel::default()
        };
    }
    let api: Api<Pod> = Api::namespaced(client, &namespace);
    let params = kube::api::LogParams {
        container: Some(container),
        tail_lines: Some(LOG_TAIL),
        ..kube::api::LogParams::default()
    };
    let result = api.logs(&pod, &params).await;
    let mut s = state.lock().expect("k8ssandra panel poisoned");
    // The selection moved while the request was in flight: this answer is about a row nobody is
    // looking at any more.
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(text) => s.lines = text.lines().map(str::to_string).collect(),
        Err(e) => s.error = Some(crate::edit::api_error_text(e)),
    }
}

/// Read the thread pools and compaction counters of one node — `nodetool tpstats` and
/// `nodetool compactionstats`, through the management API rather than through JMX.
pub async fn fetch_k8c_metrics(
    client: Client,
    namespace: String,
    pod: String,
    key: String,
    state: SharedK8cPanel,
) {
    {
        let mut s = state.lock().expect("k8ssandra panel poisoned");
        *s = K8cPanel {
            key: key.clone(),
            kind: Some(PanelKind::Metrics),
            title: pod.clone(),
            loading: true,
            ..K8cPanel::default()
        };
    }
    // The counters and the streams together: `tpstats`, `compactionstats` and `netstats` are three
    // questions about the same node and are read as one panel.
    let (counters, streams) = futures::join!(
        mgmtapi::metrics(&client, &namespace, &pod),
        mgmtapi::streams(&client, &namespace, &pod),
    );
    let mut s = state.lock().expect("k8ssandra panel poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    s.streams = streams.unwrap_or_default();
    match counters {
        Ok(m) => s.metrics = Some(m),
        Err(e) => s.error = Some(e),
    }
}

/// The snapshots sitting on one node's data volume — `nodetool listsnapshots`, through the
/// management API.
///
/// Nothing in Kubernetes carries this: a snapshot is a directory of hard links inside the PVC, and it
/// is what turns a volume that should be half empty into one at 90%. A failed Medusa run leaves its
/// tag behind, and a `TRUNCATE` leaves one forever unless someone clears it. Listing them makes the
/// node walk its snapshot directories, so this is never fetched by the refresh ticker.
pub async fn fetch_k8c_snapshots(
    client: Client,
    namespace: String,
    pod: String,
    key: String,
    state: SharedK8cPanel,
) {
    {
        let mut s = state.lock().expect("k8ssandra panel poisoned");
        *s = K8cPanel {
            key: key.clone(),
            kind: Some(PanelKind::Snapshots),
            title: pod.clone(),
            loading: true,
            ..K8cPanel::default()
        };
    }
    let result = mgmtapi::snapshots(&client, &namespace, &pod).await;
    let mut s = state.lock().expect("k8ssandra panel poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(rows) => s.snapshots = group_snapshots(&rows),
        Err(e) => s.error = Some(e),
    }
}

/// Reaper's repair schedules for one datacenter, read through its REST API.
///
/// Reaper 3.x has authentication on by default, so this logs in first with the UI credentials — read
/// from the Secret the Reaper object names in `spec.uiUserSecretRef`, never from a name derived by
/// hand. The token lives for the duration of the call and is never stored or displayed.
pub async fn fetch_k8c_repairs(
    client: Client,
    namespace: String,
    service: String,
    ui_secret: String,
    key: String,
    state: SharedK8cPanel,
) {
    {
        let mut s = state.lock().expect("k8ssandra panel poisoned");
        *s = K8cPanel {
            key: key.clone(),
            kind: Some(PanelKind::Repairs),
            title: service.clone(),
            loading: true,
            ..K8cPanel::default()
        };
    }
    let result = reaper_schedules(&client, &namespace, &service, &ui_secret).await;
    let mut s = state.lock().expect("k8ssandra panel poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(rows) => s.repairs = rows,
        Err(e) => s.error = Some(e),
    }
}

async fn reaper_schedules(
    client: &Client,
    namespace: &str,
    service: &str,
    ui_secret: &str,
) -> Result<Vec<(String, String, String, String)>, String> {
    let st = crate::lang::active();
    if ui_secret.is_empty() {
        return Err(st.k8c_reaper_no_secret.to_string());
    }
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client.clone(), namespace);
    let secret = secrets.get(ui_secret).await.map_err(crate::edit::api_error_text)?;
    let field = |k: &str| {
        secret
            .data
            .as_ref()
            .and_then(|d| d.get(k))
            .and_then(|b| String::from_utf8(b.0.clone()).ok())
            .unwrap_or_default()
    };
    let (user, password) = (field("username"), field("password"));
    if user.is_empty() || password.is_empty() {
        return Err(st.k8c_reaper_no_secret.to_string());
    }
    let session = mgmtapi::reaper_login(client, namespace, service, &user, &password).await?;
    let body = mgmtapi::reaper_get(&session, client, "/repair_schedule").await?;
    let list: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let rows = list
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| {
                    (
                        str_at(r, &["keyspace_name"]),
                        str_at(r, &["column_families"]),
                        str_at(r, &["state"]),
                        int_opt(r, &["scheduled_days_between"])
                            .map(|d| format!("{d}d"))
                            .unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(rows)
}

// --- Snapshots -----------------------------------------------------------------------------------

/// Where a snapshot tag came from, when Cassandra itself named it.
///
/// Only the two prefixes the server generates are recognised. Everything else — a Medusa run, a
/// `nodetool snapshot` typed by hand, an operator's backup hook — chooses its own name, and guessing
/// an origin from a name nobody guarantees would be exactly the invention this view refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapOrigin {
    /// `truncated-<millis>-<table>`: what `TRUNCATE` left behind, kept forever unless cleared.
    Truncate,
    /// `dropped-<millis>-<table>`: the same, for a dropped table.
    Drop,
    /// `medusa-<backup name>`: Medusa's own `SNAPSHOT_PREFIX`. The name after it is the backup's and
    /// says nothing, but the prefix is Medusa's own constant — and Medusa clears its snapshot at the
    /// end of a run, inside the `with snapshot:` that survives an exception. One still standing is
    /// therefore a run in flight, a run killed outright, or an explicit `--keep-snapshot`.
    Medusa,
    Named,
}

/// One snapshot tag on one node, with its tables folded together.
///
/// A node has one line per table per tag — a few hundred lines for a single `truncate` — and the
/// operational question is per tag: what is this snapshot holding, and since when.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SnapshotTag {
    pub tag: String,
    pub keyspaces: Vec<String>,
    pub tables: usize,
    /// Sum of the per-table `True size`: what clearing the tag would give back.
    pub true_bytes: Option<f64>,
    pub disk_bytes: Option<f64>,
    /// Set when at least one line's size could not be read: the two sums are floors, not totals, and
    /// the panel says so rather than showing a number that is quietly short.
    pub partial: bool,
    pub created: Option<i64>,
}

impl SnapshotTag {
    pub fn origin(&self) -> SnapOrigin {
        match self.tag.split('-').next() {
            Some("truncated") => SnapOrigin::Truncate,
            Some("dropped") => SnapOrigin::Drop,
            Some("medusa") => SnapOrigin::Medusa,
            _ => SnapOrigin::Named,
        }
    }
}

/// Fold the per-table lines of one node into one row per tag, biggest first.
pub fn group_snapshots(rows: &[mgmtapi::Snapshot]) -> Vec<SnapshotTag> {
    let mut by_tag: BTreeMap<String, SnapshotTag> = BTreeMap::new();
    for row in rows {
        let group = by_tag.entry(row.tag.clone()).or_insert_with(|| SnapshotTag {
            tag: row.tag.clone(),
            ..SnapshotTag::default()
        });
        group.tables += 1;
        if !row.keyspace.is_empty() && !group.keyspaces.contains(&row.keyspace) {
            group.keyspaces.push(row.keyspace.clone());
        }
        add_size(&mut group.true_bytes, row.true_bytes, &mut group.partial);
        add_size(&mut group.disk_bytes, row.disk_bytes, &mut group.partial);
        // The tables of one tag are snapshotted in one pass, so the earliest stamp is the tag's.
        if let Some(t) = row.created {
            group.created = Some(group.created.map_or(t, |cur| cur.min(t)));
        }
    }
    let mut out: Vec<SnapshotTag> = by_tag.into_values().collect();
    for group in &mut out {
        group.keyspaces.sort();
        if group.created.is_none() {
            group.created = created_from_tag(&group.tag);
        }
    }
    // What is holding the most disk first: the panel is opened because a volume is filling up.
    out.sort_by(|a, b| {
        b.true_bytes
            .unwrap_or(-1.0)
            .total_cmp(&a.true_bytes.unwrap_or(-1.0))
            .then(a.tag.cmp(&b.tag))
    });
    out
}

fn add_size(total: &mut Option<f64>, value: Option<f64>, partial: &mut bool) {
    match value {
        Some(v) => *total = Some(total.unwrap_or(0.0) + v),
        None => *partial = true,
    }
}

// `truncated-1754308800000-events`: Cassandra stamps the tag with `System.currentTimeMillis()` right
// after the prefix. On a 3.11 node, where no creation time is reported at all, this is the only date
// there is — and it is the server's own, not one this code made up.
fn created_from_tag(tag: &str) -> Option<i64> {
    let mut parts = tag.split('-');
    match parts.next() {
        Some("truncated") | Some("dropped") => {}
        _ => return None,
    }
    let millis: i64 = parts.next()?.parse().ok()?;
    real_ts(Some(millis / 1000))
}

/// What every tag on the node adds up to, and whether that sum is complete.
pub fn snapshot_total(tags: &[SnapshotTag]) -> (Option<f64>, bool) {
    let mut total = None;
    let mut partial = tags.iter().any(|t| t.partial);
    for tag in tags {
        add_size(&mut total, tag.true_bytes, &mut partial);
    }
    (total, partial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{EN, FR};

    // Fixtures use real-looking epochs on purpose: a timestamp small enough to look like a counter
    // is filtered out by [`real_ts`] as a serialised zero value, and a test built on 9_000 would
    // exercise that guard instead of the rule it is named after.
    const NOW: i64 = 1_700_000_000;
    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;

    fn dc(namespace: &str, name: &str, size: i64, joined: usize) -> K8cDatacenter {
        K8cDatacenter {
            uid: format!("k8c|dc|{namespace}/{name}"),
            namespace: namespace.to_string(),
            name: name.to_string(),
            size,
            node_statuses: (0..joined)
                .map(|i| (format!("sts-{i}"), format!("id-{i}")))
                .collect(),
            conditions: vec![("Ready".to_string(), "True".to_string())],
            ..K8cDatacenter::default()
        }
    }

    fn job(name: &str, finished: usize, failed: usize, finish: Option<i64>) -> MedJob {
        MedJob {
            uid: format!("k8c|job|ns/{name}"),
            namespace: "ns".to_string(),
            name: name.to_string(),
            datacenter: "dc1".to_string(),
            created: finish.unwrap_or(NOW - DAY),
            start: Some(finish.unwrap_or(NOW - DAY) - 60),
            finish,
            finished: (0..finished).map(|i| format!("sts-{i}")).collect(),
            failed: (finished..finished + failed).map(|i| format!("sts-{i}")).collect(),
            ..MedJob::default()
        }
    }

    fn inventory(datacenters: Vec<K8cDatacenter>, jobs: Vec<MedJob>) -> Inventory {
        Inventory {
            clusters: Vec::new(),
            datacenters,
            nodes: Vec::new(),
            schedules: Vec::new(),
            jobs,
            backups: Vec::new(),
            restores: Vec::new(),
            tasks: Vec::new(),
            cass_tasks: Vec::new(),
            reapers: Vec::new(),
            ring: Vec::new(),
            ring_known: false,
            pods_known: false,
            claims_known: false,
        }
    }

    fn snap(tag: &str, keyspace: &str, table: &str, size: Option<f64>) -> mgmtapi::Snapshot {
        mgmtapi::Snapshot {
            tag: tag.to_string(),
            keyspace: keyspace.to_string(),
            table: table.to_string(),
            true_bytes: size,
            disk_bytes: size,
            ..mgmtapi::Snapshot::default()
        }
    }

    #[test]
    fn the_tables_of_one_tag_are_one_row() {
        // A truncate snapshots every table of the keyspace: two hundred lines, one decision.
        let rows = vec![
            snap("medusa-1", "app", "events", Some(1024.0)),
            snap("medusa-1", "app", "users", Some(1024.0)),
            snap("truncated-1700000000000-events", "app", "events", Some(4096.0)),
        ];
        let tags = group_snapshots(&rows);
        assert_eq!(tags.len(), 2);
        // Biggest first: the tag holding the disk is the reason the panel is open.
        assert_eq!(tags[0].tag, "truncated-1700000000000-events");
        assert_eq!(tags[1].tables, 2);
        assert_eq!(tags[1].true_bytes, Some(2048.0));
        assert_eq!(tags[1].keyspaces, vec!["app".to_string()]);
        assert_eq!(snapshot_total(&tags), (Some(6144.0), false));
    }

    #[test]
    fn a_total_missing_a_line_is_announced_as_partial() {
        let rows = vec![
            snap("medusa-1", "app", "events", Some(1024.0)),
            snap("medusa-1", "app", "users", None),
        ];
        let tags = group_snapshots(&rows);
        assert!(tags[0].partial, "one line could not be sized");
        assert_eq!(tags[0].true_bytes, Some(1024.0), "the sum is a floor, not a total");
        assert_eq!(snapshot_total(&tags), (Some(1024.0), true));
    }

    #[test]
    fn only_a_prefix_its_author_writes_itself_names_an_origin() {
        let rows = vec![
            snap("truncated-1700000000000-events", "app", "events", None),
            snap("dropped-1700000000000-old", "app", "old", None),
            snap("medusa-medusa-daily-1786575600", "app", "events", None),
            snap("avant-migration", "app", "events", None),
        ];
        let tags = group_snapshots(&rows);
        let origin = |tag: &str| tags.iter().find(|t| t.tag == tag).expect("tag").origin();
        assert_eq!(origin("truncated-1700000000000-events"), SnapOrigin::Truncate);
        assert_eq!(origin("dropped-1700000000000-old"), SnapOrigin::Drop);
        // `medusa-` is Medusa's own SNAPSHOT_PREFIX; what follows is the backup name and is
        // user-chosen, so the prefix is read and the rest is left alone.
        assert_eq!(origin("medusa-medusa-daily-1786575600"), SnapOrigin::Medusa);
        // A tag someone typed by hand: nothing to conclude from a name nobody guarantees.
        assert_eq!(origin("avant-migration"), SnapOrigin::Named);
    }

    #[test]
    fn a_truncate_tag_carries_the_date_a_311_node_never_reports() {
        let tags = group_snapshots(&[snap("truncated-1700000000000-events", "app", "events", None)]);
        assert_eq!(tags[0].created, Some(NOW));
        // A named tag that looks like a date is not one: no stamp is invented for it.
        let named = group_snapshots(&[snap("medusa-2026-08-12", "app", "events", None)]);
        assert_eq!(named[0].created, None);
    }

    #[test]
    fn a_reported_creation_time_wins_over_the_tag() {
        let mut row = snap("truncated-1700000000000-events", "app", "events", None);
        row.created = Some(NOW + DAY);
        assert_eq!(group_snapshots(&[row])[0].created, Some(NOW + DAY));
    }

    #[test]
    fn a_finish_time_at_the_epoch_is_not_a_date() {
        // The zero value of a Go timestamp, as seen on a real MedusaBackup. Read as a date it makes
        // a never-finished backup look like the oldest restorable one on the cluster.
        assert_eq!(real_ts(Some(0)), None);
        assert_eq!(real_ts(Some(1)), None);
        assert_eq!(real_ts(Some(EPOCH_GUARD)), None);
        assert_eq!(real_ts(Some(EPOCH_GUARD + 1)), Some(EPOCH_GUARD + 1));
        assert_eq!(real_ts(None), None);
    }

    #[test]
    fn a_run_that_missed_a_node_is_not_restorable() {
        let out = analyse(
            inventory(vec![dc("ns", "dc1", 6, 6)], vec![job("b1", 4, 2, Some(NOW - HOUR))]),
            NOW,
            &FR,
        );
        assert_eq!(out.jobs[0].complete(), Some(false));
        assert!(out.jobs[0].partial());
        assert_eq!(out.jobs[0].hints[0].level, HintLevel::Danger);
        assert_eq!(out.last_restorable, None, "a partial run is not a restore point");
    }

    #[test]
    fn a_run_that_covered_every_node_is_the_restore_point() {
        let out = analyse(
            inventory(vec![dc("ns", "dc1", 6, 6)], vec![job("b1", 6, 0, Some(NOW - HOUR))]),
            NOW,
            &FR,
        );
        assert_eq!(out.jobs[0].complete(), Some(true));
        assert_eq!(out.last_restorable, Some(NOW - HOUR));
    }

    #[test]
    fn coverage_is_measured_against_the_nodes_that_joined_not_only_the_declared_size() {
        // Six declared, seven joined (a replacement still in the status): a run over six nodes has
        // not covered the ring, and calling it whole would be the optimistic answer.
        let out = analyse(
            inventory(vec![dc("ns", "dc1", 6, 7)], vec![job("b1", 6, 0, Some(NOW - HOUR))]),
            NOW,
            &FR,
        );
        assert_eq!(out.jobs[0].complete(), Some(false));
    }

    #[test]
    fn without_a_datacenter_the_view_abstains_instead_of_guessing() {
        let out = analyse(inventory(Vec::new(), vec![job("b1", 4, 0, Some(NOW - HOUR))]), NOW, &FR);
        assert_eq!(out.jobs[0].complete(), None, "unknown node count means no verdict");
        assert_eq!(out.last_restorable, None);
        assert!(
            out.jobs[0].hints.is_empty(),
            "abstention is silence, not a warning about a fact we do not have"
        );
    }

    #[test]
    fn a_green_schedule_over_failing_runs_is_reported_as_danger() {
        // The shape of the real incident: `lastExecution` fresh, `nextSchedule` clean, every run
        // failed on every node, and nothing anywhere says so.
        let mut inv = inventory(
            vec![dc("ns", "dc1", 6, 6)],
            vec![
                job("nightly-1699913600", 0, 6, Some(NOW - DAY)),
                job("nightly-1699827200", 0, 6, Some(NOW - 2 * DAY)),
            ],
        );
        inv.schedules = vec![MedSchedule {
            uid: "k8c|sched|ns/nightly".to_string(),
            namespace: "ns".to_string(),
            name: "nightly".to_string(),
            datacenter: "dc1".to_string(),
            cron: "0 23 * * *".to_string(),
            last_execution: Some(NOW - DAY),
            next_schedule: Some(NOW + HOUR),
            ..MedSchedule::default()
        }];
        let out = analyse(inv, NOW, &FR);
        assert_eq!(out.schedules[0].runs.len(), 2);
        assert!(out.schedules[0].hints.iter().any(|h| h.level == HintLevel::Danger));
        assert!(out.cluster_hints.iter().any(|h| h.level == HintLevel::Danger));
        assert_eq!(out.last_restorable, None);
    }

    #[test]
    fn a_run_is_attributed_to_its_schedule_by_the_epoch_suffix_alone() {
        assert!(run_of("medusa-daily", "medusa-daily-1781132400"));
        assert!(!run_of("medusa-daily", "medusa-daily-full-1781132400"));
        assert!(!run_of("medusa-daily", "medusa-daily"));
        assert!(!run_of("medusa-daily", "medusa-daily-"));
        assert!(!run_of("medusa-daily-full", "medusa-daily-1781132400"));
    }

    #[test]
    fn a_successful_run_missing_from_the_catalogue_is_flagged() {
        let out = analyse(
            inventory(vec![dc("ns", "dc1", 3, 3)], vec![job("b1", 3, 0, Some(NOW - HOUR))]),
            NOW,
            &FR,
        );
        assert!(!out.jobs[0].in_catalogue);
        assert!(out.jobs[0].hints.iter().any(|h| h.level == HintLevel::Warn));
    }

    #[test]
    fn a_catalogue_entry_without_coverage_information_abstains() {
        let mut inv = inventory(vec![dc("ns", "dc1", 3, 3)], Vec::new());
        inv.backups = vec![MedBackup {
            uid: "k8c|backup|ns/old".to_string(),
            namespace: "ns".to_string(),
            name: "old".to_string(),
            // The real shape on operator 1.7: a start, an epoch-zero finish, and nothing else.
            start: Some(1_690_000_000),
            finish: real_ts(Some(0)),
            ..MedBackup::default()
        }];
        let out = analyse(inv, NOW, &FR);
        assert_eq!(out.backups[0].complete, None);
        assert!(out.backups[0].hints.iter().any(|h| h.level == HintLevel::Danger));
        assert_eq!(out.last_restorable, None);
    }

    #[test]
    fn the_datacenter_conditions_are_read_as_operations_in_flight() {
        let mut d = dc("ns", "dc1", 3, 3);
        d.conditions = vec![
            ("Ready".to_string(), "True".to_string()),
            ("RollingRestart".to_string(), "True".to_string()),
            ("Stopped".to_string(), "False".to_string()),
        ];
        assert_eq!(d.in_flight(), vec!["RollingRestart"]);
        let out = analyse(inventory(vec![d], Vec::new()), NOW, &FR);
        assert!(out.datacenters[0].hints.iter().any(|h| h.level == HintLevel::Info));
    }

    #[test]
    fn both_language_tables_produce_the_same_verdicts() {
        for st in [&FR, &EN] {
            let out = analyse(
                inventory(vec![dc("ns", "dc1", 6, 6)], vec![job("b1", 4, 2, Some(NOW - HOUR))]),
                NOW,
                st,
            );
            assert_eq!(out.jobs[0].hints[0].level, HintLevel::Danger);
            assert!(!out.jobs[0].hints[0].text.is_empty());
        }
    }

    #[test]
    fn the_write_payloads_name_the_fields_the_crds_declare() {
        let backup = write_payload(&K8cWrite::BackupNow {
            namespace: "ns".to_string(),
            datacenter: "dc1".to_string(),
            backup_type: "differential".to_string(),
            prefix: "nightly".to_string(),
        });
        assert_eq!(backup["apiVersion"], "medusa.k8ssandra.io/v1alpha1");
        assert_eq!(backup["kind"], "MedusaBackupJob");
        assert_eq!(backup["spec"]["cassandraDatacenter"], "dc1");
        assert_eq!(backup["spec"]["backupType"], "differential");
        assert_eq!(backup["metadata"]["generateName"], "nightly-");
        assert!(backup["metadata"]["name"].is_null(), "never a name of our own");

        let task = write_payload(&K8cWrite::CassandraTask {
            namespace: "ns".to_string(),
            datacenter: "dc1".to_string(),
            command: "cleanup".to_string(),
        });
        assert_eq!(task["apiVersion"], "control.k8ssandra.io/v1alpha1");
        assert_eq!(task["spec"]["datacenter"]["name"], "dc1");
        assert_eq!(task["spec"]["jobs"][0]["command"], "cleanup");
    }

    #[test]
    fn a_schedule_without_a_backup_type_leaves_the_key_out_rather_than_sending_it_empty() {
        // `backupType` is an enum of exactly `differential` and `full`, defaulted to the former by
        // the CRD. The empty string is not "unset", it is a value outside the enum: sending it makes
        // the apiserver refuse the create, so the whole backup never happens.
        let backup = write_payload(&K8cWrite::BackupNow {
            namespace: "ns".to_string(),
            datacenter: "dc1".to_string(),
            backup_type: String::new(),
            prefix: "nightly".to_string(),
        });
        assert_eq!(backup["spec"]["cassandraDatacenter"], "dc1");
        assert!(
            backup["spec"].get("backupType").is_none(),
            "the key is absent so the CRD default applies: {}",
            backup["spec"]
        );
    }

    #[test]
    fn the_type_announced_is_the_type_that_will_apply() {
        assert_eq!(effective_backup_type("full"), ("full", false));
        assert_eq!(effective_backup_type(""), (DEFAULT_BACKUP_TYPE, true));
        // Whitespace is not a type either, and it would be refused just like the empty string.
        assert_eq!(effective_backup_type("  "), (DEFAULT_BACKUP_TYPE, true));
    }

    #[test]
    fn the_ring_is_joined_on_the_address_when_the_recorded_host_id_has_gone_stale() {
        // Taken from a real datacenter: every host id in `status.nodeStatuses` had been left behind
        // by a re-bootstrap, and only the addresses still lined up. Joining on the host id alone
        // left every node of that datacenter with no ring at all.
        let mut nodes = vec![K8cNode {
            namespace: "ns".to_string(),
            name: "sts-0".to_string(),
            pod_ip: "10.244.5.177".to_string(),
            host_id: "eede2d83-stale".to_string(),
            ..K8cNode::default()
        }];
        let ring = vec![Endpoint {
            ip: "10.244.5.177".to_string(),
            host_id: "124e3fc6-live".to_string(),
            state: "NORMAL".to_string(),
            alive: true,
            ..Endpoint::default()
        }];
        attach_ring(&mut nodes, &ring);
        assert!(nodes[0].ring.is_some(), "the address matched even though the host id did not");
        assert!(nodes[0].host_id_stale, "the disagreement is reported, not hidden");
        assert_eq!(nodes[0].host_id, "124e3fc6-live", "the ring wins over the stale record");
    }

    #[test]
    fn a_pod_with_no_address_yet_still_joins_on_its_host_id() {
        let mut nodes = vec![K8cNode {
            host_id: "abc".to_string(),
            ..K8cNode::default()
        }];
        let ring = vec![Endpoint {
            ip: "10.0.0.1".to_string(),
            host_id: "abc".to_string(),
            alive: true,
            ..Endpoint::default()
        }];
        attach_ring(&mut nodes, &ring);
        assert!(nodes[0].ring.is_some());
        assert!(!nodes[0].host_id_stale, "agreement is not a discrepancy");
    }

    #[test]
    fn a_load_is_rendered_from_the_java_double_cassandra_reports() {
        assert_eq!(format_load(2.723922667075E12), "2.5 TiB");
        assert_eq!(format_load(0.0), "0 B");
    }
}
