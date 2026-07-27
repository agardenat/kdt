//! Storage inventory for the `:storage` view (PVC / PV / StorageClass).
//!
//! The point of this view is not to list volumes — `kubectl get pvc` already does that — but to say
//! what is *wrong* with them, which is the part that costs an afternoon: a PVC that will never bind
//! and why, a PV still holding data for a claim that no longer exists, a `reclaimPolicy: Delete` on
//! something nobody wants to lose, a cluster with no default StorageClass (or two).
//!
//! Everything the rules need is fetched in one pass — claims, volumes, classes, the pods that mount
//! them, and the provisioning events — so the diagnosis is computed from a single consistent view
//! instead of being re-derived per row while drawing. The rules themselves ([`diagnose`]) are pure
//! functions over that snapshot: no client, no I/O, testable.
//!
//! Read-only: this view inspects, it never writes. Deletion still goes through the generic
//! `Ctrl-D` guard-rails ([`crate::delete`]), which already treat PVC/PV as persistent data.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::lang::{Strings, fill};
use k8s_openapi::api::core::v1::{
    Event as K8sEvent, PersistentVolume, PersistentVolumeClaim, Pod,
};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::format_age;

// Annotation marking the cluster's default StorageClass. The `beta` spelling is still what several
// distributions (and anything provisioned a few years ago) write, so both are accepted.
const DEFAULT_CLASS_ANNOTATIONS: &[&str] = &[
    "storageclass.kubernetes.io/is-default-class",
    "storageclass.beta.kubernetes.io/is-default-class",
];

// Provisioner of the built-in "there is no provisioner": volumes of such a class are created by a
// human, so a Pending claim on one is waiting for a PV that may simply not exist.
const NO_PROVISIONER: &str = "kubernetes.io/no-provisioner";

// --- Diagnosis ----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HintLevel {
    Info,
    Warn,
    Danger,
}

#[derive(Debug, Clone)]
pub struct Hint {
    pub level: HintLevel,
    pub text: String,
}

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- Rows ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PvcResource {
    pub namespace: String,
    pub name: String,
    // `status.phase`: Bound / Pending / Lost.
    pub phase: String,
    pub volume_name: Option<String>,
    // What the volume actually gives (`status.capacity`), which can exceed what was asked for.
    pub capacity: String,
    pub requested: String,
    pub access_modes: String,
    // `None` means the field is absent (use the default class); `Some("")` means an explicit empty
    // string, which is Kubernetes' way of saying "no dynamic provisioning at all". The two lead to
    // very different explanations for a Pending claim, so they are kept apart.
    pub storage_class: Option<String>,
    pub age: String,
    pub uid: String,
    // Pods mounting this claim, in this namespace. Empty *and* `mounts_known` says whether that
    // means "nobody" or "we could not list the pods".
    pub mounted_by: Vec<String>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone)]
pub struct PvResource {
    pub name: String,
    pub capacity: String,
    pub access_modes: String,
    // `Delete` / `Retain` / `Recycle`.
    pub reclaim_policy: String,
    // `status.phase`: Bound / Available / Released / Failed.
    pub phase: String,
    // The claim this volume is (or was) bound to, as `namespace/name`.
    pub claim: Option<String>,
    pub storage_class: String,
    // Where the bytes live, in one line: `csi:driver`, `hostPath:/data`, `nfs:host:/export`…
    pub source: String,
    // Node/zone constraint from `spec.nodeAffinity`, flattened — the usual reason a claim binds on
    // one cluster and stays Pending on another.
    pub node_affinity: String,
    pub age: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone)]
pub struct ScResource {
    pub name: String,
    pub provisioner: String,
    pub reclaim_policy: String,
    // `Immediate` / `WaitForFirstConsumer`.
    pub binding_mode: String,
    pub allow_expansion: bool,
    pub is_default: bool,
    pub age: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Default, Debug, Clone)]
pub struct StorageState {
    pub pvcs: Vec<PvcResource>,
    pub pvs: Vec<PvResource>,
    pub classes: Vec<ScResource>,
    // Cluster-level findings that belong to no single row (no default class, two defaults…).
    pub cluster_hints: Vec<Hint>,
    // Bytes held by `Released` volumes: storage that is paid for and reachable by nobody.
    pub released_bytes: i64,
    // False when listing pods failed: the "nothing mounts this claim" rule then stays silent rather
    // than reporting an absence it cannot actually observe.
    pub mounts_known: bool,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedStorage = Arc<Mutex<StorageState>>;

pub fn new_storage_state() -> SharedStorage {
    Arc::new(Mutex::new(StorageState::default()))
}

// Does volume `pv` belong to class `sc` (so it nests under it in the grouped Volumes world)?
pub fn volume_in_class(pv: &PvResource, sc: &ScResource) -> bool {
    pv.storage_class == sc.name
}

// --- Fetch --------------------------------------------------------------------------------------

// One pass over everything the storage rules need. Claims are the only hard dependency: without
// them the view has nothing to say, so a failure there is surfaced as the view's error. The rest is
// enrichment — a role that cannot read PVs or pods degrades the diagnosis instead of blanking the
// screen, and each rule that depends on missing data stays quiet rather than guessing.
pub async fn fetch_storage(client: Client, namespace: Option<String>, state: SharedStorage) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("storage poisoned");
        s.loading = true;
        s.error = None;
    }

    let classes_raw = list_classes(&client).await.unwrap_or_default();
    let pvs_raw = list_volumes(&client).await.unwrap_or_default();
    let pvcs_raw = match list_claims(&client, &namespace).await {
        Ok(v) => v,
        Err(e) => {
            let mut s = state.lock().expect("storage poisoned");
            s.loading = false;
            s.error = Some(e);
            return;
        }
    };

    let mounts = list_mounts(&client, &namespace).await;
    let mounts_known = mounts.is_some();
    let mounts = mounts.unwrap_or_default();

    // Provisioning events are only worth a round-trip when something is actually stuck: on a healthy
    // cluster this is the common case and the request is skipped entirely.
    let has_pending = pvcs_raw.iter().any(|c| c.phase == "Pending");
    let events = if has_pending {
        claim_events(&client, &namespace).await
    } else {
        HashMap::new()
    };

    let snap = diagnose(pvcs_raw, pvs_raw, classes_raw, &mounts, mounts_known, &events, st);

    let mut s = state.lock().expect("storage poisoned");
    s.loading = false;
    s.error = None;
    s.pvcs = snap.pvcs;
    s.pvs = snap.pvs;
    s.classes = snap.classes;
    s.cluster_hints = snap.cluster_hints;
    s.released_bytes = snap.released_bytes;
    s.mounts_known = mounts_known;
}

async fn list_classes(client: &Client) -> Result<Vec<ScResource>, String> {
    let api: Api<StorageClass> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let mut out: Vec<ScResource> = list.items.iter().map(class_resource).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn list_volumes(client: &Client) -> Result<Vec<PvResource>, String> {
    let api: Api<PersistentVolume> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let mut out: Vec<PvResource> = list.items.iter().map(volume_resource).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn list_claims(
    client: &Client,
    namespace: &Option<String>,
) -> Result<Vec<PvcResource>, String> {
    let api: Api<PersistentVolumeClaim> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let mut out: Vec<PvcResource> = list.items.iter().map(claim_resource).collect();
    out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    Ok(out)
}

// `(namespace, claim name) -> pods mounting it`. `None` when the pods could not be listed at all,
// which is not the same answer as "no pod mounts anything".
async fn list_mounts(
    client: &Client,
    namespace: &Option<String>,
) -> Option<HashMap<(String, String), Vec<String>>> {
    let api: Api<Pod> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api.list(&ListParams::default()).await.ok()?;
    let mut out: HashMap<(String, String), Vec<String>> = HashMap::new();
    for pod in &list.items {
        let ns = pod.metadata.namespace.clone().unwrap_or_default();
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let Some(volumes) = pod.spec.as_ref().map(|s| &s.volumes) else { continue };
        for v in volumes.iter().flatten() {
            // A plain claim reference, and the generated claim of an ephemeral volume — whose name
            // the API server derives as `<pod>-<volume>`, and which is a real PVC in the list.
            let claim = if let Some(pvc) = v.persistent_volume_claim.as_ref() {
                pvc.claim_name.clone()
            } else if v.ephemeral.is_some() {
                format!("{}-{}", pod_name, v.name)
            } else {
                continue;
            };
            let entry = out.entry((ns.clone(), claim)).or_default();
            if !entry.contains(&pod_name) {
                entry.push(pod_name.clone());
            }
        }
    }
    Some(out)
}

// Provisioning failures as the provisioner reported them, keyed by `(namespace, claim)`. The field
// selector keeps this to claim events instead of pulling the whole cluster's event stream.
async fn claim_events(
    client: &Client,
    namespace: &Option<String>,
) -> HashMap<(String, String), String> {
    let api: Api<K8sEvent> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let lp = ListParams::default().fields("involvedObject.kind=PersistentVolumeClaim");
    let Ok(list) = api.list(&lp).await else { return HashMap::new() };

    let mut out: HashMap<(String, String), (i64, String)> = HashMap::new();
    for ev in &list.items {
        let reason = ev.reason.clone().unwrap_or_default();
        if !matches!(
            reason.as_str(),
            "ProvisioningFailed" | "FailedBinding" | "VolumeFailedDelete" | "ProvisioningCleanupFailed"
        ) {
            continue;
        }
        let ns = ev.involved_object.namespace.clone().unwrap_or_default();
        let name = ev.involved_object.name.clone().unwrap_or_default();
        let Some(message) = ev.message.clone() else { continue };
        // Keep the most recent one: an old failure that the provisioner has since worked past would
        // otherwise be presented as the current cause.
        let stamp = ev
            .last_timestamp
            .as_ref()
            .map(|t| t.0.as_second())
            .or_else(|| ev.event_time.as_ref().map(|t| t.0.as_second()))
            .unwrap_or(0);
        let entry = out.entry((ns, name)).or_insert((i64::MIN, String::new()));
        if stamp >= entry.0 {
            *entry = (stamp, message);
        }
    }
    out.into_iter().map(|(k, (_, msg))| (k, msg)).collect()
}

// --- Conversion ---------------------------------------------------------------------------------

fn claim_resource(c: &PersistentVolumeClaim) -> PvcResource {
    let namespace = c.metadata.namespace.clone().unwrap_or_default();
    let name = c.metadata.name.clone().unwrap_or_default();
    let spec = c.spec.as_ref();
    let status = c.status.as_ref();
    let phase = status
        .and_then(|s| s.phase.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let capacity = status
        .and_then(|s| s.capacity.as_ref())
        .and_then(|m| m.get("storage"))
        .map(|q| q.0.clone())
        .unwrap_or_default();
    let requested = spec
        .and_then(|s| s.resources.as_ref())
        .and_then(|r| r.requests.as_ref())
        .and_then(|m| m.get("storage"))
        .map(|q| q.0.clone())
        .unwrap_or_default();
    PvcResource {
        uid: format!("pvc|{}/{}", namespace, name),
        namespace,
        name,
        phase,
        volume_name: spec.and_then(|s| s.volume_name.clone()).filter(|v| !v.is_empty()),
        capacity,
        requested,
        access_modes: short_access_modes(spec.and_then(|s| s.access_modes.as_ref())),
        storage_class: spec.and_then(|s| s.storage_class_name.clone()),
        age: c
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        mounted_by: Vec::new(),
        hints: Vec::new(),
    }
}

fn volume_resource(v: &PersistentVolume) -> PvResource {
    let name = v.metadata.name.clone().unwrap_or_default();
    let spec = v.spec.as_ref();
    let capacity = spec
        .and_then(|s| s.capacity.as_ref())
        .and_then(|m| m.get("storage"))
        .map(|q| q.0.clone())
        .unwrap_or_default();
    let claim = spec.and_then(|s| s.claim_ref.as_ref()).map(|r| {
        format!(
            "{}/{}",
            r.namespace.clone().unwrap_or_default(),
            r.name.clone().unwrap_or_default()
        )
    });
    PvResource {
        uid: format!("pv|{}", name),
        name,
        capacity,
        access_modes: short_access_modes(spec.and_then(|s| s.access_modes.as_ref())),
        reclaim_policy: spec
            .and_then(|s| s.persistent_volume_reclaim_policy.clone())
            .unwrap_or_else(|| "Retain".to_string()),
        phase: v
            .status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .unwrap_or_else(|| "Unknown".to_string()),
        claim,
        storage_class: spec.and_then(|s| s.storage_class_name.clone()).unwrap_or_default(),
        source: volume_source(v),
        node_affinity: volume_node_affinity(v),
        age: v
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        hints: Vec::new(),
    }
}

fn class_resource(c: &StorageClass) -> ScResource {
    let name = c.metadata.name.clone().unwrap_or_default();
    let is_default = c
        .metadata
        .annotations
        .as_ref()
        .map(|a| {
            DEFAULT_CLASS_ANNOTATIONS
                .iter()
                .any(|k| a.get(*k).map(|v| v == "true").unwrap_or(false))
        })
        .unwrap_or(false);
    ScResource {
        uid: format!("sc|{}", name),
        name,
        provisioner: c.provisioner.clone(),
        reclaim_policy: c.reclaim_policy.clone().unwrap_or_else(|| "Delete".to_string()),
        binding_mode: c
            .volume_binding_mode
            .clone()
            .unwrap_or_else(|| "Immediate".to_string()),
        allow_expansion: c.allow_volume_expansion.unwrap_or(false),
        is_default,
        age: c
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        hints: Vec::new(),
    }
}

// Access modes as kubectl abbreviates them, which is also how anyone reads them out loud.
fn short_access_modes(modes: Option<&Vec<String>>) -> String {
    let Some(modes) = modes else { return String::new() };
    modes
        .iter()
        .map(|m| match m.as_str() {
            "ReadWriteOnce" => "RWO",
            "ReadOnlyMany" => "ROX",
            "ReadWriteMany" => "RWX",
            "ReadWriteOncePod" => "RWOP",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(",")
}

// Where the bytes actually live, in one cell. Only the fields that identify the backend are kept —
// the full spec is one `y` away.
fn volume_source(v: &PersistentVolume) -> String {
    let Some(s) = v.spec.as_ref() else { return String::new() };
    if let Some(csi) = s.csi.as_ref() {
        return format!("csi:{}", csi.driver);
    }
    if let Some(l) = s.local.as_ref() {
        return format!("local:{}", l.path);
    }
    if let Some(h) = s.host_path.as_ref() {
        return format!("hostPath:{}", h.path);
    }
    if let Some(n) = s.nfs.as_ref() {
        return format!("nfs:{}:{}", n.server, n.path);
    }
    if let Some(i) = s.iscsi.as_ref() {
        return format!("iscsi:{}", i.iqn);
    }
    if s.fc.is_some() { return "fc".to_string(); }
    if s.cephfs.is_some() { return "cephfs".to_string(); }
    if s.rbd.is_some() { return "rbd".to_string(); }
    String::new()
}

// `spec.nodeAffinity` flattened to something readable: this is what pins a volume to one node or one
// zone, and therefore what a Pending claim on the wrong side of the cluster is colliding with.
fn volume_node_affinity(v: &PersistentVolume) -> String {
    let Some(terms) = v
        .spec
        .as_ref()
        .and_then(|s| s.node_affinity.as_ref())
        .and_then(|a| a.required.as_ref())
        .map(|r| &r.node_selector_terms)
    else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    for term in terms {
        for e in term.match_expressions.iter().flatten() {
            let values = e.values.clone().unwrap_or_default().join(",");
            if values.is_empty() {
                parts.push(format!("{} {}", e.key, e.operator));
            } else {
                parts.push(format!("{}={}", e.key, values));
            }
        }
    }
    parts.join(" · ")
}

// A storage quantity in bytes ("20Gi", "500M", "1Ti"), for the comparisons the rules make. Returns
// `None` on anything unparseable, and every rule using it then abstains.
pub fn parse_bytes(q: &str) -> Option<i64> {
    let q = q.trim();
    if q.is_empty() { return None; }
    let split = q.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(q.len());
    let (num, suffix) = q.split_at(split);
    let value: f64 = num.parse().ok()?;
    let mult: f64 = match suffix.trim() {
        "" => 1.0,
        "k" | "K" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        "Ki" => 1024.0,
        "Mi" => 1024f64.powi(2),
        "Gi" => 1024f64.powi(3),
        "Ti" => 1024f64.powi(4),
        "Pi" => 1024f64.powi(5),
        _ => return None,
    };
    Some((value * mult) as i64)
}

// --- Rules --------------------------------------------------------------------------------------

// The diagnosed snapshot: same rows, with every hint attached.
pub struct Diagnosed {
    pub pvcs: Vec<PvcResource>,
    pub pvs: Vec<PvResource>,
    pub classes: Vec<ScResource>,
    pub cluster_hints: Vec<Hint>,
    pub released_bytes: i64,
}

// Reads the whole storage picture at once and says what is wrong with it. Pure over its inputs so
// the rules can be exercised without a cluster.
pub fn diagnose(
    mut pvcs: Vec<PvcResource>,
    mut pvs: Vec<PvResource>,
    mut classes: Vec<ScResource>,
    mounts: &HashMap<(String, String), Vec<String>>,
    mounts_known: bool,
    events: &HashMap<(String, String), String>,
    st: &'static Strings,
) -> Diagnosed {
    let by_class: HashMap<&str, &ScResource> =
        classes.iter().map(|c| (c.name.as_str(), c)).collect();
    let defaults: Vec<String> = classes
        .iter()
        .filter(|c| c.is_default)
        .map(|c| c.name.clone())
        .collect();
    // Claims that exist, to spot a volume bound to a claimRef nothing answers for. Only meaningful
    // cluster-wide: scoped to one namespace, every other namespace's claim looks missing.
    let known_claims: HashSet<String> = pvcs
        .iter()
        .map(|c| format!("{}/{}", c.namespace, c.name))
        .collect();

    // --- Volumes ---
    let mut released_bytes = 0i64;
    for pv in &mut pvs {
        let mut hints = Vec::new();
        match pv.phase.as_str() {
            "Released" => {
                released_bytes += parse_bytes(&pv.capacity).unwrap_or(0);
                let claim = pv.claim.clone().unwrap_or_else(|| "?".to_string());
                hints.push(warn(fill(
                    st.sto_pv_released,
                    &[("claim", &claim), ("size", &pv.capacity)],
                )));
            }
            "Failed" => {
                hints.push(danger(fill(st.sto_pv_failed, &[("size", &pv.capacity)])))
            }
            "Available" => hints.push(info(fill(
                st.sto_pv_available,
                &[("size", &pv.capacity), ("modes", &pv.access_modes)],
            ))),
            "Bound" => {
                if let Some(claim) = &pv.claim {
                    // Only accusable when the claim list covers the whole cluster.
                    if !known_claims.is_empty()
                        && !known_claims.contains(claim)
                        && !claim.starts_with('/')
                    {
                        hints.push(info(fill(st.sto_pv_out_of_scope, &[("claim", claim)])));
                    }
                }
            }
            _ => {}
        }
        if pv.reclaim_policy == "Delete" && pv.phase == "Bound" {
            let claim = pv
                .claim
                .clone()
                .unwrap_or_else(|| st.sto_pv_claim_unnamed.to_string());
            hints.push(warn(fill(st.sto_pv_reclaim_delete, &[("claim", &claim)])));
        }
        if !pv.node_affinity.is_empty() {
            hints.push(info(fill(
                st.sto_pv_node_affinity,
                &[("affinity", &pv.node_affinity)],
            )));
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        pv.hints = hints;
    }

    // --- Claims ---
    for pvc in &mut pvcs {
        let key = (pvc.namespace.clone(), pvc.name.clone());
        pvc.mounted_by = mounts.get(&key).cloned().unwrap_or_default();
        let mut hints = Vec::new();

        match pvc.phase.as_str() {
            "Pending" => {
                hints.extend(pending_hints(pvc, &by_class, &defaults, &pvs, events, st))
            }
            "Lost" => hints.push(danger(st.sto_pvc_lost.to_string())),
            "Bound" => {
                if mounts_known && pvc.mounted_by.is_empty() {
                    let size = if pvc.capacity.is_empty() { &pvc.requested } else { &pvc.capacity };
                    hints.push(warn(fill(st.sto_pvc_unmounted, &[("size", size)])));
                }
                if pvc.access_modes.contains("RWO") && pvc.mounted_by.len() > 1 {
                    hints.push(warn(fill(
                        st.sto_pvc_rwo_shared,
                        &[("n", &pvc.mounted_by.len().to_string())],
                    )));
                }
                // The reclaim policy that decides the fate of the data lives on the PV, not here —
                // so it is restated on the claim, which is the object someone actually deletes.
                if let Some(pv) = pvc
                    .volume_name
                    .as_ref()
                    .and_then(|n| pvs.iter().find(|p| &p.name == n))
                {
                    if pv.reclaim_policy == "Delete" {
                        hints.push(warn(fill(
                            st.sto_pvc_reclaim_delete,
                            &[("pv", &pv.name)],
                        )));
                    }
                }
            }
            _ => {}
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        pvc.hints = hints;
    }

    // --- Classes and cluster-level findings ---
    let mut cluster_hints = Vec::new();
    if classes.is_empty() {
        cluster_hints.push(warn(st.sto_no_class.to_string()));
    } else if defaults.is_empty() {
        cluster_hints.push(warn(st.sto_no_default_class.to_string()));
    } else if defaults.len() > 1 {
        cluster_hints.push(danger(fill(
            st.sto_many_default_classes,
            &[("n", &defaults.len().to_string()), ("list", &defaults.join(", "))],
        )));
    }
    if released_bytes > 0 {
        cluster_hints.push(warn(fill(
            st.sto_released_total,
            &[("size", &crate::events::format_memory_bytes(released_bytes))],
        )));
    }

    let claims_per_class: HashMap<&str, usize> = {
        let mut m: HashMap<&str, usize> = HashMap::new();
        for pvc in &pvcs {
            if let Some(sc) = pvc.storage_class.as_deref().filter(|s| !s.is_empty()) {
                *m.entry(sc).or_insert(0) += 1;
            }
        }
        m
    };
    for sc in &mut classes {
        let mut hints = Vec::new();
        if defaults.len() > 1 && sc.is_default {
            hints.push(danger(fill(
                st.sto_class_one_of_defaults,
                &[("n", &defaults.len().to_string())],
            )));
        }
        if sc.reclaim_policy == "Delete" {
            hints.push(info(st.sto_class_reclaim_delete.to_string()));
        }
        if !sc.allow_expansion {
            hints.push(info(st.sto_class_no_expansion.to_string()));
        }
        if sc.provisioner == NO_PROVISIONER {
            let n = claims_per_class.get(sc.name.as_str()).copied().unwrap_or(0);
            hints.push(info(fill(
                st.sto_class_no_provisioner,
                &[("n", &n.to_string())],
            )));
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        sc.hints = hints;
    }

    Diagnosed { pvcs, pvs, classes, cluster_hints, released_bytes }
}

// Why is this claim Pending? Answered in the order a human would check, and stopping at the first
// answer that fully explains it — a claim naming a class that does not exist has nothing to gain
// from also being told about binding modes.
fn pending_hints(
    pvc: &PvcResource,
    by_class: &HashMap<&str, &ScResource>,
    defaults: &[String],
    pvs: &[PvResource],
    events: &HashMap<(String, String), String>,
    st: &'static Strings,
) -> Vec<Hint> {
    let mut out = Vec::new();
    // The provisioner's own words come first when it left any: they beat every inference below.
    if let Some(msg) = events.get(&(pvc.namespace.clone(), pvc.name.clone())) {
        out.push(danger(fill(
            st.sto_pending_provisioner_failed,
            &[("msg", msg.trim())],
        )));
    }

    // Which class this claim will actually be provisioned by: the one it names, or the default.
    let effective = match pvc.storage_class.as_deref() {
        Some("") => {
            out.push(danger(st.sto_pending_empty_class.to_string()));
            None
        }
        Some(name) => match by_class.get(name) {
            Some(sc) => Some(*sc),
            None => {
                out.push(danger(fill(st.sto_pending_class_missing, &[("name", name)])));
                None
            }
        },
        None => match defaults.first().and_then(|d| by_class.get(d.as_str())) {
            Some(sc) => Some(*sc),
            None => {
                out.push(danger(st.sto_pending_no_class_at_all.to_string()));
                None
            }
        },
    };

    if let Some(sc) = effective {
        if sc.binding_mode == "WaitForFirstConsumer" && out.is_empty() {
            out.push(info(fill(st.sto_pending_wffc, &[("name", &sc.name)])));
        }
        if sc.provisioner == NO_PROVISIONER {
            let want = parse_bytes(&pvc.requested);
            let candidates = pvs
                .iter()
                .filter(|pv| pv.phase == "Available" && pv.storage_class == sc.name)
                .filter(|pv| match (want, parse_bytes(&pv.capacity)) {
                    (Some(w), Some(c)) => c >= w,
                    _ => true,
                })
                .count();
            let text = if candidates == 0 {
                fill(
                    st.sto_pending_no_candidate,
                    &[("name", &sc.name), ("size", &pvc.requested)],
                )
            } else {
                fill(
                    st.sto_pending_candidates,
                    &[("name", &sc.name), ("n", &candidates.to_string())],
                )
            };
            out.push(if candidates == 0 { danger(text) } else { warn(text) });
        }
    }

    if out.is_empty() {
        out.push(warn(fill(st.sto_pending_unexplained, &[("age", &pvc.age)])));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{FR, reads_as};

    fn sc(name: &str, provisioner: &str, binding: &str, default: bool) -> ScResource {
        ScResource {
            uid: format!("sc|{}", name),
            name: name.to_string(),
            provisioner: provisioner.to_string(),
            reclaim_policy: "Delete".to_string(),
            binding_mode: binding.to_string(),
            allow_expansion: true,
            is_default: default,
            age: "1d".to_string(),
            hints: Vec::new(),
        }
    }

    fn pvc(name: &str, phase: &str, class: Option<&str>) -> PvcResource {
        PvcResource {
            uid: format!("pvc|default/{}", name),
            namespace: "default".to_string(),
            name: name.to_string(),
            phase: phase.to_string(),
            volume_name: None,
            capacity: String::new(),
            requested: "10Gi".to_string(),
            access_modes: "RWO".to_string(),
            storage_class: class.map(String::from),
            age: "1h".to_string(),
            mounted_by: Vec::new(),
            hints: Vec::new(),
        }
    }

    fn pv(name: &str, phase: &str, class: &str, capacity: &str) -> PvResource {
        PvResource {
            uid: format!("pv|{}", name),
            name: name.to_string(),
            capacity: capacity.to_string(),
            access_modes: "RWO".to_string(),
            reclaim_policy: "Retain".to_string(),
            phase: phase.to_string(),
            claim: None,
            storage_class: class.to_string(),
            source: String::new(),
            node_affinity: String::new(),
            age: "1d".to_string(),
            hints: Vec::new(),
        }
    }

    fn run(
        pvcs: Vec<PvcResource>,
        pvs: Vec<PvResource>,
        classes: Vec<ScResource>,
    ) -> Diagnosed {
        diagnose(pvcs, pvs, classes, &HashMap::new(), true, &HashMap::new(), &FR)
    }

    #[test]
    fn missing_class_explains_pending() {
        let d = run(vec![pvc("data", "Pending", Some("fast"))], vec![], vec![sc("slow", "csi", "Immediate", true)]);
        assert!(d.pvcs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pending_class_missing)));
        assert_eq!(d.pvcs[0].hints[0].level, HintLevel::Danger);
    }

    #[test]
    fn no_default_class_explains_pending_without_class() {
        let d = run(vec![pvc("data", "Pending", None)], vec![], vec![sc("slow", "csi", "Immediate", false)]);
        assert!(d.pvcs[0].hints.iter().any(|h| h.text == FR.sto_pending_no_class_at_all));
        assert!(d.cluster_hints.iter().any(|h| h.text == FR.sto_no_default_class));
    }

    #[test]
    fn wait_for_first_consumer_is_not_an_alarm() {
        let d = run(
            vec![pvc("data", "Pending", Some("local"))],
            vec![],
            vec![sc("local", "csi", "WaitForFirstConsumer", true)],
        );
        assert_eq!(d.pvcs[0].hints[0].level, HintLevel::Info);
        assert!(reads_as(&d.pvcs[0].hints[0].text, FR.sto_pending_wffc));
    }

    #[test]
    fn manual_provisioning_counts_candidate_volumes() {
        let classes = vec![sc("manual", NO_PROVISIONER, "Immediate", false)];
        // Nothing available: there is a volume to create.
        let d = run(vec![pvc("data", "Pending", Some("manual"))], vec![], classes.clone());
        assert!(d.pvcs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pending_no_candidate)));
        // A big enough Available volume exists: the claim is not doomed, only unmatched.
        let d = run(
            vec![pvc("data", "Pending", Some("manual"))],
            vec![pv("vol", "Available", "manual", "20Gi")],
            classes.clone(),
        );
        assert!(d.pvcs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pending_candidates)));
        // Too small to satisfy the request: back to "create one".
        let d = run(
            vec![pvc("data", "Pending", Some("manual"))],
            vec![pv("vol", "Available", "manual", "1Gi")],
            classes,
        );
        assert!(d.pvcs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pending_no_candidate)));
    }

    #[test]
    fn released_volumes_are_counted_as_sleeping_cost() {
        let mut v = pv("vol", "Released", "manual", "20Gi");
        v.claim = Some("gone/data".to_string());
        let d = run(vec![], vec![v], vec![sc("manual", NO_PROVISIONER, "Immediate", true)]);
        assert_eq!(d.released_bytes, 20 * 1024 * 1024 * 1024);
        assert!(d.pvs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pv_released)));
        assert!(d.cluster_hints.iter().any(|h| reads_as(&h.text, FR.sto_released_total)));
    }

    #[test]
    fn unmounted_claim_is_silent_when_pods_are_unknown() {
        let bound = pvc("data", "Bound", Some("slow"));
        let classes = vec![sc("slow", "csi", "Immediate", true)];
        let known = run(vec![bound.clone()], vec![], classes.clone());
        assert!(known.pvcs[0].hints.iter().any(|h| reads_as(&h.text, FR.sto_pvc_unmounted)));
        let unknown =
            diagnose(vec![bound], vec![], classes, &HashMap::new(), false, &HashMap::new(), &FR);
        assert!(unknown.pvcs[0].hints.is_empty());
    }

    #[test]
    fn two_default_classes_are_a_danger() {
        let d = run(
            vec![],
            vec![],
            vec![sc("a", "csi", "Immediate", true), sc("b", "csi", "Immediate", true)],
        );
        assert!(d.cluster_hints.iter().any(|h| h.level == HintLevel::Danger));
        assert!(d.classes.iter().all(|c| c.hints[0].level == HintLevel::Danger));
    }

    #[test]
    fn quantities_parse_in_both_unit_families() {
        assert_eq!(parse_bytes("20Gi"), Some(20 * 1024 * 1024 * 1024));
        assert_eq!(parse_bytes("500M"), Some(500_000_000));
        assert_eq!(parse_bytes("1024"), Some(1024));
        assert_eq!(parse_bytes(""), None);
        assert_eq!(parse_bytes("beaucoup"), None);
    }
}
