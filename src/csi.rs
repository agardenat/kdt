//! The CSI side of the `:storage` view: volume snapshots and volume attachments.
//!
//! Both are where storage breaks *after* a claim has bound, which is why the claim/volume worlds
//! never see it: a snapshot that never becomes ready (so the backup that took it restores nothing),
//! a snapshot content nobody references any more but the provider still bills, a VolumeAttachment
//! whose PV is gone and whose finalizer waits forever for a detach that can no longer happen, a
//! node that has used up its attach slots and leaves the next pod in `ContainerCreating`.
//!
//! The snapshot kinds are CRDs (`snapshot.storage.k8s.io/v1`), installed by the external
//! snapshotter and absent from plenty of clusters: absence is a fact the world states, never an
//! error. Each rule that depends on a list it could not read stays quiet rather than guessing — an
//! unread PV list must not turn every attachment into a ghost.

use std::collections::{BTreeMap, HashMap, HashSet};

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, VolumeAttachment};
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;

use crate::events::{format_age, format_memory_bytes, EventRecord, LineColor, Severity};
use crate::lang::{fill, Strings};
use crate::nsscope::{self, NsScope};
use crate::storage::{hints_severity, Hint, HintLevel};

const SNAPSHOT_GROUP: &str = "snapshot.storage.k8s.io";
const SNAPSHOT_API: &str = "snapshot.storage.k8s.io/v1";
const DEFAULT_SNAPSHOT_CLASS: &str = "snapshot.storage.kubernetes.io/is-default-class";
const VELERO_SNAPSHOT_CLASS: &str = "velero.io/csi-volumesnapshot-class";

// How long a state is allowed to be transitional before it is reported. A snapshot of a large
// volume takes minutes to be cut, an attach a few seconds to a minute, a detach about as long:
// anything past these has stopped progressing.
const SNAPSHOT_READY_GRACE: i64 = 600;
const ATTACH_GRACE: i64 = 300;
const DELETION_GRACE: i64 = 600;

// Share of a node's attach slots past which the next scheduling decision is worth a warning.
const ATTACH_NEAR_RATIO: f64 = 0.8;

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- Rows ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapClassResource {
    pub name: String,
    pub driver: String,
    pub deletion_policy: String,
    pub is_default: bool,
    // Labelled for velero's CSI plugin: the class velero picks for this driver.
    pub velero: bool,
    pub age: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotResource {
    pub namespace: String,
    pub name: String,
    // `Ready` / `NotReady` / `Error` / `Deleting`.
    pub phase: String,
    pub class: Option<String>,
    // The claim it was cut from; `None` for a pre-provisioned snapshot (`source.volumeSnapshotContentName`).
    pub source_pvc: Option<String>,
    // `status.boundVolumeSnapshotContentName`, or the pre-provisioned content it names.
    pub content: Option<String>,
    pub restore_size: String,
    pub error: Option<String>,
    pub age: String,
    #[serde(skip)]
    pub age_secs: i64,
    // Age of the deletion request, when one is pending, and what holds it.
    pub deleting_since: Option<String>,
    #[serde(skip)]
    pub deleting_secs: i64,
    pub finalizers: Vec<String>,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapContentResource {
    pub name: String,
    pub phase: String,
    // `spec.volumeSnapshotRef` as `namespace/name`.
    pub snapshot: Option<String>,
    #[serde(skip)]
    pub snapshot_ns: String,
    pub driver: String,
    pub deletion_policy: String,
    pub class: Option<String>,
    // The provider's handle: what is still billed when nothing in the cluster points at it.
    pub handle: String,
    pub restore_size: String,
    pub error: Option<String>,
    pub age: String,
    pub deleting_since: Option<String>,
    #[serde(skip)]
    pub deleting_secs: i64,
    pub finalizers: Vec<String>,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachResource {
    pub name: String,
    // `Attached` / `Detached` / `Error` / `Deleting`.
    pub phase: String,
    pub attacher: String,
    pub node: String,
    // The PV it attaches, or empty for an inline (CSI migration) volume.
    pub pv: String,
    // `status.attached` as last written by the attacher — on a ghost, a value frozen at the last
    // success, not a statement about the provider.
    pub attached: bool,
    pub attach_error: Option<String>,
    pub detach_error: Option<String>,
    // `attachmentMetadata` flattened (`LUN=0`…): what the provider was told.
    pub metadata: String,
    pub age: String,
    #[serde(skip)]
    pub age_secs: i64,
    pub deleting_since: Option<String>,
    #[serde(skip)]
    pub deleting_secs: i64,
    pub finalizers: Vec<String>,
    pub uid: String,
    pub hints: Vec<Hint>,
}

// One driver's slots on one node: how many volumes are attached against how many the node allows.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeSlots {
    pub driver: String,
    pub used: usize,
    // `CSINode.spec.drivers[].allocatable.count`; `None` when the driver publishes no limit.
    pub limit: Option<i32>,
}

// The header of a node's attachments in the grouped world.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeAttachResource {
    pub node: String,
    // False when the node object is gone: the attachments under it are left over.
    pub exists: bool,
    pub slots: Vec<NodeSlots>,
    pub uid: String,
    pub hints: Vec<Hint>,
}

impl NodeAttachResource {
    // `disk.csi.azure.com 3/32 · file.csi.azure.com 1`, for the one cell a header has.
    pub fn slots_label(&self) -> String {
        self.slots
            .iter()
            .map(|s| match s.limit {
                Some(l) => format!("{} {}/{}", s.driver, s.used, l),
                None => format!("{} {}", s.driver, s.used),
            })
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

#[derive(Debug, Clone, Default)]
pub struct CsiDiagnosed {
    pub snap_classes: Vec<SnapClassResource>,
    pub snapshots: Vec<SnapshotResource>,
    pub contents: Vec<SnapContentResource>,
    pub attachments: Vec<AttachResource>,
    pub nodes: Vec<NodeAttachResource>,
    // False when the snapshot CRDs are not installed: the world says so instead of showing an
    // empty table that reads as "no snapshot was ever taken".
    pub snapshots_installed: bool,
    pub cluster_hints: Vec<Hint>,
}

// --- Fetch --------------------------------------------------------------------------------------

// What the rules are computed over. Every list is an `Option`: `None` is "could not read", which
// silences the rules that need it, and is not the same as an empty list.
#[derive(Default)]
pub struct CsiRaw {
    pub snap_classes: Option<Vec<DynamicObject>>,
    pub snapshots: Option<Vec<DynamicObject>>,
    pub contents: Option<Vec<DynamicObject>>,
    pub attachments: Option<Vec<VolumeAttachment>>,
    pub csi_nodes: Option<Vec<CSINode>>,
    pub drivers: Option<Vec<String>>,
    pub nodes: Option<Vec<String>>,
    pub snapshots_installed: bool,
}

pub async fn fetch_csi(client: &Client, scope: &NsScope) -> CsiRaw {
    let snapshot_kind = |kind: &'static str| async move {
        let gvk = GroupVersionKind::gvk(SNAPSHOT_GROUP, "v1", kind);
        discovery::pinned_kind(client, &gvk).await.ok().map(|(ar, _)| ar)
    };
    let (class_ar, snap_ar, content_ar) = futures::join!(
        snapshot_kind("VolumeSnapshotClass"),
        snapshot_kind("VolumeSnapshot"),
        snapshot_kind("VolumeSnapshotContent"),
    );
    let snapshots_installed = snap_ar.is_some();

    let list_dyn = |ar: Option<kube::api::ApiResource>, scope: NsScope| async move {
        let ar = ar?;
        nsscope::list_dyn(client, &scope, &ar, &ListParams::default()).await.ok()
    };
    let attachments = async {
        let api: Api<VolumeAttachment> = Api::all(client.clone());
        api.list(&ListParams::default()).await.ok().map(|l| l.items)
    };
    let csi_nodes = async {
        let api: Api<CSINode> = Api::all(client.clone());
        api.list(&ListParams::default()).await.ok().map(|l| l.items)
    };
    let drivers = async {
        let api: Api<CSIDriver> = Api::all(client.clone());
        api.list_metadata(&ListParams::default())
            .await
            .ok()
            .map(|l| l.items.into_iter().filter_map(|d| d.metadata.name).collect())
    };
    let nodes = async {
        let api: Api<Node> = Api::all(client.clone());
        api.list_metadata(&ListParams::default())
            .await
            .ok()
            .map(|l| l.items.into_iter().filter_map(|n| n.metadata.name).collect())
    };
    let (snap_classes, snapshots, contents, attachments, csi_nodes, drivers, nodes) = futures::join!(
        list_dyn(class_ar, NsScope::All),
        list_dyn(snap_ar, scope.clone()),
        list_dyn(content_ar, NsScope::All),
        attachments,
        csi_nodes,
        drivers,
        nodes,
    );
    CsiRaw {
        snap_classes,
        snapshots,
        contents,
        attachments,
        csi_nodes,
        drivers,
        nodes,
        snapshots_installed,
    }
}

// --- Conversion ---------------------------------------------------------------------------------

fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    Some(cur)
}

fn str_at(v: &Value, path: &[&str]) -> Option<String> {
    at(v, path).and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(String::from)
}

fn secs_since(t: &Timestamp) -> i64 {
    (Timestamp::now().as_second() - t.as_second()).max(0)
}

struct Meta {
    age: String,
    age_secs: i64,
    deleting_since: Option<String>,
    deleting_secs: i64,
    finalizers: Vec<String>,
}

fn meta_of(m: &kube::api::ObjectMeta) -> Meta {
    let created = m.creation_timestamp.as_ref().map(|t| t.0);
    let deleting = m.deletion_timestamp.as_ref().map(|t| t.0);
    Meta {
        age: created.as_ref().map(format_age).unwrap_or_default(),
        age_secs: created.as_ref().map(secs_since).unwrap_or(0),
        deleting_since: deleting.as_ref().map(format_age),
        deleting_secs: deleting.as_ref().map(secs_since).unwrap_or(0),
        finalizers: m.finalizers.clone().unwrap_or_default(),
    }
}

fn snapshot_phase(deleting: bool, error: &Option<String>, ready: Option<bool>) -> String {
    if deleting {
        "Deleting"
    } else if error.is_some() {
        "Error"
    } else if ready == Some(true) {
        "Ready"
    } else {
        "NotReady"
    }
    .to_string()
}

fn snap_class_resource(o: &DynamicObject) -> SnapClassResource {
    let name = o.metadata.name.clone().unwrap_or_default();
    let flag = |map: &Option<BTreeMap<String, String>>, key: &str| {
        map.as_ref().and_then(|m| m.get(key)).map(|v| v == "true").unwrap_or(false)
    };
    SnapClassResource {
        uid: format!("vsclass|{}", name),
        name,
        driver: str_at(&o.data, &["driver"]).unwrap_or_default(),
        deletion_policy: str_at(&o.data, &["deletionPolicy"]).unwrap_or_default(),
        is_default: flag(&o.metadata.annotations, DEFAULT_SNAPSHOT_CLASS),
        velero: flag(&o.metadata.labels, VELERO_SNAPSHOT_CLASS),
        age: meta_of(&o.metadata).age,
        hints: Vec::new(),
    }
}

fn snapshot_resource(o: &DynamicObject) -> SnapshotResource {
    let namespace = o.metadata.namespace.clone().unwrap_or_default();
    let name = o.metadata.name.clone().unwrap_or_default();
    let m = meta_of(&o.metadata);
    let error = str_at(&o.data, &["status", "error", "message"]);
    let ready = at(&o.data, &["status", "readyToUse"]).and_then(|v| v.as_bool());
    let content = str_at(&o.data, &["status", "boundVolumeSnapshotContentName"])
        .or_else(|| str_at(&o.data, &["spec", "source", "volumeSnapshotContentName"]));
    SnapshotResource {
        uid: format!("vs|{}/{}", namespace, name),
        phase: snapshot_phase(m.deleting_since.is_some(), &error, ready),
        namespace,
        name,
        class: str_at(&o.data, &["spec", "volumeSnapshotClassName"]),
        source_pvc: str_at(&o.data, &["spec", "source", "persistentVolumeClaimName"]),
        content,
        restore_size: str_at(&o.data, &["status", "restoreSize"]).unwrap_or_default(),
        error,
        age: m.age,
        age_secs: m.age_secs,
        deleting_since: m.deleting_since,
        deleting_secs: m.deleting_secs,
        finalizers: m.finalizers,
        hints: Vec::new(),
    }
}

fn content_resource(o: &DynamicObject) -> SnapContentResource {
    let name = o.metadata.name.clone().unwrap_or_default();
    let m = meta_of(&o.metadata);
    let error = str_at(&o.data, &["status", "error", "message"]);
    let ready = at(&o.data, &["status", "readyToUse"]).and_then(|v| v.as_bool());
    let snapshot_ns = str_at(&o.data, &["spec", "volumeSnapshotRef", "namespace"]).unwrap_or_default();
    let snapshot = str_at(&o.data, &["spec", "volumeSnapshotRef", "name"])
        .map(|n| format!("{}/{}", snapshot_ns, n));
    // `status.restoreSize` is an integer of bytes here, where the VolumeSnapshot carries a quantity.
    let restore_size = at(&o.data, &["status", "restoreSize"])
        .and_then(|v| v.as_i64())
        .map(format_memory_bytes)
        .unwrap_or_default();
    SnapContentResource {
        uid: format!("vsc|{}", name),
        phase: snapshot_phase(m.deleting_since.is_some(), &error, ready),
        name,
        snapshot,
        snapshot_ns,
        driver: str_at(&o.data, &["spec", "driver"]).unwrap_or_default(),
        deletion_policy: str_at(&o.data, &["spec", "deletionPolicy"]).unwrap_or_default(),
        class: str_at(&o.data, &["spec", "volumeSnapshotClassName"]),
        handle: str_at(&o.data, &["status", "snapshotHandle"])
            .or_else(|| str_at(&o.data, &["spec", "source", "snapshotHandle"]))
            .unwrap_or_default(),
        restore_size,
        error,
        age: m.age,
        deleting_since: m.deleting_since,
        deleting_secs: m.deleting_secs,
        finalizers: m.finalizers,
        hints: Vec::new(),
    }
}

fn attach_resource(va: &VolumeAttachment) -> AttachResource {
    let name = va.metadata.name.clone().unwrap_or_default();
    let m = meta_of(&va.metadata);
    let status = va.status.as_ref();
    let attached = status.map(|s| s.attached).unwrap_or(false);
    let message = |e: Option<&k8s_openapi::api::storage::v1::VolumeError>| {
        e.and_then(|e| e.message.clone()).filter(|s| !s.is_empty())
    };
    let attach_error = message(status.and_then(|s| s.attach_error.as_ref()));
    let detach_error = message(status.and_then(|s| s.detach_error.as_ref()));
    let phase = if m.deleting_since.is_some() {
        "Deleting"
    } else if attach_error.is_some() {
        "Error"
    } else if attached {
        "Attached"
    } else {
        "Detached"
    }
    .to_string();
    let metadata = status
        .and_then(|s| s.attachment_metadata.as_ref())
        .map(|md| md.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(","))
        .unwrap_or_default();
    AttachResource {
        uid: format!("va|{}", name),
        name,
        phase,
        attacher: va.spec.attacher.clone(),
        node: va.spec.node_name.clone(),
        pv: va.spec.source.persistent_volume_name.clone().unwrap_or_default(),
        attached,
        attach_error,
        detach_error,
        metadata,
        age: m.age,
        age_secs: m.age_secs,
        deleting_since: m.deleting_since,
        deleting_secs: m.deleting_secs,
        finalizers: m.finalizers,
        hints: Vec::new(),
    }
}

// --- Rules --------------------------------------------------------------------------------------

/// Everything the CSI rules need besides their own objects: what the storage pass already read.
pub struct CsiContext<'a> {
    pub scope: &'a NsScope,
    // PV names, `None` when the PV list was refused.
    pub pvs: Option<&'a HashSet<String>>,
    // `namespace/name` of the claims in scope.
    pub pvcs: &'a HashSet<String>,
}

fn finalizers_label(f: &[String]) -> String {
    if f.is_empty() { "—".to_string() } else { f.join(", ") }
}

pub fn diagnose_csi(raw: CsiRaw, ctx: &CsiContext, st: &'static Strings) -> CsiDiagnosed {
    let mut snap_classes: Vec<SnapClassResource> =
        raw.snap_classes.as_deref().unwrap_or_default().iter().map(snap_class_resource).collect();
    let mut snapshots: Vec<SnapshotResource> =
        raw.snapshots.as_deref().unwrap_or_default().iter().map(snapshot_resource).collect();
    let mut contents: Vec<SnapContentResource> =
        raw.contents.as_deref().unwrap_or_default().iter().map(content_resource).collect();
    let mut attachments: Vec<AttachResource> =
        raw.attachments.as_deref().unwrap_or_default().iter().map(attach_resource).collect();
    snap_classes.sort_by(|a, b| a.name.cmp(&b.name));
    snapshots.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    contents.sort_by(|a, b| a.name.cmp(&b.name));
    attachments.sort_by(|a, b| (&a.node, &a.pv, &a.name).cmp(&(&b.node, &b.pv, &b.name)));

    let class_names: Option<HashSet<String>> =
        raw.snap_classes.as_ref().map(|_| snap_classes.iter().map(|c| c.name.clone()).collect());
    let content_names: Option<HashSet<String>> =
        raw.contents.as_ref().map(|_| contents.iter().map(|c| c.name.clone()).collect());
    let snapshot_keys: Option<HashSet<String>> = raw
        .snapshots
        .as_ref()
        .map(|_| snapshots.iter().map(|s| format!("{}/{}", s.namespace, s.name)).collect());
    let drivers: Option<HashSet<&str>> =
        raw.drivers.as_ref().map(|d| d.iter().map(|s| s.as_str()).collect());
    let nodes: Option<HashSet<&str>> =
        raw.nodes.as_ref().map(|d| d.iter().map(|s| s.as_str()).collect());

    // --- Snapshot classes ---
    let mut defaults_per_driver: HashMap<&str, usize> = HashMap::new();
    for c in snap_classes.iter().filter(|c| c.is_default) {
        *defaults_per_driver.entry(c.driver.as_str()).or_insert(0) += 1;
    }
    let defaults_per_driver: HashMap<String, usize> =
        defaults_per_driver.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    for c in &mut snap_classes {
        let mut hints = Vec::new();
        if let Some(n) = defaults_per_driver.get(&c.driver).filter(|n| **n > 1) {
            if c.is_default {
                hints.push(danger(fill(
                    st.csi_class_many_defaults,
                    &[("n", &n.to_string()), ("driver", &c.driver)],
                )));
            }
        }
        if let Some(d) = &drivers {
            if !c.driver.is_empty() && !d.contains(c.driver.as_str()) {
                hints.push(warn(fill(st.csi_class_driver_missing, &[("driver", &c.driver)])));
            }
        }
        if c.velero {
            hints.push(info(fill(st.csi_class_velero, &[("driver", &c.driver)])));
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        c.hints = hints;
    }

    // --- Snapshots ---
    for s in &mut snapshots {
        let mut hints = Vec::new();
        if let Some(msg) = &s.error {
            hints.push(danger(fill(st.csi_snap_error, &[("msg", msg.trim())])));
        }
        if s.deleting_since.is_some() {
            if s.deleting_secs > DELETION_GRACE {
                hints.push(warn(fill(
                    st.csi_deleting_stuck,
                    &[
                        ("age", s.deleting_since.as_deref().unwrap_or("")),
                        ("finalizers", &finalizers_label(&s.finalizers)),
                    ],
                )));
            }
        } else if s.phase == "NotReady" && s.age_secs > SNAPSHOT_READY_GRACE {
            hints.push(warn(fill(st.csi_snap_not_ready, &[("age", &s.age)])));
        }
        let mut restorable = s.phase == "Ready";
        if let (Some(content), Some(known)) = (&s.content, &content_names) {
            if !known.contains(content) {
                restorable = false;
                hints.push(danger(fill(st.csi_snap_content_missing, &[("content", content)])));
            }
        }
        if let (Some(class), Some(known)) = (&s.class, &class_names) {
            if !known.contains(class) {
                hints.push(warn(fill(st.csi_snap_class_missing, &[("class", class)])));
            }
        }
        if let Some(pvc) = &s.source_pvc {
            // "Still restorable" is only said of a snapshot that is: ready, and with its content.
            if restorable && !ctx.pvcs.contains(&format!("{}/{}", s.namespace, pvc)) {
                hints.push(info(fill(st.csi_snap_source_gone, &[("pvc", pvc)])));
            }
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        s.hints = hints;
    }

    // --- Contents ---
    let mut orphans_retained = 0usize;
    for c in &mut contents {
        let mut hints = Vec::new();
        if let Some(msg) = &c.error {
            hints.push(danger(fill(st.csi_snap_error, &[("msg", msg.trim())])));
        }
        if c.deleting_since.is_some() && c.deleting_secs > DELETION_GRACE {
            hints.push(warn(fill(
                st.csi_deleting_stuck,
                &[
                    ("age", c.deleting_since.as_deref().unwrap_or("")),
                    ("finalizers", &finalizers_label(&c.finalizers)),
                ],
            )));
        }
        // A content's snapshot can only be called missing where the snapshot list covers its
        // namespace: scoped to some namespaces, every other namespace's snapshot looks absent.
        let observable = ctx.scope.contains(&c.snapshot_ns);
        if let (Some(snap), Some(known), true) = (&c.snapshot, &snapshot_keys, observable) {
            if !known.contains(snap) && c.deleting_since.is_none() {
                let handle = if c.handle.is_empty() { "?" } else { c.handle.as_str() };
                if c.deletion_policy == "Retain" {
                    orphans_retained += 1;
                    hints.push(warn(fill(
                        st.csi_content_orphan_retain,
                        &[("snapshot", snap), ("handle", handle)],
                    )));
                } else {
                    hints.push(warn(fill(st.csi_content_orphan_delete, &[("snapshot", snap)])));
                }
            }
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        c.hints = hints;
    }

    // --- Attachments ---
    let mut ghosts = 0usize;
    for a in &mut attachments {
        let mut hints = Vec::new();
        let pv_gone = !a.pv.is_empty() && ctx.pvs.is_some_and(|known| !known.contains(&a.pv));
        if a.deleting_since.is_some() && pv_gone {
            ghosts += 1;
            hints.push(danger(fill(
                st.csi_va_ghost,
                &[
                    ("age", a.deleting_since.as_deref().unwrap_or("")),
                    ("pv", &a.pv),
                    ("finalizers", &finalizers_label(&a.finalizers)),
                ],
            )));
            hints.push(if a.attached {
                warn(st.csi_va_ghost_attached.to_string())
            } else {
                info(st.csi_va_ghost_never.to_string())
            });
        } else {
            if let Some(msg) = &a.attach_error {
                hints.push(danger(fill(st.csi_va_attach_error, &[("msg", msg.trim())])));
            }
            if let Some(msg) = &a.detach_error {
                hints.push(warn(fill(st.csi_va_detach_error, &[("msg", msg.trim())])));
            }
            if a.deleting_since.is_some() {
                if a.deleting_secs > DELETION_GRACE && a.detach_error.is_none() {
                    hints.push(warn(fill(
                        st.csi_va_detaching,
                        &[("age", a.deleting_since.as_deref().unwrap_or(""))],
                    )));
                }
            } else if !a.attached && a.attach_error.is_none() && a.age_secs > ATTACH_GRACE {
                hints.push(warn(fill(st.csi_va_not_attached, &[("age", &a.age)])));
            }
            if pv_gone {
                hints.push(warn(fill(st.csi_va_pv_missing, &[("pv", &a.pv)])));
            }
        }
        if let Some(known) = &nodes {
            if !known.contains(a.node.as_str()) {
                hints.push(warn(fill(st.csi_va_node_missing, &[("node", &a.node)])));
            }
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        a.hints = hints;
    }

    // --- Nodes: attach slots ---
    let limits: HashMap<(String, String), i32> = raw
        .csi_nodes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .flat_map(|n| {
            let node = n.metadata.name.clone().unwrap_or_default();
            n.spec.drivers.iter().filter_map(move |d| {
                d.allocatable
                    .as_ref()
                    .and_then(|a| a.count)
                    .map(|c| ((node.clone(), d.name.clone()), c))
            })
        })
        .collect();
    let mut per_node: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for a in &attachments {
        let slots = per_node.entry(a.node.clone()).or_default();
        let used = slots.entry(a.attacher.clone()).or_insert(0);
        if a.attached {
            *used += 1;
        }
    }
    let node_rows: Vec<NodeAttachResource> = per_node
        .into_iter()
        .map(|(node, drivers)| {
            let slots: Vec<NodeSlots> = drivers
                .into_iter()
                .map(|(driver, used)| NodeSlots {
                    limit: limits.get(&(node.clone(), driver.clone())).copied(),
                    driver,
                    used,
                })
                .collect();
            let mut hints = Vec::new();
            for s in &slots {
                let Some(limit) = s.limit.filter(|l| *l > 0) else { continue };
                let args = [
                    ("used", s.used.to_string()),
                    ("limit", limit.to_string()),
                    ("driver", s.driver.clone()),
                ];
                let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (*k, v.as_str())).collect();
                if s.used >= limit as usize {
                    hints.push(danger(fill(st.csi_node_full, &args)));
                } else if s.used as f64 >= limit as f64 * ATTACH_NEAR_RATIO {
                    hints.push(warn(fill(st.csi_node_near, &args)));
                }
            }
            let exists = nodes.as_ref().is_none_or(|known| known.contains(node.as_str()));
            if !exists {
                hints.push(warn(fill(st.csi_va_node_missing, &[("node", &node)])));
            }
            hints.sort_by_key(|h| std::cmp::Reverse(h.level));
            NodeAttachResource { uid: format!("vanode|{}", node), node, exists, slots, hints }
        })
        .collect();

    // --- Cluster-level ---
    let mut cluster_hints = Vec::new();
    if ghosts > 0 {
        cluster_hints.push(danger(fill(st.csi_cluster_ghosts, &[("n", &ghosts.to_string())])));
    }
    if orphans_retained > 0 {
        cluster_hints.push(warn(fill(
            st.csi_cluster_orphans,
            &[("n", &orphans_retained.to_string())],
        )));
    }

    CsiDiagnosed {
        snap_classes,
        snapshots,
        contents,
        attachments,
        nodes: node_rows,
        snapshots_installed: raw.snapshots_installed,
        cluster_hints,
    }
}

// --- Grouping -----------------------------------------------------------------------------------

/// The contents no snapshot in the list answers for — the tail of the grouped Snapshots world.
pub fn unreferenced_contents(d: &CsiDiagnosed) -> Vec<&SnapContentResource> {
    let shown: HashSet<&str> = d.snapshots.iter().filter_map(|s| s.content.as_deref()).collect();
    d.contents.iter().filter(|c| !shown.contains(c.name.as_str())).collect()
}

// --- Records ------------------------------------------------------------------------------------

pub fn csi_phase_tone(phase: &str) -> LineColor {
    match phase {
        "Ready" | "Attached" => LineColor::Ok,
        "NotReady" | "Detached" | "Deleting" => LineColor::Warn,
        "Error" => LineColor::Err,
        _ => LineColor::Dim,
    }
}

// `(api_version, kind)` travel together: they are the object's type, and the generic gestures resolve
// it by discovery.
fn record(
    uid: String,
    hints: &[Hint],
    reason: &str,
    (api_version, kind): (&str, &str),
    namespace: &str,
    name: &str,
    message: String,
) -> EventRecord {
    EventRecord {
        uid,
        time: Timestamp::now(),
        severity: hints_severity(hints),
        reason: reason.to_string(),
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        message,
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

pub fn snap_class_record(c: &SnapClassResource) -> EventRecord {
    record(
        format!("sto|{}", c.uid),
        &c.hints,
        "VolumeSnapshotClass",
        (SNAPSHOT_API, "VolumeSnapshotClass"),
        "",
        &c.name,
        format!(
            "{} deletionPolicy={}{}{}",
            c.driver,
            c.deletion_policy,
            if c.is_default { " (default)" } else { "" },
            if c.velero { " velero" } else { "" },
        ),
    )
}

pub fn snapshot_record(s: &SnapshotResource) -> EventRecord {
    record(
        format!("sto|{}", s.uid),
        &s.hints,
        &s.phase,
        (SNAPSHOT_API, "VolumeSnapshot"),
        &s.namespace,
        &s.name,
        format!(
            "{} class={} source={} content={}",
            s.restore_size,
            s.class.as_deref().unwrap_or("—"),
            s.source_pvc.as_deref().unwrap_or("—"),
            s.content.as_deref().unwrap_or("—"),
        ),
    )
}

pub fn content_record(c: &SnapContentResource) -> EventRecord {
    record(
        format!("sto|{}", c.uid),
        &c.hints,
        &c.phase,
        (SNAPSHOT_API, "VolumeSnapshotContent"),
        "",
        &c.name,
        format!(
            "{} {} deletionPolicy={} snapshot={} handle={}",
            c.restore_size,
            c.driver,
            c.deletion_policy,
            c.snapshot.as_deref().unwrap_or("—"),
            c.handle,
        ),
    )
}

pub fn attach_record(a: &AttachResource) -> EventRecord {
    record(
        format!("sto|{}", a.uid),
        &a.hints,
        &a.phase,
        ("storage.k8s.io/v1", "VolumeAttachment"),
        "",
        &a.name,
        format!("{} pv={} node={} attached={}", a.attacher, a.pv, a.node, a.attached),
    )
}

// A node header points at the Node itself: `y` on it shows the node, which is where the attach
// limit and the volumes in use are published.
pub fn node_attach_record(n: &NodeAttachResource) -> EventRecord {
    record(
        format!("sto|{}", n.uid),
        &n.hints,
        "",
        if n.exists { ("v1", "Node") } else { ("", "") },
        "",
        &n.node,
        n.slots_label(),
    )
}

// The header of a group that stands for no object: snapshots without a known class, contents no
// snapshot references. No kind, so the generic gestures find nothing to act on.
pub fn header_record(uid: &str, label: &str, n: usize) -> EventRecord {
    EventRecord {
        uid: format!("sto|{}", uid),
        time: Timestamp::now(),
        severity: Severity::Normal,
        reason: String::new(),
        api_version: String::new(),
        kind: String::new(),
        namespace: String::new(),
        name: label.to_string(),
        message: n.to_string(),
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::FR;
    use k8s_openapi::api::storage::v1::{
        CSINodeDriver, CSINodeSpec, VolumeAttachmentSource, VolumeAttachmentSpec,
        VolumeAttachmentStatus, VolumeError, VolumeNodeResources,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    fn ago(secs: i64) -> Time {
        Time(Timestamp::from_second(Timestamp::now().as_second() - secs).unwrap())
    }

    fn va(name: &str, pv: &str, node: &str, attached: bool) -> VolumeAttachment {
        let mut v = VolumeAttachment::default();
        v.metadata.name = Some(name.into());
        v.metadata.creation_timestamp = Some(ago(86400 * 400));
        v.spec = VolumeAttachmentSpec {
            attacher: "disk.csi.azure.com".into(),
            node_name: node.into(),
            source: VolumeAttachmentSource {
                persistent_volume_name: Some(pv.into()),
                inline_volume_spec: None,
            },
        };
        v.status = Some(VolumeAttachmentStatus { attached, ..Default::default() });
        v
    }

    fn deleting(mut v: VolumeAttachment, detach_error: &str) -> VolumeAttachment {
        v.metadata.deletion_timestamp = Some(ago(86400 * 300));
        v.metadata.finalizers = Some(vec!["external-attacher/disk-csi-azure-com".into()]);
        if let Some(s) = v.status.as_mut() {
            s.detach_error = Some(VolumeError { message: Some(detach_error.into()), ..Default::default() });
        }
        v
    }

    fn snap(ns: &str, name: &str, data: Value) -> DynamicObject {
        let mut o = DynamicObject {
            types: None,
            metadata: Default::default(),
            data,
        };
        o.metadata.namespace = Some(ns.into()).filter(|s: &String| !s.is_empty());
        o.metadata.name = Some(name.into());
        o.metadata.creation_timestamp = Some(ago(3600));
        o
    }

    fn ctx<'a>(
        pvs: Option<&'a HashSet<String>>,
        pvcs: &'a HashSet<String>,
        scope: &'a NsScope,
    ) -> CsiContext<'a> {
        CsiContext { scope, pvs, pvcs }
    }

    #[test]
    fn a_deleting_attachment_whose_pv_is_gone_is_a_ghost() {
        let pvs: HashSet<String> = ["pvc-live".to_string()].into();
        let pvcs = HashSet::new();
        let ns = NsScope::All;
        let raw = CsiRaw {
            attachments: Some(vec![
                deleting(va("csi-1", "pvc-gone", "n1", true), "persistentvolume \"pvc-gone\" not found"),
                deleting(va("csi-2", "pvc-gone-2", "n1", false), "not found"),
                va("csi-3", "pvc-live", "n1", true),
            ]),
            nodes: Some(vec!["n1".into()]),
            ..Default::default()
        };
        let d = diagnose_csi(raw, &ctx(Some(&pvs), &pvcs, &ns), &FR);
        let by = |n: &str| d.attachments.iter().find(|a| a.name == n).unwrap();
        assert_eq!(by("csi-1").hints[0].level, HintLevel::Danger);
        assert!(by("csi-1").hints.iter().any(|h| h.text == FR.csi_va_ghost_attached));
        assert!(by("csi-2").hints.iter().any(|h| h.text == FR.csi_va_ghost_never));
        assert!(by("csi-3").hints.is_empty());
        assert!(d.cluster_hints.iter().any(|h| h.level == HintLevel::Danger));
    }

    #[test]
    fn an_unread_pv_list_accuses_no_attachment() {
        let pvcs = HashSet::new();
        let ns = NsScope::All;
        let raw = CsiRaw {
            attachments: Some(vec![deleting(va("csi-1", "pvc-x", "n1", true), "boom")]),
            ..Default::default()
        };
        let d = diagnose_csi(raw, &ctx(None, &pvcs, &ns), &FR);
        assert!(!d.attachments[0].hints.iter().any(|h| h.level == HintLevel::Danger));
        assert!(d.cluster_hints.is_empty());
    }

    #[test]
    fn attach_slots_are_counted_against_the_csinode_limit() {
        let pvs: HashSet<String> = (0..2).map(|i| format!("pv{i}")).collect();
        let pvcs = HashSet::new();
        let ns = NsScope::All;
        let mut node = CSINode::default();
        node.metadata.name = Some("n1".into());
        node.spec = CSINodeSpec {
            drivers: vec![CSINodeDriver {
                name: "disk.csi.azure.com".into(),
                node_id: "n1".into(),
                allocatable: Some(VolumeNodeResources { count: Some(2) }),
                topology_keys: None,
            }],
        };
        let raw = CsiRaw {
            attachments: Some(vec![va("a", "pv0", "n1", true), va("b", "pv1", "n1", true)]),
            csi_nodes: Some(vec![node]),
            nodes: Some(vec!["n1".into()]),
            ..Default::default()
        };
        let d = diagnose_csi(raw, &ctx(Some(&pvs), &pvcs, &ns), &FR);
        assert_eq!(d.nodes.len(), 1);
        assert_eq!(d.nodes[0].slots_label(), "disk.csi.azure.com 2/2");
        assert_eq!(d.nodes[0].hints[0].level, HintLevel::Danger);
    }

    #[test]
    fn a_retained_content_nobody_references_is_an_orphan_only_where_observable() {
        let pvcs = HashSet::new();
        let content = || {
            snap(
                "",
                "snapcontent-1",
                serde_json::json!({
                    "spec": {
                        "deletionPolicy": "Retain",
                        "driver": "disk.csi.azure.com",
                        "volumeSnapshotRef": { "namespace": "app", "name": "gone" },
                        "source": { "volumeHandle": "disk-1" }
                    },
                    "status": { "readyToUse": true, "snapshotHandle": "snap-1", "restoreSize": 1073741824 }
                }),
            )
        };
        let all = NsScope::All;
        let d = diagnose_csi(
            CsiRaw { contents: Some(vec![content()]), snapshots: Some(vec![]), ..Default::default() },
            &ctx(None, &pvcs, &all),
            &FR,
        );
        assert_eq!(d.contents[0].hints[0].level, HintLevel::Warn);
        assert_eq!(d.contents[0].restore_size, "1.0Gi");
        assert!(!d.cluster_hints.is_empty());

        let other = NsScope::one("elsewhere");
        let d = diagnose_csi(
            CsiRaw { contents: Some(vec![content()]), snapshots: Some(vec![]), ..Default::default() },
            &ctx(None, &pvcs, &other),
            &FR,
        );
        assert!(d.contents[0].hints.is_empty());
    }

    #[test]
    fn a_failed_snapshot_says_why_and_a_missing_content_is_not_restorable() {
        let pvcs: HashSet<String> = ["app/data".to_string()].into();
        let ns = NsScope::All;
        let failed = snap(
            "app",
            "s1",
            serde_json::json!({
                "spec": { "source": { "persistentVolumeClaimName": "data" }, "volumeSnapshotClassName": "csi" },
                "status": { "readyToUse": false, "error": { "message": "quota exceeded" } }
            }),
        );
        let dangling = snap(
            "app",
            "s2",
            serde_json::json!({
                "spec": { "source": { "persistentVolumeClaimName": "data" }, "volumeSnapshotClassName": "csi" },
                "status": { "readyToUse": true, "boundVolumeSnapshotContentName": "snapcontent-x" }
            }),
        );
        let class = snap("", "csi", serde_json::json!({ "driver": "disk.csi.azure.com", "deletionPolicy": "Delete" }));
        let raw = CsiRaw {
            snapshots: Some(vec![failed, dangling]),
            contents: Some(vec![]),
            snap_classes: Some(vec![class]),
            drivers: Some(vec!["disk.csi.azure.com".into()]),
            snapshots_installed: true,
            ..Default::default()
        };
        let d = diagnose_csi(raw, &ctx(None, &pvcs, &ns), &FR);
        assert_eq!(d.snapshots[0].phase, "Error");
        assert!(d.snapshots[0].hints[0].text.contains("quota exceeded"));
        assert_eq!(d.snapshots[1].phase, "Ready");
        assert_eq!(d.snapshots[1].hints[0].level, HintLevel::Danger);
        assert!(d.snap_classes[0].hints.is_empty());
    }
}
