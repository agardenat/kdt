//! Cluster-wide inventory of FluxCD resources (Kustomizations, HelmReleases, sources),
//! read dynamically so the tool works regardless of which Flux API versions are installed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;

// Annotation `flux reconcile` sets to request an immediate reconcile: changing its value is enough
// for the controller to re-run its loop instead of waiting for the next interval.
const RECONCILE_ANNOTATION: &str = "reconcile.fluxcd.io/requestedAt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxReady {
    Ready,
    // Actively reconciling (Ready not yet True but a reconcile is in progress) — not a failure.
    Reconciling,
    Failed,
    Unknown,
    // Static reference with no reconciliation, hence no Ready condition (e.g. an OCI HelmRepository):
    // neutral, neither healthy-green nor a problem.
    NotApplicable,
}

#[derive(Debug, Clone)]
pub struct FluxResource {
    pub kind: String,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub ready: FluxReady,
    pub suspended: bool,
    pub message: String,
    pub revision: String,
    pub age: String,
    // (kind, name, namespace) of the referenced source — used to build the tree view.
    pub source_ref: Option<(String, String, String)>,
    // (namespace, name) of each spec.dependsOn entry, for nesting dependent Kustomizations.
    pub depends_on: Vec<(String, String)>,
    // spec.prune for a Kustomization (None for other kinds). When false, objects removed from git
    // are not garbage-collected, so we surface it as a warning.
    pub prune: Option<bool>,
}

impl FluxResource {
    // Order failed first, then unknown, reconciling, suspended, ready — so problems surface at the top.
    fn sort_key(&self) -> (u8, &str, &str, &str) {
        let bucket = match (self.suspended, self.ready) {
            (false, FluxReady::Failed) => 0,
            (false, FluxReady::Unknown) => 1,
            (false, FluxReady::Reconciling) => 2,
            (true, _) => 3,
            (false, FluxReady::Ready) => 4,
            (false, FluxReady::NotApplicable) => 5,
        };
        (bucket, self.kind.as_str(), self.namespace.as_str(), self.name.as_str())
    }
}

#[derive(Default, Debug, Clone)]
pub struct FluxState {
    pub resources: Vec<FluxResource>,
    pub error: Option<String>,
    pub loading: bool,
}

impl FluxState {
    // (ready, failed, unknown, suspended, reconciling)
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut ready = 0;
        let mut failed = 0;
        let mut unknown = 0;
        let mut suspended = 0;
        let mut reconciling = 0;
        for r in &self.resources {
            if r.suspended {
                suspended += 1;
            }
            match r.ready {
                FluxReady::Ready => ready += 1,
                FluxReady::Reconciling => reconciling += 1,
                FluxReady::Failed => failed += 1,
                FluxReady::Unknown => unknown += 1,
                // Counted as ready: a static OCI reference is neutral, not a pending/unknown problem.
                FluxReady::NotApplicable => ready += 1,
            }
        }
        (ready, failed, unknown, suspended, reconciling)
    }
}

pub type SharedFlux = Arc<Mutex<FluxState>>;

// Source kinds that sit at the root of the dependency tree (everything else hangs off them).
const SOURCE_KINDS: &[&str] = &[
    "GitRepository",
    "OCIRepository",
    "HelmRepository",
    "HelmChart",
    "Bucket",
];

// A flattened tree row: which resource it is, its depth, and whether it has (collapsed) children.
#[derive(Debug, Clone)]
pub struct FlatTreeNode {
    pub idx: usize,
    pub depth: usize,
    pub has_children: bool,
    pub collapsed: bool,
}

// Stable identifier for a Flux resource, used to remember collapsed nodes across refreshes.
pub fn flux_tree_uid(r: &FluxResource) -> String {
    format!("{}|{}/{}", r.kind, r.namespace, r.name)
}

// Builds the dependency tree: sources are roots, workloads (Kustomization/HelmRelease) hang off the
// source they reference, and a workload that dependsOn another present Kustomization nests under it.
// Resources whose parent can't be resolved stay at the root. Returns the rows to display, honouring
// the `collapsed` set (a collapsed node's descendants are omitted).
pub fn build_flux_tree(resources: &[FluxResource], collapsed: &HashSet<String>) -> Vec<FlatTreeNode> {
    let key = |kind: &str, ns: &str, name: &str| format!("{}|{}/{}", kind, ns, name);
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for (i, r) in resources.iter().enumerate() {
        by_key.insert(key(&r.kind, &r.namespace, &r.name), i);
    }

    // Resolve each resource's parent index (None = root).
    let mut parent: Vec<Option<usize>> = vec![None; resources.len()];
    for (i, r) in resources.iter().enumerate() {
        if SOURCE_KINDS.contains(&r.kind.as_str()) {
            continue;
        }
        // Prefer nesting under a dependsOn Kustomization when present.
        let dep_parent = r.depends_on.iter().find_map(|(dns, dname)| {
            by_key.get(&key("Kustomization", dns, dname)).copied()
        });
        let src_parent = r.source_ref.as_ref().and_then(|(skind, sname, sns)| {
            by_key.get(&key(skind, sns, sname)).copied()
        });
        parent[i] = dep_parent.or(src_parent);
    }

    // Children adjacency, preserving the input ordering (already sorted problems-first).
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); resources.len()];
    let mut roots: Vec<usize> = Vec::new();
    for (i, p) in parent.iter().enumerate() {
        match p {
            Some(p) if *p != i => children[*p].push(i),
            _ => roots.push(i),
        }
    }

    let mut out = Vec::new();
    let mut visited = vec![false; resources.len()];
    for r in roots {
        push_subtree(r, 0, resources, &children, collapsed, &mut visited, &mut out);
    }
    out
}

fn push_subtree(
    idx: usize,
    depth: usize,
    resources: &[FluxResource],
    children: &[Vec<usize>],
    collapsed: &HashSet<String>,
    visited: &mut [bool],
    out: &mut Vec<FlatTreeNode>,
) {
    if visited[idx] {
        return;
    }
    visited[idx] = true;
    let has_children = !children[idx].is_empty();
    let is_collapsed = collapsed.contains(&flux_tree_uid(&resources[idx]));
    out.push(FlatTreeNode { idx, depth, has_children, collapsed: is_collapsed });
    if has_children && !is_collapsed {
        for &c in &children[idx] {
            push_subtree(c, depth + 1, resources, children, collapsed, visited, out);
        }
    }
}

pub fn new_flux_state() -> SharedFlux {
    Arc::new(Mutex::new(FluxState::default()))
}

// Last reconcile/suspend outcome (success or error), drained by the UI into a toast.
pub type SharedReconcile = Arc<Mutex<Option<(Instant, String)>>>;

pub fn new_reconcile_status() -> SharedReconcile {
    Arc::new(Mutex::new(None))
}

// Reconcile scope, from the most targeted to the widest.
#[derive(Debug, Clone, Copy)]
pub enum ReconcileScope {
    // Annotate only the selected resource.
    Resource,
    // Annotate the referenced source first, then the resource (equivalent to `--with-source`).
    WithSource,
    // Annotate the bootstrap `flux-system/flux-system` GitRepository.
    RootSync,
}

// (group, candidate versions newest-first, kind) probed via discovery until one resolves.
const CANDIDATES: &[(&str, &[&str], &str)] = &[
    ("kustomize.toolkit.fluxcd.io", &["v1", "v1beta2", "v1beta1"], "Kustomization"),
    ("helm.toolkit.fluxcd.io", &["v2", "v2beta2", "v2beta1"], "HelmRelease"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "GitRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "OCIRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "HelmRepository"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "HelmChart"),
    ("source.toolkit.fluxcd.io", &["v1", "v1beta2"], "Bucket"),
];

// List every Flux resource kind present on the cluster. `found_crd` distinguishes "Flux not
// installed" from "installed but empty/errored" for a clearer message in the UI.
pub async fn fetch_flux(client: Client, state: SharedFlux) {
    {
        let mut s = state.lock().expect("flux poisoned");
        s.loading = true;
        s.error = None;
    }

    let mut resources: Vec<FluxResource> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut found_crd = false;

    for (group, versions, kind) in CANDIDATES {
        let mut resolved = None;
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(&client, &gvk).await {
                resolved = Some((ar, *v));
                break;
            }
        }
        let Some((ar, version)) = resolved else { continue };
        found_crd = true;
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                let api_version = format!("{}/{}", group, version);
                for obj in &list.items {
                    resources.push(parse_flux(obj, kind, &api_version));
                }
            }
            Err(e) => errors.push(format!("{}: {}", kind, e)),
        }
    }

    resources.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("flux poisoned");
    s.loading = false;
    s.resources = resources;
    s.error = if !found_crd {
        Some("Flux CRDs introuvables (Flux n'est pas installé sur ce cluster ?)".into())
    } else if s.resources.is_empty() && !errors.is_empty() {
        Some(errors.join(" · "))
    } else {
        None
    };
}

fn parse_flux(obj: &DynamicObject, kind: &str, api_version: &str) -> FluxResource {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let suspended = obj
        .data
        .get("spec")
        .and_then(|s| s.get("suspend"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let status = obj.data.get("status");
    let conditions = status
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array());
    let ready_cond = conditions.and_then(|arr| {
        arr.iter()
            .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Ready"))
    });
    // Flux exposes a `Reconciling` condition (status True) while a reconcile is in flight; some
    // versions instead keep Ready=False/Unknown with a progressing reason. Either means "in progress",
    // which must not be shown as a failure.
    let reconciling_cond = conditions
        .map(|arr| {
            arr.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some("Reconciling")
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            })
        })
        .unwrap_or(false);

    let (ready, message) = match ready_cond {
        Some(c) => {
            let st = c.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let msg = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let in_progress = reconciling_cond || is_progressing_reason(reason);
            let r = match st {
                "True" => FluxReady::Ready,
                "False" if in_progress => FluxReady::Reconciling,
                "False" => FluxReady::Failed,
                _ if in_progress => FluxReady::Reconciling,
                _ => FluxReady::Unknown,
            };
            let combined = if r == FluxReady::Ready {
                collapse_ws(msg)
            } else {
                let mut m = String::new();
                if !reason.is_empty() {
                    m.push_str(reason);
                }
                if !msg.is_empty() {
                    if !m.is_empty() {
                        m.push_str(": ");
                    }
                    m.push_str(&collapse_ws(msg));
                }
                m
            };
            (r, combined)
        }
        None if reconciling_cond => (FluxReady::Reconciling, "Reconciling".to_string()),
        None => (FluxReady::Unknown, "(pas de condition Ready)".to_string()),
    };

    // An OCI HelmRepository is a static reference (no reconciliation, no Ready condition): surface it
    // as N/A instead of a misleading "Unknown".
    let (ready, message) = if ready == FluxReady::Unknown && is_oci_helm_repository(obj, kind) {
        (FluxReady::NotApplicable, "OCI (référence statique, pas de réconciliation)".to_string())
    } else {
        (ready, message)
    };

    let revision = flux_revision(status);
    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    let prune = if kind == "Kustomization" {
        Some(
            obj.data
                .get("spec")
                .and_then(|s| s.get("prune"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        )
    } else {
        None
    };
    let source_ref = source_ref(obj, &namespace);
    let depends_on = obj
        .data
        .get("spec")
        .and_then(|s| s.get("dependsOn"))
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    let name = d.get("name").and_then(|v| v.as_str())?.to_string();
                    let dns = d.get("namespace").and_then(|v| v.as_str()).unwrap_or(&namespace).to_string();
                    Some((dns, name))
                })
                .collect()
        })
        .unwrap_or_default();

    FluxResource {
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        namespace,
        name,
        ready,
        suspended,
        message,
        revision,
        age,
        source_ref,
        depends_on,
        prune,
    }
}

fn flux_revision(status: Option<&serde_json::Value>) -> String {
    let Some(status) = status else { return String::new() };
    let str_at = |path: &[&str]| -> Option<String> {
        let mut cur = status;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_str().map(|s| s.to_string())
    };
    let raw = str_at(&["lastAppliedRevision"])
        .or_else(|| str_at(&["lastAttemptedRevision"]))
        .or_else(|| str_at(&["artifact", "revision"]))
        .or_else(|| {
            status
                .get("history")
                .and_then(|h| h.as_array())
                .and_then(|a| a.first())
                .and_then(|h| h.get("chartVersion"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    shorten_revision(&raw)
}

// Collapse a Flux revision like "main@sha256:abcdef..." to "main@abcdef012345" for display.
fn shorten_revision(raw: &str) -> String {
    let (branch, digest) = match raw.split_once('@') {
        Some((b, d)) => (Some(b), d),
        None => (None, raw),
    };
    let short_digest = digest
        .rsplit_once(':')
        .map(|(_, h)| h)
        .unwrap_or(digest);
    let short_digest = if short_digest.len() > 12 {
        &short_digest[..12]
    } else {
        short_digest
    };
    match branch {
        Some(b) => format!("{}@{}", b, short_digest),
        None => short_digest.to_string(),
    }
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// Ready-condition reasons that mean "still working", not "failed". Covers the common Flux
// controllers (kustomize/helm/source) while a reconcile or dependency wait is in progress.
fn is_progressing_reason(reason: &str) -> bool {
    matches!(
        reason,
        "Progressing"
            | "ProgressingWithRetry"
            | "ReconciliationProgressing"
            | "Reconciling"
            | "DependencyNotReady"
            | "ArtifactUpToDate"
            | "Upgrading"
            | "Pending"
            | "Installing"
    )
}

// Group and versions of Flux sources (GitRepository, OCIRepository, etc.), resolved via discovery.
const SOURCE_GROUP: &str = "source.toolkit.fluxcd.io";
const SOURCE_VERSIONS: &[&str] = &["v1", "v1beta2"];

// Requests a reconcile for the chosen scope, then publishes the result into `status` for the UI.
// Any error is captured and formatted for display.
pub async fn reconcile(
    client: Client,
    scope: ReconcileScope,
    api_version: String,
    kind: String,
    ns: String,
    name: String,
    status: SharedReconcile,
) {
    let msg = match run_reconcile(&client, scope, &api_version, &kind, &ns, &name).await {
        Ok(m) => m,
        Err(e) => format!("✗ reconcile : {}", e),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((Instant::now(), msg));
    }
}

async fn run_reconcile(
    client: &Client,
    scope: ReconcileScope,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<String, String> {
    match scope {
        ReconcileScope::Resource => {
            let (group, version) = split_api_version(api_version)?;
            let obj = get_obj(client, group, &[version], kind, ns, name).await?;
            if is_suspended(&obj) {
                return Err(format!("{}/{} est suspendu", kind, name));
            }
            annotate_reconcile(client, group, &[version], kind, ns, name).await?;
            Ok(format!("✓ reconcile demandé : {}/{}", kind, name))
        }
        ReconcileScope::WithSource => {
            let (group, version) = split_api_version(api_version)?;
            let obj = get_obj(client, group, &[version], kind, ns, name).await?;
            if is_suspended(&obj) {
                return Err(format!("{}/{} est suspendu", kind, name));
            }
            // A source resource (GitRepository, OCIRepository…) has no sourceRef: just reconcile it.
            match source_ref(&obj, ns) {
                Some((skind, sname, sns)) => {
                    annotate_reconcile(client, SOURCE_GROUP, SOURCE_VERSIONS, &skind, &sns, &sname).await?;
                    annotate_reconcile(client, group, &[version], kind, ns, name).await?;
                    Ok(format!("✓ reconcile {}/{} + source {}/{}", kind, name, skind, sname))
                }
                None => {
                    annotate_reconcile(client, group, &[version], kind, ns, name).await?;
                    Ok(format!("✓ reconcile demandé : {}/{}", kind, name))
                }
            }
        }
        ReconcileScope::RootSync => {
            let obj = get_obj(client, SOURCE_GROUP, SOURCE_VERSIONS, "GitRepository", "flux-system", "flux-system")
                .await
                .map_err(|_| "GitRepository flux-system/flux-system introuvable".to_string())?;
            if is_suspended(&obj) {
                return Err("GitRepository flux-system est suspendue".to_string());
            }
            annotate_reconcile(client, SOURCE_GROUP, SOURCE_VERSIONS, "GitRepository", "flux-system", "flux-system").await?;
            Ok("✓ sync racine demandé : GitRepository/flux-system".to_string())
        }
    }
}

fn split_api_version(api_version: &str) -> Result<(&str, &str), String> {
    api_version
        .split_once('/')
        .ok_or_else(|| format!("apiVersion invalide : {}", api_version))
}

fn is_suspended(obj: &DynamicObject) -> bool {
    obj.data
        .get("spec")
        .and_then(|s| s.get("suspend"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// A HelmRepository with spec.type: oci is a static OCI reference: source-controller never reconciles
// it, so it exposes no Ready condition.
fn is_oci_helm_repository(obj: &DynamicObject, kind: &str) -> bool {
    kind == "HelmRepository"
        && obj
            .data
            .get("spec")
            .and_then(|s| s.get("type"))
            .and_then(|v| v.as_str())
            == Some("oci")
}

// Extracts the source of a Kustomization (spec.sourceRef) or a HelmRelease (spec.chartRef or
// spec.chart.spec.sourceRef). The namespace defaults to the calling resource's namespace.
fn source_ref(obj: &DynamicObject, default_ns: &str) -> Option<(String, String, String)> {
    let spec = obj.data.get("spec")?;
    let sref = spec
        .get("sourceRef")
        .or_else(|| spec.get("chartRef"))
        .or_else(|| {
            spec.get("chart")
                .and_then(|c| c.get("spec"))
                .and_then(|s| s.get("sourceRef"))
        })?;
    let kind = sref.get("kind").and_then(|v| v.as_str())?.to_string();
    let name = sref.get("name").and_then(|v| v.as_str())?.to_string();
    let ns = sref
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or(default_ns)
        .to_string();
    Some((kind, name, ns))
}

async fn get_obj(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<DynamicObject, String> {
    let ar = resolve_ar(client, group, versions, kind).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);
    api.get(name).await.map_err(|e| format!("{}/{} : {}", kind, name, e))
}

async fn annotate_reconcile(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<(), String> {
    let ar = resolve_ar(client, group, versions, kind).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);
    let now = chrono::Utc::now().to_rfc3339();
    let patch = serde_json::json!({
        "metadata": { "annotations": { RECONCILE_ANNOTATION: now } }
    });
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map(|_| ())
        .map_err(|e| format!("{}/{} : {}", kind, name, e))
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

// One object owned by a Kustomization (from status.inventory), with its live readiness.
#[derive(Debug, Clone)]
pub struct InventoryItem {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub ready: Option<bool>,
    // True when the object is actively reconciling/progressing (Ready not yet True but not a failure).
    pub reconciling: bool,
    pub msg: String,
}

#[derive(Default, Debug, Clone)]
pub struct InventoryState {
    pub current_key: Option<String>,
    pub items: Vec<InventoryItem>,
    pub error: Option<String>,
    pub loading: bool,
    // spec.prune of the inspected Kustomization, surfaced as a warning when false.
    pub prune: Option<bool>,
}

pub type SharedInventory = Arc<Mutex<InventoryState>>;

pub fn new_inventory_state() -> SharedInventory {
    Arc::new(Mutex::new(InventoryState::default()))
}

// Caps the number of inventory objects we fetch live status for, to bound API load on big apps.
const INVENTORY_MAX: usize = 100;

// Lists the objects a Kustomization applied (status.inventory.entries) and fetches each one's live
// readiness, so the user can follow a rollout. Only Kustomizations expose an inventory.
pub async fn fetch_inventory(
    client: Client,
    api_version: String,
    kind: String,
    ns: String,
    name: String,
    key: String,
    state: SharedInventory,
) {
    if kind != "Kustomization" {
        let mut s = state.lock().expect("inventory poisoned");
        if s.current_key.as_deref() != Some(&key) { return; }
        s.loading = false;
        s.items.clear();
        s.error = Some("inventaire : Kustomization uniquement".to_string());
        return;
    }

    let Ok((group, version)) = split_api_version(&api_version) else { return };
    let obj = match get_obj(&client, group, &[version], &kind, &ns, &name).await {
        Ok(o) => o,
        Err(e) => {
            let mut s = state.lock().expect("inventory poisoned");
            if s.current_key.as_deref() != Some(&key) { return; }
            s.loading = false;
            s.items.clear();
            s.error = Some(e);
            return;
        }
    };

    let prune = obj
        .data
        .get("spec")
        .and_then(|s| s.get("prune"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let entries: Vec<(String, String, String, String, String)> = obj
        .data
        .get("status")
        .and_then(|s| s.get("inventory"))
        .and_then(|i| i.get("entries"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let id = e.get("id").and_then(|v| v.as_str())?;
                    let v = e.get("v").and_then(|v| v.as_str()).unwrap_or("v1");
                    let parts: Vec<&str> = id.split('_').collect();
                    if parts.len() != 4 { return None; }
                    Some((
                        parts[0].to_string(),
                        parts[1].to_string(),
                        parts[2].to_string(),
                        parts[3].to_string(),
                        v.to_string(),
                    ))
                })
                .take(INVENTORY_MAX)
                .collect()
        })
        .unwrap_or_default();

    let futs = entries.into_iter().map(|(ens, ename, egroup, ekind, ever)| {
        let client = client.clone();
        async move { fetch_item_status(client, egroup, ever, ekind, ens, ename).await }
    });
    let mut items: Vec<InventoryItem> = futures::future::join_all(futs).await;
    // Surface problems first (failed, reconciling, unknown, ready), then by kind/name.
    items.sort_by(|a, b| {
        let rank = |it: &InventoryItem| match (it.ready, it.reconciling) {
            (Some(false), _) => 0,
            (_, true) => 1,
            (None, false) => 2,
            (Some(true), _) => 3,
        };
        rank(a)
            .cmp(&rank(b))
            .then(a.kind.cmp(&b.kind))
            .then(a.name.cmp(&b.name))
    });

    let mut s = state.lock().expect("inventory poisoned");
    if s.current_key.as_deref() != Some(&key) { return; }
    s.loading = false;
    s.items = items;
    s.prune = Some(prune);
    s.error = None;
}

async fn fetch_item_status(
    client: Client,
    group: String,
    version: String,
    kind: String,
    ns: String,
    name: String,
) -> InventoryItem {
    let api_version = if group.is_empty() { version.clone() } else { format!("{}/{}", group, version) };
    let mut item = InventoryItem {
        api_version,
        kind: kind.clone(),
        namespace: ns.clone(),
        name: name.clone(),
        ready: None,
        reconciling: false,
        msg: String::new(),
    };
    let gvk = GroupVersionKind::gvk(&group, &version, &kind);
    let Ok((ar, _caps)) = discovery::pinned_kind(&client, &gvk).await else {
        item.msg = "type inconnu".to_string();
        return item;
    };
    let api: Api<DynamicObject> = if ns.is_empty() {
        Api::all_with(client.clone(), &ar)
    } else {
        Api::namespaced_with(client.clone(), &ns, &ar)
    };
    match api.get(&name).await {
        Ok(o) => {
            let (ready, reconciling, msg) = object_readiness(&o, &kind);
            item.ready = ready;
            item.reconciling = reconciling;
            item.msg = msg;
        }
        Err(_) => {
            item.ready = Some(false);
            item.msg = "introuvable".to_string();
        }
    }
    item
}

// Best-effort readiness for an arbitrary object: (ready, reconciling, message). A Ready condition is
// used when present (Ready=False with a progressing reason, or a Reconciling=True condition, means
// "in progress", not failed); otherwise workload replica counters; otherwise unknown.
fn object_readiness(obj: &DynamicObject, kind: &str) -> (Option<bool>, bool, String) {
    let status = obj.data.get("status");
    let conditions = status.and_then(|s| s.get("conditions")).and_then(|c| c.as_array());
    let reconciling_cond = conditions
        .map(|arr| {
            arr.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some("Reconciling")
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            })
        })
        .unwrap_or(false);
    if let Some(cond) = conditions
        .and_then(|arr| arr.iter().find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Ready")))
    {
        let st = cond.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let reason = cond.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        let msg = cond.get("message").and_then(|v| v.as_str()).unwrap_or("");
        let in_progress = reconciling_cond || is_progressing_reason(reason);
        return match st {
            "True" => (Some(true), false, collapse_ws(msg)),
            "False" if in_progress => (None, true, collapse_ws(msg)),
            "False" => (Some(false), false, collapse_ws(msg)),
            _ if in_progress => (None, true, collapse_ws(msg)),
            _ => (None, false, collapse_ws(msg)),
        };
    }
    let i64_at = |s: Option<&serde_json::Value>, k: &str| {
        s.and_then(|s| s.get(k)).and_then(|v| v.as_i64()).unwrap_or(0)
    };
    match kind {
        "Deployment" | "StatefulSet" | "ReplicaSet" => {
            let want = obj.data.get("spec").and_then(|s| s.get("replicas")).and_then(|v| v.as_i64()).unwrap_or(1);
            let ready = i64_at(status, "readyReplicas");
            let ok = ready >= want && want > 0 || (want == 0);
            (Some(ok), !ok && want > 0, format!("{}/{} ready", ready, want))
        }
        "DaemonSet" => {
            let want = i64_at(status, "desiredNumberScheduled");
            let ready = i64_at(status, "numberReady");
            let ok = want > 0 && ready >= want;
            (Some(ok), !ok && want > 0, format!("{}/{} ready", ready, want))
        }
        "Pod" => match status.and_then(|s| s.get("phase")).and_then(|v| v.as_str()) {
            Some("Running") | Some("Succeeded") => (Some(true), false, String::new()),
            Some("Failed") => (Some(false), false, "Failed".to_string()),
            Some("Pending") => (None, true, "Pending".to_string()),
            Some(p) => (None, false, p.to_string()),
            None => (None, false, String::new()),
        },
        "Job" => {
            let has = |t: &str| conditions.map(|a| a.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some(t)
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            })).unwrap_or(false);
            if has("Failed") {
                (Some(false), false, "Failed".to_string())
            } else if has("Complete") {
                (Some(true), false, "Complete".to_string())
            } else {
                (None, true, "Running".to_string())
            }
        }
        "PersistentVolumeClaim" => match status.and_then(|s| s.get("phase")).and_then(|v| v.as_str()) {
            Some("Bound") => (Some(true), false, "Bound".to_string()),
            Some("Pending") => (None, true, "Pending".to_string()),
            Some(p) => (Some(false), false, p.to_string()),
            None => (Some(true), false, String::new()),
        },
        "Namespace" => match status.and_then(|s| s.get("phase")).and_then(|v| v.as_str()) {
            Some("Active") | None => (Some(true), false, String::new()),
            Some(p) => (Some(false), false, p.to_string()),
        },
        "CustomResourceDefinition" => {
            let established = conditions.map(|a| a.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some("Established")
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            })).unwrap_or(true);
            (Some(established), false, String::new())
        }
        // Resources with no readiness concept (Service, ServiceAccount, NetworkPolicy, ResourceQuota,
        // ConfigMap, Secret…): a successful GET means they exist, so treat them as applied/healthy.
        _ => (Some(true), false, String::new()),
    }
}

// Every Flux controller deployment name in flux-system, used to aggregate logs (global view).
pub const ALL_CONTROLLERS: &[&str] = &[
    "source-controller",
    "kustomize-controller",
    "helm-controller",
    "notification-controller",
    "image-reflector-controller",
    "image-automation-controller",
];

// Maps a Flux resource kind to the controller that reconciles it, so we can show its logs.
pub fn controller_for_kind(kind: &str) -> &'static str {
    match kind {
        "Kustomization" => "kustomize-controller",
        "HelmRelease" => "helm-controller",
        "Receiver" | "Alert" | "Provider" => "notification-controller",
        "ImageRepository" | "ImagePolicy" => "image-reflector-controller",
        "ImageUpdateAutomation" => "image-automation-controller",
        _ => "source-controller",
    }
}

// Toggles `spec.suspend` on the selected resource. Suspending only pauses reconciliation (it never
// deletes anything); resuming re-enables it. Works for any suspendable Flux kind.
pub async fn set_suspend(
    client: Client,
    api_version: String,
    kind: String,
    ns: String,
    name: String,
    suspend: bool,
    status: SharedReconcile,
) {
    let msg = match run_set_suspend(&client, &api_version, &kind, &ns, &name, suspend).await {
        Ok(()) if suspend => format!("⏸ suspendu : {}/{}", kind, name),
        Ok(()) => format!("▶ repris : {}/{}", kind, name),
        Err(e) => format!("✗ suspend : {}", e),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((Instant::now(), msg));
    }
}

async fn run_set_suspend(
    client: &Client,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
    suspend: bool,
) -> Result<(), String> {
    let (group, version) = split_api_version(api_version)?;
    let ar = resolve_ar(client, group, &[version], kind).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);
    let patch = serde_json::json!({ "spec": { "suspend": suspend } });
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map(|_| ())
        .map_err(|e| format!("{}/{} : {}", kind, name, e))
}
