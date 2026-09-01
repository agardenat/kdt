//! Cluster-wide inventory of FluxCD resources (Kustomizations, HelmReleases, sources),
//! read dynamically so the tool works regardless of which Flux API versions are installed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::lang::{Strings, fill};
use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;

// Annotation `flux reconcile` sets to request an immediate reconcile: changing its value is enough
// for the controller to re-run its loop instead of waiting for the next interval.
const RECONCILE_ANNOTATION: &str = "reconcile.fluxcd.io/requestedAt";
// Paired with the one above (same value, same patch) to widen what the reconcile is allowed to do:
// `forceAt` makes helm-controller run the upgrade even with an unchanged chart, `resetAt` wipes the
// failure counters that put a release in "retries exhausted". Both are HelmRelease-side levers.
const FORCE_ANNOTATION: &str = "reconcile.fluxcd.io/forceAt";
const RESET_ANNOTATION: &str = "reconcile.fluxcd.io/resetAt";

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
    // are not garbage-collected, so the row is badged.
    pub prune: Option<bool>,
    // (namespace, name) of the HelmChart the helm-controller generated for a HelmRelease, read from
    // status.helmChart. The chart is what the release actually pulls from, so it is the real edge
    // between a HelmRelease and its repository — and its namespace is the source's, not the
    // release's, which is why it is read rather than derived from the name.
    pub helm_chart: Option<(String, String)>,
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

// A flattened tree row: which resource it is, its depth, and whether it has (collapsed) children.
#[derive(Debug, Clone)]
pub struct FlatTreeNode {
    pub idx: usize,
    pub depth: usize,
    pub has_children: bool,
    pub collapsed: bool,
    // How many failing / reconciling resources the fold is hiding (0/0 when the node is expanded).
    // A folded branch that says nothing about what it contains is exactly what forces a hunt through
    // the tree to find out where the error is.
    pub hidden_failed: usize,
    pub hidden_reconciling: usize,
}

// Stable identifier for a Flux resource, used to remember collapsed nodes across refreshes.
pub fn flux_tree_uid(r: &FluxResource) -> String {
    format!("{}|{}/{}", r.kind, r.namespace, r.name)
}

// Resolves each resource's parent index in the dependency tree (None = a root).
//
// The edges, in the order they are preferred:
//   * `dependsOn` — always references the referring object's own kind (a Kustomization waits on
//     Kustomizations, a HelmRelease on HelmReleases), hence the lookup keyed on `r.kind`;
//   * `status.helmChart` — the HelmChart the helm-controller generated for a HelmRelease. This is
//     the edge that puts the Helm trio in the same tree as everything else: HelmRepository →
//     HelmChart → HelmRelease. Taking `spec.chart.spec.sourceRef` instead would hang the release
//     straight off the repository and leave every generated chart floating at the root;
//   * `spec.sourceRef` / `spec.chartRef` — the source a Kustomization, a HelmRelease using
//     `chartRef`, or a HelmChart reads from.
//
// Sources are not skipped: a HelmChart is a source *and* has a source of its own, and the other
// source kinds simply have no reference to resolve, so they stay roots on their own.
fn resolve_parents(resources: &[FluxResource]) -> Vec<Option<usize>> {
    let key = |kind: &str, ns: &str, name: &str| format!("{}|{}/{}", kind, ns, name);
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for (i, r) in resources.iter().enumerate() {
        by_key.insert(key(&r.kind, &r.namespace, &r.name), i);
    }

    let mut parent: Vec<Option<usize>> = vec![None; resources.len()];
    for (i, r) in resources.iter().enumerate() {
        let dep_parent = r
            .depends_on
            .iter()
            .find_map(|(dns, dname)| by_key.get(&key(&r.kind, dns, dname)).copied());
        let chart_parent = r
            .helm_chart
            .as_ref()
            .and_then(|(cns, cname)| by_key.get(&key("HelmChart", cns, cname)).copied());
        let src_parent = r.source_ref.as_ref().and_then(|(skind, sname, sns)| {
            by_key.get(&key(skind, sns, sname)).copied()
        });
        parent[i] = dep_parent.or(chart_parent).or(src_parent);
    }
    parent
}

// Every ancestor of a resource that is failing or reconciling, as tree uids. Folding those away is
// what buries an error deep in the tree, so the view unfolds exactly this set while the trouble
// lasts and lets it close again once the resource goes back to Ready.
pub fn problem_ancestors(resources: &[FluxResource]) -> HashSet<String> {
    let parent = resolve_parents(resources);
    let mut out = HashSet::new();
    for (i, r) in resources.iter().enumerate() {
        if r.suspended || !matches!(r.ready, FluxReady::Failed | FluxReady::Reconciling) {
            continue;
        }
        walk_up(&parent, resources, i, &mut out);
    }
    out
}

// The ancestors of one resource, named by its tree uid. The row under the cursor gets the same
// treatment as a problem: a branch folding back on its own must never take the selected row with
// it, or the reconcile the user is watching ends with the cursor thrown back to the top of the tree.
pub fn ancestors_of(resources: &[FluxResource], uid: &str) -> HashSet<String> {
    let parent = resolve_parents(resources);
    let mut out = HashSet::new();
    if let Some(i) = resources.iter().position(|r| flux_tree_uid(r) == uid) {
        walk_up(&parent, resources, i, &mut out);
    }
    out
}

// Records every ancestor of `idx`. Walking up stops at an ancestor already recorded: its own chain
// is recorded too. That also terminates a dependency cycle, whose members are all each other's
// ancestors.
fn walk_up(
    parent: &[Option<usize>],
    resources: &[FluxResource],
    idx: usize,
    out: &mut HashSet<String>,
) {
    let mut cur = parent[idx];
    while let Some(p) = cur {
        if !out.insert(flux_tree_uid(&resources[p])) {
            break;
        }
        cur = parent[p];
    }
}

// Builds the dependency tree from the edges `resolve_parents` draws: repositories are roots,
// everything that references one hangs off it, and a resource whose parent can't be resolved stays
// at the root. Returns the rows to display, honouring the `collapsed` set (a collapsed node's
// descendants are omitted, and the row carries a tally of the problems they hide).
pub fn build_flux_tree(resources: &[FluxResource], collapsed: &HashSet<String>) -> Vec<FlatTreeNode> {
    let parent = resolve_parents(resources);

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
    // A dependency cycle (A dependsOn B, B dependsOn A) gives every member a parent, so none of them
    // lands in `roots` and the loop above never reaches them. Left there, the resources would simply
    // vanish from the tree — a view that silently omits rows is worse than one that misplaces them.
    // Promote whatever is still unvisited to a root, in index order so the problems-first sort holds.
    for i in 0..resources.len() {
        if !visited[i] {
            push_subtree(i, 0, resources, &children, collapsed, &mut visited, &mut out);
        }
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
    let row = out.len();
    out.push(FlatTreeNode {
        idx,
        depth,
        has_children,
        collapsed: is_collapsed,
        hidden_failed: 0,
        hidden_reconciling: 0,
    });
    if has_children {
        if is_collapsed {
            // Folded away, but still *reached*: the descendants must be marked visited all the same,
            // or the unreachable-node pass below would take them for orphans and promote them back
            // to the root — quietly undoing the fold the user just asked for.
            let mut hidden = (0usize, 0usize);
            for &c in &children[idx] {
                mark_subtree(c, resources, children, visited, &mut hidden);
            }
            out[row].hidden_failed = hidden.0;
            out[row].hidden_reconciling = hidden.1;
        } else {
            for &c in &children[idx] {
                push_subtree(c, depth + 1, resources, children, collapsed, visited, out);
            }
        }
    }
}

// Marks a subtree as reached without emitting any row, tallying the failing and reconciling
// resources it hides on the way. The `visited` guard doubles as the cycle guard, so a loop among the
// hidden descendants terminates here too.
fn mark_subtree(
    idx: usize,
    resources: &[FluxResource],
    children: &[Vec<usize>],
    visited: &mut [bool],
    hidden: &mut (usize, usize),
) {
    if visited[idx] {
        return;
    }
    visited[idx] = true;
    let r = &resources[idx];
    if !r.suspended {
        match r.ready {
            FluxReady::Failed => hidden.0 += 1,
            FluxReady::Reconciling => hidden.1 += 1,
            _ => {}
        }
    }
    for &c in &children[idx] {
        mark_subtree(c, resources, children, visited, hidden);
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileScope {
    // Annotate only the selected resource.
    Resource,
    // Annotate the referenced source first, then the resource (equivalent to `--with-source`).
    WithSource,
    // Annotate the bootstrap `flux-system/flux-system` GitRepository.
    RootSync,
    // Force a Helm upgrade even when the chart and values are unchanged. The way out of a release
    // the controller keeps skipping because it sees nothing to do, while the cluster disagrees.
    Force,
    // Clear the failure counters so the controller retries an install/upgrade it has given up on
    // ("retries exhausted"). Changes no desired state — only the controller's memory of failing.
    Reset,
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
    let st = crate::lang::active();
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
                    resources.push(parse_flux(obj, kind, &api_version, st));
                }
            }
            Err(e) => errors.push(format!("{}: {}", kind, e)),
        }
    }

    resources.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("flux poisoned");
    s.loading = false;
    s.resources = resources;
    // A kind that failed to list is reported even when the others succeeded: the view is then missing
    // rows (an RBAC-denied kind is the common case), and a silently incomplete inventory is exactly
    // what makes someone conclude a resource does not exist when it merely could not be read.
    s.error = if !found_crd {
        Some(st.flux_crds_missing.to_string())
    } else if !errors.is_empty() {
        Some(errors.join(" · "))
    } else {
        None
    };
}

fn parse_flux(
    obj: &DynamicObject,
    kind: &str,
    api_version: &str,
    st: &'static Strings,
) -> FluxResource {
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
        None => (FluxReady::Unknown, st.flux_no_ready_condition.to_string()),
    };

    // An OCI HelmRepository is a static reference (no reconciliation, no Ready condition): surface it
    // as N/A instead of a misleading "Unknown".
    let (ready, message) = if ready == FluxReady::Unknown && is_oci_helm_repository(obj, kind) {
        (FluxReady::NotApplicable, st.flux_oci_static.to_string())
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
    // status.helmChart is "<namespace>/<name>" and is the controller's own record of the chart it
    // generated — the namespace is the source's, so nothing here is derived from the release's name.
    let helm_chart = status
        .and_then(|s| s.get("helmChart"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.split_once('/'))
        .map(|(ns, name)| (ns.to_string(), name.to_string()));
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
        helm_chart,
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
    let st = crate::lang::active();
    let msg = match run_reconcile(&client, scope, &api_version, &kind, &ns, &name, st).await {
        Ok(m) => m,
        Err(e) => fill(st.flux_reconcile_failed, &[("e", &e)]),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((Instant::now(), msg));
    }
}

// Same request as [`reconcile`], but returning the outcome instead of posting it to a toast — the
// repair panel reports inside itself and needs to know whether the move actually landed.
pub async fn reconcile_once(
    client: &Client,
    scope: ReconcileScope,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<String, String> {
    run_reconcile(client, scope, api_version, kind, ns, name, crate::lang::active()).await
}

// Suspend then immediately resume: the older way of making a controller drop the state it has got
// stuck in, for the versions that do not honour `resetAt`. The resume is attempted even when the
// suspend failed — leaving an object suspended because a repair gave up halfway is a worse outcome
// than the blockage it was trying to clear.
pub async fn suspend_cycle(
    client: &Client,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<String, String> {
    let st = crate::lang::active();
    let suspended = run_set_suspend(client, api_version, kind, ns, name, true).await;
    let resumed = run_set_suspend(client, api_version, kind, ns, name, false).await;
    match (suspended, resumed) {
        (Ok(()), Ok(())) => Ok(fill(st.flux_cycle_ok, &[("kind", kind), ("name", name)])),
        (_, Err(e)) => Err(fill(
            st.flux_resume_failed,
            &[("kind", kind), ("name", name), ("e", &e)],
        )),
        (Err(e), Ok(())) => Err(fill(st.flux_suspend_failed, &[("e", &e)])),
    }
}

async fn run_reconcile(
    client: &Client,
    scope: ReconcileScope,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
    st: &'static Strings,
) -> Result<String, String> {
    match scope {
        ReconcileScope::Resource => {
            let (group, version) = split_api_version(api_version)?;
            let obj = get_obj(client, group, &[version], kind, ns, name).await?;
            if is_suspended(&obj) {
                return Err(fill(st.flux_suspended, &[("kind", kind), ("name", name)]));
            }
            annotate_reconcile(client, group, &[version], kind, ns, name).await?;
            Ok(fill(st.flux_reconcile_ok, &[("kind", kind), ("name", name)]))
        }
        ReconcileScope::WithSource => {
            let (group, version) = split_api_version(api_version)?;
            let obj = get_obj(client, group, &[version], kind, ns, name).await?;
            if is_suspended(&obj) {
                return Err(fill(st.flux_suspended, &[("kind", kind), ("name", name)]));
            }
            // A source resource (GitRepository, OCIRepository…) has no sourceRef: just reconcile it.
            match source_ref(&obj, ns) {
                Some((skind, sname, sns)) => {
                    // The source is checked too: annotating a suspended source looks like it worked
                    // while the artifact stays stale, and the resource then reconciles against the
                    // old revision — the confusing half-success this refusal exists to prevent.
                    let src = get_obj(client, SOURCE_GROUP, SOURCE_VERSIONS, &skind, &sns, &sname).await?;
                    if is_suspended(&src) {
                        return Err(fill(
                            st.flux_source_suspended,
                            &[("kind", &skind), ("name", &sname)],
                        ));
                    }
                    annotate_reconcile(client, SOURCE_GROUP, SOURCE_VERSIONS, &skind, &sns, &sname).await?;
                    annotate_reconcile(client, group, &[version], kind, ns, name).await?;
                    Ok(fill(
                        st.flux_reconcile_with_source,
                        &[
                            ("kind", kind),
                            ("name", name),
                            ("skind", &skind),
                            ("sname", &sname),
                        ],
                    ))
                }
                None => {
                    annotate_reconcile(client, group, &[version], kind, ns, name).await?;
                    Ok(fill(st.flux_reconcile_ok, &[("kind", kind), ("name", name)]))
                }
            }
        }
        ReconcileScope::RootSync => {
            let obj = get_obj(client, SOURCE_GROUP, SOURCE_VERSIONS, "GitRepository", "flux-system", "flux-system")
                .await
                .map_err(|_| st.flux_root_missing.to_string())?;
            if is_suspended(&obj) {
                return Err(st.flux_root_suspended.to_string());
            }
            annotate_reconcile(client, SOURCE_GROUP, SOURCE_VERSIONS, "GitRepository", "flux-system", "flux-system").await?;
            Ok(st.flux_root_sync_ok.to_string())
        }
        // Force and Reset only mean something to helm-controller. Refusing elsewhere rather than
        // writing an annotation nobody reads keeps the toast honest: a "✓" has to mean the
        // controller was actually asked something, not that a patch happened to succeed.
        ReconcileScope::Force | ReconcileScope::Reset => {
            if kind != "HelmRelease" {
                return Err(fill(st.flux_helmrelease_only, &[("kind", kind)]));
            }
            let (group, version) = split_api_version(api_version)?;
            let obj = get_obj(client, group, &[version], kind, ns, name).await?;
            if is_suspended(&obj) {
                return Err(fill(st.flux_suspended, &[("kind", kind), ("name", name)]));
            }
            let (extra, label) = match scope {
                ReconcileScope::Force => (FORCE_ANNOTATION, st.flux_force_label),
                _ => (RESET_ANNOTATION, st.flux_reset_label),
            };
            annotate_reconcile_with(client, group, &[version], kind, ns, name, &[extra]).await?;
            Ok(fill(
                st.flux_action_ok,
                &[("action", label), ("kind", kind), ("name", name)],
            ))
        }
    }
}

fn split_api_version(api_version: &str) -> Result<(&str, &str), String> {
    api_version
        .split_once('/')
        .ok_or_else(|| {
            fill(
                crate::lang::active().flux_bad_api_version,
                &[("v", api_version)],
            )
        })
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
    annotate_reconcile_with(client, group, versions, kind, ns, name, &[]).await
}

// Requests a reconcile, optionally carrying the extra annotations that turn it into a force or a
// reset. The controllers only honour those when their value *equals* the one on `requestedAt`, so
// every key here is stamped with the same timestamp in a single patch — writing them in separate
// calls would produce two different clock readings and the extra annotation would be ignored.
async fn annotate_reconcile_with(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
    ns: &str,
    name: &str,
    extra: &[&str],
) -> Result<(), String> {
    let ar = resolve_ar(client, group, versions, kind).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);
    let now = chrono::Utc::now().to_rfc3339();
    let mut annotations = serde_json::Map::new();
    annotations.insert(
        RECONCILE_ANNOTATION.to_string(),
        serde_json::Value::String(now.clone()),
    );
    for key in extra {
        annotations.insert((*key).to_string(), serde_json::Value::String(now.clone()));
    }
    let patch = serde_json::json!({ "metadata": { "annotations": annotations } });
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
    Err(fill(crate::lang::active().flux_kind_not_found, &[("kind", kind)]))
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
    // spec.prune of the inspected Kustomization, badged in the message column when false.
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
            item.msg = crate::lang::active().flux_item_not_found.to_string();
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

// Writes `spec.suspend`. Suspending only pauses reconciliation (it never deletes anything);
// resuming re-enables it. Works for any suspendable Flux kind. Callers go through
// [`toggle_suspend`], which decides the direction from the live object, or [`suspend_cycle`].

// Flips `spec.suspend` to the opposite of what the *cluster* currently holds. The caller cannot
// decide the direction from the list snapshot: that snapshot is up to a refresh interval old, and
// acting on a stale reading inverts the intent — pressing the key to resume something suspends it
// again. So the live object is read first, inside the same task that patches it.
pub async fn toggle_suspend(
    client: Client,
    api_version: String,
    kind: String,
    ns: String,
    name: String,
    status: SharedReconcile,
) {
    let st = crate::lang::active();
    let msg = match run_toggle_suspend(&client, &api_version, &kind, &ns, &name).await {
        Ok(true) => fill(st.flux_suspended_ok, &[("kind", &kind), ("name", &name)]),
        Ok(false) => fill(st.flux_resumed_ok, &[("kind", &kind), ("name", &name)]),
        Err(e) => fill(st.flux_toggle_failed, &[("e", &e)]),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((Instant::now(), msg));
    }
}

// Returns the value that was written, so the toast reports what actually happened.
async fn run_toggle_suspend(
    client: &Client,
    api_version: &str,
    kind: &str,
    ns: &str,
    name: &str,
) -> Result<bool, String> {
    let (group, version) = split_api_version(api_version)?;
    let obj = get_obj(client, group, &[version], kind, ns, name).await?;
    let target = !is_suspended(&obj);
    run_set_suspend(client, api_version, kind, ns, name, target).await?;
    Ok(target)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn res(kind: &str, name: &str) -> FluxResource {
        FluxResource {
            kind: kind.to_string(),
            api_version: String::new(),
            namespace: "default".to_string(),
            name: name.to_string(),
            ready: FluxReady::Ready,
            suspended: false,
            message: String::new(),
            revision: String::new(),
            age: String::new(),
            source_ref: None,
            depends_on: Vec::new(),
            prune: None,
            helm_chart: None,
        }
    }

    fn depends(mut r: FluxResource, on: &str) -> FluxResource {
        r.depends_on.push(("default".to_string(), on.to_string()));
        r
    }

    fn names(rows: &[FlatTreeNode], resources: &[FluxResource]) -> Vec<String> {
        rows.iter().map(|n| resources[n.idx].name.clone()).collect()
    }

    #[test]
    fn a_dependency_cycle_still_shows_every_resource() {
        // A and B wait on each other: neither has a resolvable root, and before the promotion pass
        // both simply disappeared from the tree instead of merely being misplaced.
        let resources = vec![
            depends(res("Kustomization", "a"), "b"),
            depends(res("Kustomization", "b"), "a"),
        ];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert_eq!(names(&rows, &resources), vec!["a", "b"]);
    }

    #[test]
    fn a_cycle_hanging_off_a_source_keeps_the_unreachable_members() {
        // The source is a root, so `a` is reachable; `b` and `c` only reference each other.
        let mut a = res("Kustomization", "a");
        a.source_ref = Some(("GitRepository".to_string(), "repo".to_string(), "default".to_string()));
        let resources = vec![
            res("GitRepository", "repo"),
            a,
            depends(res("Kustomization", "b"), "c"),
            depends(res("Kustomization", "c"), "b"),
        ];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert_eq!(names(&rows, &resources), vec!["repo", "a", "b", "c"]);
        assert_eq!(rows[1].depth, 1, "a nests under its source");
        assert_eq!(rows[2].depth, 0, "a cycle member is promoted to a root");
    }

    #[test]
    fn a_helmrelease_nests_under_the_helmrelease_it_depends_on() {
        // `dependsOn` references the referring object's own kind: resolving it against Kustomization
        // alone lost every HelmRelease-to-HelmRelease edge.
        let resources = vec![
            res("HelmRelease", "base"),
            depends(res("HelmRelease", "app"), "base"),
        ];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert_eq!(names(&rows, &resources), vec!["base", "app"]);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1);
        assert!(rows[0].has_children);
    }

    #[test]
    fn a_kustomization_does_not_adopt_a_helmrelease_of_the_same_name() {
        // Same name, different kind: the edge must not be drawn.
        let resources = vec![
            res("Kustomization", "infra"),
            depends(res("HelmRelease", "app"), "infra"),
        ];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert!(rows.iter().all(|n| n.depth == 0), "no cross-kind dependsOn edge");
    }

    fn from_source(mut r: FluxResource, kind: &str, name: &str) -> FluxResource {
        r.source_ref = Some((kind.to_string(), name.to_string(), "default".to_string()));
        r
    }

    #[test]
    fn the_helm_trio_nests_repository_chart_release() {
        // The generated HelmChart used to float at the root next to its repository, and the release
        // hung straight off the repository — the three halves of one deployment, side by side.
        let repo = res("HelmRepository", "charts");
        let chart = from_source(res("HelmChart", "default-app"), "HelmRepository", "charts");
        let mut rel = from_source(res("HelmRelease", "app"), "HelmRepository", "charts");
        rel.helm_chart = Some(("default".to_string(), "default-app".to_string()));
        let resources = vec![repo, chart, rel];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert_eq!(names(&rows, &resources), vec!["charts", "default-app", "app"]);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1, "the chart nests under its repository");
        assert_eq!(rows[2].depth, 2, "the release nests under its chart");
    }

    #[test]
    fn a_release_without_a_generated_chart_falls_back_to_its_source() {
        // spec.chartRef (Flux 2.3+) generates no HelmChart: the release references the OCIRepository
        // directly and must still find its place under it.
        let resources = vec![
            res("OCIRepository", "oci"),
            from_source(res("HelmRelease", "app"), "OCIRepository", "oci"),
        ];
        let rows = build_flux_tree(&resources, &HashSet::new());
        assert_eq!(names(&rows, &resources), vec!["oci", "app"]);
        assert_eq!(rows[1].depth, 1);
    }

    #[test]
    fn a_fold_counts_the_problems_it_hides() {
        let mut child = depends(res("Kustomization", "app"), "infra");
        child.ready = FluxReady::Failed;
        let mut grandchild = depends(res("Kustomization", "leaf"), "app");
        grandchild.ready = FluxReady::Reconciling;
        let resources = vec![res("Kustomization", "infra"), child, grandchild];
        let mut collapsed = HashSet::new();
        collapsed.insert(flux_tree_uid(&resources[0]));
        let rows = build_flux_tree(&resources, &collapsed);
        assert_eq!(names(&rows, &resources), vec!["infra"]);
        assert_eq!(rows[0].hidden_failed, 1);
        assert_eq!(rows[0].hidden_reconciling, 1);
    }

    #[test]
    fn the_ancestors_of_a_problem_are_the_ones_to_unfold() {
        let mut leaf = depends(res("Kustomization", "leaf"), "app");
        leaf.ready = FluxReady::Failed;
        let resources = vec![
            res("Kustomization", "infra"),
            depends(res("Kustomization", "app"), "infra"),
            leaf,
        ];
        let reveal = problem_ancestors(&resources);
        assert!(reveal.contains(&flux_tree_uid(&resources[0])));
        assert!(reveal.contains(&flux_tree_uid(&resources[1])));
        // The failing node is not its own ancestor: it stays folded if it was folded by hand.
        assert!(!reveal.contains(&flux_tree_uid(&resources[2])));
    }

    #[test]
    fn the_selected_row_keeps_its_branch_open() {
        // Nothing is failing here: the reveal comes from the cursor alone, so the branch the user is
        // reading does not fold shut under them when the reconcile it was showing finishes.
        let resources = vec![
            res("Kustomization", "infra"),
            depends(res("Kustomization", "app"), "infra"),
        ];
        let reveal = ancestors_of(&resources, &flux_tree_uid(&resources[1]));
        assert_eq!(reveal.len(), 1);
        assert!(reveal.contains(&flux_tree_uid(&resources[0])));
        // A uid nobody carries reveals nothing rather than panicking.
        assert!(ancestors_of(&resources, "Kustomization|nowhere/gone").is_empty());
    }

    #[test]
    fn a_suspended_failure_unfolds_nothing() {
        // Suspended is a deliberate state, not a problem to chase across the tree.
        let mut leaf = depends(res("Kustomization", "leaf"), "infra");
        leaf.ready = FluxReady::Failed;
        leaf.suspended = true;
        let resources = vec![res("Kustomization", "infra"), leaf];
        assert!(problem_ancestors(&resources).is_empty());
    }

    #[test]
    fn a_collapsed_node_hides_its_subtree_but_not_itself() {
        let resources = vec![
            res("HelmRelease", "base"),
            depends(res("HelmRelease", "app"), "base"),
        ];
        let mut collapsed = HashSet::new();
        collapsed.insert(flux_tree_uid(&resources[0]));
        let rows = build_flux_tree(&resources, &collapsed);
        assert_eq!(names(&rows, &resources), vec!["base"]);
        assert!(rows[0].collapsed);
    }
}
