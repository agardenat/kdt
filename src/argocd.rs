//! Argo CD (`argoproj.io`) inventory for the `:argocd` view.
//!
//! Argo CD answers "is the cluster what git says it is" with two independent words per Application —
//! a **sync** status and a **health** status — and the pair is where most of the confusion lives:
//!
//! * `sync: Unknown` does not mean "probably fine". It means the controller could not *build* the
//!   desired state at all — a git credential that expired, a Helm repo that is down, a plugin that
//!   failed. The `health` shown next to it is then the last one computed **before** the comparison
//!   broke, so a row reading `Unknown / Healthy` is a row nobody has actually checked since the
//!   error started. Eleven of the twenty-four Applications on the cluster this view was written
//!   against were in exactly that state, all green to the eye.
//! * `health: Healthy` with `sync: OutOfSync` is the opposite trap: what runs is fine, it is simply
//!   not what git holds.
//!
//! So the list shows both, never one, and the detail panel names the condition that explains a
//! comparison failure instead of leaving it to the reader to open the object.
//!
//! Shapes that have to be survived rather than assumed:
//!
//! * `spec.syncPolicy.automated` is an object whose mere presence used to mean "auto-sync on".
//!   Recent versions added `enabled`, so `automated: { enabled: false }` is auto-sync **declared and
//!   off** — reading presence alone reports the opposite of the truth.
//! * an Application carries `spec.source` (one) or `spec.sources` (several). Reading only the first
//!   loses every multi-source app.
//! * `operation` is a **top-level field**, sibling of `spec` and `status`, and the CRD declares no
//!   status subresource: setting `.operation` is how a sync is requested, and `status` is patchable
//!   with an ordinary merge patch. That is what `argocd app sync` and `argocd app terminate-op` do,
//!   and it is the whole write surface of this view.
//! * repositories and clusters are not CRDs: they are `Secret`s labelled
//!   `argocd.argoproj.io/secret-type`. This module decodes their *addressing* keys only — url, name,
//!   type, project, scope — and reports the authentication **method** from which keys exist, never
//!   from what they hold. No credential is read.
//! * an Application living outside the controller's namespaces is silently ignored by Argo CD. The
//!   allowed list is `application.namespaces` in `argocd-cmd-params-cm`, empty meaning "the install
//!   namespace only", and an app outside it looks exactly like an app that is merely idle.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;

use crate::events::format_age;
use crate::lang::{fill, Strings};

pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- API surface ---------------------------------------------------------------------------------

const G_ARGO: &str = "argoproj.io";
const V_ARGO: &str = "v1alpha1";
pub const API_ARGO: &str = "argoproj.io/v1alpha1";

pub const KIND_APP: &str = "Application";
pub const KIND_APPSET: &str = "ApplicationSet";
pub const KIND_PROJECT: &str = "AppProject";

/// The annotation the controller watches to force a comparison. `normal` re-reads the repo,
/// `hard` throws the manifest cache away first — the only thing that helps when the cached
/// generation is itself what is wrong.
pub const A_REFRESH: &str = "argocd.argoproj.io/refresh";

/// The finalizer that makes deleting an Application delete what it deployed. Its absence means the
/// opposite: the Application goes, the workloads stay. Which of the two is the case is not something
/// to discover after pressing `Ctrl-D`.
const F_CASCADE: &str = "resources-finalizer.argocd.argoproj.io";

/// The label Argo CD puts on the Secrets that are really repositories, credentials templates and
/// clusters. Nothing else identifies them.
const L_SECRET_TYPE: &str = "argocd.argoproj.io/secret-type";

/// Where the install's own settings live. Both are looked up by name across every namespace, which
/// is also how the install namespace is discovered without asking the user for it.
const CM_SETTINGS: &str = "argocd-cm";
const CM_PARAMS: &str = "argocd-cmd-params-cm";

/// The components a working install runs, in the order an operator reasons about them: what
/// compares, what renders, what serves.
const COMPONENTS: &[&str] = &[
    "application-controller",
    "repo-server",
    "server",
    "applicationset-controller",
    "redis",
    "dex-server",
    "notifications-controller",
];

/// Argo CD's own default comparison period, used only to say how stale a comparison is and only
/// when `argocd-cm` was actually read — an unread setting means the rule abstains.
const DEFAULT_RECONCILE_SECS: i64 = 180;

/// The in-cluster destination, which never has a cluster Secret of its own.
const IN_CLUSTER_URL: &str = "https://kubernetes.default.svc";
const IN_CLUSTER_NAME: &str = "in-cluster";

// --- Records -------------------------------------------------------------------------------------

/// One `status.conditions` entry, kept verbatim: Argo CD's condition *types* are the vocabulary an
/// operator searches the docs with, so they are never rewritten into prose.
#[derive(Debug, Clone, Default)]
pub struct ArgoCondition {
    pub kind: String,
    pub message: String,
    /// ApplicationSet conditions carry a status and a reason; Application conditions do not.
    pub status: String,
    pub reason: String,
}

impl ArgoCondition {
    /// Whether the condition names something broken rather than something noted. Argo CD's own
    /// naming is the rule: every `…Error` is a failure, the `…Warning`s are not.
    pub fn is_error(&self) -> bool {
        self.kind.ends_with("Error")
    }
}

/// One source of an Application, whether it came from `spec.source` or from `spec.sources`.
#[derive(Debug, Clone, Default)]
pub struct ArgoSource {
    pub repo_url: String,
    /// The directory inside the repo, for a git source.
    pub path: String,
    /// The chart name, for a Helm-repository source. Mutually exclusive with `path`.
    pub chart: String,
    pub target_revision: String,
    /// `ref` of a multi-source entry that exists only to be referenced by another one.
    pub reference: String,
}

impl ArgoSource {
    /// What the source points at, in one line: repo plus the part of it that is used.
    pub fn label(&self) -> String {
        // A multi-source entry that only exists to be referenced by another one has no path and no
        // chart: showing it as a bare repo url would read as a second deployment.
        if !self.reference.is_empty() && self.path.is_empty() && self.chart.is_empty() {
            return format!("ref:{} {}", self.reference, self.repo_url);
        }
        let tail = if !self.chart.is_empty() {
            self.chart.clone()
        } else {
            self.path.clone()
        };
        let base = if tail.is_empty() || tail == "." {
            self.repo_url.clone()
        } else {
            format!("{}//{}", self.repo_url.trim_end_matches('/'), tail)
        };
        if self.target_revision.is_empty() {
            base
        } else {
            format!("{} @ {}", base, self.target_revision)
        }
    }
}

/// One resource Argo CD tracks for an Application, as `status.resources` reports it.
#[derive(Debug, Clone, Default)]
pub struct ArgoResource {
    pub group: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// `Synced`, `OutOfSync`, `Unknown` — empty when the comparison never ran.
    pub sync: String,
    /// `Healthy`, `Degraded`, … — absent for kinds Argo CD has no health check for.
    pub health: String,
    pub requires_pruning: bool,
}

impl ArgoResource {
    pub fn label(&self) -> String {
        let kind = if self.group.is_empty() {
            self.kind.clone()
        } else {
            format!("{}/{}", self.group, self.kind)
        };
        if self.namespace.is_empty() {
            format!("{} {}", kind, self.name)
        } else {
            format!("{} {}/{}", kind, self.namespace, self.name)
        }
    }
}

/// One entry of `status.history` — a revision that was actually deployed, with when.
#[derive(Debug, Clone, Default)]
pub struct ArgoDeploy {
    pub revision: String,
    pub deployed_at: String,
    pub age: String,
}

/// An Argo CD `Application`.
#[derive(Debug, Clone, Default)]
pub struct ArgoApp {
    pub namespace: String,
    pub name: String,
    pub project: String,
    /// `Synced` / `OutOfSync` / `Unknown`, empty before the first comparison.
    pub sync: String,
    /// `Healthy` / `Progressing` / `Degraded` / `Suspended` / `Missing` / `Unknown`.
    pub health: String,
    pub health_message: String,
    /// Auto-sync as it actually behaves: `automated` present **and** not explicitly disabled.
    pub auto: bool,
    /// `automated` declared with `enabled: false` — off, but on purpose and visibly so.
    pub auto_disabled: bool,
    pub self_heal: bool,
    pub prune: bool,
    pub sync_options: Vec<String>,
    pub dest_server: String,
    pub dest_namespace: String,
    /// The destination as a human names it: the registered cluster's name when it is known.
    pub dest_label: String,
    pub sources: Vec<ArgoSource>,
    /// `status.sourceType` — Helm, Kustomize, Directory, Plugin.
    pub source_type: String,
    /// `status.sync.revision`, shortened to the 7 characters a commit is quoted by.
    pub revision: String,
    pub revision_full: String,
    pub reconciled_age: String,
    pub reconciled_secs: Option<i64>,
    /// `status.operationState`: the last sync Argo CD ran, whoever asked for it.
    pub op_phase: String,
    pub op_message: String,
    pub op_age: String,
    pub op_by: String,
    pub op_retries: i64,
    pub conditions: Vec<ArgoCondition>,
    pub resources: Vec<ArgoResource>,
    pub out_of_sync: usize,
    pub degraded: usize,
    pub images: Vec<String>,
    pub history: Vec<ArgoDeploy>,
    /// Deleting the Application deletes what it deployed.
    pub cascade_delete: bool,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

impl ArgoApp {
    /// True while Argo CD is running an operation on this app — the one state in which asking for
    /// another sync is not what the reader wants.
    pub fn operation_running(&self) -> bool {
        matches!(self.op_phase.as_str(), "Running" | "Terminating")
    }

    /// The comparison itself failed: nothing on this row, health included, was computed from the
    /// current state of the repo.
    pub fn comparison_broken(&self) -> bool {
        self.sync == "Unknown" || self.conditions.iter().any(|c| c.kind == "ComparisonError")
    }

    pub fn policy_label(&self) -> String {
        if !self.auto {
            return "manual".to_string();
        }
        let mut out = String::from("auto");
        if self.prune {
            out.push_str("+prune");
        }
        if self.self_heal {
            out.push_str("+heal");
        }
        out
    }
}

/// An Argo CD `ApplicationSet`.
#[derive(Debug, Clone, Default)]
pub struct ArgoAppSet {
    pub namespace: String,
    pub name: String,
    /// The generator kinds it uses (`git`, `clusters`, `matrix`, …), in declaration order.
    pub generators: Vec<String>,
    pub go_template: bool,
    /// `spec.syncPolicy.applicationsSync` — `create-only`, `create-update`, `create-delete`, `sync`.
    /// Empty means the default, which is full sync of the generated Applications.
    pub apps_sync: String,
    pub preserve_on_delete: bool,
    /// Whether a `rollingSync` strategy staggers the generated Applications.
    pub rolling: bool,
    /// The Applications this set owns, by name.
    pub apps: Vec<String>,
    pub apps_out_of_sync: usize,
    pub apps_unhealthy: usize,
    pub conditions: Vec<ArgoCondition>,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

/// One `spec.roles` entry of an AppProject: a token-or-group scoped set of policies.
#[derive(Debug, Clone, Default)]
pub struct ArgoRole {
    pub name: String,
    pub groups: Vec<String>,
    pub policies: usize,
    /// The role grants at least one `sync`, `update`, `delete` or `*` — the verbs that write.
    pub writes: bool,
}

/// An Argo CD `AppProject`: what a set of Applications is allowed to deploy, from where, to where.
#[derive(Debug, Clone, Default)]
pub struct ArgoProject {
    pub namespace: String,
    pub name: String,
    pub description: String,
    pub source_repos: Vec<String>,
    /// `server-or-name/namespace`, as declared.
    pub destinations: Vec<String>,
    pub cluster_allow: Vec<String>,
    pub cluster_deny: Vec<String>,
    pub ns_allow: Vec<String>,
    pub ns_deny: Vec<String>,
    pub roles: Vec<ArgoRole>,
    /// `name (kind, schedule)` for each declared window.
    pub windows: Vec<String>,
    pub orphaned_warn: bool,
    /// Any repository is permitted.
    pub open_sources: bool,
    /// Any cluster and any namespace are permitted.
    pub open_destinations: bool,
    pub apps: usize,
    pub apps_out_of_sync: usize,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

/// Which kind of Secret an endpoint row came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndpointKind {
    Cluster,
    #[default]
    Repo,
    /// A credentials *template*: it holds no url of its own to deploy from, it lends its
    /// authentication to every repository whose url starts with its prefix.
    RepoCreds,
}

impl EndpointKind {
    pub fn label(self) -> &'static str {
        match self {
            EndpointKind::Cluster => "cluster",
            EndpointKind::Repo => "repo",
            EndpointKind::RepoCreds => "creds",
        }
    }
}

/// A registered repository, credentials template or cluster. Built from the Secret's *addressing*
/// keys and from which credential keys exist — never from what those keys hold.
#[derive(Debug, Clone, Default)]
pub struct ArgoEndpoint {
    pub kind: EndpointKind,
    pub namespace: String,
    /// The Secret's own name, which is what `kubectl` needs and what the YAML view opens.
    pub secret: String,
    /// The repository url, or the cluster's API server url.
    pub url: String,
    /// The name Argo CD shows: the cluster's name, or the repository's declared name.
    pub label: String,
    /// `git`, `helm`, or empty when the Secret does not say.
    pub repo_type: String,
    pub oci: bool,
    pub insecure: bool,
    /// The project the endpoint is scoped to, empty when it is global.
    pub project: String,
    /// How it authenticates, from key presence alone: `ssh key`, `user/password`, `github app`,
    /// `tls cert`, `bearer token`, `exec provider`, `none`.
    pub auth: String,
    /// Cluster only: the namespaces it is restricted to, empty meaning all of them.
    pub namespaces: Vec<String>,
    /// Cluster only: whether Argo CD may manage cluster-scoped resources there.
    pub cluster_resources: Option<bool>,
    /// Applications pointing at this endpoint.
    pub used_by: usize,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

/// One Argo CD component, as its Deployment/StatefulSet reports it.
#[derive(Debug, Clone, Default)]
pub struct ArgoComponent {
    pub name: String,
    pub ready: i32,
    pub desired: i32,
    /// `app.kubernetes.io/version`, verbatim.
    pub version: String,
}

/// The installation itself, as the view's headline.
#[derive(Debug, Clone, Default)]
pub struct ArgoServer {
    /// The `argoproj.io` CRDs are served here.
    pub present: bool,
    /// Where `argocd-cm` was found — the install namespace, discovered rather than assumed.
    pub namespace: String,
    /// `url` in `argocd-cm`: the UI an operator is about to be told to open.
    pub url: String,
    /// The `app.kubernetes.io/version` label of the server workload, whatever it holds. On a
    /// rebuilt image that is the rebuild's tag, which is the honest answer to "which build is this".
    pub version: String,
    /// `timeout.reconciliation` as written, and in seconds when it parses.
    pub reconcile: String,
    pub reconcile_secs: Option<i64>,
    /// `application.namespaces` from `argocd-cmd-params-cm`: where Applications are honoured.
    pub app_namespaces: Vec<String>,
    pub components: Vec<ArgoComponent>,
    pub hints: Vec<Hint>,
}

// --- State ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ArgoState {
    pub server: ArgoServer,
    pub apps: Vec<ArgoApp>,
    pub sets: Vec<ArgoAppSet>,
    pub projects: Vec<ArgoProject>,
    pub endpoints: Vec<ArgoEndpoint>,
    pub error: Option<String>,
    pub loading: bool,
}

impl ArgoState {
    /// Applications whose comparison itself is broken — the rows whose health is stale rather than
    /// green. Counted apart from the out-of-sync ones because the two mean opposite things.
    pub fn blind(&self) -> usize {
        self.apps.iter().filter(|a| a.comparison_broken()).count()
    }

    pub fn out_of_sync(&self) -> usize {
        self.apps.iter().filter(|a| a.sync == "OutOfSync").count()
    }

    pub fn unhealthy(&self) -> usize {
        self.apps
            .iter()
            .filter(|a| matches!(a.health.as_str(), "Degraded" | "Missing"))
            .count()
    }
}

pub type SharedArgo = Arc<Mutex<ArgoState>>;

pub fn new_argo_state() -> SharedArgo {
    Arc::new(Mutex::new(ArgoState::default()))
}

// --- Fetch ---------------------------------------------------------------------------------------

type Listed = HashMap<&'static str, Vec<DynamicObject>>;

/// Everything the view shows, in one pass. A kind the cluster does not serve is absent from the map,
/// which every builder treats as "nothing" and never as an error — Argo CD without the ApplicationSet
/// controller is a normal install.
pub async fn fetch_argocd(client: Client, state: SharedArgo) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("argocd poisoned");
        s.loading = true;
        s.error = None;
    }

    let kinds = [KIND_APP, KIND_APPSET, KIND_PROJECT];
    let probes = kinds.iter().map(|kind| {
        let client = client.clone();
        async move {
            let gvk = GroupVersionKind::gvk(G_ARGO, V_ARGO, kind);
            match discovery::pinned_kind(&client, &gvk).await {
                Ok((ar, _)) => Some((*kind, ar)),
                Err(_) => None,
            }
        }
    });
    let resolved: Vec<_> = futures::future::join_all(probes).await.into_iter().flatten().collect();

    if resolved.is_empty() {
        let mut s = state.lock().expect("argocd poisoned");
        *s = ArgoState {
            loading: false,
            error: Some(st.argo_absent.to_string()),
            ..ArgoState::default()
        };
        return;
    }

    let lists = resolved.iter().map(|(kind, ar)| {
        let client = client.clone();
        let ar = ar.clone();
        let kind = *kind;
        async move {
            let api: Api<DynamicObject> = Api::all_with(client, &ar);
            let out = api
                .list(&ListParams::default())
                .await
                .map(|l| l.items)
                .map_err(|e| e.to_string());
            (kind, out)
        }
    });
    let (results, secrets, settings, workloads) = futures::join!(
        futures::future::join_all(lists),
        list_argo_secrets(&client),
        read_settings(&client),
        list_components(&client),
    );

    let apps_error = results
        .iter()
        .find(|(kind, _)| *kind == KIND_APP)
        .and_then(|(_, r)| r.as_ref().err().cloned());
    let listed: Listed = results
        .into_iter()
        .filter_map(|(kind, r)| r.ok().map(|v| (kind, v)))
        .collect();

    let mut next = build(st, &listed, &secrets, settings, workloads);
    if let Some(e) = apps_error {
        next.server.hints.push(danger(fill(st.argo_apps_unreadable, &[("e", &e)])));
        next.error = Some(e);
    }
    next.loading = false;
    *state.lock().expect("argocd poisoned") = next;
}

/// The Secrets Argo CD uses as repositories, credential templates and clusters. Listed by label so
/// that nothing else in the cluster is read: a `get secrets -A` without a selector would pull every
/// credential the reader has access to, for no reason.
async fn list_argo_secrets(client: &Client) -> Vec<Secret> {
    let api: Api<Secret> = Api::all(client.clone());
    let params = ListParams::default().labels(L_SECRET_TYPE);
    api.list(&params).await.map(|l| l.items).unwrap_or_default()
}

/// `argocd-cm` and `argocd-cmd-params-cm`, wherever they are. Both are looked up by name across the
/// cluster: the install namespace is not a constant, and asking for it would be one question too
/// many for a view whose whole point is to answer without one.
/// `(install namespace, argocd-cm data, argocd-cmd-params-cm data)`.
type Settings = (String, BTreeMap<String, String>, BTreeMap<String, String>);

async fn read_settings(client: &Client) -> Option<Settings> {
    let api: Api<ConfigMap> = Api::all(client.clone());
    let list = api
        .list(&ListParams::default().fields(&format!("metadata.name={CM_SETTINGS}")))
        .await
        .ok()?;
    let cm = list.items.into_iter().next()?;
    let namespace = cm.metadata.namespace.clone().unwrap_or_default();
    let settings = cm.data.unwrap_or_default();

    let params_api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
    let params = params_api
        .get(CM_PARAMS)
        .await
        .ok()
        .and_then(|c| c.data)
        .unwrap_or_default();
    Some((namespace, settings, params))
}

/// The install's own workloads, found by the label Argo CD's manifests carry rather than by name:
/// a chart that renames its releases still labels its parts.
async fn list_components(client: &Client) -> Vec<ArgoComponent> {
    let params = ListParams::default().labels("app.kubernetes.io/part-of=argocd");
    let deploy_api: Api<Deployment> = Api::all(client.clone());
    let sts_api: Api<StatefulSet> = Api::all(client.clone());
    let (deploys, stss) = futures::join!(deploy_api.list(&params), sts_api.list(&params));

    let mut out: Vec<ArgoComponent> = Vec::new();
    if let Ok(list) = deploys {
        for d in list.items {
            let name = component_name(&d.metadata.labels, &d.metadata.name);
            let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
            let ready = d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0);
            let version = label_version(&d.metadata.labels);
            out.push(ArgoComponent { name, ready, desired, version });
        }
    }
    if let Ok(list) = stss {
        for s in list.items {
            let name = component_name(&s.metadata.labels, &s.metadata.name);
            let desired = s.spec.as_ref().and_then(|sp| sp.replicas).unwrap_or(1);
            let ready = s.status.as_ref().map(|st| st.ready_replicas.unwrap_or(0)).unwrap_or(0);
            let version = label_version(&s.metadata.labels);
            out.push(ArgoComponent { name, ready, desired, version });
        }
    }
    // Known components first, in the order of `COMPONENTS`; anything else after, alphabetically.
    out.sort_by_key(|c| {
        (
            COMPONENTS.iter().position(|k| *k == c.name).unwrap_or(COMPONENTS.len()),
            c.name.clone(),
        )
    });
    out
}

fn label_version(labels: &Option<BTreeMap<String, String>>) -> String {
    labels
        .as_ref()
        .and_then(|l| l.get("app.kubernetes.io/version").cloned())
        .unwrap_or_default()
}

fn component_name(labels: &Option<BTreeMap<String, String>>, name: &Option<String>) -> String {
    labels
        .as_ref()
        .and_then(|l| l.get("app.kubernetes.io/component").cloned())
        .unwrap_or_else(|| name.clone().unwrap_or_default())
}

// --- Build ---------------------------------------------------------------------------------------

fn build(
    st: &'static Strings,
    listed: &Listed,
    secrets: &[Secret],
    settings: Option<Settings>,
    components: Vec<ArgoComponent>,
) -> ArgoState {
    let empty: Vec<DynamicObject> = Vec::new();
    let get = |k: &str| listed.get(k).unwrap_or(&empty);

    let mut server = ArgoServer {
        present: true,
        components,
        ..ArgoServer::default()
    };
    if let Some((ns, cm, params)) = settings {
        server.namespace = ns;
        server.url = cm.get("url").cloned().unwrap_or_default();
        server.reconcile = cm.get("timeout.reconciliation").cloned().unwrap_or_default();
        server.reconcile_secs = parse_go_duration(&server.reconcile);
        server.app_namespaces = params
            .get("application.namespaces")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
    }
    server.version = version_of(&server.components);

    let mut endpoints: Vec<ArgoEndpoint> = secrets.iter().filter_map(parse_endpoint).collect();

    // The map a destination url is resolved through. `in-cluster` is not a Secret and has to be
    // seeded, or every app deploying locally would read as pointing at an unregistered cluster.
    let mut cluster_names: HashMap<String, String> = HashMap::new();
    cluster_names.insert(IN_CLUSTER_URL.to_string(), IN_CLUSTER_NAME.to_string());
    for e in endpoints.iter().filter(|e| e.kind == EndpointKind::Cluster) {
        let label = if e.label.is_empty() { e.url.clone() } else { e.label.clone() };
        cluster_names.insert(normalize_url(&e.url), label);
    }
    // Only meaningful when at least one cluster Secret was readable: on a reader with no access to
    // them the map holds `in-cluster` alone, and "unregistered" would be a verdict about the reader.
    let clusters_known = endpoints.iter().any(|e| e.kind == EndpointKind::Cluster);

    let project_names: BTreeSet<String> = get(KIND_PROJECT)
        .iter()
        .filter_map(|o| o.metadata.name.clone())
        .collect();
    let projects_known = !project_names.is_empty();

    let now = k8s_openapi::jiff::Timestamp::now().as_second();
    let mut apps: Vec<ArgoApp> = get(KIND_APP)
        .iter()
        .map(|o| parse_app(o, now, &cluster_names))
        .collect();

    let mut sets: Vec<ArgoAppSet> = get(KIND_APPSET).iter().map(parse_appset).collect();
    let mut projects: Vec<ArgoProject> = get(KIND_PROJECT).iter().map(parse_project).collect();

    // Cross-references, computed once and read by three sets of rules.
    let mut per_project: HashMap<String, (usize, usize)> = HashMap::new();
    let mut per_repo: HashMap<String, usize> = HashMap::new();
    let mut per_cluster: HashMap<String, usize> = HashMap::new();
    for a in &apps {
        let e = per_project.entry(a.project.clone()).or_insert((0, 0));
        e.0 += 1;
        if a.sync == "OutOfSync" {
            e.1 += 1;
        }
        for s in &a.sources {
            if !s.repo_url.is_empty() {
                *per_repo.entry(normalize_url(&s.repo_url)).or_insert(0) += 1;
            }
        }
        *per_cluster.entry(normalize_url(&a.dest_server)).or_insert(0) += 1;
    }

    // The Applications each set generated, by owner reference: the only link that survives a
    // template whose names have nothing to do with the set's.
    let mut per_set: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, o) in get(KIND_APP).iter().enumerate() {
        for owner in o.metadata.owner_references.iter().flatten() {
            if owner.kind == KIND_APPSET {
                per_set.entry(owner.name.clone()).or_default().push(i);
            }
        }
    }
    for s in &mut sets {
        for i in per_set.get(&s.name).into_iter().flatten() {
            let Some(a) = apps.get(*i) else { continue };
            s.apps.push(a.name.clone());
            if a.sync == "OutOfSync" {
                s.apps_out_of_sync += 1;
            }
            if matches!(a.health.as_str(), "Degraded" | "Missing") {
                s.apps_unhealthy += 1;
            }
        }
        s.apps.sort();
    }

    for p in &mut projects {
        let (n, oos) = per_project.get(&p.name).copied().unwrap_or((0, 0));
        p.apps = n;
        p.apps_out_of_sync = oos;
    }

    for e in &mut endpoints {
        e.used_by = match e.kind {
            EndpointKind::Cluster => per_cluster.get(&normalize_url(&e.url)).copied().unwrap_or(0),
            // A credentials template lends itself to every repository url it prefixes, so counting
            // exact matches would report zero for one that is working perfectly.
            EndpointKind::RepoCreds => per_repo
                .iter()
                .filter(|(u, _)| u.starts_with(&normalize_url(&e.url)))
                .map(|(_, n)| *n)
                .sum(),
            EndpointKind::Repo => per_repo.get(&normalize_url(&e.url)).copied().unwrap_or(0),
        };
    }

    // Hints last: every rule reads facts already computed above, so none of them re-derives anything.
    let reconcile_secs = server.reconcile_secs.or(if server.namespace.is_empty() {
        None
    } else {
        Some(DEFAULT_RECONCILE_SECS)
    });
    for a in &mut apps {
        a.hints = app_hints(st, a, reconcile_secs, clusters_known, projects_known, &project_names);
    }
    for s in &mut sets {
        s.hints = set_hints(st, s);
    }
    for p in &mut projects {
        p.hints = project_hints(st, p);
    }
    for e in &mut endpoints {
        e.hints = endpoint_hints(st, e);
    }
    server.hints = server_hints(st, &server, &apps, &endpoints);

    apps.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    sets.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    projects.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    endpoints.sort_by(|a, b| {
        (a.kind, a.label.to_lowercase(), a.url.clone())
            .cmp(&(b.kind, b.label.to_lowercase(), b.url.clone()))
    });

    ArgoState {
        server,
        apps,
        sets,
        projects,
        endpoints,
        error: None,
        loading: false,
    }
}

// The build actually running, as the workloads label themselves. On a rebuilt image that label
// holds the rebuild's tag rather than an upstream version number — which is the honest answer to
// "which build is this", and the reason it is shown verbatim instead of being parsed.
pub fn looks_like_a_version(label: &str) -> bool {
    let core = label.strip_prefix('v').unwrap_or(label);
    core.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn version_of(components: &[ArgoComponent]) -> String {
    components
        .iter()
        .find(|c| c.name == "server" && !c.version.is_empty())
        .or_else(|| components.iter().find(|c| !c.version.is_empty()))
        .map(|c| c.version.clone())
        .unwrap_or_default()
}

// --- Application ---------------------------------------------------------------------------------

fn parse_app(obj: &DynamicObject, now: i64, clusters: &HashMap<String, String>) -> ArgoApp {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let d = &obj.data;

    let spec = d.get("spec");
    let status = d.get("status");

    let sources = parse_sources(spec);

    // `automated` present is not `automated` on: `enabled: false` is the modern way of declaring a
    // policy and leaving it off, and reading presence alone would report the opposite.
    let automated = spec.and_then(|s| s.get("syncPolicy")).and_then(|s| s.get("automated"));
    let auto_enabled = automated.and_then(|a| a.get("enabled")).and_then(|v| v.as_bool());
    let auto = automated.is_some() && auto_enabled != Some(false);
    let auto_disabled = automated.is_some() && auto_enabled == Some(false);

    let dest_server = str_at(spec, &["destination", "server"]);
    // A destination names its cluster either by url or by the name it was registered under. The
    // second form has no url at all, so resolving through the cluster map has to come second.
    let dest_name = str_at(spec, &["destination", "name"]);
    let dest_namespace = str_at(spec, &["destination", "namespace"]);
    let dest_label = if !dest_name.is_empty() {
        dest_name
    } else {
        clusters
            .get(&normalize_url(&dest_server))
            .cloned()
            .unwrap_or_else(|| short_server(&dest_server))
    };

    let revision_full = str_at(status, &["sync", "revision"]);
    let reconciled = str_at(status, &["reconciledAt"]);
    let reconciled_secs = parse_ts(&reconciled).map(|t| (now - t).max(0));

    let op = status.and_then(|s| s.get("operationState"));
    let op_phase = str_at(op, &["phase"]);
    let op_when = {
        let finished = str_at(op, &["finishedAt"]);
        if finished.is_empty() { str_at(op, &["startedAt"]) } else { finished }
    };
    let op_by = {
        let user = str_at(op, &["operation", "initiatedBy", "username"]);
        let automated = op
            .and_then(|o| o.pointer("/operation/initiatedBy/automated"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if automated {
            "auto".to_string()
        } else {
            user
        }
    };

    let resources: Vec<ArgoResource> = status
        .and_then(|s| s.get("resources"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(parse_resource).collect())
        .unwrap_or_default();
    let out_of_sync = resources.iter().filter(|r| r.sync == "OutOfSync").count();
    let degraded = resources
        .iter()
        .filter(|r| matches!(r.health.as_str(), "Degraded" | "Missing"))
        .count();

    let history: Vec<ArgoDeploy> = status
        .and_then(|s| s.get("history"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .rev()
                .take(5)
                .map(|h| {
                    let deployed_at = h.get("deployedAt").and_then(|v| v.as_str()).unwrap_or("");
                    ArgoDeploy {
                        revision: short_revision(
                            h.get("revision").and_then(|v| v.as_str()).unwrap_or(""),
                        ),
                        deployed_at: deployed_at.to_string(),
                        age: parse_ts(deployed_at)
                            .map(|t| human_secs((now - t).max(0)))
                            .unwrap_or_default(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let cascade_delete = obj
        .metadata
        .finalizers
        .iter()
        .flatten()
        .any(|f| f == F_CASCADE || f.starts_with(F_CASCADE));

    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    ArgoApp {
        uid: format!("argo|app|{}/{}", namespace, name),
        project: str_at(spec, &["project"]),
        sync: str_at(status, &["sync", "status"]),
        health: str_at(status, &["health", "status"]),
        health_message: str_at(status, &["health", "message"]),
        auto,
        auto_disabled,
        self_heal: automated.and_then(|a| a.get("selfHeal")).and_then(|v| v.as_bool()).unwrap_or(false),
        prune: automated.and_then(|a| a.get("prune")).and_then(|v| v.as_bool()).unwrap_or(false),
        sync_options: strings_at(spec, &["syncPolicy", "syncOptions"]),
        dest_server,
        dest_namespace,
        dest_label,
        sources,
        source_type: str_at(status, &["sourceType"]),
        revision: short_revision(&revision_full),
        revision_full,
        reconciled_age: reconciled_secs.map(human_secs).unwrap_or_default(),
        reconciled_secs,
        op_phase,
        op_message: str_at(op, &["message"]),
        op_age: parse_ts(&op_when).map(|t| human_secs((now - t).max(0))).unwrap_or_default(),
        op_by,
        op_retries: op.and_then(|o| o.get("retryCount")).and_then(|v| v.as_i64()).unwrap_or(0),
        conditions: parse_conditions(status),
        resources,
        out_of_sync,
        degraded,
        images: strings_at(status, &["summary", "images"]),
        history,
        cascade_delete,
        age,
        hints: Vec::new(),
        namespace,
        name,
    }
}

/// Both source shapes at once. `spec.sources` wins when present, which is what Argo CD itself does.
fn parse_sources(spec: Option<&Value>) -> Vec<ArgoSource> {
    let one = |v: &Value| ArgoSource {
        repo_url: v.get("repoURL").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        path: v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        chart: v.get("chart").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        target_revision: v
            .get("targetRevision")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        reference: v.get("ref").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    };
    if let Some(list) = spec.and_then(|s| s.get("sources")).and_then(|v| v.as_array()) {
        if !list.is_empty() {
            return list.iter().map(one).collect();
        }
    }
    spec.and_then(|s| s.get("source")).map(|v| vec![one(v)]).unwrap_or_default()
}

fn parse_resource(v: &Value) -> ArgoResource {
    ArgoResource {
        group: v.get("group").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        kind: v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        namespace: v.get("namespace").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        name: v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        sync: v.get("status").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        health: v
            .pointer("/health/status")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        requires_pruning: v
            .get("requiresPruning")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
    }
}

fn parse_conditions(status: Option<&Value>) -> Vec<ArgoCondition> {
    status
        .and_then(|s| s.get("conditions"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|c| ArgoCondition {
                    kind: c.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    message: c.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    status: c.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    reason: c.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

// --- ApplicationSet ------------------------------------------------------------------------------

fn parse_appset(obj: &DynamicObject) -> ArgoAppSet {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    // A generator entry is an object with exactly one populated key, which is the generator's kind.
    let generators: Vec<String> = spec
        .and_then(|s| s.get("generators"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .flat_map(|g| {
                    g.as_object()
                        .map(|o| {
                            o.iter()
                                .filter(|(k, v)| *k != "selector" && !v.is_null())
                                .map(|(k, _)| k.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    ArgoAppSet {
        uid: format!("argo|set|{}/{}", namespace, name),
        generators,
        go_template: spec.and_then(|s| s.get("goTemplate")).and_then(|v| v.as_bool()).unwrap_or(false),
        apps_sync: str_at(spec, &["syncPolicy", "applicationsSync"]),
        preserve_on_delete: spec
            .and_then(|s| s.pointer("/syncPolicy/preserveResourcesOnDeletion"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        rolling: spec.and_then(|s| s.pointer("/strategy/rollingSync")).is_some(),
        apps: Vec::new(),
        apps_out_of_sync: 0,
        apps_unhealthy: 0,
        conditions: parse_conditions(status),
        age: obj
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        hints: Vec::new(),
        namespace,
        name,
    }
}

// --- AppProject ----------------------------------------------------------------------------------

fn parse_project(obj: &DynamicObject) -> ArgoProject {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec");

    let source_repos = strings_at(spec, &["sourceRepos"]);
    let destinations: Vec<String> = spec
        .and_then(|s| s.get("destinations"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|d| {
                    let server = d.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let server = if server.is_empty() {
                        short_server(d.get("server").and_then(|v| v.as_str()).unwrap_or(""))
                    } else {
                        server.to_string()
                    };
                    let ns = d.get("namespace").and_then(|v| v.as_str()).unwrap_or("*");
                    format!("{}/{}", server, ns)
                })
                .collect()
        })
        .unwrap_or_default();

    let gk_list = |key: &str| -> Vec<String> {
        spec.and_then(|s| s.get(key))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|g| {
                        let group = g.get("group").and_then(|v| v.as_str()).unwrap_or("*");
                        let kind = g.get("kind").and_then(|v| v.as_str()).unwrap_or("*");
                        if group.is_empty() {
                            kind.to_string()
                        } else {
                            format!("{}/{}", group, kind)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let roles: Vec<ArgoRole> = spec
        .and_then(|s| s.get("roles"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|r| {
                    let policies: Vec<String> = r
                        .get("policies")
                        .and_then(|v| v.as_array())
                        .map(|p| {
                            p.iter().filter_map(|x| x.as_str().map(String::from)).collect()
                        })
                        .unwrap_or_default();
                    ArgoRole {
                        name: r.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        groups: r
                            .get("groups")
                            .and_then(|v| v.as_array())
                            .map(|g| {
                                g.iter().filter_map(|x| x.as_str().map(String::from)).collect()
                            })
                            .unwrap_or_default(),
                        writes: policies.iter().any(|p| policy_writes(p)),
                        policies: policies.len(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let windows: Vec<String> = spec
        .and_then(|s| s.get("syncWindows"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|w| {
                    let kind = w.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                    let schedule = w.get("schedule").and_then(|v| v.as_str()).unwrap_or("");
                    let duration = w.get("duration").and_then(|v| v.as_str()).unwrap_or("");
                    format!("{} {} ({})", kind, schedule, duration)
                })
                .collect()
        })
        .unwrap_or_default();

    let open_sources = source_repos.iter().any(|r| r == "*");
    let open_destinations = destinations.iter().any(|d| d == "*/*");

    ArgoProject {
        uid: format!("argo|proj|{}/{}", namespace, name),
        description: str_at(spec, &["description"]),
        source_repos,
        destinations,
        cluster_allow: gk_list("clusterResourceWhitelist"),
        cluster_deny: gk_list("clusterResourceBlacklist"),
        ns_allow: gk_list("namespaceResourceWhitelist"),
        ns_deny: gk_list("namespaceResourceBlacklist"),
        roles,
        windows,
        orphaned_warn: spec
            .and_then(|s| s.pointer("/orphanedResources/warn"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        open_sources,
        open_destinations,
        apps: 0,
        apps_out_of_sync: 0,
        age: obj
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        hints: Vec::new(),
        namespace,
        name,
    }
}

/// Whether a Casbin policy line grants a verb that changes something. The line's shape is
/// `p, subject, resource, action, object, effect`; the action is the fourth field, and `update/*`
/// counts as `update`.
fn policy_writes(policy: &str) -> bool {
    let Some(action) = policy.split(',').nth(3) else { return false };
    let action = action.trim();
    let head = action.split('/').next().unwrap_or(action);
    matches!(head, "sync" | "update" | "delete" | "create" | "override" | "*")
}

// --- Repositories and clusters -------------------------------------------------------------------

/// One labelled Secret, read for its addressing keys only. Credential keys are consulted for their
/// *presence* — which tells how the endpoint authenticates — and never decoded.
fn parse_endpoint(secret: &Secret) -> Option<ArgoEndpoint> {
    let kind = match secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(L_SECRET_TYPE))
        .map(String::as_str)
    {
        Some("cluster") => EndpointKind::Cluster,
        Some("repository") => EndpointKind::Repo,
        Some("repo-creds") => EndpointKind::RepoCreds,
        _ => return None,
    };

    let data = secret.data.clone().unwrap_or_default();
    let text = |k: &str| -> String {
        data.get(k)
            .map(|b| String::from_utf8_lossy(&b.0).trim().to_string())
            .unwrap_or_default()
    };
    let has = |k: &str| data.contains_key(k);

    let namespace = secret.metadata.namespace.clone().unwrap_or_default();
    let name = secret.metadata.name.clone().unwrap_or_default();

    let url = if kind == EndpointKind::Cluster { text("server") } else { text("url") };
    let label = {
        let declared = text("name");
        if declared.is_empty() { short_server(&url) } else { declared }
    };

    // The cluster's `config` holds the credential *and* says which kind it is. Only the key names
    // are looked at: knowing a bearer token is used never requires reading it.
    let mut namespaces = Vec::new();
    let mut cluster_resources = None;
    let mut auth = String::new();
    if kind == EndpointKind::Cluster {
        namespaces = text("namespaces")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        cluster_resources = match text("clusterResources").as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        if let Ok(cfg) = serde_json::from_slice::<Value>(
            data.get("config").map(|b| b.0.as_slice()).unwrap_or(b"{}"),
        ) {
            let mut methods: Vec<&str> = Vec::new();
            if cfg.get("bearerToken").is_some() {
                methods.push("bearer token");
            }
            if cfg.get("username").is_some() {
                methods.push("user/password");
            }
            if cfg.get("execProviderConfig").is_some() {
                methods.push("exec provider");
            }
            if cfg.get("awsAuthConfig").is_some() {
                methods.push("aws");
            }
            if cfg.pointer("/tlsClientConfig/certData").is_some() {
                methods.push("tls cert");
            }
            auth = methods.join(", ");
        }
    } else {
        let mut methods: Vec<&str> = Vec::new();
        if has("sshPrivateKey") {
            methods.push("ssh key");
        }
        if has("githubAppPrivateKey") || has("githubAppID") {
            methods.push("github app");
        }
        if has("password") || has("username") {
            methods.push("user/password");
        }
        if has("tlsClientCertData") {
            methods.push("tls cert");
        }
        auth = methods.join(", ");
    }
    if auth.is_empty() {
        auth = "none".to_string();
    }

    Some(ArgoEndpoint {
        kind,
        uid: format!("argo|ep|{}/{}", namespace, name),
        url,
        label,
        repo_type: text("type"),
        oci: text("enableOCI") == "true",
        insecure: text("insecure") == "true",
        project: text("project"),
        auth,
        namespaces,
        cluster_resources,
        used_by: 0,
        age: secret
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        hints: Vec::new(),
        namespace,
        secret: name,
    })
}

// --- Rules ---------------------------------------------------------------------------------------

fn app_hints(
    st: &'static Strings,
    a: &ArgoApp,
    reconcile_secs: Option<i64>,
    clusters_known: bool,
    projects_known: bool,
    project_names: &BTreeSet<String>,
) -> Vec<Hint> {
    let mut out = Vec::new();

    // The one thing this view exists to say out loud. A broken comparison makes every other column
    // of the row a memory, health included, so it is stated before anything else.
    if a.comparison_broken() {
        let cause = a
            .conditions
            .iter()
            .find(|c| c.kind == "ComparisonError")
            .map(|c| c.message.clone())
            .unwrap_or_default();
        if cause.is_empty() {
            out.push(warn(st.argo_sync_unknown.to_string()));
        } else {
            out.push(danger(fill(st.argo_comparison_error, &[("e", &clip(&cause, 400))])));
        }
        if !a.health.is_empty() {
            out.push(warn(fill(st.argo_health_stale, &[("health", &a.health)])));
        }
    }

    for c in &a.conditions {
        match c.kind.as_str() {
            // Already said above, with its cause.
            "ComparisonError" => {}
            // A deliberate project setting produced this one: the project asked to be told about
            // resources it does not own. Noted, not flagged.
            "OrphanedResourceWarning" | "ExcludedResourceWarning" => {
                out.push(info(format!("{}: {}", c.kind, clip(&c.message, 240))))
            }
            _ if c.is_error() => {
                out.push(danger(format!("{}: {}", c.kind, clip(&c.message, 400))))
            }
            _ => out.push(warn(format!("{}: {}", c.kind, clip(&c.message, 240)))),
        }
    }

    match a.health.as_str() {
        "Degraded" => {
            let msg = if a.health_message.is_empty() {
                fill(st.argo_health_degraded, &[("n", &a.degraded.to_string())])
            } else {
                format!(
                    "{} — {}",
                    fill(st.argo_health_degraded, &[("n", &a.degraded.to_string())]),
                    clip(&a.health_message, 240)
                )
            };
            out.push(danger(msg));
        }
        // Missing is not a failure of what runs: it is the absence of what should. It becomes one
        // only through the sync that was supposed to create it, which has its own line below.
        "Missing" => out.push(warn(st.argo_health_missing.to_string())),
        "Progressing" => out.push(info(st.argo_health_progressing.to_string())),
        "Suspended" => out.push(info(st.argo_health_suspended.to_string())),
        _ => {}
    }

    match a.op_phase.as_str() {
        "Failed" | "Error" => out.push(danger(fill(
            st.argo_op_failed,
            &[
                ("age", &a.op_age),
                ("retries", &a.op_retries.to_string()),
                ("e", &clip(&a.op_message, 400)),
            ],
        ))),
        "Running" => out.push(info(fill(st.argo_op_running, &[("age", &a.op_age)]))),
        "Terminating" => out.push(warn(st.argo_op_terminating.to_string())),
        _ => {}
    }

    // Auto-sync on and still out of sync is not a transient: the controller had every chance to
    // close the gap and did not. What it is *waiting* on is what the operation line above says.
    if a.auto && a.sync == "OutOfSync" && !a.operation_running() {
        out.push(warn(fill(
            st.argo_auto_still_out_of_sync,
            &[("n", &a.out_of_sync.to_string())],
        )));
    }
    if a.auto_disabled {
        out.push(info(st.argo_auto_disabled.to_string()));
    } else if !a.auto {
        out.push(info(st.argo_manual_sync.to_string()));
    }

    // Three comparison periods with no comparison: the controller is not looking at this app.
    if let (Some(secs), Some(age)) = (reconcile_secs, a.reconciled_secs) {
        if age > secs.saturating_mul(3) {
            out.push(warn(fill(
                st.argo_not_compared,
                &[("age", &human_secs(age)), ("period", &human_secs(secs))],
            )));
        }
    }

    if projects_known && !a.project.is_empty() && !project_names.contains(&a.project) {
        out.push(danger(fill(st.argo_project_missing, &[("project", &a.project)])));
    }
    if clusters_known
        && !a.dest_server.is_empty()
        && normalize_url(&a.dest_server) != normalize_url(IN_CLUSTER_URL)
        && a.dest_label == short_server(&a.dest_server)
    {
        out.push(warn(fill(st.argo_dest_unregistered, &[("server", &a.dest_server)])));
    }

    if a.cascade_delete {
        out.push(info(st.argo_cascade_delete.to_string()));
    } else {
        out.push(info(st.argo_no_cascade_delete.to_string()));
    }

    out
}

fn set_hints(st: &'static Strings, s: &ArgoAppSet) -> Vec<Hint> {
    let mut out = Vec::new();
    for c in &s.conditions {
        match (c.kind.as_str(), c.status.as_str()) {
            ("ErrorOccurred", "True") => {
                out.push(danger(format!("{}: {}", c.kind, clip(&c.message, 400))))
            }
            ("ResourcesUpToDate", "False") | ("ParametersGenerated", "False") => {
                out.push(warn(format!("{}: {}", c.kind, clip(&c.message, 240))))
            }
            _ => {}
        }
    }
    if s.apps.is_empty() {
        out.push(warn(st.argo_set_generates_nothing.to_string()));
    }
    // Both of these are deliberate choices with a real consequence, so they are said — and neither
    // is a fault, so neither is yellow.
    if !s.apps_sync.is_empty() && s.apps_sync != "sync" {
        out.push(info(fill(st.argo_set_policy, &[("policy", &s.apps_sync)])));
    }
    if s.preserve_on_delete {
        out.push(info(st.argo_set_preserve.to_string()));
    }
    if s.apps_out_of_sync > 0 {
        out.push(info(fill(
            st.argo_set_children,
            &[
                ("out", &s.apps_out_of_sync.to_string()),
                ("bad", &s.apps_unhealthy.to_string()),
                ("total", &s.apps.len().to_string()),
            ],
        )));
    }
    out
}

fn project_hints(st: &'static Strings, p: &ArgoProject) -> Vec<Hint> {
    let mut out = Vec::new();
    // A project that restricts nothing is a project that is not doing the one job it has. Said as a
    // fact, because plenty of installs run a single open project on purpose.
    if p.open_sources {
        out.push(info(st.argo_project_any_repo.to_string()));
    }
    if p.open_destinations {
        out.push(info(st.argo_project_any_destination.to_string()));
    }
    if p.source_repos.is_empty() {
        out.push(warn(st.argo_project_no_repo.to_string()));
    }
    if p.destinations.is_empty() {
        out.push(warn(st.argo_project_no_destination.to_string()));
    }
    if p.apps == 0 {
        out.push(info(st.argo_project_unused.to_string()));
    }
    if p.orphaned_warn {
        out.push(info(st.argo_project_orphan_warn.to_string()));
    }
    for w in &p.windows {
        out.push(info(fill(st.argo_project_window, &[("w", w)])));
    }
    let writers: Vec<&ArgoRole> = p.roles.iter().filter(|r| r.writes).collect();
    if !writers.is_empty() {
        out.push(info(fill(
            st.argo_project_write_roles,
            &[
                ("n", &writers.len().to_string()),
                (
                    "roles",
                    &writers.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", "),
                ),
            ],
        )));
    }
    out
}

fn endpoint_hints(st: &'static Strings, e: &ArgoEndpoint) -> Vec<Hint> {
    let mut out = Vec::new();
    if e.used_by == 0 && e.kind != EndpointKind::RepoCreds {
        out.push(info(st.argo_endpoint_unused.to_string()));
    }
    if e.insecure {
        out.push(warn(st.argo_endpoint_insecure.to_string()));
    }
    // The in-cluster entry has no credential of its own — the controller uses its own
    // ServiceAccount — so an empty `auth` there is the normal case, not a finding.
    if e.auth == "none"
        && e.kind == EndpointKind::Cluster
        && normalize_url(&e.url) != normalize_url(IN_CLUSTER_URL)
    {
        out.push(warn(st.argo_cluster_no_auth.to_string()));
    }
    if e.kind == EndpointKind::Cluster && !e.namespaces.is_empty() {
        out.push(info(fill(
            st.argo_cluster_scoped,
            &[("ns", &e.namespaces.join(", "))],
        )));
    }
    if !e.project.is_empty() {
        out.push(info(fill(st.argo_endpoint_project, &[("project", &e.project)])));
    }
    out
}

fn server_hints(
    st: &'static Strings,
    server: &ArgoServer,
    apps: &[ArgoApp],
    endpoints: &[ArgoEndpoint],
) -> Vec<Hint> {
    let mut out = Vec::new();

    if server.namespace.is_empty() {
        out.push(warn(st.argo_no_settings.to_string()));
    }

    for c in &server.components {
        if c.ready < c.desired {
            let h = fill(
                st.argo_component_degraded,
                &[
                    ("name", &c.name),
                    ("ready", &c.ready.to_string()),
                    ("desired", &c.desired.to_string()),
                ],
            );
            if c.ready == 0 { out.push(danger(h)) } else { out.push(warn(h)) }
        }
    }

    // An Application outside the namespaces the controller honours is not managed by anything, and
    // looks exactly like one that is simply idle. Only checked once the install namespace is known.
    if !server.namespace.is_empty() {
        let stray: Vec<&str> = apps
            .iter()
            .filter(|a| {
                a.namespace != server.namespace
                    && !server.app_namespaces.iter().any(|p| ns_matches(p, &a.namespace))
            })
            .map(|a| a.namespace.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !stray.is_empty() {
            out.push(danger(fill(
                st.argo_apps_outside,
                &[("ns", &stray.join(", "))],
            )));
        }
    }

    let clusters = endpoints.iter().filter(|e| e.kind == EndpointKind::Cluster).count();
    let repos = endpoints.iter().filter(|e| e.kind == EndpointKind::Repo).count();
    if clusters == 0 && repos == 0 {
        out.push(info(st.argo_no_endpoints.to_string()));
    }

    out
}

/// `application.namespaces` accepts a trailing `*` glob, which is how a whole family of tenant
/// namespaces is opened at once.
fn ns_matches(pattern: &str, ns: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => ns.starts_with(prefix),
        None => pattern == ns,
    }
}

// --- Writes --------------------------------------------------------------------------------------

/// The four things this view writes. Each is exactly what the `argocd` CLI does through the API
/// server, expressed as the object mutation the controller actually watches — kdt adds no privilege
/// and no side channel of its own.
#[derive(Debug, Clone)]
pub enum ArgoWrite {
    /// Annotate the Application so the controller re-reads its sources. `hard` also throws the
    /// rendered-manifest cache away, which is the only thing that helps when the cache is what is
    /// wrong.
    Refresh { namespace: String, name: String, hard: bool },
    /// Set `.operation`, which is how a sync is requested. The revision is left empty on purpose:
    /// the controller then resolves the app's own `targetRevision` afresh, which is what
    /// `argocd app sync` without `--revision` does.
    Sync { namespace: String, name: String, prune: bool },
    /// Ask the controller to stop the operation in flight, by moving its phase to `Terminating`.
    Terminate { namespace: String, name: String },
}

impl ArgoWrite {
    pub fn target(&self) -> String {
        match self {
            ArgoWrite::Refresh { namespace, name, .. }
            | ArgoWrite::Sync { namespace, name, .. }
            | ArgoWrite::Terminate { namespace, name } => format!("{}/{}", namespace, name),
        }
    }
}

pub async fn apply_argo_write(client: Client, write: ArgoWrite) -> Result<(), String> {
    match write {
        ArgoWrite::Refresh { namespace, name, hard } => {
            let value = if hard { "hard" } else { "normal" };
            let patch = serde_json::json!({
                "metadata": { "annotations": { A_REFRESH: value } }
            });
            patch_app(&client, &namespace, &name, patch).await
        }
        ArgoWrite::Sync { namespace, name, prune } => {
            let patch = serde_json::json!({
                "operation": {
                    "initiatedBy": { "username": "kdt" },
                    "info": [{ "name": "Reason", "value": "triggered from kdt" }],
                    "sync": { "prune": prune, "syncStrategy": { "hook": {} } }
                }
            });
            patch_app(&client, &namespace, &name, patch).await
        }
        ArgoWrite::Terminate { namespace, name } => {
            // The Application CRD declares no status subresource, so the phase is reachable with an
            // ordinary merge patch — the same write the API server performs for `terminate-op`.
            let patch = serde_json::json!({
                "status": { "operationState": { "phase": "Terminating" } }
            });
            patch_app(&client, &namespace, &name, patch).await
        }
    }
}

async fn patch_app(client: &Client, namespace: &str, name: &str, patch: Value) -> Result<(), String> {
    let api = crate::yaml::dynamic_api(client, API_ARGO, KIND_APP, namespace).await?;
    api.patch(name, &kube::api::PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(())
}

// --- Helpers -------------------------------------------------------------------------------------

fn str_at(v: Option<&Value>, path: &[&str]) -> String {
    let mut cur = match v {
        Some(v) => v,
        None => return String::new(),
    };
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or("").to_string()
}

fn strings_at(v: Option<&Value>, path: &[&str]) -> Vec<String> {
    let mut cur = match v {
        Some(v) => v,
        None => return Vec::new(),
    };
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    cur.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn parse_ts(raw: &str) -> Option<i64> {
    if raw.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(raw).ok().map(|t| t.timestamp())
}

/// A Go duration as `argocd-cm` writes it (`180s`, `3m`, `1h30m`), in seconds. `0s` — Argo CD's way
/// of switching a timeout off — parses to zero, which every rule reading it treats as "no period".
fn parse_go_duration(raw: &str) -> Option<i64> {
    if raw.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    let mut seen = false;
    for c in raw.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let value: i64 = num.parse().ok()?;
        num.clear();
        let mult = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return None,
        };
        total += value * mult;
        seen = true;
    }
    if !num.is_empty() || !seen {
        return None;
    }
    // A zero period is a switched-off timeout, not a period of zero seconds.
    if total == 0 { None } else { Some(total) }
}

fn human_secs(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86400 {
        format!("{}h", s / 3600)
    } else {
        format!("{}d", s / 86400)
    }
}

/// The seven characters a commit is quoted by. A revision that is not a sha — a Helm chart version,
/// a branch name — is left alone: shortening `1.4.2` to `1.4.2` would be luck, not design.
fn short_revision(rev: &str) -> String {
    if rev.len() >= 40 && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        rev.chars().take(7).collect()
    } else {
        rev.to_string()
    }
}

/// A cluster API url as a human recognises it: the host, without the scheme or the port.
fn short_server(url: &str) -> String {
    if url == IN_CLUSTER_URL {
        return IN_CLUSTER_NAME.to_string();
    }
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url);
    host.rsplit_once(':')
        .map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { host })
        .unwrap_or(host)
        .to_string()
}

/// Two urls that address the same thing rarely look the same: a trailing slash, a `.git` suffix, a
/// difference in case. Repositories are matched on this form and nothing else.
fn normalize_url(url: &str) -> String {
    url.trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_lowercase()
}

fn clip(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= max {
        return s;
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn app(value: serde_json::Value) -> ArgoApp {
        let obj: DynamicObject = serde_json::from_value(value).unwrap();
        parse_app(&obj, 1_700_000_000, &HashMap::new())
    }

    #[test]
    fn automated_with_enabled_false_is_auto_sync_off() {
        // The trap the module header names: `automated` exists, and auto-sync is off.
        let a = app(json!({
            "apiVersion": API_ARGO, "kind": KIND_APP,
            "metadata": { "name": "a", "namespace": "argocd" },
            "spec": { "syncPolicy": { "automated": { "enabled": false, "prune": true } } }
        }));
        assert!(!a.auto);
        assert!(a.auto_disabled);
        assert_eq!(a.policy_label(), "manual");

        let on = app(json!({
            "apiVersion": API_ARGO, "kind": KIND_APP,
            "metadata": { "name": "a", "namespace": "argocd" },
            "spec": { "syncPolicy": { "automated": { "prune": true, "selfHeal": true } } }
        }));
        assert!(on.auto);
        assert!(!on.auto_disabled);
        assert_eq!(on.policy_label(), "auto+prune+heal");
    }

    #[test]
    fn unknown_sync_makes_a_green_health_stale() {
        // The shape read off the production cluster: git auth failed, so the comparison never ran,
        // and the health left on the object is the one from before the credential expired.
        let a = app(json!({
            "apiVersion": API_ARGO, "kind": KIND_APP,
            "metadata": { "name": "blanche", "namespace": "argocd" },
            "spec": { "project": "p", "source": { "repoURL": "https://git/x.git" },
                      "destination": { "server": IN_CLUSTER_URL, "namespace": "x" } },
            "status": {
                "sync": { "status": "Unknown" },
                "health": { "status": "Healthy" },
                "conditions": [{ "type": "ComparisonError", "message": "authentication required" }]
            }
        }));
        assert!(a.comparison_broken());
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let hints = app_hints(st, &a, None, false, false, &BTreeSet::new());
        assert!(hints.iter().any(|h| h.level == HintLevel::Danger && h.text.contains("authentication required")));
        // The health is not left standing on its own.
        assert!(hints.iter().any(|h| h.level == HintLevel::Warn && h.text.contains("Healthy")));
    }

    #[test]
    fn orphaned_resource_warning_is_a_setting_not_a_fault() {
        // The project asked to be told. That is a deliberate choice, so it stays informational.
        let a = app(json!({
            "apiVersion": API_ARGO, "kind": KIND_APP,
            "metadata": { "name": "a", "namespace": "argocd" },
            "spec": { "syncPolicy": { "automated": {} } },
            "status": {
                "sync": { "status": "Synced" }, "health": { "status": "Healthy" },
                "conditions": [{ "type": "OrphanedResourceWarning", "message": "10 orphaned resources" }]
            }
        }));
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let hints = app_hints(st, &a, None, false, false, &BTreeSet::new());
        let orphan = hints.iter().find(|h| h.text.contains("Orphaned")).expect("hint");
        assert_eq!(orphan.level, HintLevel::Info);
    }

    #[test]
    fn multi_source_apps_keep_every_source() {
        let a = app(json!({
            "apiVersion": API_ARGO, "kind": KIND_APP,
            "metadata": { "name": "a", "namespace": "argocd" },
            "spec": { "sources": [
                { "repoURL": "https://git/x.git", "path": "chart", "targetRevision": "main" },
                { "repoURL": "https://charts/", "chart": "redis", "targetRevision": "1.2.3" }
            ] }
        }));
        assert_eq!(a.sources.len(), 2);
        assert_eq!(a.sources[0].label(), "https://git/x.git//chart @ main");
        assert_eq!(a.sources[1].label(), "https://charts//redis @ 1.2.3");
    }

    #[test]
    fn revision_is_shortened_only_when_it_is_a_sha() {
        assert_eq!(short_revision("4097485d00206a5fb6ce11b7a3c8c6f3c294f770"), "4097485");
        assert_eq!(short_revision("1.4.2"), "1.4.2");
        assert_eq!(short_revision("main"), "main");
    }

    #[test]
    fn go_durations_and_the_switched_off_zero() {
        assert_eq!(parse_go_duration("180s"), Some(180));
        assert_eq!(parse_go_duration("3m"), Some(180));
        assert_eq!(parse_go_duration("1h30m"), Some(5400));
        // `0s` is how Argo CD switches the hard reconciliation off: not a zero-second period.
        assert_eq!(parse_go_duration("0s"), None);
        assert_eq!(parse_go_duration(""), None);
        assert_eq!(parse_go_duration("later"), None);
    }

    #[test]
    fn urls_match_across_the_git_suffix_and_the_trailing_slash() {
        assert_eq!(normalize_url("https://git/x.git"), normalize_url("https://git/x/"));
        assert_eq!(short_server("https://dsm-staging.privatelink.azmk8s.io:443"), "dsm-staging.privatelink.azmk8s.io");
        assert_eq!(short_server(IN_CLUSTER_URL), IN_CLUSTER_NAME);
    }

    #[test]
    fn a_generator_entry_names_its_kind() {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": API_ARGO, "kind": KIND_APPSET,
            "metadata": { "name": "s", "namespace": "argocd" },
            "spec": { "generators": [
                { "git": { "repoURL": "https://git/x" }, "selector": null },
                { "matrix": { "generators": [] } }
            ] }
        }))
        .unwrap();
        let s = parse_appset(&obj);
        assert_eq!(s.generators, vec!["git".to_string(), "matrix".to_string()]);
    }

    #[test]
    fn only_the_write_verbs_make_a_project_role_a_writer() {
        assert!(policy_writes("p, proj:x:ops, applications, sync, x/*, allow"));
        assert!(policy_writes("p, proj:x:ops, applications, update/*, x/a, allow"));
        assert!(!policy_writes("p, proj:x:ro, applications, get, x/*, allow"));
        assert!(!policy_writes("p, proj:x:ro, logs, get, x/*, allow"));
    }

    #[test]
    fn application_namespaces_honours_the_trailing_glob() {
        assert!(ns_matches("tenant-*", "tenant-a"));
        assert!(!ns_matches("tenant-*", "other"));
        assert!(ns_matches("argocd", "argocd"));
    }
}
