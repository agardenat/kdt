//! kdt-identity (`identity.kdt.sh`) local accounts, for the `:identity` view.
//!
//! Kubernetes has no `User` and no `Group`: authentication is delegated, and a group is a string
//! carried by a credential. kdt-identity fills that hole with two cluster-scoped CRDs and a
//! controller, and issues X.509 client certificates through the CSR API. This view is the operator
//! side of it — who exists, who is in what, and who can actually reach anything.
//!
//! Three shapes of the upstream project decide what this module may and may not show:
//!
//! * **The status lies by omission.** `status.lastLogin`, `lastIssuedAt`, `issuedCount` and the
//!   `conditions` of both CRDs are in the schema and are *never written* by the controller. No
//!   column here reads them. The phase `Locked` is in the enum and is never set either: lockout
//!   lives in the credential Secret, so it is read from there and named as such.
//! * **The invitation is not an API write.** `kdt-identity-server invite` needs the operator's own
//!   configuration and credential store; it can only run inside the controller pod. kdt execs it
//!   and captures the output rather than reimplementing the invitation crypto in a second repo.
//! * **Membership is held by the group, never by the user.** `status.memberOf` is derived. Adding
//!   someone is a JSON patch on `spec.members`; a merge patch replaces the whole array, which is
//!   how one silently deletes the other members.
//!
//! * **Revocation is a second Secret, and it is what makes the rest legible.** Since 1.0 a
//!   credential lives minutes and is renewed against a *session* held in the cluster, one Secret
//!   per account. Closing those sessions is the revocation, and it is the only reason an operator
//!   can act on someone's access at all — so the count of live sessions is a column, not a detail.
//! * **The delivery mode belongs to the deployment, not to a row.** `certificate` or `oidc` is a
//!   chart value, readable off the controller pod's environment, and it decides how long a
//!   revocation takes to bite and whether the non-revocable kubeconfig download exists at all.
//!   Absent variable, absent statement: kdt reads what the deployment declares and invents no
//!   default, because a missing variable also describes a pre-1.0 deployment.
//!
//! Nothing secret is carried into a row. The credential Secret is read by name for three
//! non-secret facts — when the pending invitation expires, whether the account is locked, and how
//! many attempts failed — and `password-hash` and `totp-secret` are never taken out of the map.
//! The sessions Secret is parsed into two timestamps per entry: `secretHash` has no field to land
//! in, so it cannot reach a row even by accident.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleBinding};
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;

use crate::events::format_age;
use crate::lang::{fill, Strings};

pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint {
    Hint { level: HintLevel::Info, text }
}
fn warn(text: String) -> Hint {
    Hint { level: HintLevel::Warn, text }
}

// --- API surface ---------------------------------------------------------------------------------

const G_IDENTITY: &str = "identity.kdt.sh";
const V_IDENTITY: &str = "v1alpha1";
pub const API_IDENTITY: &str = "identity.kdt.sh/v1alpha1";
pub const KIND_USER: &str = "KdtUser";
pub const KIND_GROUP: &str = "KdtGroup";

const KINDS: &[&str] = &[KIND_USER, KIND_GROUP];

/// The prefix every identity kdt-identity issues carries. Not disableable upstream, which is what
/// makes a `kdt:`-prefixed RBAC subject attributable to this system and to nothing else.
pub const SUBJECT_PREFIX: &str = "kdt:";

/// The chart's own labels on the controller pod. The Deployment is named `<fullname>-controller`,
/// and `fullnameOverride` changes that in practice — so the pod is found by label, never by name.
pub const CONTROLLER_SELECTOR: &str =
    "app.kubernetes.io/name=kdt-identity,app.kubernetes.io/component=controller";
/// The container the chart declares. Read off the pod when present rather than assumed.
const CONTROLLER_CONTAINER: &str = "controller";
/// Absolute, because the image is `FROM scratch`: it has neither a shell nor a `PATH`.
const SERVER_BIN: &str = "/usr/local/bin/kdt-identity-server";

/// Name prefix of the per-user credential Secret, from the upstream `CredentialStore`.
const CRED_SECRET_PREFIX: &str = "kdt-identity-cred-";
const K_INVITE_EXPIRES: &str = "invite-expires-at";
const K_LOCKED_UNTIL: &str = "locked-until";
const K_FAILED_ATTEMPTS: &str = "failed-attempts";

/// Name prefix of the per-user *sessions* Secret. `oidc-` in both delivery modes: upstream named
/// it when sessions were an OIDC detail, then found the mechanism was not OIDC at all and kept the
/// name. Reading it under another name would find nothing on a certificate-mode cluster.
const SESSION_SECRET_PREFIX: &str = "kdt-identity-oidc-";
const K_SESSIONS: &str = "sessions";

/// What the chart puts on both Deployments. The controller carries them too — the admin commands
/// run there — which is why one pod answers for the whole deployment.
const ENV_MODE: &str = "KDT_IDENTITY_CREDENTIAL_MODE";
const ENV_CERT_TTL: &str = "KDT_IDENTITY_CERT_TTL";
const ENV_TOKEN_TTL: &str = "KDT_IDENTITY_OIDC_TOKEN_TTL";
const ENV_REFRESH_TTL: &str = "KDT_IDENTITY_REFRESH_TTL";
const ENV_KUBECONFIG_DOWNLOAD: &str = "KDT_IDENTITY_KUBECONFIG_DOWNLOAD";

/// Default validity offered for a new invitation, matching the upstream default.
pub const DEFAULT_VALIDITY: &str = "72h";

// --- Rows ----------------------------------------------------------------------------------------

/// What the PHASE column shows. `Locked` is kdt's own: the controller never writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Unknown,
    Pending,
    Active,
    Disabled,
    Locked,
}

impl Phase {
    pub fn label(&self, st: &'static Strings) -> &'static str {
        match self {
            Phase::Unknown => st.ident_phase_unknown,
            Phase::Pending => st.ident_phase_pending,
            Phase::Active => st.ident_phase_active,
            Phase::Disabled => st.ident_phase_disabled,
            Phase::Locked => st.ident_phase_locked,
        }
    }
}

/// State of the pending invitation, as far as the credential Secret says.
///
/// `Unreadable` is not `None`: a Secret that cannot be read says nothing about whether an
/// invitation is outstanding, and the two must not render alike in the operator's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Invitation {
    /// No credential Secret: the account was created and never invited.
    #[default]
    None,
    Pending {
        expires: i64,
    },
    Expired {
        expires: i64,
    },
    Unreadable,
}

/// The three non-secret facts read out of the credential Secret.
#[derive(Debug, Clone, Default)]
pub struct CredentialFacts {
    pub invite_expires: Option<i64>,
    pub locked_until: Option<i64>,
    pub failed_attempts: u32,
}

/// How this deployment hands out credentials. A property of the cluster, chosen once at install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// X.509 signed by the cluster CA. Needs nothing of the apiserver, and offers a downloadable
    /// kubeconfig that no revocation reaches.
    Certificate,
    /// A token kdt-identity signs and the apiserver validates. Needs the control plane configured,
    /// and has no downloadable kubeconfig at all.
    Oidc,
}

impl CredentialMode {
    pub fn label(&self) -> &'static str {
        match self {
            CredentialMode::Certificate => "certificate",
            CredentialMode::Oidc => "oidc",
        }
    }
}

/// What the deployment declares about delivery, read off the controller pod's environment.
///
/// Every field is an `Option` on purpose. Upstream defaults `credentialMode` to `certificate` when
/// the variable is unset, but an unset variable also describes a 0.1 deployment that had no modes,
/// no sessions and no `revoke` — so kdt reports the absence rather than restating a default that
/// would make a pre-1.0 cluster look like a configured one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delivery {
    pub mode: Option<CredentialMode>,
    pub cert_ttl: Option<String>,
    pub token_ttl: Option<String>,
    pub refresh_ttl: Option<String>,
    /// Only rendered by the chart in certificate mode; `None` in OIDC, where the path does not
    /// exist.
    pub kubeconfig_download: Option<bool>,
}

impl Delivery {
    /// How long an access survives its revocation: the TTL of whatever is handed out in this mode.
    /// `None` when the deployment says neither, in which case kdt states no window at all.
    pub fn revocation_window(&self) -> Option<&str> {
        match self.mode? {
            CredentialMode::Certificate => self.cert_ttl.as_deref(),
            CredentialMode::Oidc => self.token_ttl.as_deref(),
        }
    }

    /// Whether the one access revocation cannot reach is open. Certificate mode only, and only
    /// when the download was left on.
    pub fn download_open(&self) -> bool {
        self.mode == Some(CredentialMode::Certificate) && self.kubeconfig_download == Some(true)
    }
}

/// The sessions of one account, as far as its sessions Secret says.
///
/// Only the two timestamps of each entry are parsed. The identifier and the hash of the refresh
/// secret have no field to land in, which is a stronger guarantee than a rule not to display them.
#[derive(Debug, Clone, Default)]
pub struct SessionFacts {
    pub open: usize,
    /// Entries past their expiry. Upstream prunes them on the next write, so they are stale rows,
    /// not access — and counting them as open would overstate what a revocation would close.
    pub stale: usize,
    /// When the last session standing runs out on its own.
    pub last_expiry: Option<i64>,
}

/// A binding whose subject is one of this system's groups.
#[derive(Debug, Clone)]
pub struct BindingRef {
    /// `RoleBinding` or `ClusterRoleBinding`.
    pub kind: String,
    /// Empty for a ClusterRoleBinding.
    pub namespace: String,
    pub name: String,
    /// `ClusterRole/edit`, `Role/reader` — what the binding actually grants.
    pub role: String,
}

impl BindingRef {
    /// How the detail panel names it. The kind is spelled out rather than inferred from an empty
    /// namespace: a ClusterRoleBinding to `cluster-admin` and a RoleBinding in one namespace are
    /// not the same news, and the reader should not have to deduce which one this is.
    pub fn label(&self) -> String {
        if self.namespace.is_empty() {
            format!("{} {} → {}", self.kind, self.name, self.role)
        } else {
            format!("{} {}/{} → {}", self.kind, self.namespace, self.name, self.role)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IdentUser {
    pub name: String,
    pub email: String,
    pub display_name: String,
    pub disabled: bool,
    pub phase: Phase,
    /// What `status.phase` actually said, kept so the detail panel can show kdt's `Locked` next to
    /// the controller's own word instead of quietly overwriting it.
    pub raw_phase: String,
    pub member_of: Vec<String>,
    pub invitation: Invitation,
    pub creds: Option<CredentialFacts>,
    /// `None` when the sessions Secret could not be read at all, which is not the same news as an
    /// account that has never opened one — that is `Some` with a zero count.
    pub sessions: Option<SessionFacts>,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

impl IdentUser {
    /// The identity the apiserver will see. Built the same way upstream builds it, and shown so
    /// nobody has to guess that the prefix is there.
    pub fn subject(&self) -> String {
        format!("{SUBJECT_PREFIX}{}", self.name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct IdentGroup {
    pub name: String,
    /// `status.subject`, published by the controller. Empty until it has reconciled once.
    pub subject: String,
    pub description: String,
    /// `spec.members`, in order — the index is what a JSON patch removal needs.
    pub members: Vec<String>,
    pub resolved: Vec<String>,
    pub unknown: Vec<String>,
    pub bindings: Vec<BindingRef>,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

impl IdentGroup {
    /// The subject to reference in a binding. Falls back to the derived form when the controller
    /// has not published one yet — the rule is fixed upstream, so this is a restatement, not a
    /// guess.
    pub fn effective_subject(&self) -> String {
        if self.subject.is_empty() {
            format!("{SUBJECT_PREFIX}{}", self.name)
        } else {
            self.subject.clone()
        }
    }
}

/// Where the `invite` command can be run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerRef {
    pub namespace: String,
    pub pod: String,
    pub container: String,
}

// --- State ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct IdentityState {
    pub users: Vec<IdentUser>,
    pub groups: Vec<IdentGroup>,
    /// Resolved controller pod, or `None` — in which case inviting is unavailable and says so.
    pub controller: Option<ControllerRef>,
    /// What the deployment declares about how it delivers and revokes access.
    pub delivery: Delivery,
    /// Why the credential Secrets could not be read, when that is the case. One statement for the
    /// whole view rather than a dash on every row.
    pub creds_error: Option<String>,
    /// Same, for the sessions Secrets. Kept apart from `creds_error`: the two are different reads
    /// and silence one column each, so merging them would blame the wrong column.
    pub sessions_error: Option<String>,
    pub installed: bool,
    pub error: Option<String>,
    pub loading: bool,
}

impl IdentityState {
    pub fn active_users(&self) -> usize {
        self.users.iter().filter(|u| u.phase == Phase::Active).count()
    }

    /// Groups nothing references. The number that says whether this directory grants anything at
    /// all.
    pub fn unbound_groups(&self) -> usize {
        self.groups.iter().filter(|g| g.bindings.is_empty()).count()
    }

    /// Accounts holding at least one live session — the ones a revocation would actually cut.
    pub fn connected_users(&self) -> usize {
        self.users
            .iter()
            .filter(|u| u.sessions.as_ref().is_some_and(|s| s.open > 0))
            .count()
    }
}

pub type SharedIdentity = Arc<Mutex<IdentityState>>;

pub fn new_identity_state() -> SharedIdentity {
    Arc::new(Mutex::new(IdentityState::default()))
}

// --- Fetch ---------------------------------------------------------------------------------------

pub async fn fetch_identity(client: Client, state: SharedIdentity) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("identity poisoned");
        s.loading = true;
        s.error = None;
    }

    // Discovery as one wave, like every other add-on view: sequential probes on a remote cluster
    // are seconds of blank screen.
    let probes = KINDS.iter().map(|kind| {
        let client = client.clone();
        async move {
            let gvk = GroupVersionKind::gvk(G_IDENTITY, V_IDENTITY, kind);
            match discovery::pinned_kind(&client, &gvk).await {
                Ok((ar, _)) => Some((*kind, ar)),
                Err(_) => None,
            }
        }
    });
    let resolved: Vec<_> = futures::future::join_all(probes).await.into_iter().flatten().collect();

    if resolved.is_empty() {
        // The view still opens — saying kdt-identity is not here *is* the answer to "does this
        // cluster have local accounts". Whether Rancher answers is checked so the message can send
        // the reader to the directory that does exist.
        let rancher_present = rancher_answers(&client).await;
        let mut s = state.lock().expect("identity poisoned");
        *s = IdentityState {
            loading: false,
            error: Some(if rancher_present {
                st.ident_absent_rancher.to_string()
            } else {
                st.ident_absent.to_string()
            }),
            ..IdentityState::default()
        };
        return;
    }

    let lists = resolved.iter().map(|(kind, ar)| {
        let client = client.clone();
        let ar = ar.clone();
        let kind = *kind;
        async move {
            let api: Api<DynamicObject> = Api::all_with(client, &ar);
            let out = api.list(&ListParams::default()).await.map(|l| l.items).map_err(|e| e.to_string());
            (kind, out)
        }
    });

    let (results, bindings, controller) = futures::join!(
        futures::future::join_all(lists),
        list_group_bindings(&client),
        find_controller(&client),
    );

    let mut listed: BTreeMap<&'static str, Vec<DynamicObject>> = BTreeMap::new();
    let mut list_error: Option<String> = None;
    for (kind, r) in results {
        match r {
            Ok(v) => {
                listed.insert(kind, v);
            }
            // A kind served by the cluster that refuses to list is not an absence: say it.
            Err(e) => list_error = Some(fill(st.ident_list_failed, &[("kind", kind), ("e", &e)])),
        }
    }

    let user_objs = listed.remove(KIND_USER).unwrap_or_default();
    let group_objs = listed.remove(KIND_GROUP).unwrap_or_default();

    // Credentials and sessions only once the operator namespace is known — it comes from the
    // controller pod, and there is nowhere else to read it from. Both Secrets are fetched in one
    // wave: they are two `get`s per account, and doing them in turn doubles the wait on a
    // directory of any size.
    let (creds, creds_error, sessions, sessions_error) = match &controller {
        Some((c, _)) => {
            let names: Vec<String> =
                user_objs.iter().filter_map(|o| o.metadata.name.clone()).collect();
            let (creds, sessions) = futures::join!(
                read_credentials(&client, &c.namespace, &names),
                read_sessions(&client, &c.namespace, &names),
            );
            (creds.0, creds.1, sessions.0, sessions.1)
        }
        None => (BTreeMap::new(), None, BTreeMap::new(), None),
    };

    let (controller, delivery) = match controller {
        Some((c, d)) => (Some(c), d),
        None => (None, Delivery::default()),
    };

    let mut next = IdentityState {
        groups: build_groups(st, &group_objs, &user_objs, &bindings),
        users: build_users(
            st,
            &user_objs,
            &group_objs,
            &creds,
            creds_error.is_some(),
            &sessions,
        ),
        controller,
        delivery,
        creds_error,
        sessions_error,
        installed: true,
        error: list_error,
        loading: false,
    };
    if next.controller.is_none() && next.error.is_none() {
        next.error = Some(fill(st.ident_no_controller, &[("sel", CONTROLLER_SELECTOR)]));
    }
    *state.lock().expect("identity poisoned") = next;
}

/// Whether `management.cattle.io` is served here. One probe, only ever asked when kdt-identity is
/// absent.
async fn rancher_answers(client: &Client) -> bool {
    let gvk = GroupVersionKind::gvk("management.cattle.io", "v3", "User");
    discovery::pinned_kind(client, &gvk).await.is_ok()
}

/// Every binding whose subject is a `kdt:`-prefixed group, indexed by that subject.
///
/// Listing both binding kinds cluster-wide is the same read `:rbac` already does; doing it here
/// keeps the two views independent rather than coupling this one to the graph's state.
async fn list_group_bindings(client: &Client) -> BTreeMap<String, Vec<BindingRef>> {
    let rb_api: Api<RoleBinding> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let params = ListParams::default();
    let (rbs, crbs) = futures::join!(rb_api.list(&params), crb_api.list(&params));

    let mut out: BTreeMap<String, Vec<BindingRef>> = BTreeMap::new();
    if let Ok(list) = rbs {
        for b in list.items {
            let name = b.metadata.name.clone().unwrap_or_default();
            let namespace = b.metadata.namespace.clone().unwrap_or_default();
            let role = format!("{}/{}", b.role_ref.kind, b.role_ref.name);
            for s in b.subjects.iter().flatten() {
                if is_group_subject(&s.kind, &s.name) {
                    out.entry(s.name.clone()).or_default().push(BindingRef {
                        kind: "RoleBinding".to_string(),
                        namespace: namespace.clone(),
                        name: name.clone(),
                        role: role.clone(),
                    });
                }
            }
        }
    }
    if let Ok(list) = crbs {
        for b in list.items {
            let name = b.metadata.name.clone().unwrap_or_default();
            let role = format!("{}/{}", b.role_ref.kind, b.role_ref.name);
            for s in b.subjects.iter().flatten() {
                if is_group_subject(&s.kind, &s.name) {
                    out.entry(s.name.clone()).or_default().push(BindingRef {
                        kind: "ClusterRoleBinding".to_string(),
                        namespace: String::new(),
                        name: name.clone(),
                        role: role.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Whether an RBAC subject is one of this system's groups. Public because `:rbac` names the
/// provenance of a grant with the very same test.
pub fn is_group_subject(kind: &str, name: &str) -> bool {
    kind == "Group" && name.starts_with(SUBJECT_PREFIX)
}

/// The controller pod, by the chart's labels. Everything about it is read: the namespace, the pod
/// name, the container, and the delivery settings the chart wrote into its environment. Nothing is
/// defaulted into a plausible value.
async fn find_controller(client: &Client) -> Option<(ControllerRef, Delivery)> {
    let pods: Api<Pod> = Api::all(client.clone());
    let list = pods
        .list(&ListParams::default().labels(CONTROLLER_SELECTOR))
        .await
        .ok()?;

    list.items.into_iter().find_map(|p| {
        let running = p
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .map(|ph| ph == "Running")
            .unwrap_or(false);
        if !running {
            return None;
        }
        let containers = p.spec.as_ref().map(|s| s.containers.as_slice()).unwrap_or(&[]);
        // The chart names it `controller`; a single-container pod answers for itself.
        let container = containers
            .iter()
            .find(|c| c.name == CONTROLLER_CONTAINER)
            .or_else(|| if containers.len() == 1 { containers.first() } else { None })?;
        let delivery = delivery_from_env(container);
        Some((
            ControllerRef {
                namespace: p.metadata.namespace.clone().unwrap_or_default(),
                pod: p.metadata.name.clone().unwrap_or_default(),
                container: container.name.clone(),
            },
            delivery,
        ))
    })
}

/// The delivery settings, from the container's literal `env` values.
///
/// Only plain values are read: a `valueFrom` carries no value here, and resolving one would mean
/// guessing at a Secret kdt has no reason to open. An unreadable variable is an absent one.
fn delivery_from_env(container: &k8s_openapi::api::core::v1::Container) -> Delivery {
    let get = |key: &str| -> Option<String> {
        container
            .env
            .as_ref()?
            .iter()
            .find(|e| e.name == key)
            .and_then(|e| e.value.clone())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Delivery {
        mode: get(ENV_MODE).and_then(|v| match v.as_str() {
            "certificate" => Some(CredentialMode::Certificate),
            "oidc" => Some(CredentialMode::Oidc),
            _ => None,
        }),
        cert_ttl: get(ENV_CERT_TTL),
        token_ttl: get(ENV_TOKEN_TTL),
        refresh_ttl: get(ENV_REFRESH_TTL),
        kubeconfig_download: get(ENV_KUBECONFIG_DOWNLOAD).and_then(|v| match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }),
    }
}

/// The three non-secret facts of each credential Secret.
///
/// Read one by one **by name**, never listed. The upstream Role deliberately withholds `list` on
/// Secrets so that the controller cannot enumerate accounts; kdt holds an admin kubeconfig and
/// could list anyway, and does not — the shape of the read is part of what the design says.
///
/// A 404 is an answer: that account was never invited. Anything else is reported once, for the
/// whole view.
async fn read_credentials(
    client: &Client,
    namespace: &str,
    users: &[String],
) -> (BTreeMap<String, CredentialFacts>, Option<String>) {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let gets = users.iter().map(|u| {
        let api = api.clone();
        let user = u.clone();
        async move {
            let name = format!("{CRED_SECRET_PREFIX}{user}");
            (user, api.get_opt(&name).await)
        }
    });

    let mut out = BTreeMap::new();
    let mut error = None;
    for (user, res) in futures::future::join_all(gets).await {
        match res {
            Ok(Some(secret)) => {
                out.insert(user, credential_facts(&secret));
            }
            Ok(None) => {}
            Err(e) => {
                error.get_or_insert_with(|| crate::edit::api_error_text(e));
            }
        }
    }
    (out, error)
}

/// The sessions of each account, read the same way as the credentials: by name, one `get` per
/// account, never a `list`.
///
/// A 404 is an answer and the honest one: that account has never opened a session, which is a zero
/// count and not an unknown. Only an actual failure leaves an account without facts.
async fn read_sessions(
    client: &Client,
    namespace: &str,
    users: &[String],
) -> (BTreeMap<String, SessionFacts>, Option<String>) {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let now = now_secs();
    let gets = users.iter().map(|u| {
        let api = api.clone();
        let user = u.clone();
        async move {
            let name = format!("{SESSION_SECRET_PREFIX}{user}");
            (user, api.get_opt(&name).await)
        }
    });

    let mut out = BTreeMap::new();
    let mut error = None;
    for (user, res) in futures::future::join_all(gets).await {
        match res {
            Ok(Some(secret)) => {
                out.insert(user, session_facts(&secret, now));
            }
            Ok(None) => {
                out.insert(user, SessionFacts::default());
            }
            Err(e) => {
                error.get_or_insert_with(|| crate::edit::api_error_text(e));
            }
        }
    }
    (out, error)
}

/// One session entry, cut down to what a row may show.
///
/// The upstream entry also carries `id` and `secretHash`; neither is declared here, so no amount
/// of later editing can leak them into a cell. Unparseable JSON yields no entries rather than an
/// invented count.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionEntry {
    expires_at: String,
}

pub fn session_facts(secret: &Secret, now: i64) -> SessionFacts {
    let raw = secret.data.as_ref().and_then(|d| d.get(K_SESSIONS));
    let entries: Vec<SessionEntry> = raw
        .and_then(|b| serde_json::from_slice(&b.0).ok())
        .unwrap_or_default();

    let mut facts = SessionFacts::default();
    for e in &entries {
        let Some(expires) = parse_rfc3339(&e.expires_at) else { continue };
        if expires > now {
            facts.open += 1;
            facts.last_expiry = Some(facts.last_expiry.map_or(expires, |cur: i64| cur.max(expires)));
        } else {
            facts.stale += 1;
        }
    }
    facts
}

/// Only the three fields that are not credentials. `password-hash` and `totp-secret` are in the
/// same map and are never touched.
fn credential_facts(secret: &Secret) -> CredentialFacts {
    let text = |key: &str| -> Option<String> {
        secret
            .data
            .as_ref()
            .and_then(|d| d.get(key))
            .and_then(|b| String::from_utf8(b.0.clone()).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    CredentialFacts {
        invite_expires: text(K_INVITE_EXPIRES).as_deref().and_then(parse_rfc3339),
        locked_until: text(K_LOCKED_UNTIL).as_deref().and_then(parse_rfc3339),
        failed_attempts: text(K_FAILED_ATTEMPTS).and_then(|s| s.parse().ok()).unwrap_or(0),
    }
}

fn parse_rfc3339(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw).ok().map(|t| t.timestamp())
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

// --- Builders ------------------------------------------------------------------------------------

fn build_users(
    st: &'static Strings,
    objs: &[DynamicObject],
    groups: &[DynamicObject],
    creds: &BTreeMap<String, CredentialFacts>,
    creds_unreadable: bool,
    sessions: &BTreeMap<String, SessionFacts>,
) -> Vec<IdentUser> {
    // Who is listed where, straight off `spec.members` — the source of truth. `status.memberOf` is
    // derived and can lag a reconciliation behind, so it is not what the "still a member" checks
    // read.
    let mut listed_in: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for g in groups {
        let gname = g.metadata.name.clone().unwrap_or_default();
        for m in spec_members(g) {
            listed_in.entry(m).or_default().push(gname.clone());
        }
    }

    let now = now_secs();
    let mut out: Vec<IdentUser> = objs
        .iter()
        .map(|o| {
            let name = o.metadata.name.clone().unwrap_or_default();
            let spec = o.data.get("spec").cloned().unwrap_or(Value::Null);
            let status = o.data.get("status").cloned().unwrap_or(Value::Null);

            let disabled = spec.get("disabled").and_then(Value::as_bool).unwrap_or(false);
            let raw_phase = str_at(&status, "phase").unwrap_or_default();
            let facts = creds.get(&name).cloned();

            let locked = facts
                .as_ref()
                .and_then(|f| f.locked_until)
                .map(|t| t > now)
                .unwrap_or(false);

            // `Locked` is never written by the controller; it is derived here, and the hint below
            // says where it came from so nobody goes looking for it in the CRD.
            let phase = if disabled {
                Phase::Disabled
            } else if locked {
                Phase::Locked
            } else {
                match raw_phase.as_str() {
                    "Pending" => Phase::Pending,
                    "Active" => Phase::Active,
                    "Disabled" => Phase::Disabled,
                    "Locked" => Phase::Locked,
                    _ => Phase::Unknown,
                }
            };

            let invitation = match (&facts, creds_unreadable) {
                (_, true) => Invitation::Unreadable,
                (None, false) => Invitation::None,
                (Some(f), false) => match f.invite_expires {
                    Some(exp) if exp > now => Invitation::Pending { expires: exp },
                    Some(exp) => Invitation::Expired { expires: exp },
                    None => Invitation::None,
                },
            };

            let member_of = arr_at(&status, "memberOf");
            let age = o
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_default();

            let mut user = IdentUser {
                email: str_at(&spec, "email").unwrap_or_default(),
                display_name: str_at(&spec, "displayName").unwrap_or_default(),
                disabled,
                phase,
                raw_phase,
                member_of,
                invitation,
                creds: facts,
                sessions: sessions.get(&name).cloned(),
                age,
                uid: o.metadata.uid.clone().unwrap_or_default(),
                hints: Vec::new(),
                name,
            };
            user.hints = user_hints(st, &user, listed_in.get(&user.name).map(Vec::as_slice));
            user
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn user_hints(
    st: &'static Strings,
    u: &IdentUser,
    listed_in: Option<&[String]>,
) -> Vec<Hint> {
    let mut out = Vec::new();

    if u.phase == Phase::Locked && !u.disabled {
        let until = u
            .creds
            .as_ref()
            .and_then(|f| f.locked_until)
            .map(format_stamp)
            .unwrap_or_default();
        let attempts = u.creds.as_ref().map(|f| f.failed_attempts).unwrap_or(0).to_string();
        out.push(warn(fill(
            st.ident_hint_locked,
            &[("until", &until), ("n", &attempts)],
        )));
    }

    if let Invitation::Expired { expires } = u.invitation {
        out.push(warn(fill(
            st.ident_hint_invite_expired,
            &[("date", &format_stamp(expires))],
        )));
    }

    // An account that authenticates and is in no group gets what any authenticated identity gets:
    // self-reviews and API discovery. Worth naming, never an alert.
    if u.phase == Phase::Active && u.member_of.is_empty() {
        out.push(info(st.ident_hint_no_group.to_string()));
    }

    // Disabling blocks issuance; it does not take the name out of any group. The member list is the
    // one an operator has to clean by hand.
    if u.disabled {
        if let Some(groups) = listed_in.filter(|g| !g.is_empty()) {
            out.push(info(fill(
                st.ident_hint_disabled_member,
                &[("groups", &groups.join(", "))],
            )));
        }
    }

    let open = u.sessions.as_ref().map(|s| s.open).unwrap_or(0);

    // Since 1.0 the controller closes the sessions of a disabled account by itself. Finding them
    // still open is not a state to explain away: it says the controller has not reconciled this
    // account, and the person is still renewing access every few minutes.
    if u.disabled && open > 0 {
        out.push(warn(fill(
            st.ident_hint_disabled_sessions,
            &[("n", &open.to_string())],
        )));
    }

    out
}

fn build_groups(
    st: &'static Strings,
    objs: &[DynamicObject],
    users: &[DynamicObject],
    bindings: &BTreeMap<String, Vec<BindingRef>>,
) -> Vec<IdentGroup> {
    let known: BTreeSet<String> =
        users.iter().filter_map(|o| o.metadata.name.clone()).collect();

    let mut out: Vec<IdentGroup> = objs
        .iter()
        .map(|o| {
            let name = o.metadata.name.clone().unwrap_or_default();
            let spec = o.data.get("spec").cloned().unwrap_or(Value::Null);
            let status = o.data.get("status").cloned().unwrap_or(Value::Null);

            let members = spec_members(o);
            // `status.resolvedMembers` / `unknownMembers` are written by the controller and are the
            // authority. They are recomputed here only when the status has not landed yet, so a
            // freshly created group does not read as "no unknown members" before its first
            // reconciliation.
            let status_resolved = arr_at(&status, "resolvedMembers");
            let status_unknown = arr_at(&status, "unknownMembers");
            let reconciled = status.get("resolvedMembers").is_some()
                || status.get("unknownMembers").is_some();
            let (resolved, unknown) = if reconciled {
                (status_resolved, status_unknown)
            } else {
                members.iter().cloned().partition(|m| known.contains(m))
            };

            let subject = str_at(&status, "subject").unwrap_or_default();
            let age = o
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_default();

            let mut group = IdentGroup {
                subject,
                description: str_at(&spec, "description").unwrap_or_default(),
                members,
                resolved,
                unknown,
                bindings: Vec::new(),
                age,
                uid: o.metadata.uid.clone().unwrap_or_default(),
                hints: Vec::new(),
                name,
            };
            group.bindings =
                bindings.get(&group.effective_subject()).cloned().unwrap_or_default();
            group.hints = group_hints(st, &group);
            group
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn group_hints(st: &'static Strings, g: &IdentGroup) -> Vec<Hint> {
    let mut out = Vec::new();

    if !g.unknown.is_empty() {
        out.push(warn(fill(
            st.ident_hint_unknown_members,
            &[("members", &g.unknown.join(", "))],
        )));
    }

    // A group nothing references grants nothing. It stays Info: at creation that is simply what a
    // group looks like, and a badge marks the exception, not the norm.
    if g.bindings.is_empty() {
        out.push(info(fill(
            st.ident_hint_no_binding,
            &[("subject", &g.effective_subject())],
        )));
    }

    out
}

// --- Formatting ----------------------------------------------------------------------------------

/// What the INVITATION column shows: how long is left, or that it ran out.
pub fn invitation_label(inv: &Invitation, st: &'static Strings) -> String {
    match inv {
        Invitation::None => st.ident_inv_none.to_string(),
        Invitation::Unreadable => st.ident_inv_unreadable.to_string(),
        Invitation::Expired { .. } => st.ident_inv_expired.to_string(),
        Invitation::Pending { expires } => format_left(expires - now_secs()),
    }
}

/// A remaining duration, in the same shape as an age so the two columns read alike.
pub fn format_left(secs: i64) -> String {
    let secs = secs.max(0) as u64;
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// An absolute stamp for the detail panel, where "in 3 days" is not enough to plan a phone call.
pub fn format_stamp(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|t| t.format("%d/%m/%Y %H:%M UTC").to_string())
        .unwrap_or_default()
}

fn str_at(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn arr_at(data: &Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn spec_members(o: &DynamicObject) -> Vec<String> {
    o.data
        .get("spec")
        .map(|s| arr_at(s, "members"))
        .unwrap_or_default()
}

// --- Writes --------------------------------------------------------------------------------------

/// What this view is allowed to write.
///
/// Creating an account and a group is two small objects; the two that earn their place are
/// membership — always as a JSON patch, because a merge patch replaces the array and drops the
/// other members — and the invitation, which is not an API write at all.
#[derive(Debug, Clone)]
pub enum IdentityWrite {
    CreateUser { name: String, email: String, display_name: String },
    CreateGroup { name: String, description: String },
    /// Blocks every new issuance immediately. Certificates already handed out keep working until
    /// they expire: Kubernetes consults no CRL.
    SetDisabled { user: String, disabled: bool },
    AddMember { group: String, user: String },
    /// The index in `spec.members`, which is what a JSON patch removal addresses.
    RemoveMember { group: String, user: String, index: usize },
    /// Runs `kdt-identity-server invite` inside the controller pod.
    Invite { user: String, validity: String, controller: Box<ControllerRef> },
    /// Closes every open session of an account, on every machine. Runs
    /// `kdt-identity-server revoke` inside the controller pod, for the same reason the invitation
    /// does: the command needs the operator's own configuration and session store.
    ///
    /// This is not `spec.disabled`. It logs someone out — a lost laptop — and leaves them free to
    /// sign in again from anywhere. Cutting an account off is the field on the spec.
    Revoke { user: String, controller: Box<ControllerRef> },
}

impl IdentityWrite {
    /// What the confirmation line names.
    pub fn target(&self) -> String {
        match self {
            IdentityWrite::CreateUser { name, .. } | IdentityWrite::CreateGroup { name, .. } => {
                name.clone()
            }
            IdentityWrite::SetDisabled { user, .. }
            | IdentityWrite::Invite { user, .. }
            | IdentityWrite::Revoke { user, .. } => user.clone(),
            IdentityWrite::AddMember { group, user } => format!("{user} → {group}"),
            IdentityWrite::RemoveMember { group, user, .. } => format!("{user} ✗ {group}"),
        }
    }
}

/// An invitation as handed back by [`apply_identity_write`], exactly once.
///
/// The link and the code exist in this struct and nowhere else — upstream refuses to log them or
/// to write them into the status, and kdt holds the same line: never in the state, never on disk.
/// They are meant to travel by two different channels, which is why they are copied separately.
#[derive(Debug, Clone)]
pub struct IdentInvite {
    pub user: String,
    pub expires: String,
    pub link: Option<String>,
    pub code: Option<String>,
    /// What the command actually printed. Shown as-is when the two fields above could not be
    /// picked out of it, so an operator is never left with nothing because a wording changed.
    pub raw: String,
}

/// What a write hands back.
///
/// Three shapes rather than one, because the three outcomes are not interchangeable: an API write
/// says nothing, an invitation carries values that exist once and must land in their own overlay,
/// and a command run in the pod has its own words — how many sessions it closed, and how long the
/// access it did not close still lives — which kdt reports rather than paraphrases.
#[derive(Debug, Clone)]
pub enum WriteOutcome {
    Done,
    Invited(Box<IdentInvite>),
    Said(String),
}

pub async fn apply_identity_write(
    client: Client,
    write: IdentityWrite,
) -> Result<WriteOutcome, String> {
    match write {
        IdentityWrite::CreateUser { name, email, display_name } => {
            let body = user_payload(&name, &email, &display_name);
            create(&client, KIND_USER, body).await?;
            Ok(WriteOutcome::Done)
        }
        IdentityWrite::CreateGroup { name, description } => {
            let body = group_payload(&name, &description);
            create(&client, KIND_GROUP, body).await?;
            Ok(WriteOutcome::Done)
        }
        IdentityWrite::SetDisabled { user, disabled } => {
            // A scalar: a merge patch is the right shape here, unlike on `members`.
            let patch = serde_json::json!({ "spec": { "disabled": disabled } });
            let api = identity_api(&client, KIND_USER).await?;
            api.patch(&user, &kube::api::PatchParams::default(), &kube::api::Patch::Merge(&patch))
                .await
                .map_err(crate::edit::api_error_text)?;
            Ok(WriteOutcome::Done)
        }
        IdentityWrite::AddMember { group, user } => {
            json_patch_members(&client, &group, add_member_patch(&user)).await?;
            Ok(WriteOutcome::Done)
        }
        IdentityWrite::RemoveMember { group, user, index } => {
            json_patch_members(&client, &group, remove_member_patch(index, &user)).await?;
            Ok(WriteOutcome::Done)
        }
        IdentityWrite::Invite { user, validity, controller } => {
            let invite = run_invite(&client, &controller, &user, &validity).await?;
            Ok(WriteOutcome::Invited(Box::new(invite)))
        }
        IdentityWrite::Revoke { user, controller } => {
            let said = run_in_controller(&client, &controller, &["revoke", &user]).await?;
            Ok(WriteOutcome::Said(said))
        }
    }
}

async fn identity_api(client: &Client, kind: &str) -> Result<Api<DynamicObject>, String> {
    crate::yaml::dynamic_api(client, API_IDENTITY, kind, "").await
}

async fn create(client: &Client, kind: &str, body: Value) -> Result<(), String> {
    let api = identity_api(client, kind).await?;
    let obj: DynamicObject = serde_json::from_value(body).map_err(|e| e.to_string())?;
    api.create(&kube::api::PostParams::default(), &obj)
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(())
}

/// JSON patch, never merge. A merge patch on `members` replaces the whole array, which is how the
/// other members get deleted by someone who only meant to add one.
async fn json_patch_members(client: &Client, group: &str, ops: Value) -> Result<(), String> {
    let api = identity_api(client, KIND_GROUP).await?;
    let patch: json_patch::Patch = serde_json::from_value(ops).map_err(|e| e.to_string())?;
    api.patch(group, &kube::api::PatchParams::default(), &kube::api::Patch::Json::<()>(patch))
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(())
}

// --- Payloads (pure) -----------------------------------------------------------------------------

/// The naming rules are **not** restated here. `metadata.name` is validated upstream both by a
/// ValidatingAdmissionPolicy and by the constructor of `Subject`; a third copy in another repo
/// would drift from both. kdt sends what was typed and shows the apiserver's own refusal.
pub fn user_payload(name: &str, email: &str, display_name: &str) -> Value {
    let mut spec = serde_json::Map::new();
    spec.insert("email".to_string(), Value::String(email.trim().to_string()));
    if !display_name.trim().is_empty() {
        spec.insert(
            "displayName".to_string(),
            Value::String(display_name.trim().to_string()),
        );
    }
    serde_json::json!({
        "apiVersion": API_IDENTITY,
        "kind": KIND_USER,
        "metadata": { "name": name.trim() },
        "spec": Value::Object(spec),
    })
}

/// `members` is set explicitly to an empty array rather than left out: the field defaults to `[]`
/// upstream, and a group created with the key present is one a JSON patch can append to on the
/// first try, without a `/spec/members` that does not exist yet.
pub fn group_payload(name: &str, description: &str) -> Value {
    let mut spec = serde_json::Map::new();
    spec.insert("members".to_string(), Value::Array(Vec::new()));
    if !description.trim().is_empty() {
        spec.insert(
            "description".to_string(),
            Value::String(description.trim().to_string()),
        );
    }
    serde_json::json!({
        "apiVersion": API_IDENTITY,
        "kind": KIND_GROUP,
        "metadata": { "name": name.trim() },
        "spec": Value::Object(spec),
    })
}

pub fn add_member_patch(user: &str) -> Value {
    serde_json::json!([{ "op": "add", "path": "/spec/members/-", "value": user }])
}

/// Guarded by a `test` on the value: an index alone would remove whatever moved into that slot
/// between the read and the write, and the row an operator clicked is up to a refresh old. A failed
/// `test` makes the apiserver reject the whole patch, which is the outcome to want.
pub fn remove_member_patch(index: usize, user: &str) -> Value {
    let path = format!("/spec/members/{index}");
    serde_json::json!([
        { "op": "test", "path": path, "value": user },
        { "op": "remove", "path": path },
    ])
}

// --- Commands run in the controller pod ---------------------------------------------------------

/// Runs `kdt-identity-server invite` in the controller pod and captures what it printed.
async fn run_invite(
    client: &Client,
    controller: &ControllerRef,
    user: &str,
    validity: &str,
) -> Result<IdentInvite, String> {
    let stdout =
        run_in_controller(client, controller, &["invite", user, "--validity", validity]).await?;
    Ok(parse_invite_output(user, &stdout))
}

/// Runs one `kdt-identity-server` subcommand in the controller pod and hands back its stdout.
///
/// kdt does not shell out to `kubectl` here, the way [`crate::exec`] does for an interactive
/// shell: that hands the terminal away, which would put the activation link and the code into the
/// scrollback and the tmux history — precisely what upstream refuses to do by never logging them.
/// `revoke` prints nothing secret, but it goes through the same path: one way in means one place
/// where that property is enforced.
///
/// The command is passed as argv, never through a shell: the image is `FROM scratch` and has
/// neither.
async fn run_in_controller(
    client: &Client,
    controller: &ControllerRef,
    args: &[&str],
) -> Result<String, String> {
    use tokio::io::AsyncReadExt;

    let st = crate::lang::active();
    let pods: Api<Pod> = Api::namespaced(client.clone(), &controller.namespace);
    let params = kube::api::AttachParams::default()
        .container(&controller.container)
        .stdin(false)
        .stdout(true)
        .stderr(true)
        .tty(false);

    let mut command = vec![SERVER_BIN];
    command.extend_from_slice(args);
    let mut process = pods
        .exec(&controller.pod, command, &params)
        .await
        .map_err(crate::edit::api_error_text)?;

    let status = process.take_status();
    // Both pipes are drained together: they are bounded duplex buffers, and reading one to the end
    // before touching the other is how a process that writes to both deadlocks.
    let mut out = process.stdout().ok_or_else(|| st.ident_invite_no_stdout.to_string())?;
    let mut err = process.stderr().ok_or_else(|| st.ident_invite_no_stdout.to_string())?;
    let (mut so, mut se) = (Vec::new(), Vec::new());
    let (ro, re) = tokio::join!(out.read_to_end(&mut so), err.read_to_end(&mut se));
    ro.map_err(|e| e.to_string())?;
    re.map_err(|e| e.to_string())?;

    let code = match status {
        Some(f) => f.await,
        None => None,
    };
    let _ = process.join().await;

    let stdout = String::from_utf8_lossy(&so).to_string();
    let stderr = String::from_utf8_lossy(&se).to_string();

    // The binary writes its traces to stderr and its result to stdout, on purpose — an `issue`
    // whose logs landed on stdout would produce a kubeconfig kubectl refuses. A failure is
    // therefore an empty stdout plus a reason on stderr.
    let failed = code.map(|s| s.status.as_deref() != Some("Success")).unwrap_or(false);
    if failed || stdout.trim().is_empty() {
        let reason = if stderr.trim().is_empty() {
            st.ident_invite_no_output.to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(fill(st.ident_invite_failed, &[("e", &reason)]));
    }

    Ok(stdout)
}

/// Picks the link and the code out of what `invite` printed.
///
/// Upstream has no machine-readable output, so this reads the labelled lines first and falls back
/// to shape — an `http` URL, and the eight-character code in its own alphabet. When neither finds
/// anything, both stay `None` and the raw text is what the operator is shown: kdt never announces a
/// code it did not actually find.
pub fn parse_invite_output(user: &str, stdout: &str) -> IdentInvite {
    let mut link = None;
    let mut code = None;
    let mut expires = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("lien") {
            link = Some(rest.trim().to_string()).filter(|s| !s.is_empty());
        } else if let Some(rest) = trimmed.strip_prefix("code") {
            code = Some(rest.trim().to_string()).filter(|s| !s.is_empty());
        } else if let Some(rest) = trimmed.strip_prefix("expire le") {
            expires = rest.trim().to_string();
        }
    }

    if link.is_none() {
        link = stdout
            .split_whitespace()
            .find(|w| w.starts_with("http://") || w.starts_with("https://"))
            .map(str::to_string);
    }
    if code.is_none() {
        code = stdout.split_whitespace().find(|w| looks_like_code(w)).map(str::to_string);
    }

    IdentInvite { user: user.to_string(), expires, link, code, raw: stdout.trim().to_string() }
}

/// The activation code as upstream formats it: two groups of four, drawn from an alphabet with no
/// confusable characters — no `O`/`0`, no `I`/`1`/`L`.
fn looks_like_code(word: &str) -> bool {
    const ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let Some((a, b)) = word.split_once('-') else { return false };
    a.len() == 4
        && b.len() == 4
        && a.chars().chain(b.chars()).all(|c| ALPHABET.contains(c))
}

// --- Absence -------------------------------------------------------------------------------------

/// The installation sequence, prefilled with what kdt already knows.
///
/// kdt does not run this: it does not speak Helm, there is no chart in any registry yet, and a
/// component whose own README calls itself cluster-admin-equivalent is not installed from a
/// keystroke. The two values kdt cannot know stay visibly `example.com` rather than becoming a
/// plausible guess.
pub fn install_command(cluster: &str, apiserver: &str) -> String {
    let cluster = if cluster.trim().is_empty() { "production" } else { cluster.trim() };
    let apiserver = if apiserver.trim().is_empty() {
        "https://k8s.example.com:6443"
    } else {
        apiserver.trim()
    };
    format!(
        "git clone https://github.com/agardenat/kdt-identity\n\
         cd kdt-identity\n\
         helm install kdt-identity deploy/helm/kdt-identity \\\n    \
         --namespace kdt-identity --create-namespace \\\n    \
         --set clusterName={cluster} \\\n    \
         --set portalUrl=https://identity.example.com \\\n    \
         --set apiserverUrl={apiserver} \\\n    \
         --set ingress.enabled=true \\\n    \
         --set ingress.host=identity.example.com\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::FR;

    fn user_obj(name: &str, phase: &str, disabled: bool, groups: &[&str]) -> DynamicObject {
        let body = serde_json::json!({
            "apiVersion": API_IDENTITY,
            "kind": KIND_USER,
            "metadata": { "name": name, "uid": format!("uid-{name}") },
            "spec": { "email": format!("{name}@example.com"), "disabled": disabled },
            "status": { "phase": phase, "memberOf": groups },
        });
        serde_json::from_value(body).unwrap()
    }

    fn group_obj(name: &str, members: &[&str], resolved: Option<&[&str]>) -> DynamicObject {
        let mut status = serde_json::json!({ "subject": format!("kdt:{name}") });
        if let Some(r) = resolved {
            let unknown: Vec<&str> =
                members.iter().copied().filter(|m| !r.contains(m)).collect();
            status["resolvedMembers"] = serde_json::json!(r);
            status["unknownMembers"] = serde_json::json!(unknown);
        }
        let body = serde_json::json!({
            "apiVersion": API_IDENTITY,
            "kind": KIND_GROUP,
            "metadata": { "name": name, "uid": format!("uid-{name}") },
            "spec": { "members": members },
            "status": status,
        });
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn a_merge_patch_is_never_produced_for_members() {
        let add = add_member_patch("alice");
        assert_eq!(add[0]["op"], "add");
        assert_eq!(add[0]["path"], "/spec/members/-");
        // The removal is guarded: the index the row carries is up to one refresh old, and a `test`
        // that fails takes the whole patch down instead of deleting the wrong member.
        let remove = remove_member_patch(2, "bob");
        assert_eq!(remove[0]["op"], "test");
        assert_eq!(remove[0]["value"], "bob");
        assert_eq!(remove[1]["op"], "remove");
        assert_eq!(remove[1]["path"], "/spec/members/2");
    }

    #[test]
    fn a_created_group_carries_an_empty_member_array() {
        // Without the key, the very first `add` to `/spec/members/-` has no array to append to.
        let g = group_payload("ops", "");
        assert_eq!(g["spec"]["members"], serde_json::json!([]));
        assert!(g["spec"].get("description").is_none());
    }

    #[test]
    fn an_empty_display_name_is_left_out_rather_than_written_empty() {
        let u = user_payload(" alice ", "alice@example.com", "  ");
        assert_eq!(u["metadata"]["name"], "alice");
        assert!(u["spec"].get("displayName").is_none());
        let named = user_payload("alice", "alice@example.com", "Alice Martin");
        assert_eq!(named["spec"]["displayName"], "Alice Martin");
    }

    #[test]
    fn the_invitation_is_read_off_the_labelled_lines() {
        let out = "Invitation pour alice <alice@example.com>\n  \
                   expire le      24/08/2026 à 12:17 UTC\n  \
                   lien           https://identity.example.com/activate?u=alice&t=rcMTOCK\n  \
                   code           FXJK-MNUQ\n";
        let inv = parse_invite_output("alice", out);
        assert_eq!(inv.code.as_deref(), Some("FXJK-MNUQ"));
        assert_eq!(
            inv.link.as_deref(),
            Some("https://identity.example.com/activate?u=alice&t=rcMTOCK")
        );
        assert_eq!(inv.expires, "24/08/2026 à 12:17 UTC");
    }

    #[test]
    fn a_reworded_output_still_yields_the_link_and_the_code() {
        // The fallback is by shape, so a label change upstream does not silence the view.
        let out = "Invitation for alice\n  url  https://portal.example.com/activate?t=x\n  \
                   otp  FXJK-MNUQ\n";
        let inv = parse_invite_output("alice", out);
        assert_eq!(inv.code.as_deref(), Some("FXJK-MNUQ"));
        assert!(inv.link.as_deref().unwrap().starts_with("https://portal"));
    }

    #[test]
    fn nothing_recognisable_leaves_both_fields_empty_rather_than_guessed() {
        let inv = parse_invite_output("alice", "quelque chose d'inattendu\n");
        assert!(inv.link.is_none());
        assert!(inv.code.is_none());
        assert_eq!(inv.raw, "quelque chose d'inattendu");
    }

    #[test]
    fn a_confusable_free_alphabet_is_what_makes_a_code() {
        assert!(looks_like_code("FXJK-MNUQ"));
        // `0`, `O`, `1`, `I` and `L` are excluded upstream so the code can be dictated.
        assert!(!looks_like_code("FXJK-MN0Q"));
        assert!(!looks_like_code("FXJKMNUQ"));
        assert!(!looks_like_code("FXJ-MNUQ"));
    }

    #[test]
    fn unknown_members_come_from_the_status_when_it_has_landed() {
        let users = vec![user_obj("alice", "Active", false, &["lecteurs"])];
        let groups = vec![group_obj("lecteurs", &["alice", "fantome"], Some(&["alice"]))];
        let rows = build_groups(&FR, &groups, &users, &BTreeMap::new());
        assert_eq!(rows[0].unknown, vec!["fantome".to_string()]);
        assert!(rows[0].hints.iter().any(|h| h.text.contains("fantome")));
    }

    #[test]
    fn a_group_awaiting_its_first_reconciliation_resolves_its_own_members() {
        // Without this, a freshly created group would read as "no unknown members" before the
        // controller has said anything, which is the opposite of what is known.
        let users = vec![user_obj("alice", "Active", false, &[])];
        let groups = vec![group_obj("ops", &["alice", "fantome"], None)];
        let rows = build_groups(&FR, &groups, &users, &BTreeMap::new());
        assert_eq!(rows[0].resolved, vec!["alice".to_string()]);
        assert_eq!(rows[0].unknown, vec!["fantome".to_string()]);
    }

    #[test]
    fn a_group_nothing_references_is_named_without_being_raised_to_a_warning() {
        let groups = vec![group_obj("ops", &[], Some(&[]))];
        let rows = build_groups(&FR, &groups, &[], &BTreeMap::new());
        assert!(rows[0].bindings.is_empty());
        assert!(rows[0].hints.iter().all(|h| h.level == HintLevel::Info));
    }

    #[test]
    fn a_bound_group_says_what_the_binding_grants() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "kdt:ops".to_string(),
            vec![BindingRef {
                kind: "RoleBinding".to_string(),
                namespace: "prod".to_string(),
                name: "kdt-ops-edit".to_string(),
                role: "ClusterRole/edit".to_string(),
            }],
        );
        let groups = vec![group_obj("ops", &[], Some(&[]))];
        let rows = build_groups(&FR, &groups, &[], &bindings);
        assert_eq!(rows[0].bindings.len(), 1);
        assert_eq!(
            rows[0].bindings[0].label(),
            "RoleBinding prod/kdt-ops-edit → ClusterRole/edit"
        );
        assert!(rows[0].hints.is_empty());
    }

    #[test]
    fn only_a_prefixed_group_subject_belongs_to_this_system() {
        assert!(is_group_subject("Group", "kdt:ops"));
        // A user named the same way is not a group, and an unprefixed group is someone else's.
        assert!(!is_group_subject("User", "kdt:alice"));
        assert!(!is_group_subject("Group", "ops"));
        assert!(!is_group_subject("Group", "system:masters"));
    }

    #[test]
    fn a_locked_account_is_derived_from_the_secret_because_the_status_never_says_so() {
        let mut creds = BTreeMap::new();
        creds.insert(
            "alice".to_string(),
            CredentialFacts {
                locked_until: Some(now_secs() + 600),
                failed_attempts: 7,
                ..CredentialFacts::default()
            },
        );
        let users = vec![user_obj("alice", "Active", false, &["ops"])];
        let rows = build_users(&FR, &users, &[], &creds, false, &BTreeMap::new());
        assert_eq!(rows[0].phase, Phase::Locked);
        // The controller's own word is kept, so the detail panel can show both.
        assert_eq!(rows[0].raw_phase, "Active");
        assert!(rows[0].hints.iter().any(|h| h.level == HintLevel::Warn));
    }

    #[test]
    fn disabled_wins_over_a_lockout_and_over_the_status() {
        let mut creds = BTreeMap::new();
        creds.insert(
            "alice".to_string(),
            CredentialFacts { locked_until: Some(now_secs() + 600), ..CredentialFacts::default() },
        );
        let users = vec![user_obj("alice", "Active", true, &[])];
        let rows = build_users(&FR, &users, &[], &creds, false, &BTreeMap::new());
        assert_eq!(rows[0].phase, Phase::Disabled);
    }

    #[test]
    fn an_unreadable_secret_does_not_read_as_never_invited() {
        let users = vec![user_obj("alice", "Pending", false, &[])];
        let rows = build_users(&FR, &users, &[], &BTreeMap::new(), true, &BTreeMap::new());
        assert_eq!(rows[0].invitation, Invitation::Unreadable);
        let readable = build_users(&FR, &users, &[], &BTreeMap::new(), false, &BTreeMap::new());
        assert_eq!(readable[0].invitation, Invitation::None);
    }

    #[test]
    fn an_expired_invitation_is_a_warning_and_a_live_one_is_not() {
        let mut creds = BTreeMap::new();
        creds.insert(
            "alice".to_string(),
            CredentialFacts {
                invite_expires: Some(now_secs() - 60),
                ..CredentialFacts::default()
            },
        );
        let users = vec![user_obj("alice", "Pending", false, &[])];
        let rows = build_users(&FR, &users, &[], &creds, false, &BTreeMap::new());
        assert!(matches!(rows[0].invitation, Invitation::Expired { .. }));
        assert!(rows[0].hints.iter().any(|h| h.level == HintLevel::Warn));

        creds.insert(
            "alice".to_string(),
            CredentialFacts {
                invite_expires: Some(now_secs() + 5400),
                ..CredentialFacts::default()
            },
        );
        let live = build_users(&FR, &users, &[], &creds, false, &BTreeMap::new());
        assert!(matches!(live[0].invitation, Invitation::Pending { .. }));
        assert!(live[0].hints.is_empty());
        assert_eq!(invitation_label(&live[0].invitation, &FR), "1h");
    }

    #[test]
    fn a_remaining_duration_reads_like_an_age() {
        assert_eq!(format_left(45), "45s");
        assert_eq!(format_left(90), "1m");
        assert_eq!(format_left(7_200), "2h");
        assert_eq!(format_left(3 * 86_400), "3d");
        // Already past: clamped rather than rendered negative. The `Expired` variant is what says
        // it ran out.
        assert_eq!(format_left(-10), "0s");
    }

    #[test]
    fn a_disabled_account_still_listed_in_a_group_is_named_from_the_spec() {
        // `status.memberOf` can lag; `spec.members` is the source of truth for "still listed".
        let users = vec![user_obj("alice", "Active", true, &[])];
        let groups = vec![group_obj("ops", &["alice"], Some(&["alice"]))];
        let rows = build_users(&FR, &users, &groups, &BTreeMap::new(), false, &BTreeMap::new());
        assert!(rows[0].hints.iter().any(|h| h.text.contains("ops")));
    }

    #[test]
    fn an_active_account_in_no_group_is_noted_without_alarm() {
        let users = vec![user_obj("alice", "Active", false, &[])];
        let rows = build_users(&FR, &users, &[], &BTreeMap::new(), false, &BTreeMap::new());
        assert!(rows[0].hints.iter().any(|h| h.level == HintLevel::Info));
        assert!(rows[0].hints.iter().all(|h| h.level != HintLevel::Warn));
    }

    #[test]
    fn the_subject_falls_back_to_the_derived_form_before_the_first_reconciliation() {
        let g = IdentGroup { name: "ops".to_string(), ..IdentGroup::default() };
        assert_eq!(g.effective_subject(), "kdt:ops");
        let published = IdentGroup {
            name: "ops".to_string(),
            subject: "kdt:ops".to_string(),
            ..IdentGroup::default()
        };
        assert_eq!(published.effective_subject(), "kdt:ops");
    }

    fn sessions_secret(entries: serde_json::Value) -> Secret {
        Secret {
            data: Some(std::collections::BTreeMap::from([(
                K_SESSIONS.to_string(),
                k8s_openapi::ByteString(serde_json::to_vec(&entries).unwrap()),
            )])),
            ..Secret::default()
        }
    }

    // An expired session is not access. Counting it as open would say a revocation has work to do
    // when it has none, and would make the SESS column disagree with what `revoke` then prints.
    #[test]
    fn an_expired_session_is_stale_not_open() {
        let now = 1_700_000_000;
        let secret = sessions_secret(serde_json::json!([
            { "id": "a", "secretHash": "deadbeef",
              "issuedAt": "2023-11-14T22:13:20Z", "expiresAt": "2023-11-21T22:13:20Z" },
            { "id": "b", "secretHash": "deadbeef",
              "issuedAt": "2023-10-14T22:13:20Z", "expiresAt": "2023-10-21T22:13:20Z" },
        ]));
        let facts = session_facts(&secret, now);
        assert_eq!(facts.open, 1);
        assert_eq!(facts.stale, 1);
        assert_eq!(facts.last_expiry, Some(1_700_604_800));
    }

    // Unreadable content yields no count rather than a zero: "nobody is connected" is a claim, and
    // kdt has no basis for it here.
    #[test]
    fn unparseable_sessions_count_nothing() {
        let secret = Secret {
            data: Some(std::collections::BTreeMap::from([(
                K_SESSIONS.to_string(),
                k8s_openapi::ByteString(b"not json".to_vec()),
            )])),
            ..Secret::default()
        };
        let facts = session_facts(&secret, 1_700_000_000);
        assert_eq!(facts.open, 0);
        assert_eq!(facts.stale, 0);
        assert_eq!(facts.last_expiry, None);
    }

    // The window is the TTL of what this mode hands out, and nothing is stated when the deployment
    // declared neither — a default restated here would describe a cluster kdt has not read.
    #[test]
    fn the_revocation_window_follows_the_declared_mode() {
        let mut d = Delivery {
            mode: Some(CredentialMode::Certificate),
            cert_ttl: Some("10m".to_string()),
            token_ttl: Some("5m".to_string()),
            refresh_ttl: Some("7d".to_string()),
            kubeconfig_download: Some(true),
        };
        assert_eq!(d.revocation_window(), Some("10m"));
        assert!(d.download_open());

        d.mode = Some(CredentialMode::Oidc);
        assert_eq!(d.revocation_window(), Some("5m"));
        // No download exists in OIDC, whatever the leftover variable says.
        assert!(!d.download_open());

        d.mode = None;
        assert_eq!(d.revocation_window(), None, "a window without a mode is a guess");
        assert!(!d.download_open());
    }

    // A mode kdt does not know is an absent mode, not a certificate one: a deployment that says
    // something unexpected must not be reported as the default.
    #[test]
    fn the_delivery_is_read_off_literal_env_values_only() {
        use k8s_openapi::api::core::v1::{Container, EnvVar, EnvVarSource, SecretKeySelector};
        let container = Container {
            name: "controller".to_string(),
            env: Some(vec![
                EnvVar {
                    name: ENV_MODE.to_string(),
                    value: Some("oidc".to_string()),
                    ..EnvVar::default()
                },
                EnvVar {
                    name: ENV_TOKEN_TTL.to_string(),
                    value: Some("5m".to_string()),
                    ..EnvVar::default()
                },
                // A value that lives in a Secret carries none here, and kdt does not go opening it.
                EnvVar {
                    name: ENV_REFRESH_TTL.to_string(),
                    value_from: Some(EnvVarSource {
                        secret_key_ref: Some(SecretKeySelector::default()),
                        ..EnvVarSource::default()
                    }),
                    ..EnvVar::default()
                },
            ]),
            ..Container::default()
        };
        let d = delivery_from_env(&container);
        assert_eq!(d.mode, Some(CredentialMode::Oidc));
        assert_eq!(d.token_ttl.as_deref(), Some("5m"));
        assert_eq!(d.refresh_ttl, None);
        assert_eq!(d.kubeconfig_download, None);

        let unknown = Container {
            env: Some(vec![EnvVar {
                name: ENV_MODE.to_string(),
                value: Some("certificat".to_string()),
                ..EnvVar::default()
            }]),
            ..Container::default()
        };
        assert_eq!(delivery_from_env(&unknown).mode, None);
    }

    #[test]
    fn the_install_command_keeps_the_values_kdt_cannot_know_visibly_fake() {
        let cmd = install_command("demo", "https://k8s.example.com:6443");
        assert!(cmd.contains("--set clusterName=demo"));
        assert!(cmd.contains("--set apiserverUrl=https://k8s.example.com:6443"));
        // Never invented: a portal hostname kdt cannot possibly know stays an example.
        assert!(cmd.contains("identity.example.com"));
        assert!(cmd.starts_with("git clone"));
    }
}
