//! Rancher (`management.cattle.io`) inventory for the `:rancher` view. Read-only.
//!
//! On a Rancher-managed cluster every human is an opaque `u-4oivhvq2jk`. That id is what the
//! RoleBindings carry, what the audit log carries, and what `kubectl get rolebinding -o yaml` shows;
//! the person behind it lives in a `User` object nobody looks at and in a `UserAttribute` object
//! nobody knows exists. Answering "who is u-4oivhvq2jk, and what can they reach" today means opening
//! the Rancher UI, which is exactly the round trip this view removes: the pair
//! *(Rancher identity, real identity)* is the first two columns of the list.
//!
//! Two cluster roles have to be told apart, because the same CRDs exist on both and only one of them
//! holds the data:
//!
//! * the **local** cluster — the one running the `rancher` deployment — owns `User`, `UserAttribute`,
//!   `GlobalRoleBinding`, `Project`, the two RoleTemplateBinding kinds and `Token`. Everything the
//!   view shows comes from there.
//! * a **downstream** cluster carries the same CRDs, registered by the agent, and they are *empty*.
//!   Listing `users` there returns zero items, which is not "no users" — it is "not here". What a
//!   downstream does hold is the RBAC the agent projected: RoleBindings labelled with the
//!   ProjectRoleTemplateBinding that created them, whose subjects are those same `u-…` ids for users
//!   and, for groups, the **full LDAP/AD distinguished name in clear text**. So on a downstream the
//!   view falls back to that projection: the access map is real, the user identities are not
//!   resolvable, and it says so rather than showing an empty screen.
//!
//! Shapes that have to be survived rather than assumed:
//!
//! * `UserAttribute` serialises its fields in **PascalCase** (`UserName`, `GroupPrincipals`,
//!   `LastRefresh`) — it has no json tags. Reading `groupPrincipals` returns nothing, silently.
//! * inside it, each provider entry carries both `Items` (null) and `items` (the real list). Reading
//!   only one of the two loses every group on some Rancher versions.
//! * `User.enabled` is a `*bool`: **absent means active**. 153 of 159 accounts on a production
//!   Rancher have no `enabled` field at all, so treating absent as disabled would report the whole
//!   directory as locked out. Only `enabled: false` is a disabled account.
//! * `AuthConfig.enabled` is a `*bool` too, and every provider Rancher knows about exists as an
//!   object whether it is configured or not. Only `enabled: true` is a configured provider.
//! * a `Token` has both `expiresAt` (a string, often empty) and `ttl` (milliseconds, `0` meaning it
//!   never expires). `expired` is the field Rancher itself maintains, so it wins when present.
//!
//! Nothing here writes. The rows stand in for their real object through apiVersion/kind/namespace/
//! name, so the shared YAML/Status/Related/search machinery works unchanged.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleBinding};
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;

use crate::events::format_age;
use crate::lang::{fill, Strings};

pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }

// --- API surface ---------------------------------------------------------------------------------

const G_MGMT: &str = "management.cattle.io";
const V_MGMT: &str = "v3";
pub const API_MGMT: &str = "management.cattle.io/v3";

// The annotation Rancher stamps on every namespace it placed in a project, as `<clusterId>:<projectId>`.
// It is the only link between a namespace and its project, and — unlike the Project objects — it is
// readable from a downstream cluster.
const A_PROJECT_ID: &str = "field.cattle.io/projectId";
// The creator of a project/cluster, as a user id.
const A_CREATOR_ID: &str = "field.cattle.io/creatorId";

// The label the agent puts on each RoleBinding it projects from a ProjectRoleTemplateBinding, as
// `<projectId>_<bindingName>`. Older Rancher versions instead add that same string as a label *key*
// with the value "true", so both shapes are read — see `rtb_owner`.
const L_RTB_OWNER: &str = "authz.cluster.cattle.io/rtb-owner-updated";
const L_RTB_OWNER_LEGACY: &str = "authz.cluster.cattle.io/rtb-owner";
// The token's kind (kubeconfig, session, provisioning, telemetry). Absent on tokens created through
// the API, which is what makes an API key recognisable.
const L_TOKEN_KIND: &str = "authn.management.cattle.io/kind";

// Kinds listed on the local cluster. Namespaced ones are listed across all namespaces: Projects and
// the two binding kinds live in the cluster's own namespace (`local`, `c-xxxxx`) or the project's.
const KINDS: &[&str] = &[
    "User",
    "UserAttribute",
    "GlobalRole",
    "GlobalRoleBinding",
    "RoleTemplate",
    "ClusterRoleTemplateBinding",
    "ProjectRoleTemplateBinding",
    "Project",
    "Cluster",
    "Token",
    "AuthConfig",
    "Setting",
];

// --- Identity ------------------------------------------------------------------------------------

/// Which side of an identity a principal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Group,
}

/// A Rancher principal id, split into what it actually says.
///
/// The wire form is `<provider>_<kind>://<id>` (`openldap_user://CN=…`, `activedirectory_group://…`)
/// with two exceptions that carry no kind at all: `local://u-xxxxx` and `system://…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// `openldap`, `activedirectory`, `freeipa`, `keycloakoidc`, `local`, `system`…
    pub provider: String,
    pub kind: PrincipalKind,
    /// Everything after `://`, untouched.
    pub id: String,
    /// The readable part of `id` — the CN of a DN, the uid, or `id` itself when it is opaque.
    pub display: String,
    /// True when `display` is `id` because nothing readable could be extracted (a GUID, a numeric
    /// GitHub id). The raw value is shown as-is rather than dressed up as a name.
    pub opaque: bool,
}

impl Principal {
    pub fn is_local(&self) -> bool {
        self.provider == "local"
    }
}

/// Parse a principal id. Returns None for an empty string, never for an unknown provider: a
/// provider this build has never heard of still names a real person, and dropping it would hide them.
pub fn parse_principal(raw: &str) -> Option<Principal> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (head, id) = match raw.split_once("://") {
        Some((h, i)) => (h, i),
        // A bare id with no scheme is a local user id in every place Rancher emits one.
        None => ("local", raw),
    };
    let (provider, kind) = match head.rsplit_once('_') {
        Some((p, "user")) => (p.to_string(), PrincipalKind::User),
        Some((p, "group")) => (p.to_string(), PrincipalKind::Group),
        // `local://`, `system://`, and any provider that does not spell its kind out.
        _ => (head.to_string(), PrincipalKind::User),
    };
    let (display, opaque) = readable_id(id);
    Some(Principal { provider, kind, id: id.to_string(), display, opaque })
}

/// The readable part of a principal id, and whether it had to fall back to the raw value.
///
/// LDAP/AD principals are distinguished names (`CN=LE SECH Clementine,OU=USERS,DC=…`), FreeIPA ones
/// are `uid=jdoe,cn=users,…`. OIDC and SAML providers put an opaque subject there instead, and a GUID
/// dressed as a name would be worse than the GUID.
fn readable_id(id: &str) -> (String, bool) {
    let rdns = split_dn(id);
    if rdns.len() < 2 {
        return (id.to_string(), true);
    }
    // The leftmost RDN is the entry's own name — and it is the only one that is. Searching the whole
    // chain for a `cn` instead turns FreeIPA's `uid=jdoe,cn=users,cn=accounts,…` into "users", the
    // name of the container rather than of the person.
    match rdns.first() {
        Some((_, v)) if !v.is_empty() => (v.clone(), false),
        _ => (id.to_string(), true),
    }
}

/// Split a distinguished name into its `key=value` components. Commas escaped as `\,` belong to the
/// value — a CN of `Doe\, John` is one RDN, not two.
fn split_dn(dn: &str) -> Vec<(String, String)> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in dn.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            ',' => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
        .into_iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

// --- Records -------------------------------------------------------------------------------------

/// Which cluster the view is looking at. Decides what the data means, and what its absence means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClusterRole {
    /// The cluster running the Rancher server: every identity object is here.
    Local,
    /// A registered cluster: the CRDs exist, the identity objects live upstream.
    Downstream,
    /// No `management.cattle.io` at all.
    #[default]
    Absent,
}

/// An authentication provider, as configured — not as merely present. Rancher creates an `AuthConfig`
/// for every provider it supports, so existence says nothing; `enabled: true` does.
#[derive(Debug, Clone, Default)]
pub struct AuthProvider {
    pub name: String,
    /// `required`, `restricted`, `unrestricted` — empty when Rancher never set it.
    pub access_mode: String,
}

/// The Rancher installation itself, as the view's headline.
#[derive(Debug, Clone, Default)]
pub struct RancherServer {
    pub role: ClusterRole,
    /// `settings/server-version`, empty when unreadable.
    pub version: String,
    /// `settings/server-url` on the local cluster; on a downstream, the URL the agent points at.
    pub url: String,
    /// The cluster's own Rancher id (`local`, `c-5h42c`). On a downstream it is recovered from the
    /// project annotations, which is the only place it appears without reading the agent's config.
    pub cluster_id: String,
    pub cluster_name: String,
    pub providers: Vec<AuthProvider>,
    pub hints: Vec<Hint>,
}

/// One human (or service account) known to Rancher, with both of its identities.
#[derive(Debug, Clone, Default)]
pub struct RancherUser {
    /// The Rancher identity: `u-4oivhvq2jk`. What every RoleBinding and audit line carries.
    pub id: String,
    /// The local login, when the account has one.
    pub username: String,
    pub display_name: String,
    /// The external provider backing the account, `local` when there is none.
    pub provider: String,
    /// The external principal, verbatim (`openldap_user://CN=…`). Empty for a local-only account.
    pub principal: String,
    /// The readable form of `principal` — the CN, the uid, or the raw subject when it is opaque.
    pub identity: String,
    pub identity_opaque: bool,
    pub local_only: bool,
    /// `Some(false)` only when Rancher explicitly disabled the account.
    pub enabled: Option<bool>,
    pub must_change_password: bool,
    /// Global roles, by display name where one is known.
    pub global_roles: Vec<String>,
    pub is_admin: bool,
    /// Group principals from the UserAttribute, readable form.
    pub groups: Vec<String>,
    /// When Rancher last refreshed those groups from the provider.
    pub last_refresh: String,
    pub token_count: usize,
    /// Cluster + project bindings this user holds directly (group-granted access is not counted here:
    /// it is attached to the group, not to the account).
    pub binding_count: usize,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

/// The scope a binding grants access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindScope {
    Global,
    Cluster,
    Project,
}

impl BindScope {
    pub fn label(&self) -> &'static str {
        match self {
            BindScope::Global => "global",
            BindScope::Cluster => "cluster",
            BindScope::Project => "project",
        }
    }
}

/// One grant: a subject, a scope, a role. The three binding kinds collapse into this because the
/// question they answer is the same one.
#[derive(Debug, Clone, Default)]
pub struct RancherBinding {
    pub scope: Option<BindScopeInner>,
    /// `local`, `local:p-22ldd`, empty for a global binding.
    pub scope_id: String,
    /// What the scope is called for a human: a project display name where it is known.
    pub scope_label: String,
    pub subject_kind: Option<PrincipalKind>,
    /// `u-4oivhvq2jk` for a user, the group principal for a group.
    pub subject_id: String,
    /// The readable subject: the account's display name, or the group's CN.
    pub subject_label: String,
    pub provider: String,
    /// The role as Rancher names it (`project-owner`, `admin`).
    pub role: String,
    /// Its display name when the RoleTemplate/GlobalRole is readable.
    pub role_label: String,
    /// True for the roles that own their scope — surfaced, never judged.
    pub owner_role: bool,
    /// False when this row was rebuilt from a projected RoleBinding on a downstream cluster rather
    /// than read from a Rancher binding object.
    pub authoritative: bool,
    /// True when Rancher created this binding by itself for every account — the global role marked
    /// `newUserDefault`. It grants nothing anyone chose to grant, so it sorts below the rest and is
    /// drawn dim: 155 identical rows at the top of the list is 155 rows of noise.
    pub automatic: bool,
    pub kind: String,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

// `BindScope` needs to be optional in a Default-derived struct without giving the enum a meaningless
// default variant: an alias keeps the field readable.
pub type BindScopeInner = BindScope;

/// A Rancher project and the namespaces it owns.
#[derive(Debug, Clone, Default)]
pub struct RancherProject {
    pub id: String,
    pub display_name: String,
    pub cluster: String,
    pub namespaces: Vec<String>,
    /// Distinct subjects bound to the project.
    pub members: usize,
    pub owners: Vec<String>,
    /// A one-line summary of `resourceQuota.limit`, empty when the project has no quota.
    pub quota: String,
    pub creator: String,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
    pub namespace: String,
    pub name: String,
}

/// A Rancher API token. Read for what it says about access, never for its secret — the `token` field
/// is not carried into the row.
#[derive(Debug, Clone, Default)]
pub struct RancherToken {
    pub name: String,
    pub user_id: String,
    /// The account's readable identity when it could be resolved.
    pub user_label: String,
    pub provider: String,
    /// `kubeconfig`, `session`, `provisioning`, `telemetry`, or empty for a token created through
    /// the API — which is what an API key looks like.
    pub kind: String,
    pub description: String,
    /// Milliseconds. `0` means the token never expires.
    pub ttl_ms: i64,
    pub expires_at: String,
    pub expired: bool,
    pub cluster: String,
    pub age: String,
    pub hints: Vec<Hint>,
    pub uid: String,
}

// --- State ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct RancherState {
    pub server: RancherServer,
    pub users: Vec<RancherUser>,
    pub bindings: Vec<RancherBinding>,
    pub projects: Vec<RancherProject>,
    pub tokens: Vec<RancherToken>,
    /// Namespaces carrying no `field.cattle.io/projectId`. Counted, not listed as rows: they have no
    /// Rancher object to stand in for.
    pub orphan_namespaces: usize,
    pub error: Option<String>,
    pub loading: bool,
}

impl RancherState {
    /// Accounts backed by a directory. Read off the provider rather than off `local_only` so that a
    /// downstream cluster — where no account has a resolvable provider — counts none instead of
    /// counting them all.
    pub fn external_users(&self) -> usize {
        self.users
            .iter()
            .filter(|u| !u.provider.is_empty() && u.provider != "local")
            .count()
    }

    pub fn admins(&self) -> usize {
        self.users.iter().filter(|u| u.is_admin).count()
    }
}

pub type SharedRancher = Arc<Mutex<RancherState>>;

pub fn new_rancher_state() -> SharedRancher {
    Arc::new(Mutex::new(RancherState::default()))
}

// --- Fetch ---------------------------------------------------------------------------------------

// Everything listed in one pass, by kind. A kind the cluster does not serve — or refuses — is simply
// absent from the map, which every builder below treats as "nothing", never as an error.
type Listed = HashMap<&'static str, Vec<DynamicObject>>;

pub async fn fetch_rancher(client: Client, state: SharedRancher) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("rancher poisoned");
        s.loading = true;
        s.error = None;
    }

    // Discovery first, as one wave: twelve sequential probes on a remote cluster is ten seconds of
    // blank screen.
    let probes = KINDS.iter().map(|kind| {
        let client = client.clone();
        async move {
            let gvk = GroupVersionKind::gvk(G_MGMT, V_MGMT, kind);
            match discovery::pinned_kind(&client, &gvk).await {
                Ok((ar, _)) => Some((*kind, ar)),
                Err(_) => None,
            }
        }
    });
    let resolved: Vec<_> = futures::future::join_all(probes).await.into_iter().flatten().collect();

    if resolved.is_empty() {
        let mut s = state.lock().expect("rancher poisoned");
        *s = RancherState {
            loading: false,
            error: Some(st.ranch_absent.to_string()),
            ..RancherState::default()
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
    let (results, namespaces) = futures::join!(
        futures::future::join_all(lists),
        list_namespaces(&client),
    );
    // A kind that failed to list is dropped from the map, but *why* it failed matters for `User`:
    // see below.
    let users_error = results
        .iter()
        .find(|(kind, _)| *kind == "User")
        .and_then(|(_, r)| r.as_ref().err().cloned());
    let listed: Listed = results
        .into_iter()
        .filter_map(|(kind, r)| r.ok().map(|v| (kind, v)))
        .collect();

    // Zero User objects on a cluster that serves the CRD is the downstream signature. It is not an
    // error and not an empty directory: the identities live on the Rancher server. A *refused* list
    // looks exactly the same from here and means something else entirely, so it is carried through
    // and said out loud rather than read as an absence.
    let role = if listed.get("User").map(|v| !v.is_empty()).unwrap_or(false) {
        ClusterRole::Local
    } else {
        ClusterRole::Downstream
    };

    let mut next = match role {
        ClusterRole::Local => build_local(st, &listed, &namespaces),
        _ => {
            let projected = list_projected_rbac(&client).await;
            build_downstream(st, &listed, &namespaces, &projected)
        }
    };
    if let Some(e) = users_error {
        next.server
            .hints
            .push(warn(fill(st.ranch_users_unreadable, &[("e", &e)])));
    }
    next.loading = false;
    *state.lock().expect("rancher poisoned") = next;
}

async fn list_namespaces(client: &Client) -> Vec<Namespace> {
    let api: Api<Namespace> = Api::all(client.clone());
    api.list(&ListParams::default()).await.map(|l| l.items).unwrap_or_default()
}

// The RBAC the cluster agent projected. Only read on a downstream, where it is the only trace of who
// has access — 2900 RoleBindings on a large cluster, which is why this view refreshes on a minute
// rather than on the usual few seconds.
struct Projected {
    role_bindings: Vec<RoleBinding>,
    cluster_role_bindings: Vec<ClusterRoleBinding>,
}

async fn list_projected_rbac(client: &Client) -> Projected {
    let rb_api: Api<RoleBinding> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let params = ListParams::default();
    let (rb, crb) = futures::join!(rb_api.list(&params), crb_api.list(&params));
    Projected {
        role_bindings: rb.map(|l| l.items).unwrap_or_default(),
        cluster_role_bindings: crb.map(|l| l.items).unwrap_or_default(),
    }
}

// --- Local cluster -------------------------------------------------------------------------------

fn build_local(st: &'static Strings, listed: &Listed, namespaces: &[Namespace]) -> RancherState {
    let empty: Vec<DynamicObject> = Vec::new();
    let get = |k: &str| listed.get(k).unwrap_or(&empty);

    let settings = index_settings(get("Setting"));
    let providers = auth_providers(get("AuthConfig"));
    let role_labels = display_names(get("RoleTemplate"));
    let global_role_labels = display_names(get("GlobalRole"));
    let admin_roles = admin_global_roles(get("GlobalRole"));
    let default_roles = default_global_roles(get("GlobalRole"));

    // Projects first: their display names are what makes a project binding readable.
    let ns_by_project = namespaces_by_project(namespaces);
    let (cluster_id, cluster_name) = local_cluster(get("Cluster"), &ns_by_project);

    let attributes = index_attributes(get("UserAttribute"));
    let grbs = get("GlobalRoleBinding");
    let crtbs = get("ClusterRoleTemplateBinding");
    let prtbs = get("ProjectRoleTemplateBinding");

    let mut projects = build_projects(st, get("Project"), prtbs, &ns_by_project);
    let project_labels: BTreeMap<String, String> = projects
        .iter()
        .map(|p| (p.id.clone(), p.display_name.clone()))
        .collect();

    let users = build_users(
        st,
        get("User"),
        &attributes,
        grbs,
        crtbs,
        prtbs,
        get("Token"),
        &global_role_labels,
        &admin_roles,
        &providers,
    );
    let user_labels: BTreeMap<String, String> = users
        .iter()
        .map(|u| (u.id.clone(), user_label(u)))
        .collect();

    let bindings = build_bindings(
        st,
        &default_roles,
        grbs,
        crtbs,
        prtbs,
        &user_labels,
        &project_labels,
        &role_labels,
        &global_role_labels,
    );

    // A project's owner list needs the resolved user labels, so it is filled once both exist.
    fill_project_owners(&mut projects, prtbs, &user_labels);

    let tokens = build_tokens(st, get("Token"), &user_labels);

    let mut server = RancherServer {
        role: ClusterRole::Local,
        version: settings.get("server-version").cloned().unwrap_or_default(),
        url: settings.get("server-url").cloned().unwrap_or_default(),
        cluster_id,
        cluster_name,
        providers,
        hints: Vec::new(),
    };
    server_hints(st, &mut server, &users, &tokens);

    RancherState {
        server,
        users,
        bindings,
        projects,
        tokens,
        orphan_namespaces: namespaces
            .iter()
            .filter(|n| project_of_namespace(n).is_none())
            .count(),
        error: None,
        loading: false,
    }
}

fn index_settings(objs: &[DynamicObject]) -> BTreeMap<String, String> {
    objs.iter()
        .filter_map(|o| {
            let name = o.metadata.name.clone()?;
            // `value` is what an operator set; `default` is what the chart shipped. Rancher itself
            // resolves in that order.
            let value = str_at(&o.data, "value")
                .filter(|v| !v.is_empty())
                .or_else(|| str_at(&o.data, "default"))
                .unwrap_or_default();
            Some((name, value))
        })
        .collect()
}

fn auth_providers(objs: &[DynamicObject]) -> Vec<AuthProvider> {
    let mut out: Vec<AuthProvider> = objs
        .iter()
        .filter(|o| o.data.get("enabled").and_then(Value::as_bool).unwrap_or(false))
        .map(|o| AuthProvider {
            name: o.metadata.name.clone().unwrap_or_default(),
            access_mode: str_at(&o.data, "accessMode").unwrap_or_default(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// Display names by object name, for RoleTemplate and GlobalRole alike.
fn display_names(objs: &[DynamicObject]) -> BTreeMap<String, String> {
    objs.iter()
        .filter_map(|o| {
            let name = o.metadata.name.clone()?;
            let display = str_at(&o.data, "displayName").unwrap_or_default();
            Some((name, display))
        })
        .collect()
}

// The global roles Rancher binds to every account it creates.
fn default_global_roles(objs: &[DynamicObject]) -> BTreeSet<String> {
    objs.iter()
        .filter(|o| o.data.get("newUserDefault").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|o| o.metadata.name.clone())
        .collect()
}

// The global roles that carry cluster-wide administration. Read from the object rather than from a
// hardcoded name list: a custom global role granting `*` on `*` is an admin role too.
fn admin_global_roles(objs: &[DynamicObject]) -> BTreeSet<String> {
    objs.iter()
        .filter(|o| {
            let Some(rules) = o.data.get("rules").and_then(Value::as_array) else {
                return false;
            };
            rules.iter().any(|r| {
                let has = |key: &str| {
                    r.get(key)
                        .and_then(Value::as_array)
                        .map(|a| a.iter().any(|v| v.as_str() == Some("*")))
                        .unwrap_or(false)
                };
                has("apiGroups") && has("resources") && has("verbs")
            })
        })
        .filter_map(|o| o.metadata.name.clone())
        .collect()
}

// UserAttribute, indexed by user id. PascalCase throughout — see the module header.
struct Attributes {
    groups: Vec<String>,
    last_refresh: String,
    /// The identity the provider last reported, which is more current than `User.principalIds` when
    /// a user was renamed in the directory.
    extra_identity: Option<String>,
}

fn index_attributes(objs: &[DynamicObject]) -> BTreeMap<String, Attributes> {
    objs.iter()
        .filter_map(|o| {
            let id = o.metadata.name.clone()?;
            let mut groups: Vec<String> = Vec::new();
            let mut seen: BTreeSet<String> = BTreeSet::new();
            if let Some(map) = o.data.get("GroupPrincipals").and_then(Value::as_object) {
                for entry in map.values() {
                    // Both spellings exist, and which one is filled depends on the Rancher version.
                    for key in ["items", "Items"] {
                        let Some(items) = entry.get(key).and_then(Value::as_array) else {
                            continue;
                        };
                        for item in items {
                            let Some(name) = item
                                .get("metadata")
                                .and_then(|m| m.get("name"))
                                .and_then(Value::as_str)
                            else {
                                continue;
                            };
                            if let Some(p) = parse_principal(name) {
                                if seen.insert(p.id.clone()) {
                                    groups.push(p.display.clone());
                                }
                            }
                        }
                    }
                }
            }
            // Providers are walked in whatever order the map deserialises in; the list a human
            // reads should not depend on that.
            groups.sort();
            let extra_identity = o
                .data
                .get("ExtraByProvider")
                .and_then(Value::as_object)
                .and_then(|by_provider| {
                    by_provider.values().find_map(|entry| {
                        entry
                            .get("principalid")
                            .and_then(Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                });
            Some((
                id,
                Attributes {
                    groups,
                    last_refresh: str_at(&o.data, "LastRefresh").unwrap_or_default(),
                    extra_identity,
                },
            ))
        })
        .collect()
}

// The cluster this Rancher calls itself. On a local cluster the Cluster object is authoritative; the
// namespace annotations are the fallback that also works downstream.
fn local_cluster(
    objs: &[DynamicObject],
    ns_by_project: &BTreeMap<String, Vec<String>>,
) -> (String, String) {
    if let Some(o) = objs.first() {
        let id = o.metadata.name.clone().unwrap_or_default();
        let name = o
            .data
            .get("spec")
            .and_then(|s| s.get("displayName"))
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_string();
        if !id.is_empty() {
            return (id, name);
        }
    }
    let id = ns_by_project
        .keys()
        .find_map(|k| k.split_once(':').map(|(c, _)| c.to_string()))
        .unwrap_or_default();
    (id.clone(), id)
}

// `<clusterId>:<projectId>` → the namespaces carrying it.
fn namespaces_by_project(namespaces: &[Namespace]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ns in namespaces {
        let Some(pid) = project_of_namespace(ns) else { continue };
        out.entry(pid).or_default().push(ns.metadata.name.clone().unwrap_or_default());
    }
    out
}

fn project_of_namespace(ns: &Namespace) -> Option<String> {
    ns.metadata
        .annotations
        .as_ref()?
        .get(A_PROJECT_ID)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn build_projects(
    st: &'static Strings,
    objs: &[DynamicObject],
    prtbs: &[DynamicObject],
    ns_by_project: &BTreeMap<String, Vec<String>>,
) -> Vec<RancherProject> {
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for b in prtbs {
        let Some(project) = str_at(&b.data, "projectName") else { continue };
        let subject = str_at(&b.data, "userName")
            .or_else(|| str_at(&b.data, "groupPrincipalName"))
            .unwrap_or_default();
        if !subject.is_empty() {
            members.entry(project).or_default().insert(subject);
        }
    }

    let mut out: Vec<RancherProject> = objs
        .iter()
        .map(|o| {
            let id = o.metadata.name.clone().unwrap_or_default();
            let namespace = o.metadata.namespace.clone().unwrap_or_default();
            let spec = o.data.get("spec");
            let cluster = spec
                .and_then(|s| s.get("clusterName"))
                .and_then(Value::as_str)
                .unwrap_or(&namespace)
                .to_string();
            let display_name = spec
                .and_then(|s| s.get("displayName"))
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_string();
            let key = format!("{}:{}", cluster, id);
            let namespaces = ns_by_project.get(&key).cloned().unwrap_or_default();
            let quota = quota_summary(spec);
            let creator = o
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(A_CREATOR_ID))
                .cloned()
                .unwrap_or_default();
            let age = o
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_default();
            let member_count = members.get(&key).map(BTreeSet::len).unwrap_or(0);

            let mut hints = Vec::new();
            if namespaces.is_empty() {
                hints.push(info(st.ranch_project_no_namespace.to_string()));
            }
            if member_count == 0 {
                hints.push(info(st.ranch_project_no_member.to_string()));
            }

            RancherProject {
                uid: format!("ranch|project|{}", key),
                name: id.clone(),
                namespace,
                id,
                display_name,
                cluster,
                namespaces,
                members: member_count,
                owners: Vec::new(),
                quota,
                creator,
                age,
                hints,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        a.cluster
            .cmp(&b.cluster)
            .then_with(|| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()))
    });
    out
}

fn fill_project_owners(
    projects: &mut [RancherProject],
    prtbs: &[DynamicObject],
    user_labels: &BTreeMap<String, String>,
) {
    // The creator annotation holds a `u-…` id like everything else Rancher writes down.
    for p in projects.iter_mut() {
        if let Some(label) = user_labels.get(&p.creator) {
            p.creator = format!("{} ({})", label, p.creator);
        }
    }
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for b in prtbs {
        if str_at(&b.data, "roleTemplateName").as_deref() != Some("project-owner") {
            continue;
        }
        let Some(project) = str_at(&b.data, "projectName") else { continue };
        // An owner is whoever the binding names — an account resolved to its real identity, or a
        // directory group under its CN.
        let label = match str_at(&b.data, "userName") {
            Some(user) if !user.is_empty() => {
                user_labels.get(&user).cloned().unwrap_or(user)
            }
            _ => str_at(&b.data, "groupPrincipalName")
                .and_then(|g| parse_principal(&g))
                .map(|p| p.display)
                .unwrap_or_default(),
        };
        if !label.is_empty() {
            let entry = owners.entry(project).or_default();
            if !entry.contains(&label) {
                entry.push(label);
            }
        }
    }
    for p in projects.iter_mut() {
        let key = format!("{}:{}", p.cluster, p.id);
        if let Some(list) = owners.remove(&key) {
            p.owners = list;
        }
    }
}

// `resourceQuota.limit` as one line. Empty when the project sets no quota — which is the common case,
// and is shown as nothing rather than as a zero.
fn quota_summary(spec: Option<&Value>) -> String {
    let limit = spec
        .and_then(|s| s.get("resourceQuota"))
        .and_then(|q| q.get("limit"))
        .and_then(Value::as_object);
    let Some(limit) = limit else { return String::new() };
    let mut parts: Vec<String> = limit
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|v| format!("{}={}", k, v)))
        .collect();
    parts.sort();
    parts.join(" ")
}

#[allow(clippy::too_many_arguments)]
fn build_users(
    st: &'static Strings,
    objs: &[DynamicObject],
    attributes: &BTreeMap<String, Attributes>,
    grbs: &[DynamicObject],
    crtbs: &[DynamicObject],
    prtbs: &[DynamicObject],
    tokens: &[DynamicObject],
    global_role_labels: &BTreeMap<String, String>,
    admin_roles: &BTreeSet<String>,
    providers: &[AuthProvider],
) -> Vec<RancherUser> {
    let mut roles_by_user: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    for b in grbs {
        let Some(user) = str_at(&b.data, "userName") else { continue };
        let Some(role) = str_at(&b.data, "globalRoleName") else { continue };
        let label = global_role_labels
            .get(&role)
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| role.clone());
        roles_by_user
            .entry(user)
            .or_default()
            .push((label, admin_roles.contains(&role)));
    }

    let mut bindings_by_user: BTreeMap<String, usize> = BTreeMap::new();
    for b in crtbs.iter().chain(prtbs.iter()) {
        if let Some(user) = str_at(&b.data, "userName") {
            *bindings_by_user.entry(user).or_default() += 1;
        }
    }

    let mut tokens_by_user: BTreeMap<String, usize> = BTreeMap::new();
    for t in tokens {
        if let Some(user) = str_at(&t.data, "userId") {
            *tokens_by_user.entry(user).or_default() += 1;
        }
    }

    // Whether any external provider is configured decides what a local-only account means: on a
    // directory-backed Rancher it is an account outside the directory, worth naming; on a Rancher
    // with local auth only it is simply how every account looks.
    let external_provider = providers.iter().find(|p| p.name != "local").map(|p| p.name.clone());

    let mut out: Vec<RancherUser> = objs
        .iter()
        .map(|o| {
            let id = o.metadata.name.clone().unwrap_or_default();
            let attrs = attributes.get(&id);
            let principals: Vec<Principal> = o
                .data
                .get("principalIds")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).filter_map(parse_principal).collect())
                .unwrap_or_default();
            // The external principal is the identity; `local://` is the Rancher id restated.
            let external = principals.iter().find(|p| !p.is_local()).cloned();
            // A directory rename lands in the UserAttribute before it lands in `principalIds`.
            let external = match (&external, attrs.and_then(|a| a.extra_identity.as_deref())) {
                (Some(_), Some(extra)) => parse_principal(extra).or_else(|| external.clone()),
                (Some(_), None) => external.clone(),
                (None, _) => None,
            };

            let username = str_at(&o.data, "username").unwrap_or_default();
            let display_name = str_at(&o.data, "displayName").unwrap_or_default();
            let enabled = o.data.get("enabled").and_then(Value::as_bool);
            let must_change_password = o
                .data
                .get("mustChangePassword")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let global_roles: Vec<String> = roles_by_user
                .get(&id)
                .map(|v| v.iter().map(|(l, _)| l.clone()).collect())
                .unwrap_or_default();
            let is_admin = roles_by_user
                .get(&id)
                .map(|v| v.iter().any(|(_, admin)| *admin))
                .unwrap_or(false);

            let token_count = tokens_by_user.get(&id).copied().unwrap_or(0);
            let binding_count = bindings_by_user.get(&id).copied().unwrap_or(0);
            let groups = attrs.map(|a| a.groups.clone()).unwrap_or_default();
            let last_refresh = attrs.map(|a| a.last_refresh.clone()).unwrap_or_default();

            let age = o
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_default();

            let mut user = RancherUser {
                uid: format!("ranch|user|{}", id),
                identity: external
                    .as_ref()
                    .map(|p| p.display.clone())
                    .unwrap_or_else(|| username.clone()),
                identity_opaque: external.as_ref().map(|p| p.opaque).unwrap_or(false),
                provider: external
                    .as_ref()
                    .map(|p| p.provider.clone())
                    .unwrap_or_else(|| "local".to_string()),
                principal: external
                    .as_ref()
                    .map(|p| format!("{}_user://{}", p.provider, p.id))
                    .unwrap_or_default(),
                local_only: external.is_none(),
                id,
                username,
                display_name,
                enabled,
                must_change_password,
                global_roles,
                is_admin,
                groups,
                last_refresh,
                token_count,
                binding_count,
                age,
                hints: Vec::new(),
            };
            user_hints(st, &mut user, external_provider.as_deref());
            user
        })
        .collect();

    out.sort_by(|a, b| {
        // Admins first — the answer to "who can do everything here" should not need scrolling —
        // then by the name a human would search for.
        b.is_admin
            .cmp(&a.is_admin)
            .then_with(|| user_sort_key(a).cmp(&user_sort_key(b)))
    });
    out
}

fn user_sort_key(u: &RancherUser) -> String {
    let base = if !u.identity.is_empty() {
        &u.identity
    } else if !u.display_name.is_empty() {
        &u.display_name
    } else {
        &u.id
    };
    base.to_lowercase()
}

/// The name to show for an account wherever a binding or a token points at it.
pub fn user_label(u: &RancherUser) -> String {
    if !u.display_name.is_empty() {
        u.display_name.clone()
    } else if !u.identity.is_empty() && !u.identity_opaque {
        u.identity.clone()
    } else if !u.username.is_empty() {
        u.username.clone()
    } else {
        u.id.clone()
    }
}

fn user_hints(st: &'static Strings, u: &mut RancherUser, external_provider: Option<&str>) {
    if u.enabled == Some(false) {
        u.hints.push(warn(st.ranch_user_disabled.to_string()));
    }
    if u.must_change_password {
        u.hints.push(info(st.ranch_user_must_change_pw.to_string()));
    }
    if u.is_admin {
        u.hints.push(info(st.ranch_user_admin.to_string()));
    }
    // A local account on a directory-backed Rancher is a credential that no directory offboarding
    // will ever revoke. Stated, not judged: bootstrap and break-glass accounts are legitimate.
    if u.local_only {
        if let Some(provider) = external_provider {
            u.hints.push(info(fill(st.ranch_user_local_only, &[("provider", provider)])));
        }
    }
    if !u.local_only && u.last_refresh.is_empty() {
        u.hints.push(info(st.ranch_user_never_refreshed.to_string()));
    }
    if u.binding_count == 0 && u.groups.is_empty() && !u.is_admin {
        u.hints.push(info(st.ranch_user_no_access.to_string()));
    }
}

#[allow(clippy::too_many_arguments)]
fn build_bindings(
    st: &'static Strings,
    default_roles: &BTreeSet<String>,
    grbs: &[DynamicObject],
    crtbs: &[DynamicObject],
    prtbs: &[DynamicObject],
    user_labels: &BTreeMap<String, String>,
    project_labels: &BTreeMap<String, String>,
    role_labels: &BTreeMap<String, String>,
    global_role_labels: &BTreeMap<String, String>,
) -> Vec<RancherBinding> {
    let mut out: Vec<RancherBinding> = Vec::new();

    for b in grbs {
        let role = str_at(&b.data, "globalRoleName").unwrap_or_default();
        let automatic = default_roles.contains(&role);
        let mut row = one_binding(
            st,
            b,
            "GlobalRoleBinding",
            BindScope::Global,
            String::new(),
            String::new(),
            role,
            global_role_labels,
            user_labels,
        );
        row.automatic = automatic;
        out.push(row);
    }
    for b in crtbs {
        let cluster = str_at(&b.data, "clusterName").unwrap_or_default();
        let role = str_at(&b.data, "roleTemplateName").unwrap_or_default();
        out.push(one_binding(
            st,
            b,
            "ClusterRoleTemplateBinding",
            BindScope::Cluster,
            cluster.clone(),
            cluster,
            role,
            role_labels,
            user_labels,
        ));
    }
    for b in prtbs {
        let project = str_at(&b.data, "projectName").unwrap_or_default();
        let label = project_labels
            .get(project.split(':').next_back().unwrap_or_default())
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| project.clone());
        let role = str_at(&b.data, "roleTemplateName").unwrap_or_default();
        out.push(one_binding(
            st,
            b,
            "ProjectRoleTemplateBinding",
            BindScope::Project,
            project,
            label,
            role,
            role_labels,
            user_labels,
        ));
    }

    out.sort_by(|a, b| {
        a.automatic
            .cmp(&b.automatic)
            .then_with(|| a.scope.cmp(&b.scope))
            .then_with(|| a.scope_label.to_lowercase().cmp(&b.scope_label.to_lowercase()))
            .then_with(|| a.subject_label.to_lowercase().cmp(&b.subject_label.to_lowercase()))
    });
    out
}

#[allow(clippy::too_many_arguments)]
fn one_binding(
    st: &'static Strings,
    o: &DynamicObject,
    kind: &str,
    scope: BindScope,
    scope_id: String,
    scope_label: String,
    role: String,
    role_labels: &BTreeMap<String, String>,
    user_labels: &BTreeMap<String, String>,
) -> RancherBinding {
    let name = o.metadata.name.clone().unwrap_or_default();
    let namespace = o.metadata.namespace.clone().unwrap_or_default();
    let user = str_at(&o.data, "userName").unwrap_or_default();
    let group = str_at(&o.data, "groupPrincipalName").unwrap_or_default();

    let (subject_kind, subject_id, subject_label, provider) = if !user.is_empty() {
        let label = user_labels.get(&user).cloned().unwrap_or_else(|| user.clone());
        // `userPrincipalName` names the provider the binding was created through, which can differ
        // from the account's current one.
        // A GlobalRoleBinding carries no principal at all: leaving the column empty says the binding
        // does not name a provider, where "local" would claim it named one.
        let provider = str_at(&o.data, "userPrincipalName")
            .and_then(|p| parse_principal(&p))
            .map(|p| p.provider)
            .unwrap_or_default();
        (Some(PrincipalKind::User), user, label, provider)
    } else if !group.is_empty() {
        match parse_principal(&group) {
            Some(p) => (Some(PrincipalKind::Group), p.id.clone(), p.display, p.provider),
            None => (Some(PrincipalKind::Group), group.clone(), group, String::new()),
        }
    } else {
        (None, String::new(), String::new(), String::new())
    };

    let role_label = role_labels
        .get(&role)
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| role.clone());
    let age = o
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    let mut hints = Vec::new();
    if subject_kind.is_none() {
        hints.push(warn(st.ranch_binding_no_subject.to_string()));
    }
    // A binding whose user id resolves to nothing grants access to an account that no longer exists:
    // harmless, but it is dead RBAC nobody will ever clean up otherwise. Only ever raised on the
    // local cluster, where the user list is authoritative.
    if subject_kind == Some(PrincipalKind::User) && !user_labels.contains_key(&subject_id) {
        hints.push(warn(fill(st.ranch_binding_unknown_user, &[("user", &subject_id)])));
    }

    RancherBinding {
        uid: format!("ranch|binding|{}|{}/{}", kind, namespace, name),
        scope: Some(scope),
        scope_id,
        scope_label,
        subject_kind,
        subject_id,
        subject_label,
        provider,
        owner_role: is_owner_role(&role),
        role,
        role_label,
        authoritative: true,
        automatic: false,
        kind: kind.to_string(),
        api_version: API_MGMT.to_string(),
        namespace,
        name,
        age,
        hints,
    }
}

// The built-in roles that own their scope. Used to colour a row, never to compute a verdict.
fn is_owner_role(role: &str) -> bool {
    matches!(role, "admin" | "restricted-admin" | "cluster-owner" | "project-owner")
}

fn build_tokens(
    st: &'static Strings,
    objs: &[DynamicObject],
    user_labels: &BTreeMap<String, String>,
) -> Vec<RancherToken> {
    let mut out: Vec<RancherToken> = objs
        .iter()
        .map(|o| {
            let name = o.metadata.name.clone().unwrap_or_default();
            let user_id = str_at(&o.data, "userId").unwrap_or_default();
            let user_label = user_labels.get(&user_id).cloned().unwrap_or_default();
            let kind = o
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(L_TOKEN_KIND))
                .cloned()
                .unwrap_or_default();
            let ttl_ms = o.data.get("ttl").and_then(Value::as_i64).unwrap_or(0);
            let expires_at = str_at(&o.data, "expiresAt").unwrap_or_default();
            let expired = o.data.get("expired").and_then(Value::as_bool).unwrap_or(false);
            let age = o
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_default();

            let mut hints = Vec::new();
            if expired {
                hints.push(info(st.ranch_token_expired.to_string()));
            }
            // A token with no user is a credential pointing at nothing — or at an account this view
            // could not read. Either way it is worth a look.
            if !user_id.is_empty() && !user_labels.contains_key(&user_id) {
                hints.push(warn(fill(st.ranch_token_unknown_user, &[("user", &user_id)])));
            }
            // An API key that never expires is the one credential a directory offboarding cannot
            // revoke. Session and kubeconfig tokens are excluded: Rancher manages their lifecycle.
            if ttl_ms == 0 && !expired && kind.is_empty() {
                hints.push(info(st.ranch_token_no_expiry.to_string()));
            }

            RancherToken {
                uid: format!("ranch|token|{}", name),
                name,
                user_id,
                user_label,
                provider: str_at(&o.data, "authProvider").unwrap_or_default(),
                kind,
                description: str_at(&o.data, "description").unwrap_or_default(),
                ttl_ms,
                expires_at,
                expired,
                cluster: str_at(&o.data, "clusterName").unwrap_or_default(),
                age,
                hints,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        a.user_label
            .to_lowercase()
            .cmp(&b.user_label.to_lowercase())
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn server_hints(
    st: &'static Strings,
    server: &mut RancherServer,
    users: &[RancherUser],
    tokens: &[RancherToken],
) {
    if server.providers.iter().all(|p| p.name == "local") {
        server.hints.push(info(st.ranch_server_local_auth_only.to_string()));
    }
    let admins = users.iter().filter(|u| u.is_admin).count();
    if admins == 0 {
        server.hints.push(info(st.ranch_server_no_admin.to_string()));
    }
    let expired = tokens.iter().filter(|t| t.expired).count();
    if expired > 0 {
        server
            .hints
            .push(info(fill(st.ranch_server_expired_tokens, &[("n", &expired.to_string())])));
    }
}

// --- Downstream cluster --------------------------------------------------------------------------

// What a registered cluster can still answer: the access map the agent projected, and the namespace
// → project annotations. No identity is resolvable here, and every row says so by carrying
// `authoritative: false`.
fn build_downstream(
    st: &'static Strings,
    listed: &Listed,
    namespaces: &[Namespace],
    projected: &Projected,
) -> RancherState {
    let empty: Vec<DynamicObject> = Vec::new();
    let get = |k: &str| listed.get(k).unwrap_or(&empty);
    let settings = index_settings(get("Setting"));
    let ns_by_project = namespaces_by_project(namespaces);

    let cluster_id = ns_by_project
        .keys()
        .find_map(|k| k.split_once(':').map(|(c, _)| c.to_string()))
        .unwrap_or_default();

    let mut bindings: Vec<RancherBinding> = Vec::new();
    let mut subjects: BTreeMap<String, RancherUser> = BTreeMap::new();

    for rb in &projected.role_bindings {
        let Some(owner) = rtb_owner(rb.metadata.labels.as_ref()) else { continue };
        let namespace = rb.metadata.namespace.clone().unwrap_or_default();
        let name = rb.metadata.name.clone().unwrap_or_default();
        let role = rb.role_ref.name.clone();
        let age = rb
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default();
        let project = owner.split('_').next().unwrap_or_default().to_string();
        for subject in rb.subjects.iter().flatten() {
            let (kind, id, label, provider) = projected_subject(&subject.kind, &subject.name);
            note_subject(&mut subjects, kind, &id, &provider);
            bindings.push(RancherBinding {
                uid: format!("ranch|rb|{}/{}|{}", namespace, name, id),
                scope: Some(BindScope::Project),
                scope_id: project.clone(),
                scope_label: project.clone(),
                subject_kind: Some(kind),
                subject_id: id,
                subject_label: label,
                provider,
                role: role.clone(),
                role_label: role.clone(),
                owner_role: is_owner_role(&role),
                authoritative: false,
                automatic: false,
                kind: "RoleBinding".to_string(),
                api_version: "rbac.authorization.k8s.io/v1".to_string(),
                namespace: namespace.clone(),
                name: name.clone(),
                age: age.clone(),
                hints: Vec::new(),
            });
        }
    }

    for crb in &projected.cluster_role_bindings {
        let Some(_owner) = rtb_owner(crb.metadata.labels.as_ref()) else { continue };
        let name = crb.metadata.name.clone().unwrap_or_default();
        let role = crb.role_ref.name.clone();
        let age = crb
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default();
        for subject in crb.subjects.iter().flatten() {
            let (kind, id, label, provider) = projected_subject(&subject.kind, &subject.name);
            note_subject(&mut subjects, kind, &id, &provider);
            bindings.push(RancherBinding {
                uid: format!("ranch|crb|{}|{}", name, id),
                scope: Some(BindScope::Cluster),
                scope_id: cluster_id.clone(),
                scope_label: cluster_id.clone(),
                subject_kind: Some(kind),
                subject_id: id,
                subject_label: label,
                provider,
                role: role.clone(),
                role_label: role.clone(),
                owner_role: is_owner_role(&role),
                authoritative: false,
                automatic: false,
                kind: "ClusterRoleBinding".to_string(),
                api_version: "rbac.authorization.k8s.io/v1".to_string(),
                namespace: String::new(),
                name: name.clone(),
                age: age.clone(),
                hints: Vec::new(),
            });
        }
    }

    bindings.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then_with(|| a.scope_label.cmp(&b.scope_label))
            .then_with(|| a.subject_label.to_lowercase().cmp(&b.subject_label.to_lowercase()))
    });

    // Projects, from the annotations alone: the ids are real, the display names live upstream.
    let mut projects: Vec<RancherProject> = ns_by_project
        .iter()
        .map(|(key, namespaces)| {
            let (cluster, id) = key.split_once(':').unwrap_or(("", key.as_str()));
            let members = bindings
                .iter()
                .filter(|b| b.scope == Some(BindScope::Project) && b.scope_id == id)
                .map(|b| b.subject_id.clone())
                .collect::<BTreeSet<_>>()
                .len();
            RancherProject {
                uid: format!("ranch|project|{}", key),
                id: id.to_string(),
                // No Project object to read a name from: the id is the truth available here.
                display_name: id.to_string(),
                cluster: cluster.to_string(),
                namespaces: namespaces.clone(),
                members,
                owners: Vec::new(),
                quota: String::new(),
                creator: String::new(),
                age: String::new(),
                hints: vec![info(st.ranch_project_upstream.to_string())],
                namespace: String::new(),
                name: id.to_string(),
            }
        })
        .collect();
    projects.sort_by(|a, b| a.id.cmp(&b.id));

    let mut users: Vec<RancherUser> = subjects.into_values().collect();
    for u in users.iter_mut() {
        u.binding_count = bindings.iter().filter(|b| b.subject_id == u.id).count();
    }
    users.sort_by_key(user_sort_key);

    let mut server = RancherServer {
        role: ClusterRole::Downstream,
        version: settings.get("server-version").cloned().unwrap_or_default(),
        url: settings.get("server-url").cloned().unwrap_or_default(),
        cluster_id,
        cluster_name: String::new(),
        providers: auth_providers(get("AuthConfig")),
        hints: vec![info(st.ranch_downstream.to_string())],
    };
    if server.url.is_empty() {
        server.url = settings.get("api-host").cloned().unwrap_or_default();
    }

    RancherState {
        server,
        users,
        bindings,
        projects,
        tokens: Vec::new(),
        orphan_namespaces: namespaces
            .iter()
            .filter(|n| project_of_namespace(n).is_none())
            .count(),
        error: None,
        loading: false,
    }
}

// The binding a projected RoleBinding came from, in either of the two shapes Rancher has used: a
// label value, or the same string as a label *key* set to "true".
fn rtb_owner(labels: Option<&BTreeMap<String, String>>) -> Option<String> {
    let labels = labels?;
    if let Some(v) = labels.get(L_RTB_OWNER).or_else(|| labels.get(L_RTB_OWNER_LEGACY)) {
        return Some(v.clone());
    }
    labels
        .iter()
        .find(|(k, v)| v.as_str() == "true" && k.starts_with("p-") && k.contains('_'))
        .map(|(k, _)| k.clone())
}

// A subject of a projected binding. Users are `u-…` ids with nothing to resolve them against here;
// groups carry their full principal, which does read as a real identity.
fn projected_subject(
    kind: &str,
    name: &str,
) -> (PrincipalKind, String, String, String) {
    if kind == "Group" {
        return match parse_principal(name) {
            Some(p) => (PrincipalKind::Group, p.id, p.display, p.provider),
            None => (PrincipalKind::Group, name.to_string(), name.to_string(), String::new()),
        };
    }
    // Nothing on a downstream says which provider a `u-…` authenticated through: an empty provider
    // is what "unknown" looks like, and "local" would be a claim.
    (PrincipalKind::User, name.to_string(), name.to_string(), String::new())
}

fn note_subject(
    subjects: &mut BTreeMap<String, RancherUser>,
    kind: PrincipalKind,
    id: &str,
    provider: &str,
) {
    if kind != PrincipalKind::User || id.is_empty() {
        return;
    }
    subjects.entry(id.to_string()).or_insert_with(|| RancherUser {
        uid: format!("ranch|user|{}", id),
        id: id.to_string(),
        // Repeating the id in the identity column would dress an unresolved account up as a
        // resolved one; an empty identity is what the view renders as "not resolvable from here".
        identity: String::new(),
        // Nothing upstream is readable from here, so the id is all there is — and saying it is
        // opaque is what stops the view from presenting it as a name.
        identity_opaque: true,
        provider: provider.to_string(),
        ..RancherUser::default()
    });
}

// --- Helpers -------------------------------------------------------------------------------------

fn str_at(data: &Value, key: &str) -> Option<String> {
    data.get(key).and_then(Value::as_str).map(|s| s.trim().to_string())
}

/// A token TTL rendered for a human. `0` is Rancher's "never expires", not "expired".
pub fn format_ttl(ttl_ms: i64, st: &'static Strings) -> String {
    if ttl_ms <= 0 {
        return st.ranch_ttl_never.to_string();
    }
    let secs = ttl_ms / 1000;
    if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// A `LastRefresh` timestamp as an age. Rancher writes RFC 3339; anything else is passed through
/// rather than guessed at.
pub fn format_refresh(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match raw.parse::<k8s_openapi::jiff::Timestamp>() {
        Ok(t) => format_age(&t),
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(value: serde_json::Value) -> DynamicObject {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn ldap_principal_reads_as_a_person() {
        let p = parse_principal(
            "openldap_user://CN=LE SECH Clementine,OU=USERS,OU=GENERALI,DC=Groupe,DC=fr",
        )
        .unwrap();
        assert_eq!(p.provider, "openldap");
        assert_eq!(p.kind, PrincipalKind::User);
        assert_eq!(p.display, "LE SECH Clementine");
        assert!(!p.opaque);
    }

    #[test]
    fn freeipa_principal_reads_as_a_uid() {
        let p = parse_principal("freeipa_user://uid=jdoe,cn=users,cn=accounts,dc=example").unwrap();
        assert_eq!(p.provider, "freeipa");
        assert_eq!(p.display, "jdoe");
    }

    #[test]
    fn group_principal_keeps_its_kind() {
        let p = parse_principal(
            "openldap_group://CN=dsm-ppl-k8s,OU=Groups,OU=Hadoop,DC=Groupe,DC=fr",
        )
        .unwrap();
        assert_eq!(p.kind, PrincipalKind::Group);
        assert_eq!(p.display, "dsm-ppl-k8s");
    }

    #[test]
    fn opaque_subject_is_shown_raw() {
        // An OIDC subject is a GUID: dressing it up as a name would invent an identity.
        let p = parse_principal("keycloakoidc_user://8f14e45f-ceea-467a-9575-1ad0f4d3e9a2").unwrap();
        assert_eq!(p.display, "8f14e45f-ceea-467a-9575-1ad0f4d3e9a2");
        assert!(p.opaque);
        // So is a local id.
        let p = parse_principal("local://u-4oivhvq2jk").unwrap();
        assert!(p.is_local());
        assert!(p.opaque);
        assert_eq!(p.display, "u-4oivhvq2jk");
    }

    #[test]
    fn escaped_comma_stays_inside_the_cn() {
        let p = parse_principal("activedirectory_user://CN=Doe\\, John,OU=Users,DC=corp").unwrap();
        assert_eq!(p.display, "Doe, John");
    }

    #[test]
    fn absent_enabled_is_an_active_account() {
        // 153 of 159 accounts on a production Rancher have no `enabled` field: reading absent as
        // disabled would report the whole directory as locked out.
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let users = build_users(
            st,
            &[obj(json!({
                "apiVersion": "management.cattle.io/v3",
                "kind": "User",
                "metadata": { "name": "u-abc" },
                "username": "jdoe",
                "principalIds": ["openldap_user://CN=John Doe,DC=corp", "local://u-abc"]
            }))],
            &BTreeMap::new(),
            &[],
            &[],
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            &[],
        );
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].enabled, None);
        assert!(users[0].hints.iter().all(|h| h.level < HintLevel::Warn));
        assert_eq!(users[0].identity, "John Doe");
        assert_eq!(users[0].provider, "openldap");
        assert!(!users[0].local_only);
    }

    #[test]
    fn disabled_account_warns() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let users = build_users(
            st,
            &[obj(json!({
                "apiVersion": "management.cattle.io/v3",
                "kind": "User",
                "metadata": { "name": "u-abc" },
                "enabled": false,
                "username": "jdoe",
                "principalIds": ["local://u-abc"]
            }))],
            &BTreeMap::new(),
            &[],
            &[],
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            &[],
        );
        assert!(users[0].hints.iter().any(|h| h.level == HintLevel::Warn));
        assert!(users[0].local_only);
    }

    #[test]
    fn admin_is_read_from_the_global_role_rules() {
        let roles = vec![
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRole",
                "metadata": { "name": "admin" }, "displayName": "Admin",
                "rules": [{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }]
            })),
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRole",
                "metadata": { "name": "user" }, "displayName": "User",
                "rules": [{ "apiGroups": ["management.cattle.io"], "resources": ["preferences"], "verbs": ["*"] }]
            })),
        ];
        let admins = admin_global_roles(&roles);
        assert!(admins.contains("admin"));
        assert!(!admins.contains("user"));
    }

    #[test]
    fn group_principals_are_read_from_either_spelling() {
        // PascalCase container, lowercase `items` — and the `Items` twin that some versions fill.
        let attrs = index_attributes(&[obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "UserAttribute",
            "metadata": { "name": "u-abc" },
            "UserName": "jdoe",
            "LastRefresh": "2026-08-14T00:00:06Z",
            "GroupPrincipals": {
                "openldap": { "Items": null, "items": [
                    { "metadata": { "name": "openldap_group://CN=team-a,OU=Groups,DC=corp" } }
                ]},
                "activedirectory": { "Items": [
                    { "metadata": { "name": "activedirectory_group://CN=team-b,OU=Groups,DC=corp" } }
                ], "items": [] },
                "azuread": { "Items": null, "items": [] }
            }
        }))]);
        let a = attrs.get("u-abc").unwrap();
        assert_eq!(a.groups, vec!["team-a", "team-b"]);
        assert_eq!(a.last_refresh, "2026-08-14T00:00:06Z");
    }

    #[test]
    fn only_enabled_auth_providers_count() {
        let providers = auth_providers(&[
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "AuthConfig",
                "metadata": { "name": "azuread" }, "type": "azureADConfig"
            })),
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "AuthConfig",
                "metadata": { "name": "openldap" }, "type": "openLdapConfig",
                "enabled": true, "accessMode": "required"
            })),
        ]);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "openldap");
        assert_eq!(providers[0].access_mode, "required");
    }

    #[test]
    fn binding_resolves_its_subject_and_scope() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let prtb = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "ProjectRoleTemplateBinding",
            "metadata": { "name": "prtb-1", "namespace": "p-22ldd" },
            "projectName": "local:p-22ldd",
            "roleTemplateName": "project-owner",
            "userName": "u-abc",
            "userPrincipalName": "openldap_user://CN=John Doe,DC=corp"
        }));
        let users: BTreeMap<String, String> =
            [("u-abc".to_string(), "John Doe".to_string())].into_iter().collect();
        let projects: BTreeMap<String, String> =
            [("p-22ldd".to_string(), "selenium".to_string())].into_iter().collect();
        let roles: BTreeMap<String, String> =
            [("project-owner".to_string(), "Project Owner".to_string())].into_iter().collect();

        let out = build_bindings(st, &BTreeSet::new(), &[], &[], &[prtb], &users, &projects, &roles, &BTreeMap::new());
        assert_eq!(out.len(), 1);
        let b = &out[0];
        assert_eq!(b.scope, Some(BindScope::Project));
        assert_eq!(b.scope_label, "selenium");
        assert_eq!(b.subject_label, "John Doe");
        assert_eq!(b.role_label, "Project Owner");
        assert_eq!(b.provider, "openldap");
        assert!(b.owner_role);
        assert!(b.authoritative);
        assert!(b.hints.is_empty());
    }

    #[test]
    fn the_default_global_binding_sorts_below_a_real_grant() {
        // Every account carries the `user` global role because Rancher put it there. Left in place,
        // 155 such rows sit above every binding anyone actually granted.
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let roles = vec![
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRole",
                "metadata": { "name": "user" }, "displayName": "User", "newUserDefault": true
            })),
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRole",
                "metadata": { "name": "admin" }, "displayName": "Admin"
            })),
        ];
        let defaults = default_global_roles(&roles);
        assert_eq!(defaults.len(), 1);
        let grbs = vec![
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRoleBinding",
                "metadata": { "name": "grb-default" },
                "globalRoleName": "user", "userName": "u-abc"
            })),
            obj(json!({
                "apiVersion": "management.cattle.io/v3", "kind": "GlobalRoleBinding",
                "metadata": { "name": "grb-admin" },
                "globalRoleName": "admin", "userName": "u-abc"
            })),
        ];
        let users: BTreeMap<String, String> =
            [("u-abc".to_string(), "John Doe".to_string())].into_iter().collect();
        let out = build_bindings(
            st, &defaults, &grbs, &[], &[], &users, &BTreeMap::new(), &BTreeMap::new(),
            &display_names(&roles),
        );
        assert_eq!(out[0].role, "admin");
        assert!(!out[0].automatic);
        assert!(out[1].automatic);
        // A GlobalRoleBinding names no principal, so no provider is claimed for it.
        assert!(out[0].provider.is_empty());
    }

    #[test]
    fn binding_to_a_deleted_account_warns() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let crtb = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "ClusterRoleTemplateBinding",
            "metadata": { "name": "crtb-1", "namespace": "local" },
            "clusterName": "local",
            "roleTemplateName": "cluster-owner",
            "userName": "u-gone"
        }));
        let out = build_bindings(
            st, &BTreeSet::new(), &[], &[crtb], &[], &BTreeMap::new(), &BTreeMap::new(),
            &BTreeMap::new(), &BTreeMap::new(),
        );
        assert!(out[0].hints.iter().any(|h| h.level == HintLevel::Warn));
    }

    #[test]
    fn group_binding_keeps_the_directory_name() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let crtb = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "ClusterRoleTemplateBinding",
            "metadata": { "name": "crtb-1", "namespace": "local" },
            "clusterName": "local",
            "roleTemplateName": "projects-create",
            "groupPrincipalName": "openldap_group://CN=dsm-ppl-k8s,OU=Groups,DC=corp"
        }));
        let out = build_bindings(
            st, &BTreeSet::new(), &[], &[crtb], &[], &BTreeMap::new(), &BTreeMap::new(),
            &BTreeMap::new(), &BTreeMap::new(),
        );
        assert_eq!(out[0].subject_kind, Some(PrincipalKind::Group));
        assert_eq!(out[0].subject_label, "dsm-ppl-k8s");
        // A group binding names no account, so the unknown-user rule must stay quiet.
        assert!(out[0].hints.is_empty());
    }

    #[test]
    fn project_counts_its_namespaces_and_members() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let project = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "Project",
            "metadata": { "name": "p-22ldd", "namespace": "local" },
            "spec": {
                "clusterName": "local",
                "displayName": "selenium",
                "resourceQuota": { "limit": { "limitsCpu": "10", "limitsMemory": "20Gi" } }
            }
        }));
        let prtb = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "ProjectRoleTemplateBinding",
            "metadata": { "name": "prtb-1", "namespace": "p-22ldd" },
            "projectName": "local:p-22ldd",
            "roleTemplateName": "project-owner",
            "userName": "u-abc"
        }));
        let ns_by_project: BTreeMap<String, Vec<String>> = [(
            "local:p-22ldd".to_string(),
            vec!["selenium".to_string(), "selenium-dev".to_string()],
        )]
        .into_iter()
        .collect();

        let projects = build_projects(st, &[project], &[prtb], &ns_by_project);
        assert_eq!(projects[0].display_name, "selenium");
        assert_eq!(projects[0].namespaces.len(), 2);
        assert_eq!(projects[0].members, 1);
        assert_eq!(projects[0].quota, "limitsCpu=10 limitsMemory=20Gi");
        assert!(projects[0].hints.is_empty());
    }

    #[test]
    fn project_without_namespace_or_member_says_so() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let project = obj(json!({
            "apiVersion": "management.cattle.io/v3",
            "kind": "Project",
            "metadata": { "name": "p-empty", "namespace": "local" },
            "spec": { "clusterName": "local", "displayName": "empty" }
        }));
        let projects = build_projects(st, &[project], &[], &BTreeMap::new());
        assert_eq!(projects[0].hints.len(), 2);
        assert!(projects[0].quota.is_empty());
    }

    #[test]
    fn token_ttl_zero_never_expires() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        assert_eq!(format_ttl(0, st), st.ranch_ttl_never);
        assert_eq!(format_ttl(7_776_000_000, st), "90d");
    }

    #[test]
    fn api_key_without_expiry_is_surfaced_but_kubeconfig_is_not() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let users: BTreeMap<String, String> =
            [("u-abc".to_string(), "John Doe".to_string())].into_iter().collect();
        let tokens = build_tokens(
            st,
            &[
                obj(json!({
                    "apiVersion": "management.cattle.io/v3", "kind": "Token",
                    "metadata": { "name": "token-api" },
                    "userId": "u-abc", "authProvider": "openldap", "ttl": 0
                })),
                obj(json!({
                    "apiVersion": "management.cattle.io/v3", "kind": "Token",
                    "metadata": {
                        "name": "kubeconfig-u-abc",
                        "labels": { "authn.management.cattle.io/kind": "kubeconfig" }
                    },
                    "userId": "u-abc", "authProvider": "openldap", "ttl": 0
                })),
            ],
            &users,
        );
        let api = tokens.iter().find(|t| t.name == "token-api").unwrap();
        let kubeconfig = tokens.iter().find(|t| t.name.starts_with("kubeconfig")).unwrap();
        assert_eq!(api.user_label, "John Doe");
        assert!(!api.hints.is_empty());
        assert!(kubeconfig.hints.is_empty());
        assert_eq!(kubeconfig.kind, "kubeconfig");
    }

    #[test]
    fn downstream_rebuilds_access_from_projected_bindings() {
        let st = crate::lang::t(crate::ai::AiLanguage::En);
        let rb: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": "rb-1", "namespace": "app-dev",
                "labels": { "authz.cluster.cattle.io/rtb-owner-updated": "p-8f87r_creator-project-owner" }
            },
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin" },
            "subjects": [
                { "apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "u-dwr2rc7oeb" },
                { "apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                  "name": "openldap_group://CN=dsm-ppl-admins,OU=Groups,DC=corp" }
            ]
        }))
        .unwrap();
        let ns: Namespace = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {
                "name": "app-dev",
                "annotations": { "field.cattle.io/projectId": "c-5h42c:p-8f87r" }
            }
        }))
        .unwrap();

        let state = build_downstream(
            st,
            &Listed::new(),
            &[ns],
            &Projected { role_bindings: vec![rb], cluster_role_bindings: Vec::new() },
        );
        assert_eq!(state.server.role, ClusterRole::Downstream);
        assert_eq!(state.server.cluster_id, "c-5h42c");
        assert_eq!(state.bindings.len(), 2);
        // The group reads as its directory name; the user id has nothing to resolve against here.
        let group = state.bindings.iter().find(|b| b.subject_kind == Some(PrincipalKind::Group)).unwrap();
        assert_eq!(group.subject_label, "dsm-ppl-admins");
        assert!(!group.authoritative);
        assert_eq!(state.users.len(), 1);
        assert!(state.users[0].identity_opaque);
        // Neither the person nor the provider is knowable from here, and the view claims neither.
        assert!(state.users[0].identity.is_empty());
        assert!(state.users[0].provider.is_empty());
        assert_eq!(state.external_users(), 0);
        assert_eq!(state.users[0].binding_count, 1);
        // The project map survives without any Project object.
        assert_eq!(state.projects.len(), 1);
        assert_eq!(state.projects[0].id, "p-8f87r");
        assert_eq!(state.projects[0].namespaces, vec!["app-dev"]);
        assert_eq!(state.projects[0].members, 2);
    }

    #[test]
    fn legacy_rtb_owner_label_key_is_recognised() {
        let mut labels = BTreeMap::new();
        labels.insert("p-28frt_creator-project-owner".to_string(), "true".to_string());
        labels.insert("cattle.io/creator".to_string(), "norman".to_string());
        assert_eq!(rtb_owner(Some(&labels)).as_deref(), Some("p-28frt_creator-project-owner"));
    }
}
