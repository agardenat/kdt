//! RBAC security view: lists every effective binding (RoleBinding/ClusterRoleBinding) resolved
//! down to its rules, and scores each one so the dangerous/admin grants surface first.
//!
//! The model is binding-centric on purpose: a Role/ClusterRole alone is inert until bound, and the
//! same ClusterRole can be low risk as a namespaced RoleBinding yet critical as a ClusterRoleBinding.
//! Severity is therefore computed per binding, from three inputs: the resolved rules' signatures,
//! the subjects (public groups, system:masters, default SA), and the namespace (kube-system/
//! flux-system… where a local foothold escalates cluster-wide).
//!
//! Scoring stays binding-centric, but the *graph* around it is materialised too: Roles/ClusterRoles,
//! their aggregation edges and the ServiceAccounts are kept as entities of their own so the view can
//! be read from any end (by subject, by binding, by role) and so `y`/`e` can open the ClusterRole
//! itself rather than only the binding that points at it.
//!
//! `classify()` is pure and unit-tested; `fetch_rbac()` wires it to the live cluster following the
//! same Shared-state pattern as `pods.rs`/`flux.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule as K8sPolicyRule, Role, RoleBinding,
};
use crate::lang::{Strings, fill};
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::events::format_age;

// Namespaces where a local binding escalates cluster-wide (controller SA tokens, GitOps controllers,
// admission webhooks…). User-overridable; the override is merged with this default list.
pub const CRITICAL_NS_DEFAULT: &[&str] = &[
    "kube-system",
    "kube-node-lease",
    "kube-public",
    "flux-system",
    "argocd",
    "argo-cd",
    "cert-manager",
    "external-secrets",
    "vault",
    "ingress-nginx",
    "istio-system",
    "linkerd",
    "kyverno",
    "gatekeeper-system",
    "velero",
    "cluster-api",
    "capi-system",
    "calico-system",
    "tigera-operator",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    ClusterWide,
    Namespace(String),
}

impl Scope {
    pub fn label(&self) -> String {
        match self {
            Scope::ClusterWide => "cluster".to_string(),
            Scope::Namespace(ns) => format!("ns:{ns}"),
        }
    }
}

// Where a binding came from, derived from its own metadata (labels/annotations/ownerRefs). Flux and
// Helm label every object they apply, so attribution needs no correlation guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    FluxKustomization { namespace: String, name: String },
    FluxHelmRelease { namespace: String, name: String },
    Helm { namespace: String, name: String },
    Argo { app: String },
    Owner { kind: String, name: String },
    Kubectl,
    Unmanaged,
}

impl Provenance {
    pub fn label(&self) -> String {
        match self {
            Provenance::FluxKustomization { namespace, name } => format!("ks:{namespace}/{name}"),
            Provenance::FluxHelmRelease { namespace, name } => format!("hr:{namespace}/{name}"),
            Provenance::Helm { namespace, name } => format!("helm:{namespace}/{name}"),
            Provenance::Argo { app } => format!("argo:{app}"),
            Provenance::Owner { kind, name } => format!("{kind}:{name}"),
            Provenance::Kubectl => "kubectl".to_string(),
            Provenance::Unmanaged => "unmanaged".to_string(),
        }
    }
    // A grant applied outside GitOps is an audit blind spot worth flagging on risky bindings.
    fn out_of_gitops(&self) -> bool {
        matches!(self, Provenance::Kubectl | Provenance::Unmanaged | Provenance::Owner { .. })
    }
}

// Flux/Helm/Argo provenance labels and annotations stamped on managed objects.
const LBL_KS_NAME: &str = "kustomize.toolkit.fluxcd.io/name";
const LBL_KS_NS: &str = "kustomize.toolkit.fluxcd.io/namespace";
const LBL_HR_NAME: &str = "helm.toolkit.fluxcd.io/name";
const LBL_HR_NS: &str = "helm.toolkit.fluxcd.io/namespace";
const LBL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
const ANN_HELM_NAME: &str = "meta.helm.sh/release-name";
const ANN_HELM_NS: &str = "meta.helm.sh/release-namespace";
const ANN_ARGO_TRACK: &str = "argocd.argoproj.io/tracking-id";
const LBL_ARGO_INSTANCE: &str = "argocd.argoproj.io/instance";
const ANN_KUBECTL: &str = "kubectl.kubernetes.io/last-applied-configuration";

// Attribute a binding from its metadata. Order matters: GitOps labels are the most reliable, then
// Helm/Argo, then an owning controller, then a kubectl-apply fingerprint, else unmanaged.
pub fn detect_provenance(meta: &ObjectMeta) -> Provenance {
    let labels = meta.labels.clone().unwrap_or_default();
    let anns = meta.annotations.clone().unwrap_or_default();

    if let Some(name) = labels.get(LBL_KS_NAME) {
        return Provenance::FluxKustomization {
            namespace: labels.get(LBL_KS_NS).cloned().unwrap_or_default(),
            name: name.clone(),
        };
    }
    if let Some(name) = labels.get(LBL_HR_NAME) {
        return Provenance::FluxHelmRelease {
            namespace: labels.get(LBL_HR_NS).cloned().unwrap_or_default(),
            name: name.clone(),
        };
    }
    if let Some(name) = anns.get(ANN_HELM_NAME) {
        return Provenance::Helm {
            namespace: anns.get(ANN_HELM_NS).cloned().unwrap_or_default(),
            name: name.clone(),
        };
    }
    if labels.get(LBL_MANAGED_BY).map(|v| v == "Helm").unwrap_or(false) {
        return Provenance::Helm { namespace: String::new(), name: String::new() };
    }
    if let Some(track) = anns.get(ANN_ARGO_TRACK) {
        // tracking-id format: "app:group/Kind:ns/name" — the app name is the leading segment.
        let app = track.split(':').next().unwrap_or(track).to_string();
        return Provenance::Argo { app };
    }
    if let Some(app) = labels.get(LBL_ARGO_INSTANCE) {
        return Provenance::Argo { app: app.clone() };
    }
    if let Some(refs) = &meta.owner_references {
        if let Some(o) = refs.iter().find(|r| r.controller == Some(true)).or_else(|| refs.first()) {
            return Provenance::Owner { kind: o.kind.clone(), name: o.name.clone() };
        }
    }
    if anns.contains_key(ANN_KUBECTL) {
        return Provenance::Kubectl;
    }
    Provenance::Unmanaged
}

// A rule flattened to plain strings so scoring is independent of the kube types (and testable).
#[derive(Debug, Clone, Default)]
pub struct PolicyRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

impl PolicyRule {
    fn has_verb(&self, v: &str) -> bool {
        self.verbs.iter().any(|x| x == "*" || x == v)
    }
    fn has_write(&self) -> bool {
        WRITE_VERBS.iter().any(|v| self.has_verb(v))
    }
    fn has_read(&self) -> bool {
        READ_VERBS.iter().any(|v| self.has_verb(v))
    }
    fn group(&self, g: &str) -> bool {
        self.api_groups.iter().any(|x| x == "*" || x == g)
    }
    fn res(&self, r: &str) -> bool {
        self.resources.iter().any(|x| x == "*" || x == r)
    }
    fn is_full_wildcard(&self) -> bool {
        self.verbs.iter().any(|x| x == "*")
            && self.resources.iter().any(|x| x == "*")
            && self.api_groups.iter().any(|x| x == "*")
    }
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
}

impl Subject {
    pub fn label(&self) -> String {
        let prefix = match self.kind.as_str() {
            "ServiceAccount" => "sa",
            "User" => "user",
            "Group" => "grp",
            other => other,
        };
        match (&self.namespace, self.kind.as_str()) {
            (Some(ns), "ServiceAccount") => format!("{prefix}:{ns}/{}", self.name),
            _ => format!("{prefix}:{}", self.name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoleRef {
    pub kind: String,
    pub name: String,
}

impl RoleRef {
    pub fn label(&self) -> String {
        let k = if self.kind == "ClusterRole" { "CRole" } else { "Role" };
        format!("{} ({k})", self.name)
    }
}

// One scored reason a binding was flagged; collected for the detail view.
#[derive(Debug, Clone)]
pub struct Finding {
    pub sev: Severity,
    pub tag: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct RbacBinding {
    pub scope: Scope,
    pub binding_kind: String,
    pub binding_name: String,
    pub subjects: Vec<Subject>,
    pub role_ref: RoleRef,
    pub rules: Vec<PolicyRule>,
    pub via_clusterrole: bool,
    pub aggregated: bool,
    pub provenance: Provenance,
    // Resolved Git/OCI/Helm source descriptor for Flux-managed bindings (chained via sourceRef).
    pub source: Option<String>,
    pub severity: Severity,
    pub findings: Vec<Finding>,
    pub age: String,
    // Index into `RbacState::roles` of the Role/ClusterRole this binding points at; `None` when the
    // roleRef dangles (the role was deleted, or lives outside what we could list).
    pub role_idx: Option<usize>,
    // Index into `RbacState::service_accounts`, aligned with `subjects`. `None` for User/Group
    // subjects and for ServiceAccounts that do not exist.
    pub sa_idx: Vec<Option<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    Role,
    ClusterRole,
}

impl RoleKind {
    pub fn label(self) -> &'static str {
        match self {
            RoleKind::Role => "Role",
            RoleKind::ClusterRole => "ClusterRole",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            RoleKind::Role => "Role",
            RoleKind::ClusterRole => "CRole",
        }
    }
}

// A Role or ClusterRole as an object in its own right. The binding-centric rows flatten these into
// `RbacBinding::rules`; keeping them separate is what lets the tree show aggregation composition,
// the ClusterRoles reused as per-namespace templates, and the roles nobody ever bound.
#[derive(Debug, Clone)]
pub struct RoleEntry {
    pub kind: RoleKind,
    pub namespace: String, // empty for a ClusterRole
    pub name: String,
    // Rules as they apply: inline rules, or the union pulled in by aggregation.
    pub rules: Vec<PolicyRule>,
    // How many rules the object itself declares, before aggregation filled it in.
    pub own_rules: usize,
    pub aggregated: bool,
    // Indices of the ClusterRoles whose labels match this one's aggregation selectors.
    pub aggregates: Vec<usize>,
    // Reverse edge: the aggregated ClusterRoles this one feeds.
    pub aggregates_into: Vec<usize>,
    // Set when an aggregation selector uses matchExpressions, which we do not evaluate: the rule
    // union is then a lower bound, and saying so beats silently under-reporting.
    pub aggregation_partial: bool,
    pub bound_cluster: usize,
    // Namespaces where a RoleBinding rebinds this role. A ClusterRole listed in several namespaces
    // is the "template" pattern: one definition, re-granted namespace by namespace.
    pub bound_namespaces: Vec<String>,
    pub provenance: Provenance,
    pub source: Option<String>,
    pub age: String,
    // Severity of the rules themselves, scored cluster-wide: the *potential* of the role, which is
    // an upper bound on what any single binding of it can grant.
    pub severity: Severity,
    pub findings: Vec<Finding>,
}

impl RoleEntry {
    pub fn uid(&self) -> String {
        format!("{}|{}/{}", self.kind.label(), self.namespace, self.name)
    }
    // A ClusterRole re-granted in several namespaces: edited once, it moves rights everywhere.
    pub fn is_template(&self) -> bool {
        self.kind == RoleKind::ClusterRole && self.bound_namespaces.len() >= 2
    }
    // Nobody binds it, so it grants nothing today — inert, but a standing offer.
    pub fn is_unbound(&self) -> bool {
        self.bound_cluster == 0 && self.bound_namespaces.is_empty()
    }
    // Worst first, like the binding rows: a role nobody can reach yet still ranks by what it would
    // grant, because that is the question the role view asks.
    fn sort_key(&self) -> (std::cmp::Reverse<u8>, String, String) {
        (
            std::cmp::Reverse(self.severity as u8),
            self.namespace.clone(),
            self.name.clone(),
        )
    }
}

// A ServiceAccount as an object, not just a subject string. Lets the view tell "granted to a SA that
// exists" from "granted to a name nobody created".
#[derive(Debug, Clone)]
pub struct SaEntry {
    pub namespace: String,
    pub name: String,
    // False when a binding names it but the cluster has no such object. Never false while
    // `RbacState::sa_degraded` is set — an unreadable list is not evidence of absence.
    pub exists: bool,
    pub automount: Option<bool>,
    pub secrets: usize,
    pub image_pull_secrets: usize,
    // Indices into `RbacState::bindings` that name this ServiceAccount.
    pub bindings: Vec<usize>,
    pub provenance: Provenance,
    pub source: Option<String>,
    pub age: String,
}

impl SaEntry {
    pub fn label(&self) -> String {
        format!("sa:{}/{}", self.namespace, self.name)
    }
}

impl RbacBinding {
    fn sort_key(&self) -> (std::cmp::Reverse<u8>, String, String) {
        (
            std::cmp::Reverse(self.severity as u8),
            self.scope.label(),
            self.binding_name.clone(),
        )
    }
    // Short comma-joined risk tags for the table's RISK column.
    pub fn risk_tags(&self) -> String {
        if self.findings.is_empty() {
            return "read-only".to_string();
        }
        let mut tags: Vec<&str> = self.findings.iter().map(|f| f.tag).collect();
        tags.dedup();
        tags.join(", ")
    }
}

const WRITE_VERBS: &[&str] = &["create", "update", "patch", "delete", "deletecollection"];
const READ_VERBS: &[&str] = &["get", "list", "watch"];

// Workload kinds whose creation lets the holder schedule a pod (and thus run code / use a SA).
const WORKLOADS: &[&str] = &[
    "deployments",
    "statefulsets",
    "daemonsets",
    "replicasets",
    "replicationcontrollers",
    "jobs",
    "cronjobs",
];

// Resources that only exist cluster-wide: rules touching them are inert in a namespaced binding.
const CLUSTER_SCOPED: &[&str] = &[
    "nodes",
    "persistentvolumes",
    "namespaces",
    "clusterroles",
    "clusterrolebindings",
    "certificatesigningrequests",
    "mutatingwebhookconfigurations",
    "validatingwebhookconfigurations",
    "storageclasses",
    "priorityclasses",
    "customresourcedefinitions",
    "apiservices",
    "podsecuritypolicies",
];

fn sensitive_resource(r: &str) -> bool {
    matches!(
        r,
        "secrets" | "pods" | "serviceaccounts" | "pods/exec" | "pods/attach"
    ) || WORKLOADS.contains(&r)
}

// Pure scoring core: rule signatures + subject amplifiers + critical-namespace amplifier.
// Returns the final severity and every finding (for the detail view), deduplicated by tag.
pub fn classify(
    scope: &Scope,
    subjects: &[Subject],
    rules: &[PolicyRule],
    critical_ns: &[String],
    st: &'static Strings,
) -> (Severity, Vec<Finding>) {
    let cluster = matches!(scope, Scope::ClusterWide);
    let mut findings: Vec<Finding> = Vec::new();
    let mut push = |sev, tag, detail: String| findings.push(Finding { sev, tag, detail });

    for r in rules {
        // --- CRITICAL: direct cluster takeover / privilege escalation primitives.
        if r.is_full_wildcard() {
            push(
                Severity::Critical,
                "wildcard-all",
                st.rbac_wildcard_all.into(),
            );
        }
        if r.group("rbac.authorization.k8s.io")
            && (r.res("roles") || r.res("clusterroles"))
            && (r.has_verb("escalate") || r.has_verb("bind"))
        {
            push(
                Severity::Critical,
                "rbac-escalate",
                st.rbac_escalate.into(),
            );
        }
        if r.has_verb("impersonate") {
            push(
                Severity::Critical,
                "impersonate",
                st.rbac_impersonate.into(),
            );
        }

        // --- HIGH: indirect escalation (code exec, credential theft, scheduling).
        if r.group("") && (r.res("pods/exec") || r.res("pods/attach")) {
            push(
                Severity::High,
                "pod-exec",
                st.rbac_pod_exec.into(),
            );
        }
        if r.group("") && r.res("pods") && r.has_verb("create") {
            push(
                Severity::High,
                "pod-create",
                st.rbac_pod_create.into(),
            );
        }
        if r.group("") && r.res("secrets") && r.has_read() {
            push(
                Severity::High,
                "secrets-read",
                st.rbac_secrets_read.into(),
            );
        }
        if WORKLOADS.iter().any(|w| r.res(w)) && r.has_write() {
            push(
                Severity::High,
                "workload-write",
                st.rbac_workload_write.into(),
            );
        }
        if r.group("") && r.res("serviceaccounts/token") && r.has_verb("create") {
            push(
                Severity::High,
                "sa-token",
                st.rbac_sa_token.into(),
            );
        }
        if r.group("") && r.res("serviceaccounts") && r.has_write() {
            push(
                Severity::High,
                "sa-write",
                st.rbac_sa_write.into(),
            );
        }
        // Cluster-scoped resources: only count when the binding is actually cluster-wide.
        if cluster {
            if r.res("certificatesigningrequests") && (r.has_verb("approve") || r.has_verb("update"))
            {
                push(
                    Severity::High,
                    "csr-sign",
                    st.rbac_csr_sign.into(),
                );
            }
            if (r.res("mutatingwebhookconfigurations")
                || r.res("validatingwebhookconfigurations"))
                && r.has_write()
            {
                push(
                    Severity::High,
                    "webhook-write",
                    st.rbac_webhook_write.into(),
                );
            }
            if r.res("nodes") || r.res("nodes/proxy") {
                push(
                    Severity::High,
                    "node-access",
                    st.rbac_node_access.into(),
                );
            }
        }
        // Wildcard verb on a sensitive resource even without full wildcard.
        if r.verbs.iter().any(|v| v == "*")
            && r.resources.iter().any(|res| sensitive_resource(res))
        {
            push(
                Severity::High,
                "wildcard-verb",
                st.rbac_wildcard_verb.into(),
            );
        }

        // --- MEDIUM: broad but non-escalating.
        if r.api_groups.iter().any(|g| g == "*") && r.resources.iter().any(|x| x == "*") && r.has_read()
            && !r.is_full_wildcard()
        {
            push(
                Severity::Medium,
                "wide-read",
                st.rbac_wide_read.into(),
            );
        }
        if r.has_write() {
            push(Severity::Medium, "write", st.rbac_write.into());
        }
    }

    // --- Subject amplifiers (blast radius).
    for s in subjects {
        if s.kind == "Group" && s.name == "system:masters" {
            push(
                Severity::Critical,
                "system-masters",
                st.rbac_system_masters.into(),
            );
        }
        if s.kind == "Group" && (s.name == "system:authenticated" || s.name == "system:unauthenticated")
        {
            push(
                Severity::High,
                "subject-public",
                fill(st.rbac_subject_public, &[("name", &s.name)]),
            );
        }
        if s.kind == "ServiceAccount" && s.name == "default" {
            push(
                Severity::Medium,
                "default-sa",
                st.rbac_default_sa.into(),
            );
        }
    }

    // --- Critical-namespace amplifier: a local foothold here escalates cluster-wide.
    if let Scope::Namespace(ns) = scope {
        if critical_ns.iter().any(|c| c == ns) {
            let hot_write = rules.iter().any(|r| {
                r.has_write()
                    && (r.res("pods")
                        || r.res("secrets")
                        || r.res("serviceaccounts")
                        || WORKLOADS.iter().any(|w| r.res(w)))
            });
            let any_write = rules.iter().any(|r| r.has_write());
            let secrets_read = rules
                .iter()
                .any(|r| r.group("") && r.res("secrets") && r.has_read());
            let sev = if hot_write {
                Severity::Critical
            } else if any_write || secrets_read {
                Severity::High
            } else {
                Severity::Medium
            };
            push(
                sev,
                "critical-ns",
                fill(st.rbac_critical_ns, &[("ns", ns)]),
            );
        }
    }

    // Inert cluster-scoped rules in a namespaced binding: informative, never raises severity.
    if !cluster {
        let inert: Vec<&str> = rules
            .iter()
            .flat_map(|r| r.resources.iter())
            .filter(|res| CLUSTER_SCOPED.contains(&res.as_str()))
            .map(|s| s.as_str())
            .collect();
        if !inert.is_empty() {
            push(
                Severity::Info,
                "inert-cluster-rules",
                fill(st.rbac_inert_cluster_rules, &[("list", &inert.join(", "))]),
            );
        }
    }

    dedup_findings(&mut findings);
    let base = if rules.is_empty() { Severity::Info } else { Severity::Low };
    let severity = findings
        .iter()
        .map(|f| f.sev)
        .max()
        .map(|m| m.max(base))
        .unwrap_or(base);
    (severity, findings)
}

// Keep one finding per tag (the highest severity), ordered by severity desc for the detail view.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut best: HashMap<&'static str, Finding> = HashMap::new();
    for f in findings.drain(..) {
        match best.get(f.tag) {
            Some(prev) if prev.sev >= f.sev => {}
            _ => {
                best.insert(f.tag, f);
            }
        }
    }
    *findings = best.into_values().collect();
    findings.sort_by(|a, b| b.sev.cmp(&a.sev).then(a.tag.cmp(b.tag)));
}

#[derive(Default, Debug, Clone)]
pub struct RbacState {
    pub bindings: Vec<RbacBinding>,
    pub roles: Vec<RoleEntry>,
    pub service_accounts: Vec<SaEntry>,
    // The ServiceAccount list failed while the bindings came through (a common read-only setup).
    // While set, no "this SA does not exist" claim is made anywhere.
    pub sa_degraded: bool,
    // Bumped on every successful fetch. The view copies the graph only when this moves, instead of
    // cloning a few thousand roles on every frame.
    pub generation: u64,
    pub error: Option<String>,
    pub loading: bool,
}

impl RbacState {
    // Display order for the role view: worst potential first. Returns indices, so every cross-link
    // stored in the graph keeps pointing at the right entry.
    pub fn role_order(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.roles.len()).collect();
        idx.sort_by(|&a, &b| self.roles[a].sort_key().cmp(&self.roles[b].sort_key()));
        idx
    }
}

pub type SharedRbac = Arc<Mutex<RbacState>>;

pub fn new_rbac_state() -> SharedRbac {
    Arc::new(Mutex::new(RbacState::default()))
}

fn conv_rule(p: &K8sPolicyRule) -> PolicyRule {
    PolicyRule {
        api_groups: p.api_groups.clone().unwrap_or_default(),
        resources: p.resources.clone().unwrap_or_default(),
        verbs: p.verbs.clone(),
        resource_names: p.resource_names.clone().unwrap_or_default(),
    }
}

type Labels = std::collections::BTreeMap<String, String>;

// The evaluable part of a ClusterRole's `aggregationRule`. Only selectors we can fully evaluate land
// in `match_labels`; a selector carrying matchExpressions is dropped and flips `partial`, because
// keeping it as an empty (match-everything) map would invent contributors rather than miss them.
#[derive(Debug, Clone, Default)]
pub struct AggregationSelectors {
    pub match_labels: Vec<Labels>,
    pub partial: bool,
}

// Which ClusterRoles feed each aggregated one, by index. Pure so the label matching is testable:
// `labels[i]` and `selectors[i]` describe the same ClusterRole, and a role never aggregates itself.
pub fn resolve_aggregation(labels: &[Labels], selectors: &[Option<AggregationSelectors>]) -> Vec<Vec<usize>> {
    selectors
        .iter()
        .enumerate()
        .map(|(i, sel)| {
            let Some(sel) = sel else {
                return Vec::new();
            };
            (0..labels.len())
                .filter(|&j| j != i)
                .filter(|&j| {
                    // An empty selector matches everything, as the apiserver does.
                    sel.match_labels
                        .iter()
                        .any(|ml| ml.iter().all(|(k, v)| labels[j].get(k) == Some(v)))
                })
                .collect()
        })
        .collect()
}

fn agg_selectors(rule: &k8s_openapi::api::rbac::v1::AggregationRule) -> AggregationSelectors {
    let mut out = AggregationSelectors::default();
    for sel in rule.cluster_role_selectors.as_deref().unwrap_or_default() {
        if sel.match_expressions.as_ref().map(|e| !e.is_empty()).unwrap_or(false) {
            out.partial = true;
            continue;
        }
        out.match_labels
            .push(sel.match_labels.clone().unwrap_or_default().into_iter().collect());
    }
    out
}

pub async fn fetch_rbac(client: Client, critical_ns: Vec<String>, state: SharedRbac) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("rbac poisoned");
        s.loading = true;
        s.error = None;
    }

    let cr_api: Api<ClusterRole> = Api::all(client.clone());
    let role_api: Api<Role> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let rb_api: Api<RoleBinding> = Api::all(client.clone());
    let sa_api: Api<ServiceAccount> = Api::all(client.clone());
    let lp = ListParams::default();

    let (crs, ns_roles, crbs, rbs, sas) = tokio::join!(
        cr_api.list(&lp),
        role_api.list(&lp),
        crb_api.list(&lp),
        rb_api.list(&lp),
        sa_api.list(&lp),
    );

    let crs = match crs {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    let ns_roles = match ns_roles {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    let crbs = match crbs {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    let rbs = match rbs {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    // The ServiceAccount list is the one that may legitimately be denied while RBAC itself reads
    // fine. Losing it costs the SA nodes, not the view — and it must silence every "SA missing"
    // claim, since an unreadable list is not evidence of absence.
    let (sa_items, sa_degraded) = match sas {
        Ok(l) => (l.items, false),
        Err(_) => (Vec::new(), true),
    };

    // --- Roles and ClusterRoles as objects. ClusterRoles come first so their indices line up with
    // the label/selector vectors the aggregation pass works on.
    let mut roles: Vec<RoleEntry> = Vec::new();
    let mut labels: Vec<Labels> = Vec::new();
    let mut selectors: Vec<Option<AggregationSelectors>> = Vec::new();

    for cr in &crs.items {
        let rules: Vec<PolicyRule> =
            cr.rules.as_ref().map(|rs| rs.iter().map(conv_rule).collect()).unwrap_or_default();
        labels.push(cr.metadata.labels.clone().unwrap_or_default().into_iter().collect());
        selectors.push(cr.aggregation_rule.as_ref().map(agg_selectors));
        roles.push(RoleEntry {
            kind: RoleKind::ClusterRole,
            namespace: String::new(),
            name: cr.metadata.name.clone().unwrap_or_default(),
            own_rules: rules.len(),
            rules,
            aggregated: cr.aggregation_rule.is_some(),
            aggregates: Vec::new(),
            aggregates_into: Vec::new(),
            aggregation_partial: false,
            bound_cluster: 0,
            bound_namespaces: Vec::new(),
            provenance: detect_provenance(&cr.metadata),
            source: None,
            age: age_of(&cr.metadata),
            severity: Severity::Info,
            findings: Vec::new(),
        });
    }
    let n_cr = roles.len();

    // Aggregation edges are recorded even when the controller already wrote the union into `rules`:
    // they are what lets the tree show what a role like `admin` is actually made of.
    let contributors = resolve_aggregation(&labels, &selectors);
    for i in 0..n_cr {
        roles[i].aggregates = contributors[i].clone();
        roles[i].aggregation_partial = selectors[i].as_ref().map(|s| s.partial).unwrap_or(false);
        for &j in &contributors[i] {
            roles[j].aggregates_into.push(i);
        }
    }
    // Aggregated roles that ship without inline rules: union what they pull in, so the scoring sees
    // the rights the binding really grants.
    for i in 0..n_cr {
        if !roles[i].aggregated || roles[i].own_rules > 0 {
            continue;
        }
        let acc: Vec<PolicyRule> =
            contributors[i].iter().flat_map(|&j| roles[j].rules.clone()).collect();
        roles[i].rules = acc;
    }

    for r in &ns_roles.items {
        let rules: Vec<PolicyRule> =
            r.rules.as_ref().map(|rs| rs.iter().map(conv_rule).collect()).unwrap_or_default();
        roles.push(RoleEntry {
            kind: RoleKind::Role,
            namespace: r.metadata.namespace.clone().unwrap_or_default(),
            name: r.metadata.name.clone().unwrap_or_default(),
            own_rules: rules.len(),
            rules,
            aggregated: false,
            aggregates: Vec::new(),
            aggregates_into: Vec::new(),
            aggregation_partial: false,
            bound_cluster: 0,
            bound_namespaces: Vec::new(),
            provenance: detect_provenance(&r.metadata),
            source: None,
            age: age_of(&r.metadata),
            severity: Severity::Info,
            findings: Vec::new(),
        });
    }

    let mut cr_by_name: HashMap<String, usize> = HashMap::new();
    let mut role_by_key: HashMap<(String, String), usize> = HashMap::new();
    for (i, r) in roles.iter().enumerate() {
        match r.kind {
            RoleKind::ClusterRole => {
                cr_by_name.insert(r.name.clone(), i);
            }
            RoleKind::Role => {
                role_by_key.insert((r.namespace.clone(), r.name.clone()), i);
            }
        }
    }

    // --- ServiceAccounts as objects.
    let mut service_accounts: Vec<SaEntry> = sa_items
        .iter()
        .map(|sa| SaEntry {
            namespace: sa.metadata.namespace.clone().unwrap_or_default(),
            name: sa.metadata.name.clone().unwrap_or_default(),
            exists: true,
            automount: sa.automount_service_account_token,
            secrets: sa.secrets.as_ref().map(|v| v.len()).unwrap_or(0),
            image_pull_secrets: sa.image_pull_secrets.as_ref().map(|v| v.len()).unwrap_or(0),
            bindings: Vec::new(),
            provenance: detect_provenance(&sa.metadata),
            source: None,
            age: age_of(&sa.metadata),
        })
        .collect();
    let mut sa_by_key: HashMap<(String, String), usize> = service_accounts
        .iter()
        .enumerate()
        .map(|(i, sa)| ((sa.namespace.clone(), sa.name.clone()), i))
        .collect();

    let mut bindings: Vec<RbacBinding> = Vec::new();

    for crb in &crbs.items {
        let role_ref = RoleRef {
            kind: crb.role_ref.kind.clone(),
            name: crb.role_ref.name.clone(),
        };
        let role_idx = cr_by_name.get(&role_ref.name).copied();
        let (rules, aggregated) = role_rules(&roles, role_idx);
        let subjects = conv_subjects(crb.subjects.as_deref());
        let scope = Scope::ClusterWide;
        let (severity, mut findings) = classify(&scope, &subjects, &rules, &critical_ns, st);
        let provenance = detect_provenance(&crb.metadata);
        push_gitops_finding(&provenance, severity, &mut findings, st);
        bindings.push(RbacBinding {
            scope,
            binding_kind: "ClusterRoleBinding".into(),
            binding_name: crb.metadata.name.clone().unwrap_or_default(),
            sa_idx: vec![None; subjects.len()],
            subjects,
            via_clusterrole: false,
            aggregated,
            provenance,
            source: None,
            role_ref,
            role_idx,
            rules,
            severity,
            findings,
            age: age_of(&crb.metadata),
        });
    }

    for rb in &rbs.items {
        let ns = rb.metadata.namespace.clone().unwrap_or_default();
        let role_ref = RoleRef {
            kind: rb.role_ref.kind.clone(),
            name: rb.role_ref.name.clone(),
        };
        let via_clusterrole = role_ref.kind == "ClusterRole";
        let role_idx = if via_clusterrole {
            cr_by_name.get(&role_ref.name).copied()
        } else {
            role_by_key.get(&(ns.clone(), role_ref.name.clone())).copied()
        };
        let (rules, aggregated) = role_rules(&roles, role_idx);
        let subjects = conv_subjects(rb.subjects.as_deref());
        let scope = Scope::Namespace(ns);
        let (severity, mut findings) = classify(&scope, &subjects, &rules, &critical_ns, st);
        let provenance = detect_provenance(&rb.metadata);
        push_gitops_finding(&provenance, severity, &mut findings, st);
        bindings.push(RbacBinding {
            scope,
            binding_kind: "RoleBinding".into(),
            binding_name: rb.metadata.name.clone().unwrap_or_default(),
            sa_idx: vec![None; subjects.len()],
            subjects,
            via_clusterrole,
            aggregated,
            provenance,
            source: None,
            role_ref,
            role_idx,
            rules,
            severity,
            findings,
            age: age_of(&rb.metadata),
        });
    }

    bindings.sort_by_key(|a| a.sort_key());

    // --- Wire the graph back together, now that the binding order is final: who binds each role,
    // which SA each subject resolves to, and the SAs that only exist as a name in a binding.
    for (bi, b) in bindings.iter_mut().enumerate() {
        if let Some(ri) = b.role_idx {
            match &b.scope {
                Scope::ClusterWide => roles[ri].bound_cluster += 1,
                Scope::Namespace(ns) => {
                    if !roles[ri].bound_namespaces.iter().any(|x| x == ns) {
                        roles[ri].bound_namespaces.push(ns.clone());
                    }
                }
            }
        }
        for si in 0..b.subjects.len() {
            let s = &b.subjects[si];
            if s.kind != "ServiceAccount" {
                continue;
            }
            // A ClusterRoleBinding subject carries its own namespace; a RoleBinding subject may omit
            // it, in which case it means the binding's namespace.
            let ns = match (&s.namespace, &b.scope) {
                (Some(ns), _) => ns.clone(),
                (None, Scope::Namespace(ns)) => ns.clone(),
                (None, Scope::ClusterWide) => String::new(),
            };
            let sa_name = s.name.clone();
            match sa_by_key.get(&(ns.clone(), sa_name.clone())).copied() {
                Some(idx) => {
                    service_accounts[idx].bindings.push(bi);
                    b.sa_idx[si] = Some(idx);
                }
                None if !sa_degraded && !ns.is_empty() => {
                    // Informational, never a severity bump: the grant is dormant until someone
                    // creates that ServiceAccount — at which point it lights up silently.
                    let detail = fill(st.rbac_dangling_sa, &[("sa", &format!("{ns}/{sa_name}"))]);
                    if !b.findings.iter().any(|f| f.tag == "dangling-sa") {
                        b.findings.push(Finding {
                            sev: Severity::Info,
                            tag: "dangling-sa",
                            detail,
                        });
                    }
                    // Keep it in the graph so the subject view can show the hole.
                    let idx = service_accounts.len();
                    service_accounts.push(SaEntry {
                        namespace: ns.clone(),
                        name: sa_name.clone(),
                        exists: false,
                        automount: None,
                        secrets: 0,
                        image_pull_secrets: 0,
                        bindings: vec![bi],
                        provenance: Provenance::Unmanaged,
                        source: None,
                        age: String::new(),
                    });
                    sa_by_key.insert((ns, sa_name), idx);
                    b.sa_idx[si] = Some(idx);
                }
                None => {}
            }
        }
    }

    // Score each role on its own rules: cluster-wide for a ClusterRole (the worst it can be bound
    // as), in its own namespace for a Role. That severity is a ceiling, not a live risk.
    for r in roles.iter_mut() {
        let scope = match r.kind {
            RoleKind::ClusterRole => Scope::ClusterWide,
            RoleKind::Role => Scope::Namespace(r.namespace.clone()),
        };
        let (sev, mut findings) = classify(&scope, &[], &r.rules, &critical_ns, st);
        if r.is_unbound() {
            findings.push(Finding {
                sev: Severity::Info,
                tag: "unbound-role",
                detail: st.rbac_unbound_role.into(),
            });
        }
        if r.aggregation_partial {
            findings.push(Finding {
                sev: Severity::Info,
                tag: "aggregation-partial",
                detail: st.rbac_aggregation_partial.into(),
            });
        }
        r.severity = sev;
        r.findings = findings;
    }

    // `roles` and `service_accounts` stay in API order: every cross-link above is positional, and a
    // sort here would silently invalidate all of them. Display order is the view's business — it
    // sorts a vector of indices (`role_order()`) instead of moving the entries.

    // Chain Flux-managed objects to their real source (Git/OCI/Helm) via the Kustomization /
    // HelmRelease sourceRef. One GET per distinct Flux object, cached across all three lists.
    let mut src_cache: HashMap<String, Option<String>> = HashMap::new();
    for b in &mut bindings {
        b.source = chain_source(&client, &b.provenance, &mut src_cache).await;
    }
    for r in &mut roles {
        r.source = chain_source(&client, &r.provenance, &mut src_cache).await;
    }
    for sa in &mut service_accounts {
        sa.source = chain_source(&client, &sa.provenance, &mut src_cache).await;
    }

    let mut s = state.lock().expect("rbac poisoned");
    s.loading = false;
    s.bindings = bindings;
    s.roles = roles;
    s.service_accounts = service_accounts;
    s.sa_degraded = sa_degraded;
    s.generation = s.generation.wrapping_add(1);
    s.error = None;
}

// Rules a binding actually grants, plus whether they came from an aggregated ClusterRole. A dangling
// roleRef grants nothing, which is exactly what an empty rule set scores.
fn role_rules(roles: &[RoleEntry], idx: Option<usize>) -> (Vec<PolicyRule>, bool) {
    match idx {
        Some(i) => (roles[i].rules.clone(), roles[i].aggregated),
        None => (Vec::new(), false),
    }
}

// Resolve one object's Flux source, memoised per Flux object so a hundred roles from the same
// Kustomization cost a single pair of GETs.
async fn chain_source(
    client: &Client,
    prov: &Provenance,
    cache: &mut HashMap<String, Option<String>>,
) -> Option<String> {
    let key = match prov {
        Provenance::FluxKustomization { namespace, name } => format!("ks/{namespace}/{name}"),
        Provenance::FluxHelmRelease { namespace, name } => format!("hr/{namespace}/{name}"),
        _ => return None,
    };
    if !cache.contains_key(&key) {
        let resolved = resolve_flux_source(client, prov).await;
        cache.insert(key.clone(), resolved);
    }
    cache.get(&key).cloned().flatten()
}

// Flag a risky grant that lives outside GitOps (kubectl/unmanaged/owned): an audit blind spot.
// Informational — it never raises severity, only surfaces a tag on already-risky bindings.
fn push_gitops_finding(
    prov: &Provenance,
    severity: Severity,
    findings: &mut Vec<Finding>,
    st: &'static Strings,
) {
    if prov.out_of_gitops() && severity >= Severity::High {
        findings.push(Finding {
            sev: Severity::Info,
            tag: "out-of-gitops",
            detail: fill(st.rbac_out_of_gitops, &[("origin", &prov.label())]),
        });
    }
}

const FLUX_KS: (&str, &[&str]) = ("kustomize.toolkit.fluxcd.io", &["v1", "v1beta2", "v1beta1"]);
const FLUX_HR: (&str, &[&str]) = ("helm.toolkit.fluxcd.io", &["v2", "v2beta2", "v2beta1"]);
const FLUX_SRC: (&str, &[&str]) = ("source.toolkit.fluxcd.io", &["v1", "v1beta2"]);

// Fetch one Flux object dynamically, tolerating whichever CRD version the cluster serves.
async fn get_dyn(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
    ns: &str,
    name: &str,
) -> Option<DynamicObject> {
    for v in versions {
        let gvk = GroupVersionKind::gvk(group, v, kind);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);
            return api.get(name).await.ok();
        }
    }
    None
}

// spec.sourceRef of a Kustomization, or chartRef / chart.spec.sourceRef of a HelmRelease.
fn obj_source_ref(obj: &DynamicObject, default_ns: &str) -> Option<(String, String, String)> {
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

fn source_url(obj: &DynamicObject) -> String {
    let spec = obj.data.get("spec");
    spec.and_then(|s| s.get("url"))
        .or_else(|| spec.and_then(|s| s.get("endpoint")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// Resolve a Flux-managed binding to a human-readable source: the referenced source object plus,
// for a Kustomization, the in-repo path it applies.
async fn resolve_flux_source(client: &Client, prov: &Provenance) -> Option<String> {
    let (group, versions, kind, ns, name, want_path) = match prov {
        Provenance::FluxKustomization { namespace, name } => {
            (FLUX_KS.0, FLUX_KS.1, "Kustomization", namespace.as_str(), name.as_str(), true)
        }
        Provenance::FluxHelmRelease { namespace, name } => {
            (FLUX_HR.0, FLUX_HR.1, "HelmRelease", namespace.as_str(), name.as_str(), false)
        }
        _ => return None,
    };
    let obj = get_dyn(client, group, versions, kind, ns, name).await?;
    let (skind, sname, sns) = obj_source_ref(&obj, ns)?;
    let url = get_dyn(client, FLUX_SRC.0, FLUX_SRC.1, &skind, &sns, &sname)
        .await
        .map(|o| source_url(&o))
        .unwrap_or_default();

    let mut out = format!("{skind} {sns}/{sname}");
    if !url.is_empty() {
        out.push_str(&format!(" · {url}"));
    }
    if want_path {
        if let Some(path) = obj.data.get("spec").and_then(|s| s.get("path")).and_then(|v| v.as_str()) {
            if !path.is_empty() {
                out.push_str(&format!(" · {path}"));
            }
        }
    }
    Some(out)
}

fn conv_subjects(subjects: Option<&[k8s_openapi::api::rbac::v1::Subject]>) -> Vec<Subject> {
    subjects
        .unwrap_or(&[])
        .iter()
        .map(|s| Subject {
            kind: s.kind.clone(),
            name: s.name.clone(),
            namespace: s.namespace.clone(),
        })
        .collect()
}

fn age_of(meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta) -> String {
    meta.creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default()
}

fn fail(state: &SharedRbac, msg: String) {
    let mut s = state.lock().expect("rbac poisoned");
    s.loading = false;
    s.error = Some(msg);
}

// Merge the built-in critical namespaces with the user's overrides (deduplicated).
pub fn critical_namespaces(extra: &[String]) -> Vec<String> {
    let mut v: Vec<String> = CRITICAL_NS_DEFAULT.iter().map(|s| s.to_string()).collect();
    for e in extra {
        if !v.iter().any(|x| x == e) {
            v.push(e.clone());
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::FR;

    fn rule(groups: &[&str], resources: &[&str], verbs: &[&str]) -> PolicyRule {
        PolicyRule {
            api_groups: groups.iter().map(|s| s.to_string()).collect(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
            verbs: verbs.iter().map(|s| s.to_string()).collect(),
            resource_names: vec![],
        }
    }

    fn sa(ns: &str, name: &str) -> Subject {
        Subject { kind: "ServiceAccount".into(), name: name.into(), namespace: Some(ns.into()) }
    }

    fn group(name: &str) -> Subject {
        Subject { kind: "Group".into(), name: name.into(), namespace: None }
    }

    fn classify_cluster(rules: &[PolicyRule]) -> Severity {
        classify(&Scope::ClusterWide, &[sa("app", "x")], rules, &[], &FR).0
    }

    fn classify_ns(ns: &str, rules: &[PolicyRule], crit: &[&str]) -> Severity {
        let crit: Vec<String> = crit.iter().map(|s| s.to_string()).collect();
        classify(&Scope::Namespace(ns.into()), &[sa(ns, "x")], rules, &crit, &FR).0
    }

    #[test]
    fn full_wildcard_is_critical() {
        assert_eq!(classify_cluster(&[rule(&["*"], &["*"], &["*"])]), Severity::Critical);
    }

    #[test]
    fn impersonate_is_critical() {
        let r = rule(&[""], &["users"], &["impersonate"]);
        assert_eq!(classify_cluster(&[r]), Severity::Critical);
    }

    #[test]
    fn escalate_on_roles_is_critical() {
        let r = rule(&["rbac.authorization.k8s.io"], &["clusterroles"], &["escalate"]);
        assert_eq!(classify_cluster(&[r]), Severity::Critical);
    }

    #[test]
    fn secrets_read_is_high() {
        let r = rule(&[""], &["secrets"], &["get", "list"]);
        assert_eq!(classify_ns("app", &[r], &[]), Severity::High);
    }

    #[test]
    fn configmap_read_is_low() {
        let r = rule(&[""], &["configmaps"], &["get", "list"]);
        assert_eq!(classify_ns("app", &[r], &[]), Severity::Low);
    }

    #[test]
    fn workload_write_is_high() {
        let r = rule(&["apps"], &["deployments"], &["create", "update"]);
        assert_eq!(classify_ns("app", &[r], &[]), Severity::High);
    }

    #[test]
    fn same_workload_write_in_critical_ns_is_critical() {
        let r = rule(&["apps"], &["deployments"], &["create"]);
        assert_eq!(classify_ns("flux-system", &[r], &["flux-system"]), Severity::Critical);
    }

    #[test]
    fn readonly_in_critical_ns_is_at_least_medium() {
        let r = rule(&[""], &["configmaps"], &["get"]);
        assert!(classify_ns("kube-system", &[r], &["kube-system"]) >= Severity::Medium);
    }

    #[test]
    fn node_write_in_namespaced_binding_is_inert_not_high() {
        // nodes are cluster-scoped: a RoleBinding granting them does nothing cluster-relevant.
        let r = rule(&[""], &["nodes"], &["update"]);
        assert!(classify_ns("app", &[r], &[]) < Severity::High);
    }

    #[test]
    fn public_group_floors_high() {
        let r = rule(&[""], &["configmaps"], &["get"]);
        let s = classify(&Scope::Namespace("app".into()), &[group("system:authenticated")], &[r], &[], &FR).0;
        assert_eq!(s, Severity::High);
    }

    #[test]
    fn system_masters_is_critical() {
        let s = classify(&Scope::ClusterWide, &[group("system:masters")], &[], &[], &FR).0;
        assert_eq!(s, Severity::Critical);
    }

    // --- graph model ------------------------------------------------------------------------

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn sel(match_labels: &[&[(&str, &str)]], partial: bool) -> Option<AggregationSelectors> {
        Some(AggregationSelectors {
            match_labels: match_labels.iter().map(|ml| labels(ml)).collect(),
            partial,
        })
    }

    fn role(kind: RoleKind, namespace: &str, name: &str) -> RoleEntry {
        RoleEntry {
            kind,
            namespace: namespace.into(),
            name: name.into(),
            rules: vec![],
            own_rules: 0,
            aggregated: false,
            aggregates: vec![],
            aggregates_into: vec![],
            aggregation_partial: false,
            bound_cluster: 0,
            bound_namespaces: vec![],
            provenance: Provenance::Unmanaged,
            source: None,
            age: String::new(),
            severity: Severity::Info,
            findings: vec![],
        }
    }

    #[test]
    fn aggregation_matches_labelled_contributors() {
        // 0 = `admin` aggregating aggregate-to-admin=true; 1 carries the label, 2 does not.
        let lbl = vec![
            labels(&[]),
            labels(&[("rbac.authorization.k8s.io/aggregate-to-admin", "true")]),
            labels(&[("other", "x")]),
        ];
        let sels = vec![
            sel(&[&[("rbac.authorization.k8s.io/aggregate-to-admin", "true")]], false),
            None,
            None,
        ];
        let out = resolve_aggregation(&lbl, &sels);
        assert_eq!(out[0], vec![1]);
        assert!(out[1].is_empty() && out[2].is_empty());
    }

    #[test]
    fn aggregation_never_includes_itself() {
        // A ClusterRole carrying the very label it aggregates must not become its own contributor.
        let lbl = vec![labels(&[("agg", "yes")])];
        let sels = vec![sel(&[&[("agg", "yes")]], false)];
        assert!(resolve_aggregation(&lbl, &sels)[0].is_empty());
    }

    #[test]
    fn match_expressions_selector_is_dropped_not_treated_as_match_all() {
        // The unevaluable selector is skipped: no contributor is invented, and `partial` says so.
        let lbl = vec![labels(&[]), labels(&[("a", "b")])];
        let sels = vec![sel(&[], true), None];
        assert!(resolve_aggregation(&lbl, &sels)[0].is_empty());
        assert!(sels[0].as_ref().unwrap().partial);
    }

    #[test]
    fn clusterrole_bound_in_two_namespaces_is_a_template() {
        let mut r = role(RoleKind::ClusterRole, "", "app-editor");
        r.bound_namespaces = vec!["a".into(), "b".into()];
        assert!(r.is_template());
        assert!(!r.is_unbound());

        r.bound_namespaces = vec!["a".into()];
        assert!(!r.is_template(), "a single namespace is a plain grant, not a reused template");
    }

    #[test]
    fn namespaced_role_is_never_a_template() {
        let mut r = role(RoleKind::Role, "app", "reader");
        r.bound_namespaces = vec!["app".into(), "app".into()];
        assert!(!r.is_template());
    }

    #[test]
    fn role_nobody_binds_is_unbound() {
        let mut r = role(RoleKind::ClusterRole, "", "leftover");
        assert!(r.is_unbound());

        r.bound_cluster = 1;
        assert!(!r.is_unbound());
    }
}
