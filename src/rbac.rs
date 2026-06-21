//! RBAC security view: lists every effective binding (RoleBinding/ClusterRoleBinding) resolved
//! down to its rules, and scores each one so the dangerous/admin grants surface first.
//!
//! The model is binding-centric on purpose: a Role/ClusterRole alone is inert until bound, and the
//! same ClusterRole can be low risk as a namespaced RoleBinding yet critical as a ClusterRoleBinding.
//! Severity is therefore computed per binding, from three inputs: the resolved rules' signatures,
//! the subjects (public groups, system:masters, default SA), and the namespace (kube-system/
//! flux-system… where a local foothold escalates cluster-wide).
//!
//! `classify()` is pure and unit-tested; `fetch_rbac()` wires it to the live cluster following the
//! same Shared-state pattern as `pods.rs`/`flux.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule as K8sPolicyRule, Role, RoleBinding,
};
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
                "verbs:* resources:* apiGroups:* — équivaut cluster-admin".into(),
            );
        }
        if r.group("rbac.authorization.k8s.io")
            && (r.res("roles") || r.res("clusterroles"))
            && (r.has_verb("escalate") || r.has_verb("bind"))
        {
            push(
                Severity::Critical,
                "rbac-escalate",
                "escalate/bind sur (cluster)roles — peut s'octroyer plus de droits".into(),
            );
        }
        if r.has_verb("impersonate") {
            push(
                Severity::Critical,
                "impersonate",
                "verbe impersonate — peut devenir n'importe quel user/group/SA".into(),
            );
        }

        // --- HIGH: indirect escalation (code exec, credential theft, scheduling).
        if r.group("") && (r.res("pods/exec") || r.res("pods/attach")) {
            push(
                Severity::High,
                "pod-exec",
                "exec/attach sur pods — exécution de code dans un pod".into(),
            );
        }
        if r.group("") && r.res("pods") && r.has_verb("create") {
            push(
                Severity::High,
                "pod-create",
                "create pods — peut planifier un pod privilégié et voler son token SA".into(),
            );
        }
        if r.group("") && r.res("secrets") && r.has_read() {
            push(
                Severity::High,
                "secrets-read",
                "lecture des secrets — accès aux credentials".into(),
            );
        }
        if WORKLOADS.iter().any(|w| r.res(w)) && r.has_write() {
            push(
                Severity::High,
                "workload-write",
                "écriture sur workloads — planifie indirectement des pods".into(),
            );
        }
        if r.group("") && r.res("serviceaccounts/token") && r.has_verb("create") {
            push(
                Severity::High,
                "sa-token",
                "create serviceaccounts/token — émission de jetons SA".into(),
            );
        }
        if r.group("") && r.res("serviceaccounts") && r.has_write() {
            push(
                Severity::High,
                "sa-write",
                "écriture sur serviceaccounts".into(),
            );
        }
        // Cluster-scoped resources: only count when the binding is actually cluster-wide.
        if cluster {
            if r.res("certificatesigningrequests") && (r.has_verb("approve") || r.has_verb("update"))
            {
                push(
                    Severity::High,
                    "csr-sign",
                    "approbation de CSR — peut forger des certificats client".into(),
                );
            }
            if (r.res("mutatingwebhookconfigurations")
                || r.res("validatingwebhookconfigurations"))
                && r.has_write()
            {
                push(
                    Severity::High,
                    "webhook-write",
                    "écriture sur les admission webhooks — interception/altération des requêtes".into(),
                );
            }
            if r.res("nodes") || r.res("nodes/proxy") {
                push(
                    Severity::High,
                    "node-access",
                    "accès aux nodes/proxy".into(),
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
                "verbe * sur une ressource sensible".into(),
            );
        }

        // --- MEDIUM: broad but non-escalating.
        if r.api_groups.iter().any(|g| g == "*") && r.resources.iter().any(|x| x == "*") && r.has_read()
            && !r.is_full_wildcard()
        {
            push(
                Severity::Medium,
                "wide-read",
                "lecture sur toutes les ressources".into(),
            );
        }
        if r.has_write() {
            push(Severity::Medium, "write", "écriture sur des ressources".into());
        }
    }

    // --- Subject amplifiers (blast radius).
    for s in subjects {
        if s.kind == "Group" && s.name == "system:masters" {
            push(
                Severity::Critical,
                "system-masters",
                "sujet system:masters — bypass total de RBAC".into(),
            );
        }
        if s.kind == "Group" && (s.name == "system:authenticated" || s.name == "system:unauthenticated")
        {
            push(
                Severity::High,
                "subject-public",
                format!("sujet {} — accordé à un public très large", s.name),
            );
        }
        if s.kind == "ServiceAccount" && s.name == "default" {
            push(
                Severity::Medium,
                "default-sa",
                "lié au ServiceAccount default — tout pod du ns hérite des droits".into(),
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
                format!("namespace critique ({ns}) — escalade cluster probable"),
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
                format!("règles cluster-scoped inertes dans ce ns : {}", inert.join(", ")),
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
    pub error: Option<String>,
    pub loading: bool,
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

// A ClusterRole's own rules plus, for aggregated roles with no inline rules, the union of the rules
// of every ClusterRole whose labels match the aggregation selectors.
struct ClusterRoleEntry {
    labels: std::collections::BTreeMap<String, String>,
    rules: Vec<PolicyRule>,
    aggregated: bool,
}

fn resolve_cluster_rules(
    name: &str,
    index: &HashMap<String, ClusterRoleEntry>,
) -> (Vec<PolicyRule>, bool) {
    let Some(entry) = index.get(name) else {
        return (Vec::new(), false);
    };
    if !entry.rules.is_empty() || !entry.aggregated {
        return (entry.rules.clone(), entry.aggregated);
    }
    (entry.rules.clone(), true)
}

pub async fn fetch_rbac(client: Client, critical_ns: Vec<String>, state: SharedRbac) {
    {
        let mut s = state.lock().expect("rbac poisoned");
        s.loading = true;
        s.error = None;
    }

    let cr_api: Api<ClusterRole> = Api::all(client.clone());
    let role_api: Api<Role> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let rb_api: Api<RoleBinding> = Api::all(client.clone());
    let lp = ListParams::default();

    let (crs, roles, crbs, rbs) = tokio::join!(
        cr_api.list(&lp),
        role_api.list(&lp),
        crb_api.list(&lp),
        rb_api.list(&lp),
    );

    let crs = match crs {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    let roles = match roles {
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

    // Index ClusterRoles (with labels for aggregation) and namespaced Roles.
    let mut cr_index: HashMap<String, ClusterRoleEntry> = HashMap::new();
    for cr in &crs.items {
        let name = cr.metadata.name.clone().unwrap_or_default();
        let rules = cr.rules.as_ref().map(|rs| rs.iter().map(conv_rule).collect()).unwrap_or_default();
        cr_index.insert(
            name,
            ClusterRoleEntry {
                labels: cr.metadata.labels.clone().unwrap_or_default().into_iter().collect(),
                rules,
                aggregated: cr.aggregation_rule.is_some(),
            },
        );
    }
    // Fill aggregated roles that ship without inline rules by unioning matching ClusterRoles.
    let label_snapshot: Vec<(String, std::collections::BTreeMap<String, String>, Vec<PolicyRule>)> = cr_index
        .iter()
        .map(|(n, e)| (n.clone(), e.labels.clone(), e.rules.clone()))
        .collect();
    for cr in &crs.items {
        if cr.aggregation_rule.is_none() {
            continue;
        }
        let name = cr.metadata.name.clone().unwrap_or_default();
        if cr_index.get(&name).map(|e| !e.rules.is_empty()).unwrap_or(true) {
            continue;
        }
        let selectors = cr
            .aggregation_rule
            .as_ref()
            .and_then(|a| a.cluster_role_selectors.clone())
            .unwrap_or_default();
        let mut acc: Vec<PolicyRule> = Vec::new();
        for (_, labels, rules) in &label_snapshot {
            let matches = selectors.iter().any(|sel| {
                sel.match_labels
                    .as_ref()
                    .map(|ml| ml.iter().all(|(k, v)| labels.get(k) == Some(v)))
                    .unwrap_or(false)
            });
            if matches {
                acc.extend(rules.clone());
            }
        }
        if let Some(e) = cr_index.get_mut(&name) {
            e.rules = acc;
        }
    }

    let mut role_index: HashMap<(String, String), Vec<PolicyRule>> = HashMap::new();
    for r in &roles.items {
        let ns = r.metadata.namespace.clone().unwrap_or_default();
        let name = r.metadata.name.clone().unwrap_or_default();
        let rules = r.rules.as_ref().map(|rs| rs.iter().map(conv_rule).collect()).unwrap_or_default();
        role_index.insert((ns, name), rules);
    }

    let mut bindings: Vec<RbacBinding> = Vec::new();

    for crb in &crbs.items {
        let role_ref = RoleRef {
            kind: crb.role_ref.kind.clone(),
            name: crb.role_ref.name.clone(),
        };
        let (rules, aggregated) = resolve_cluster_rules(&role_ref.name, &cr_index);
        let subjects = conv_subjects(crb.subjects.as_deref());
        let scope = Scope::ClusterWide;
        let (severity, mut findings) = classify(&scope, &subjects, &rules, &critical_ns);
        let provenance = detect_provenance(&crb.metadata);
        push_gitops_finding(&provenance, severity, &mut findings);
        bindings.push(RbacBinding {
            scope,
            binding_kind: "ClusterRoleBinding".into(),
            binding_name: crb.metadata.name.clone().unwrap_or_default(),
            subjects,
            via_clusterrole: false,
            aggregated,
            provenance,
            source: None,
            role_ref,
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
        let (rules, aggregated) = if via_clusterrole {
            resolve_cluster_rules(&role_ref.name, &cr_index)
        } else {
            (
                role_index
                    .get(&(ns.clone(), role_ref.name.clone()))
                    .cloned()
                    .unwrap_or_default(),
                false,
            )
        };
        let subjects = conv_subjects(rb.subjects.as_deref());
        let scope = Scope::Namespace(ns);
        let (severity, mut findings) = classify(&scope, &subjects, &rules, &critical_ns);
        let provenance = detect_provenance(&rb.metadata);
        push_gitops_finding(&provenance, severity, &mut findings);
        bindings.push(RbacBinding {
            scope,
            binding_kind: "RoleBinding".into(),
            binding_name: rb.metadata.name.clone().unwrap_or_default(),
            subjects,
            via_clusterrole,
            aggregated,
            provenance,
            source: None,
            role_ref,
            rules,
            severity,
            findings,
            age: age_of(&rb.metadata),
        });
    }

    // Chain Flux-managed bindings to their real source (Git/OCI/Helm) via the Kustomization /
    // HelmRelease sourceRef. One GET per distinct Flux object, cached.
    let mut src_cache: HashMap<String, Option<String>> = HashMap::new();
    for b in &mut bindings {
        let key = match &b.provenance {
            Provenance::FluxKustomization { namespace, name } => Some(format!("ks/{namespace}/{name}")),
            Provenance::FluxHelmRelease { namespace, name } => Some(format!("hr/{namespace}/{name}")),
            _ => None,
        };
        if let Some(k) = key {
            if !src_cache.contains_key(&k) {
                let resolved = resolve_flux_source(&client, &b.provenance).await;
                src_cache.insert(k.clone(), resolved);
            }
            b.source = src_cache.get(&k).cloned().flatten();
        }
    }

    bindings.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("rbac poisoned");
    s.loading = false;
    s.bindings = bindings;
    s.error = None;
}

// Flag a risky grant that lives outside GitOps (kubectl/unmanaged/owned): an audit blind spot.
// Informational — it never raises severity, only surfaces a tag on already-risky bindings.
fn push_gitops_finding(prov: &Provenance, severity: Severity, findings: &mut Vec<Finding>) {
    if prov.out_of_gitops() && severity >= Severity::High {
        findings.push(Finding {
            sev: Severity::Info,
            tag: "out-of-gitops",
            detail: format!("origine {} — grant hors GitOps, dérive non auditée", prov.label()),
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
        classify(&Scope::ClusterWide, &[sa("app", "x")], rules, &[]).0
    }

    fn classify_ns(ns: &str, rules: &[PolicyRule], crit: &[&str]) -> Severity {
        let crit: Vec<String> = crit.iter().map(|s| s.to_string()).collect();
        classify(&Scope::Namespace(ns.into()), &[sa(ns, "x")], rules, &crit).0
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
        let s = classify(&Scope::Namespace("app".into()), &[group("system:authenticated")], &[r], &[]).0;
        assert_eq!(s, Severity::High);
    }

    #[test]
    fn system_masters_is_critical() {
        let s = classify(&Scope::ClusterWide, &[group("system:masters")], &[], &[]).0;
        assert_eq!(s, Severity::Critical);
    }
}
