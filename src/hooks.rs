//! The hooks the API server calls out to, in one inventory.
//!
//! Three kinds of extension share one failure mode — a backing Service that cannot answer — and
//! three very different consequences, which is why they are three worlds of one view rather than
//! three views:
//!
//! * **admission** — `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration`. When the
//!   backend is down and `failurePolicy` is `Fail`, every write matching the rules is rejected.
//! * **conversion** — `CustomResourceDefinition` with `spec.conversion.strategy: Webhook`. When the
//!   backend is down, `kubectl get <cr>` fails: reads break, not just writes.
//! * **apiservice** — aggregated `APIService` objects. When one is not `Available`, discovery of its
//!   group is incomplete for every client of the cluster.
//!
//! This module owns the model; [`crate::repair`] and [`crate::diagnostic`] consume it. The reverse
//! would not hold: `repair` judges deletion targets, and that judgement has no business here.
//!
//! # What it refuses to say
//!
//! A backend that could not be queried is [`Reach::Unchecked`], never a fault. `repair` used to fold
//! "healthy" and "could not ask" into the same `None`; splitting them is the point of this module,
//! and [`Reach::fault`] maps `Unchecked` back to `None` so that `Ctrl-R` keeps behaving exactly as
//! it did. Inventing an outage would push someone to delete working admission control.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, RuleWithOperations, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService;
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::{format_age, EventRecord, LineColor};
use crate::lang::{fill, Strings};
use crate::storage::{Hint, HintLevel};

// The label EndpointSlices carry to name the Service they back.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

// The namespaces a cluster cannot be repaired without. A hook that stands in front of these and
// fails closed takes the cluster down with itself.
const SYSTEM_NAMESPACES: &[&str] = &["kube-system", "kube-public", "kube-node-lease"];

// Below this many days left, an expiring CA bundle is worth a warning rather than a fact.
const CA_EXPIRY_WARN_DAYS: i64 = 30;

// A fail-closed webhook this slow makes every matching request wait that long before failing.
const SLOW_TIMEOUT_SECONDS: i32 = 20;

// --- Worlds and kinds ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HookWorld {
    Admission,
    Conversion,
    ApiService,
}

impl HookWorld {
    // The order `g` cycles through, admission first because it is the one that blocks writes.
    pub fn next(self) -> HookWorld {
        match self {
            HookWorld::Admission => HookWorld::Conversion,
            HookWorld::Conversion => HookWorld::ApiService,
            HookWorld::ApiService => HookWorld::Admission,
        }
    }
}

/// Which of the two admission configurations a webhook lives in.
///
/// They are separate cluster-scoped kinds with an identical `webhooks[]` structure, so everything
/// below treats them as one list; only a delete, a patch, and the KIND badge need to tell them
/// apart. Mutating webhooks run *before* validating ones and are the only ones carrying
/// `reinvocationPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookKind {
    Validating,
    Mutating,
}

impl WebhookKind {
    pub fn api_kind(&self) -> &'static str {
        match self {
            WebhookKind::Validating => "ValidatingWebhookConfiguration",
            WebhookKind::Mutating => "MutatingWebhookConfiguration",
        }
    }

    // The KIND column: four columns are all this distinction needs.
    pub fn label(&self) -> &'static str {
        match self {
            WebhookKind::Validating => "val",
            WebhookKind::Mutating => "mut",
        }
    }
}

/// Why a backend cannot be reached.
///
/// The three cases are worth distinguishing because they say different things about whether the
/// operator is coming back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookFault {
    // The namespace the backing service lives in is gone: the operator was uninstalled.
    NamespaceGone,
    // The namespace is there but the Service is not.
    ServiceGone,
    // The Service exists and resolves, but nothing is behind it — the operator is scaled to zero or
    // crash-looping. This one may well fix itself, which is why it is not treated as an orphan.
    NoEndpoints,
}

impl WebhookFault {
    fn text(self, st: &'static Strings) -> &'static str {
        match self {
            WebhookFault::NamespaceGone => st.hk_fault_namespace_gone,
            WebhookFault::ServiceGone => st.hk_fault_service_gone,
            WebhookFault::NoEndpoints => st.hk_fault_no_endpoints,
        }
    }
}

// --- Backend ------------------------------------------------------------------------------------

/// Where a hook sends its request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Backend {
    Service {
        namespace: String,
        name: String,
        path: String,
        port: i32,
    },
    // `clientConfig.url`: the hook points outside the cluster. Nothing here can judge it.
    Url {
        url: String,
    },
    // An `APIService` with no `spec.service` is the API server describing itself.
    Local,
}

impl Backend {
    pub fn service(&self) -> Option<(&str, &str)> {
        match self {
            Backend::Service { namespace, name, .. } => Some((namespace, name)),
            _ => None,
        }
    }

    // The BACKEND column: "kyverno/kyverno-svc:443", the bare URL, or the API server itself.
    pub fn label(&self) -> String {
        match self {
            Backend::Service { namespace, name, port, .. } => {
                format!("{}/{}:{}", namespace, name, port)
            }
            Backend::Url { url } => url.clone(),
            Backend::Local => "apiserver".to_string(),
        }
    }

    // Same, without the port: what a sentence about the service should name.
    pub fn short(&self) -> String {
        match self {
            Backend::Service { namespace, name, .. } => format!("{}/{}", namespace, name),
            Backend::Url { url } => url.clone(),
            Backend::Local => "apiserver".to_string(),
        }
    }
}

/// The *observed* state of a backend.
///
/// `Unchecked` exists so that "I could not ask" never reads as "it is fine", which is what
/// `repair::service_fault` was forced to do by returning `None` for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    Ready,
    NoEndpoints,
    ServiceGone,
    NamespaceGone,
    // Out-of-cluster URL, or the API server itself: not ours to judge.
    NotOurs,
    // The lookup failed for a reason other than a clean 404. Never a verdict.
    Unchecked,
}

impl Reach {
    /// The three cases `repair` calls an outage. `Unchecked` maps to `None`, exactly as the old
    /// `service_fault` did, which is what keeps `Ctrl-R` unchanged.
    pub fn fault(self) -> Option<WebhookFault> {
        match self {
            Reach::NoEndpoints => Some(WebhookFault::NoEndpoints),
            Reach::ServiceGone => Some(WebhookFault::ServiceGone),
            Reach::NamespaceGone => Some(WebhookFault::NamespaceGone),
            _ => None,
        }
    }

    pub fn is_broken(self) -> bool {
        self.fault().is_some()
    }

    // The REACH column. Kubernetes jargon, so it reads the same in both languages.
    pub fn label(&self) -> &'static str {
        match self {
            Reach::Ready => "ready",
            Reach::NoEndpoints => "no-eps",
            Reach::ServiceGone => "no-svc",
            Reach::NamespaceGone => "no-ns",
            Reach::NotOurs => "extern",
            Reach::Unchecked => "?",
        }
    }

    pub fn tone(&self) -> LineColor {
        match self {
            Reach::Ready => LineColor::Ok,
            Reach::NoEndpoints | Reach::ServiceGone | Reach::NamespaceGone => LineColor::Err,
            Reach::NotOurs => LineColor::Dim,
            Reach::Unchecked => LineColor::Dim,
        }
    }
}

/// One lookup per distinct (namespace, service), memoized.
///
/// A configuration commonly declares a dozen webhooks all pointing at the same Service, and the
/// cert-manager Service backs both admission webhooks and a conversion webhook: without the cache
/// the same question would be asked ten times over a remote link.
#[derive(Default)]
pub struct ServiceProbe {
    seen: Vec<(String, String, Reach)>,
}

impl ServiceProbe {
    pub async fn reach(&mut self, client: &Client, ns: &str, name: &str) -> Reach {
        if let Some((_, _, r)) = self
            .seen
            .iter()
            .find(|(n, s, _)| n == ns && s == name)
        {
            return *r;
        }
        let r = probe_service(client, ns, name).await;
        self.seen.push((ns.to_string(), name.to_string(), r));
        r
    }

    pub async fn backend(&mut self, client: &Client, backend: &Backend) -> Reach {
        match backend.service() {
            Some((ns, name)) => self.reach(client, ns, name).await,
            None => Reach::NotOurs,
        }
    }
}

/// Can this Service serve? `Unchecked` when the question could not be asked.
pub async fn probe_service(client: &Client, ns: &str, name: &str) -> Reach {
    let svc: Api<Service> = Api::namespaced(client.clone(), ns);
    match svc.get_opt(name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Distinguish "the operator is gone" from "this one service was removed".
            let ns_api: Api<Namespace> = Api::all(client.clone());
            return match ns_api.get_opt(ns).await {
                Ok(None) => Reach::NamespaceGone,
                Ok(Some(_)) => Reach::ServiceGone,
                // The Service is a clean 404 but the namespace could not be read: the Service is
                // still gone, we just cannot say why.
                Err(_) => Reach::ServiceGone,
            };
        }
        Err(_) => return Reach::Unchecked,
    }

    let slices: Api<EndpointSlice> = Api::namespaced(client.clone(), ns);
    let lp = ListParams::default().labels(&format!("{}={}", SERVICE_NAME_LABEL, name));
    let Ok(list) = slices.list(&lp).await else {
        return Reach::Unchecked;
    };
    let ready = list.items.iter().any(|s| {
        s.endpoints
            .iter()
            .any(|e| e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true))
    });
    if ready {
        Reach::Ready
    } else {
        Reach::NoEndpoints
    }
}

// --- CA bundle ----------------------------------------------------------------------------------

/// The state of a `caBundle`.
///
/// `Opaque` is said as such rather than guessed at: a bundle kdt cannot read is not a bundle the API
/// server cannot read, and writing "expired" here would be inventing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CaBundle {
    // No caBundle at all. Legitimate while a controller injects it, so the annotation found on the
    // object — if any — is named.
    Absent { injector: Option<String> },
    // Present and decoded. One entry per certificate of the PEM chain.
    Parsed { bytes: usize, certs: Vec<CaCert> },
    // Present, undecodable.
    Opaque { bytes: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaCert {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_ca: bool,
    pub self_signed: bool,
}

impl CaBundle {
    /// The soonest expiry of the chain: one expired certificate in it is enough to break the
    /// handshake, so the whole bundle is only as good as its worst link.
    pub fn soonest(&self) -> Option<&CaCert> {
        match self {
            CaBundle::Parsed { certs, .. } => certs.iter().min_by_key(|c| c.days_remaining),
            _ => None,
        }
    }

    // The CA column: days left, or why there is no number to show.
    pub fn label(&self, st: &'static Strings) -> String {
        match self {
            CaBundle::Absent { injector: Some(_) } => st.hk_ca_col_inject.to_string(),
            CaBundle::Absent { injector: None } => st.hk_ca_col_absent.to_string(),
            CaBundle::Opaque { .. } => st.hk_ca_col_opaque.to_string(),
            CaBundle::Parsed { .. } => match self.soonest() {
                Some(c) if c.days_remaining <= 0 => st.hk_ca_col_expired.to_string(),
                Some(c) => fill(st.hk_ca_col_days, &[("n", &c.days_remaining.to_string())]),
                None => st.hk_ca_col_opaque.to_string(),
            },
        }
    }
}

/// The CA-injection annotations kdt knows about, and the product behind each.
///
/// An absent caBundle means something very different depending on whether one of these is present:
/// with it, the controller simply has not run yet; without it, nothing will ever validate the
/// backend's certificate.
const CA_INJECTORS: &[(&str, &str)] = &[
    ("cert-manager.io/inject-ca-from", "cert-manager"),
    ("cert-manager.io/inject-ca-from-secret", "cert-manager"),
    ("cert-manager.io/inject-apiserver-ca", "cert-manager"),
    ("service.beta.openshift.io/inject-cabundle", "openshift"),
    ("kyverno.io/inject-ca", "kyverno"),
];

fn ca_injector(meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta) -> Option<String> {
    let annotations = meta.annotations.as_ref()?;
    CA_INJECTORS
        .iter()
        .find(|(key, _)| annotations.contains_key(*key))
        .map(|(_, product)| product.to_string())
}

/// Read a `caBundle` field.
///
/// `caBundle` is a `ByteString`, so serde has already undone the base64: what arrives here is PEM,
/// and decoding it a second time would fail. The whole chain is read — `Pem::iter_from_buffer`, not
/// `parse_x509_pem`, which stops at the first certificate.
fn read_ca_bundle(
    raw: Option<&k8s_openapi::ByteString>,
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> CaBundle {
    let Some(bytes) = raw.map(|b| &b.0).filter(|b| !b.is_empty()) else {
        return CaBundle::Absent { injector: ca_injector(meta) };
    };
    let certs = parse_ca_chain(bytes);
    if certs.is_empty() {
        CaBundle::Opaque { bytes: bytes.len() }
    } else {
        CaBundle::Parsed { bytes: bytes.len(), certs }
    }
}

fn parse_ca_chain(bytes: &[u8]) -> Vec<CaCert> {
    use x509_parser::prelude::*;

    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(bytes).flatten() {
        let Ok(cert) = pem.parse_x509() else { continue };
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        out.push(CaCert {
            subject_cn: crate::secrets::first_cn(cert.subject()),
            issuer_cn: crate::secrets::first_cn(cert.issuer()),
            not_before: crate::secrets::fmt_date(not_before),
            not_after: crate::secrets::fmt_date(not_after),
            days_remaining: crate::secrets::days_until(not_after),
            is_ca: cert
                .basic_constraints()
                .ok()
                .flatten()
                .map(|b| b.value.ca)
                .unwrap_or(false),
            self_signed: cert.subject() == cert.issuer(),
        });
    }
    out
}

// --- Scope --------------------------------------------------------------------------------------

/// One `rules[]` entry of an admission webhook, flattened.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RuleScope {
    pub api_groups: Vec<String>,
    pub api_versions: Vec<String>,
    pub resources: Vec<String>,
    pub operations: Vec<String>,
    pub scope: String,
}

impl RuleScope {
    fn from(rule: &RuleWithOperations) -> RuleScope {
        RuleScope {
            api_groups: rule.api_groups.clone().unwrap_or_default(),
            api_versions: rule.api_versions.clone().unwrap_or_default(),
            resources: rule.resources.clone().unwrap_or_default(),
            operations: rule.operations.clone().unwrap_or_default(),
            scope: rule.scope.clone().unwrap_or_else(|| "*".to_string()),
        }
    }

    /// `apiGroups: ["*"]` x `apiVersions: ["*"]` x `resources: ["*"]` — the rule that puts this hook
    /// in front of every write in the cluster, `Namespace` and `Node` included.
    pub fn is_catch_all(&self) -> bool {
        let star = |v: &[String]| v.iter().any(|s| s == "*");
        star(&self.api_groups) && star(&self.api_versions) && star(&self.resources)
    }

    /// Does the rule cover the operations that change the cluster?
    pub fn covers_writes(&self) -> bool {
        self.operations.iter().any(|o| o == "*")
            || ["CREATE", "UPDATE", "DELETE"]
                .iter()
                .all(|op| self.operations.iter().any(|o| o == op))
    }

    // "apps/v1 deployments [CREATE,UPDATE]"
    pub fn summary(&self) -> String {
        let join = |v: &[String]| {
            if v.is_empty() {
                "*".to_string()
            } else {
                v.join(",")
            }
        };
        let group = if self.api_groups.iter().any(|g| g.is_empty()) && self.api_groups.len() == 1 {
            "core".to_string()
        } else {
            join(&self.api_groups)
        };
        format!(
            "{}/{} {} [{}]",
            group,
            join(&self.api_versions),
            join(&self.resources),
            join(&self.operations)
        )
    }
}

/// A `namespaceSelector` or `objectSelector`, reduced to what a verdict needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Selector {
    // Empty when the selector is absent, which in admission means "everything".
    pub summary: String,
    pub matches_everything: bool,
    /// The selector keeps at least one system namespace out, either by `NotIn` on
    /// `kubernetes.io/metadata.name` or by an exclusion label the operator sets there.
    pub excludes_system: bool,
}

fn read_selector(sel: Option<&LabelSelector>) -> Selector {
    let Some(sel) = sel else {
        return Selector { summary: String::new(), matches_everything: true, excludes_system: false };
    };
    let labels: Vec<String> = sel
        .match_labels
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
        .unwrap_or_default();
    let exprs = sel.match_expressions.clone().unwrap_or_default();
    if labels.is_empty() && exprs.is_empty() {
        return Selector { summary: String::new(), matches_everything: true, excludes_system: false };
    }

    // A `NotIn`/`DoesNotExist` expression naming a system namespace is the usual way to keep a hook
    // out of kube-system; a `matchLabels` on a per-namespace opt-in label is the other.
    let excludes_system = exprs.iter().any(|e| {
        let op = e.operator.as_str();
        if op == "DoesNotExist" {
            return true;
        }
        if op != "NotIn" {
            return false;
        }
        e.values
            .as_ref()
            .map(|v| v.iter().any(|x| SYSTEM_NAMESPACES.contains(&x.as_str())))
            .unwrap_or(false)
    }) || !labels.is_empty();

    let mut summary = labels.join(",");
    for e in &exprs {
        if !summary.is_empty() {
            summary.push(',');
        }
        let values = e
            .values
            .as_ref()
            .map(|v| v.join("|"))
            .unwrap_or_default();
        if values.is_empty() {
            summary.push_str(&format!("{} {}", e.key, e.operator));
        } else {
            summary.push_str(&format!("{} {} {}", e.key, e.operator, values));
        }
    }
    Selector { summary, matches_everything: false, excludes_system }
}

// --- Rows ---------------------------------------------------------------------------------------

/// One admission webhook: a **named entry** of `webhooks[]`, not the configuration holding it.
///
/// The grain is the entry because everything a verdict reads — `failurePolicy`, `rules`,
/// `timeoutSeconds`, `clientConfig` — lives there: Kyverno declares `validate.kyverno.svc-fail` and
/// `validate.kyverno.svc-ignore` in one object, with opposite policies. And the API server names the
/// entry, not the configuration, in `failed calling webhook "..."` — which is the string someone
/// arrives with.
///
/// The object the row *designates* is still the configuration: [`admission_record`] carries its kind
/// and name, so `y`/`e`/`Ctrl-D` act on it. The detail panel says so in as many words, because
/// deleting it takes every webhook it holds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdmissionHook {
    pub kind: WebhookKind,
    // `metadata.name` of the configuration: the object this row stands for.
    pub config: String,
    // Index in `webhooks[]`. What a JSON patch has to address.
    pub index: usize,
    // `webhooks[i].name`.
    pub name: String,
    // Combien de webhooks la configuration porte en tout — ce que `Ctrl-D` emporterait avec elle.
    pub siblings: usize,
    pub backend: Backend,
    pub reach: Reach,
    // `Fail` (the default when the field is absent) rather than `Ignore`.
    pub fail_closed: bool,
    // True when `failurePolicy` was absent: the column dims the value it inferred.
    pub failure_policy_defaulted: bool,
    // `None` means the API server default of 10s.
    pub timeout_seconds: Option<i32>,
    // Required in v1, so never empty in practice.
    pub side_effects: String,
    pub match_policy: String,
    // Mutating only.
    pub reinvocation_policy: Option<String>,
    pub admission_review_versions: Vec<String>,
    pub rules: Vec<RuleScope>,
    pub namespace_selector: Selector,
    pub object_selector: Selector,
    // Counted, never evaluated: kdt does not run CEL, and pretending to would be guessing.
    pub match_conditions: usize,
    pub ca: CaBundle,
    pub hints: Vec<Hint>,
    pub age: String,
    pub uid: String,
}

impl AdmissionHook {
    // The SCOPE column: the catch-all is called out, anything else is counted.
    pub fn scope_label(&self, st: &'static Strings) -> String {
        if self.rules.iter().any(|r| r.is_catch_all()) {
            return "*/*/*".to_string();
        }
        match self.rules.len() {
            0 => st.hk_scope_none.to_string(),
            n => st.plural(n, st.hk_scope_rule, st.hk_scope_rules),
        }
    }

    pub fn severity(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }
}

/// A configuration, the parent row under `t`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdmissionConfig {
    pub kind: WebhookKind,
    pub name: String,
    pub hooks: usize,
    // The worst verdict of its webhooks: a parent must never read healthier than its children.
    pub hints: Vec<Hint>,
    pub age: String,
    pub uid: String,
}

/// A CRD that hands its conversion to a webhook.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversionHook {
    // "certificates.cert-manager.io"
    pub name: String,
    pub group: String,
    pub kind: String,
    pub scope: String,
    pub versions: Vec<CrdVersion>,
    pub storage_version: String,
    pub storage_version_served: bool,
    pub backend: Backend,
    pub reach: Reach,
    pub ca: CaBundle,
    pub conversion_review_versions: Vec<String>,
    pub hints: Vec<Hint>,
    pub age: String,
    pub uid: String,
}

impl ConversionHook {
    // The SERVIES column: served versions in declaration order, storage one first when it is served.
    pub fn served_label(&self) -> String {
        self.versions
            .iter()
            .filter(|v| v.served)
            .map(|v| v.name.clone())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CrdVersion {
    pub name: String,
    pub served: bool,
    pub storage: bool,
    pub deprecated: bool,
}

/// An **aggregated** `APIService` — one with a `spec.service`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiServiceHook {
    // "v1beta1.metrics.k8s.io"
    pub name: String,
    pub group: String,
    pub version: String,
    pub backend: Backend,
    pub reach: Reach,
    pub ca: CaBundle,
    pub insecure: bool,
    pub group_priority_minimum: i32,
    pub version_priority: i32,
    // `status.conditions[type=Available]`, verbatim. "True" | "False" | "Unknown".
    pub available: Option<String>,
    pub reason: String,
    pub message: String,
    pub hints: Vec<Hint>,
    pub age: String,
    pub uid: String,
}

impl ApiServiceHook {
    pub fn available_label(&self) -> &str {
        self.available.as_deref().unwrap_or("?")
    }
}

// --- State --------------------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
pub struct HooksState {
    pub configs: Vec<AdmissionConfig>,
    pub admission: Vec<AdmissionHook>,
    pub conversion: Vec<ConversionHook>,
    pub apiservices: Vec<ApiServiceHook>,
    // One error field per world, on purpose. An RBAC refusal on `apiextensions.k8s.io` must not
    // whiten the admission world, which is the one that matters most.
    pub error: Option<String>,
    pub conversion_error: Option<String>,
    pub apiservice_error: Option<String>,
    pub loading: bool,
    // Always true in practice — the four kinds are native. Kept so that a cluster refusing the list
    // reads as "refused" rather than "empty".
    pub installed: bool,
    // Local APIServices left out of the list, for the panel title.
    pub local_apiservices: usize,
}

/// What the panel title shows for one world.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HookCounts {
    pub rows: usize,
    pub fail_closed: usize,
    pub broken: usize,
    pub catch_all: usize,
}

impl HooksState {
    pub fn counts(&self, world: HookWorld) -> HookCounts {
        let mut c = HookCounts::default();
        match world {
            HookWorld::Admission => {
                for h in &self.admission {
                    c.rows += 1;
                    if h.fail_closed {
                        c.fail_closed += 1;
                    }
                    if h.reach.is_broken() {
                        c.broken += 1;
                    }
                    if h.rules.iter().any(|r| r.is_catch_all()) {
                        c.catch_all += 1;
                    }
                }
            }
            HookWorld::Conversion => {
                for h in &self.conversion {
                    c.rows += 1;
                    if h.reach.is_broken() {
                        c.broken += 1;
                    }
                }
            }
            HookWorld::ApiService => {
                for h in &self.apiservices {
                    c.rows += 1;
                    if h.reach.is_broken() {
                        c.broken += 1;
                    }
                    if h.available.as_deref() == Some("False") {
                        c.fail_closed += 1;
                    }
                }
            }
        }
        c
    }

    pub fn error_for(&self, world: HookWorld) -> Option<&String> {
        match world {
            HookWorld::Admission => self.error.as_ref(),
            HookWorld::Conversion => self.conversion_error.as_ref(),
            HookWorld::ApiService => self.apiservice_error.as_ref(),
        }
    }
}

pub type SharedHooks = Arc<Mutex<HooksState>>;

pub fn new_hooks_state() -> SharedHooks {
    Arc::new(Mutex::new(HooksState::default()))
}

// --- Reading the cluster ------------------------------------------------------------------------

pub const ADMISSION_API_VERSION: &str = "admissionregistration.k8s.io/v1";
pub const CRD_API_VERSION: &str = "apiextensions.k8s.io/v1";
pub const APISERVICE_API_VERSION: &str = "apiregistration.k8s.io/v1";

// `ValidatingWebhook` and `MutatingWebhook` are two Rust types with no trait in common, so the
// fields are lifted into this shape once per kind and everything downstream is written once.
struct RawWebhook {
    name: String,
    backend: Backend,
    ca: CaBundle,
    fail_closed: bool,
    failure_policy_defaulted: bool,
    timeout_seconds: Option<i32>,
    side_effects: String,
    match_policy: String,
    reinvocation_policy: Option<String>,
    admission_review_versions: Vec<String>,
    rules: Vec<RuleScope>,
    namespace_selector: Selector,
    object_selector: Selector,
    match_conditions: usize,
}

fn client_backend(
    service: Option<(&str, &str, Option<&str>, Option<i32>)>,
    url: Option<&str>,
) -> Backend {
    match (service, url) {
        (Some((ns, name, path, port)), _) => Backend::Service {
            namespace: ns.to_string(),
            name: name.to_string(),
            path: path.unwrap_or("/").to_string(),
            // 443 is what the API server assumes when the field is absent.
            port: port.unwrap_or(443),
        },
        (None, Some(url)) => Backend::Url { url: url.to_string() },
        (None, None) => Backend::Local,
    }
}

fn raw_validating(
    w: &k8s_openapi::api::admissionregistration::v1::ValidatingWebhook,
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> RawWebhook {
    let cc = &w.client_config;
    RawWebhook {
        name: w.name.clone(),
        backend: client_backend(
            cc.service
                .as_ref()
                .map(|s| (s.namespace.as_str(), s.name.as_str(), s.path.as_deref(), s.port)),
            cc.url.as_deref(),
        ),
        ca: read_ca_bundle(cc.ca_bundle.as_ref(), meta),
        fail_closed: w.failure_policy.as_deref() != Some("Ignore"),
        failure_policy_defaulted: w.failure_policy.is_none(),
        timeout_seconds: w.timeout_seconds,
        side_effects: w.side_effects.clone(),
        match_policy: w.match_policy.clone().unwrap_or_else(|| "Equivalent".to_string()),
        reinvocation_policy: None,
        admission_review_versions: w.admission_review_versions.clone(),
        rules: w.rules.iter().flatten().map(RuleScope::from).collect(),
        namespace_selector: read_selector(w.namespace_selector.as_ref()),
        object_selector: read_selector(w.object_selector.as_ref()),
        match_conditions: w.match_conditions.as_ref().map(|m| m.len()).unwrap_or(0),
    }
}

fn raw_mutating(
    w: &k8s_openapi::api::admissionregistration::v1::MutatingWebhook,
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> RawWebhook {
    let cc = &w.client_config;
    RawWebhook {
        name: w.name.clone(),
        backend: client_backend(
            cc.service
                .as_ref()
                .map(|s| (s.namespace.as_str(), s.name.as_str(), s.path.as_deref(), s.port)),
            cc.url.as_deref(),
        ),
        ca: read_ca_bundle(cc.ca_bundle.as_ref(), meta),
        fail_closed: w.failure_policy.as_deref() != Some("Ignore"),
        failure_policy_defaulted: w.failure_policy.is_none(),
        timeout_seconds: w.timeout_seconds,
        side_effects: w.side_effects.clone(),
        match_policy: w.match_policy.clone().unwrap_or_else(|| "Equivalent".to_string()),
        reinvocation_policy: Some(
            w.reinvocation_policy.clone().unwrap_or_else(|| "Never".to_string()),
        ),
        admission_review_versions: w.admission_review_versions.clone(),
        rules: w.rules.iter().flatten().map(RuleScope::from).collect(),
        namespace_selector: read_selector(w.namespace_selector.as_ref()),
        object_selector: read_selector(w.object_selector.as_ref()),
        match_conditions: w.match_conditions.as_ref().map(|m| m.len()).unwrap_or(0),
    }
}

fn hook_from_raw(
    kind: WebhookKind,
    config: &str,
    index: usize,
    siblings: usize,
    age: &str,
    raw: RawWebhook,
) -> AdmissionHook {
    AdmissionHook {
        kind,
        config: config.to_string(),
        index,
        siblings,
        uid: format!("hooks|adm|{}/{}#{}", kind.label(), config, index),
        name: raw.name,
        backend: raw.backend,
        reach: Reach::Unchecked,
        fail_closed: raw.fail_closed,
        failure_policy_defaulted: raw.failure_policy_defaulted,
        timeout_seconds: raw.timeout_seconds,
        side_effects: raw.side_effects,
        match_policy: raw.match_policy,
        reinvocation_policy: raw.reinvocation_policy,
        admission_review_versions: raw.admission_review_versions,
        rules: raw.rules,
        namespace_selector: raw.namespace_selector,
        object_selector: raw.object_selector,
        match_conditions: raw.match_conditions,
        ca: raw.ca,
        hints: Vec::new(),
        age: age.to_string(),
    }
}

fn age_of(meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta) -> String {
    meta.creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default()
}

// One configuration, flattened into its parent row and one row per named webhook. Pure, so the
// grain of the table is testable against a manifest without a cluster.
fn validating_rows(
    c: &ValidatingWebhookConfiguration,
) -> (AdmissionConfig, Vec<AdmissionHook>) {
    let name = c.metadata.name.clone().unwrap_or_default();
    let age = age_of(&c.metadata);
    let webhooks = c.webhooks.clone().unwrap_or_default();
    let hooks = webhooks
        .iter()
        .enumerate()
        .map(|(i, w)| {
            hook_from_raw(
                WebhookKind::Validating,
                &name,
                i,
                webhooks.len(),
                &age,
                raw_validating(w, &c.metadata),
            )
        })
        .collect();
    let config = AdmissionConfig {
        kind: WebhookKind::Validating,
        uid: format!("hooks|cfg|val/{}", name),
        name,
        hooks: webhooks.len(),
        hints: Vec::new(),
        age,
    };
    (config, hooks)
}

fn mutating_rows(c: &MutatingWebhookConfiguration) -> (AdmissionConfig, Vec<AdmissionHook>) {
    let name = c.metadata.name.clone().unwrap_or_default();
    let age = age_of(&c.metadata);
    let webhooks = c.webhooks.clone().unwrap_or_default();
    let hooks = webhooks
        .iter()
        .enumerate()
        .map(|(i, w)| {
            hook_from_raw(
                WebhookKind::Mutating,
                &name,
                i,
                webhooks.len(),
                &age,
                raw_mutating(w, &c.metadata),
            )
        })
        .collect();
    let config = AdmissionConfig {
        kind: WebhookKind::Mutating,
        uid: format!("hooks|cfg|mut/{}", name),
        name,
        hooks: webhooks.len(),
        hints: Vec::new(),
        age,
    };
    (config, hooks)
}

// Both configuration kinds, listed and flattened. No probing yet: the lists of all three worlds go
// out as one wave, and only then is each distinct Service asked once.
async fn admission_rows(
    client: &Client,
) -> Result<(Vec<AdmissionConfig>, Vec<AdmissionHook>), String> {
    let validating: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    let mutating: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let (v, m) = futures::future::join(
        validating.list(&ListParams::default()),
        mutating.list(&ListParams::default()),
    )
    .await;

    let mut configs = Vec::new();
    let mut hooks = Vec::new();
    for c in v.map_err(|e| e.to_string())?.items {
        let (config, mut rows) = validating_rows(&c);
        configs.push(config);
        hooks.append(&mut rows);
    }
    for c in m.map_err(|e| e.to_string())?.items {
        let (config, mut rows) = mutating_rows(&c);
        configs.push(config);
        hooks.append(&mut rows);
    }
    Ok((configs, hooks))
}

/// `None` for a CRD that does not hand its conversion to a webhook.
///
/// `strategy: None` is the overwhelming majority and has no backend to speak of, so listing those
/// would bury the ones that do.
fn conversion_from_crd(crd: &CustomResourceDefinition) -> Option<ConversionHook> {
    let conv = crd.spec.conversion.as_ref()?;
    if conv.strategy != "Webhook" {
        return None;
    }
    let webhook = conv.webhook.as_ref();
    let cc = webhook.and_then(|w| w.client_config.as_ref());
    let backend = match cc {
        Some(cc) => client_backend(
            cc.service
                .as_ref()
                .map(|s| (s.namespace.as_str(), s.name.as_str(), s.path.as_deref(), s.port)),
            cc.url.as_deref(),
        ),
        None => Backend::Local,
    };
    let ca = read_ca_bundle(cc.and_then(|c| c.ca_bundle.as_ref()), &crd.metadata);
    let name = crd.metadata.name.clone().unwrap_or_default();
    let versions: Vec<CrdVersion> = crd
        .spec
        .versions
        .iter()
        .map(|v| CrdVersion {
            name: v.name.clone(),
            served: v.served,
            storage: v.storage,
            deprecated: v.deprecated.unwrap_or(false),
        })
        .collect();
    let storage = versions.iter().find(|v| v.storage);
    Some(ConversionHook {
        uid: format!("hooks|conv|{}", name),
        age: age_of(&crd.metadata),
        name,
        group: crd.spec.group.clone(),
        kind: crd.spec.names.kind.clone(),
        scope: crd.spec.scope.clone(),
        storage_version: storage.map(|v| v.name.clone()).unwrap_or_default(),
        storage_version_served: storage.map(|v| v.served).unwrap_or(true),
        versions,
        backend,
        reach: Reach::Unchecked,
        ca,
        conversion_review_versions: webhook
            .map(|w| w.conversion_review_versions.clone())
            .unwrap_or_default(),
        hints: Vec::new(),
    })
}

async fn conversion_rows(client: &Client) -> Result<Vec<ConversionHook>, String> {
    let api: Api<CustomResourceDefinition> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    Ok(list.items.iter().filter_map(conversion_from_crd).collect())
}

/// `None` for a local APIService.
///
/// A local APIService is the API server describing itself: no backend, no caBundle, no failure this
/// view can speak about, and there are dozens of them. Counted, not listed.
fn apiservice_from(item: &APIService) -> Option<ApiServiceHook> {
    let spec = item.spec.as_ref()?;
    let svc = spec.service.as_ref()?;
    let name = item.metadata.name.clone().unwrap_or_default();
    let available = item
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|c| c.iter().find(|c| c.type_ == "Available"));
    Some(ApiServiceHook {
        uid: format!("hooks|api|{}", name),
        age: age_of(&item.metadata),
        name,
        group: spec.group.clone().unwrap_or_default(),
        version: spec.version.clone().unwrap_or_default(),
        backend: client_backend(
            Some((
                svc.namespace.as_deref().unwrap_or_default(),
                svc.name.as_deref().unwrap_or_default(),
                None,
                svc.port,
            )),
            None,
        ),
        reach: Reach::Unchecked,
        ca: read_ca_bundle(spec.ca_bundle.as_ref(), &item.metadata),
        insecure: spec.insecure_skip_tls_verify.unwrap_or(false),
        group_priority_minimum: spec.group_priority_minimum,
        version_priority: spec.version_priority,
        available: available.map(|c| c.status.clone()),
        reason: available.and_then(|c| c.reason.clone()).unwrap_or_default(),
        message: available.and_then(|c| c.message.clone()).unwrap_or_default(),
        hints: Vec::new(),
    })
}

// The aggregated APIServices, and how many local ones were left out.
async fn apiservice_rows(client: &Client) -> Result<(Vec<ApiServiceHook>, usize), String> {
    let api: Api<APIService> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let total = list.items.len();
    let rows: Vec<ApiServiceHook> = list.items.iter().filter_map(apiservice_from).collect();
    let local = total - rows.len();
    Ok((rows, local))
}

// --- Verdicts -----------------------------------------------------------------------------------

fn info(text: String) -> Hint {
    Hint { level: HintLevel::Info, text }
}
fn warn(text: String) -> Hint {
    Hint { level: HintLevel::Warn, text }
}
fn danger(text: String) -> Hint {
    Hint { level: HintLevel::Danger, text }
}

// The findings a caBundle carries, shared by the three worlds: the field means the same thing in
// all of them, and so does its expiry.
fn ca_hints(ca: &CaBundle, st: &'static Strings, out: &mut Vec<Hint>) {
    match ca {
        CaBundle::Absent { injector: Some(injector) } => {
            out.push(info(fill(st.hk_ca_injected, &[("injector", injector)])));
        }
        CaBundle::Absent { injector: None } => out.push(warn(st.hk_ca_absent.to_string())),
        CaBundle::Opaque { bytes } => {
            out.push(warn(fill(st.hk_ca_opaque, &[("n", &bytes.to_string())])));
        }
        CaBundle::Parsed { .. } => {
            let Some(cert) = ca.soonest() else { return };
            if cert.days_remaining <= 0 {
                out.push(danger(fill(st.hk_ca_expired, &[("date", &cert.not_after)])));
            } else if cert.days_remaining <= CA_EXPIRY_WARN_DAYS {
                out.push(warn(fill(
                    st.hk_ca_expiring,
                    &[("n", &cert.days_remaining.to_string()), ("date", &cert.not_after)],
                )));
            }
        }
    }
}

// What an unreachable backend means, said once for the worlds that share the wording.
fn reach_hints(backend: &Backend, reach: Reach, st: &'static Strings, out: &mut Vec<Hint>) {
    match reach {
        Reach::NotOurs => {
            if let Backend::Url { url } = backend {
                out.push(info(fill(st.hk_url_backend, &[("url", url)])));
            }
        }
        Reach::Unchecked => {
            out.push(info(fill(st.hk_unchecked, &[("svc", &backend.short())])));
        }
        _ => {}
    }
}

/// Does this hook stand in front of the namespace its own service lives in?
///
/// Only asserted when there is no `namespaceSelector` at all, so the answer is certain: with a
/// selector, saying whether the namespace is excluded would mean evaluating it against labels this
/// module has not read.
fn self_locking(h: &AdmissionHook) -> bool {
    if !h.fail_closed || !h.namespace_selector.matches_everything {
        return false;
    }
    let Some((ns, _)) = h.backend.service() else { return false };
    if ns.is_empty() {
        return false;
    }
    h.rules.iter().any(|r| {
        r.covers_writes()
            && (r.is_catch_all()
                || r.resources.iter().any(|res| {
                    matches!(
                        res.as_str(),
                        "*" | "pods" | "deployments" | "replicasets" | "statefulsets" | "daemonsets"
                    )
                }))
    })
}

fn admission_hints(h: &AdmissionHook, st: &'static Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    let svc = h.backend.short();
    let catch_all = h.rules.iter().any(|r| r.is_catch_all());
    let excludes_system = h.namespace_selector.excludes_system;

    if let Some(fault) = h.reach.fault() {
        let args = [("svc", svc.as_str()), ("fault", fault.text(st))];
        if h.fail_closed {
            out.push(danger(fill(st.hk_dead_fail_closed, &args)));
        } else {
            let seconds = h.timeout_seconds.unwrap_or(10).to_string();
            out.push(warn(fill(
                st.hk_dead_fail_open,
                &[("svc", svc.as_str()), ("fault", fault.text(st)), ("n", &seconds)],
            )));
        }
    }

    if self_locking(h) {
        let ns = h.backend.service().map(|(ns, _)| ns).unwrap_or_default();
        out.push(danger(fill(st.hk_self_locking, &[("ns", ns)])));
    }

    if catch_all && h.fail_closed && !excludes_system {
        out.push(danger(st.hk_catch_all_fail_closed.to_string()));
    } else if catch_all {
        out.push(warn(st.hk_catch_all.to_string()));
    } else if h.rules.iter().any(|r| r.covers_writes()) && !excludes_system {
        out.push(warn(st.hk_no_system_exclusion.to_string()));
    }

    if let Some(t) = h.timeout_seconds {
        if t >= SLOW_TIMEOUT_SECONDS && h.fail_closed {
            out.push(warn(fill(st.hk_timeout_long, &[("n", &t.to_string())])));
        }
    }

    if matches!(h.side_effects.as_str(), "Some" | "Unknown") {
        out.push(warn(fill(st.hk_side_effects, &[("v", &h.side_effects)])));
    }

    ca_hints(&h.ca, st, &mut out);
    reach_hints(&h.backend, h.reach, st, &mut out);
    out
}

fn conversion_hints(c: &ConversionHook, st: &'static Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    if c.reach.is_broken() {
        out.push(danger(fill(
            st.hk_conv_dead,
            &[("svc", &c.backend.short()), ("kind", &c.kind)],
        )));
    }
    if !c.storage_version_served && !c.storage_version.is_empty() {
        out.push(warn(fill(st.hk_conv_storage_unserved, &[("v", &c.storage_version)])));
    }
    for v in c.versions.iter().filter(|v| v.served && v.deprecated) {
        out.push(info(fill(st.hk_conv_deprecated, &[("v", &v.name)])));
    }
    ca_hints(&c.ca, st, &mut out);
    reach_hints(&c.backend, c.reach, st, &mut out);
    out
}

fn apiservice_hints(a: &ApiServiceHook, st: &'static Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    if a.available.as_deref() == Some("False") {
        // The API server's own reason, verbatim: it knows why it gave up, and rewording it would
        // lose the only lead there is.
        let reason = if a.reason.is_empty() { "-" } else { a.reason.as_str() };
        out.push(danger(fill(
            st.hk_apisvc_unavailable,
            &[("reason", reason), ("group", &a.group)],
        )));
    } else if a.reach.is_broken() {
        out.push(danger(fill(
            st.hk_apisvc_dead,
            &[("svc", &a.backend.short()), ("group", &a.group)],
        )));
    }
    if a.insecure {
        out.push(warn(st.hk_apisvc_insecure.to_string()));
    }
    ca_hints(&a.ca, st, &mut out);
    reach_hints(&a.backend, a.reach, st, &mut out);
    out
}

// The worst verdict of a configuration's webhooks, so a parent row never reads healthier than its
// children, plus the tombstone note for a configuration with nothing left in it.
fn config_hints(config: &AdmissionConfig, hooks: &[AdmissionHook], st: &'static Strings) -> Vec<Hint> {
    if config.hooks == 0 {
        return vec![info(st.hk_empty_config.to_string())];
    }
    let worst = hooks
        .iter()
        .filter(|h| h.kind == config.kind && h.config == config.name)
        .filter_map(|h| worst_hint(&h.hints))
        .min_by_key(|h| std::cmp::Reverse(h.level));
    worst.cloned().into_iter().collect()
}

// --- Entry points -------------------------------------------------------------------------------

async fn probe_admission(client: &Client, probe: &mut ServiceProbe, hooks: &mut [AdmissionHook]) {
    for h in hooks.iter_mut() {
        h.reach = probe.backend(client, &h.backend).await;
    }
}

/// The admission world alone, probed and written up. What [`crate::repair`] consumes.
///
/// Kept separate from [`hooks_inventory`] on purpose: widening `Ctrl-R` to conversion webhooks and
/// APIServices would change its contract, and there is no safe "delete the CRD" remedy to offer.
pub async fn list_admission(
    client: &Client,
    st: &'static Strings,
) -> Result<(Vec<AdmissionConfig>, Vec<AdmissionHook>), String> {
    let (mut configs, mut hooks) = admission_rows(client).await?;
    let mut probe = ServiceProbe::default();
    probe_admission(client, &mut probe, &mut hooks).await;
    for h in hooks.iter_mut() {
        h.hints = admission_hints(h, st);
    }
    for c in configs.iter_mut() {
        c.hints = config_hints(c, &hooks, st);
    }
    sort_rows(&mut configs, &mut hooks);
    Ok((configs, hooks))
}

fn sort_rows(configs: &mut [AdmissionConfig], hooks: &mut [AdmissionHook]) {
    // Mutating before validating: c'est l'ordre dans lequel l'apiserver les appelle, et la question
    // « qui a touché à mon objet avant qu'on le refuse » se lit alors de haut en bas. Puis par nom de
    // configuration, puis par ordre de déclaration : l'index est ce qu'un patch adresse, donc
    // réordonner les entrées d'une configuration ferait mentir la table sur l'objet.
    configs.sort_by(|a, b| {
        (a.kind.label(), &a.name).cmp(&(b.kind.label(), &b.name))
    });
    hooks.sort_by(|a, b| {
        (a.kind.label(), &a.config, a.index).cmp(&(b.kind.label(), &b.config, b.index))
    });
}

/// The whole inventory, for kdt-web and for the TUI alike.
///
/// The three lists go out as one wave, and only then is each distinct Service asked once: the
/// cert-manager Service backs admission webhooks *and* the conversion of
/// `certificates.cert-manager.io`, and it should be queried once, not twice.
pub async fn hooks_inventory(client: &Client, st: &'static Strings) -> HooksState {
    let (admission, conversion, apiservices) = futures::future::join3(
        admission_rows(client),
        conversion_rows(client),
        apiservice_rows(client),
    )
    .await;

    let mut state = HooksState { installed: true, ..Default::default() };
    let mut probe = ServiceProbe::default();

    match admission {
        Ok((mut configs, mut hooks)) => {
            probe_admission(client, &mut probe, &mut hooks).await;
            for h in hooks.iter_mut() {
                h.hints = admission_hints(h, st);
            }
            for c in configs.iter_mut() {
                c.hints = config_hints(c, &hooks, st);
            }
            sort_rows(&mut configs, &mut hooks);
            state.configs = configs;
            state.admission = hooks;
        }
        Err(e) => state.error = Some(e),
    }

    match conversion {
        Ok(mut rows) => {
            for c in rows.iter_mut() {
                c.reach = probe.backend(client, &c.backend).await;
                c.hints = conversion_hints(c, st);
            }
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            state.conversion = rows;
        }
        Err(e) => state.conversion_error = Some(e),
    }

    match apiservices {
        Ok((mut rows, local)) => {
            for a in rows.iter_mut() {
                a.reach = probe.backend(client, &a.backend).await;
                a.hints = apiservice_hints(a, st);
            }
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            state.apiservices = rows;
            state.local_apiservices = local;
        }
        Err(e) => state.apiservice_error = Some(e),
    }

    state
}

/// The TUI wrapper: deposits into the shared state and reads the language in force, because this
/// task outlives the `l` key that may change it.
pub async fn fetch_hooks(client: Client, state: SharedHooks) {
    {
        let mut s = state.lock().expect("hooks poisoned");
        s.loading = true;
        s.error = None;
        s.conversion_error = None;
        s.apiservice_error = None;
    }

    let fresh = hooks_inventory(&client, crate::lang::active()).await;

    let mut s = state.lock().expect("hooks poisoned");
    *s = fresh;
    s.loading = false;
}

/// The product likely behind a configuration name, to explain the blast radius of an outage.
///
/// Lives here rather than in the diagnostic because the detail panel needs the same answer, and two
/// tables would drift.
pub fn hook_owner(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase();
    const KNOWN: &[(&str, &str)] = &[
        ("kyverno", "policy engine"),
        ("gatekeeper", "OPA"),
        ("cert-manager", "TLS"),
        ("rancher", "rancher webhook"),
        ("istio", "service mesh"),
        ("linkerd", "service mesh"),
        ("vault", "secrets"),
        ("argo", "argo"),
        ("flux", "fluxcd"),
        ("trivy", "image scan"),
        ("capsule", "multi-tenancy"),
        ("kubevirt", "virtualization"),
        ("velero", "backup"),
    ];
    KNOWN.iter().find(|(k, _)| n.contains(k)).map(|(_, label)| *label)
}

// --- Records ------------------------------------------------------------------------------------

pub fn worst_hint(hints: &[Hint]) -> Option<&Hint> {
    hints.iter().min_by_key(|h| std::cmp::Reverse(h.level))
}

fn worst_text(hints: &[Hint], fallback: String) -> String {
    worst_hint(hints).map(|h| h.text.clone()).unwrap_or(fallback)
}

/// The record of an admission row.
///
/// It designates the **configuration**, not the webhook: a named webhook is not an API object, so
/// `y`, `e` and `Ctrl-D` have to act on the object that holds it. Same shape as the network view,
/// where an endpoint row designates its Pod.
pub fn admission_record(h: &AdmissionHook) -> EventRecord {
    crate::events::hint_record(
        &h.uid,
        ADMISSION_API_VERSION,
        h.kind.api_kind(),
        "",
        &h.config,
        "AdmissionWebhook",
        worst_text(&h.hints, format!("{} -> {}", h.name, h.backend.label())),
        &h.hints,
    )
}

pub fn config_record(c: &AdmissionConfig) -> EventRecord {
    crate::events::hint_record(
        &c.uid,
        ADMISSION_API_VERSION,
        c.kind.api_kind(),
        "",
        &c.name,
        "AdmissionConfiguration",
        worst_text(&c.hints, format!("{} webhooks", c.hooks)),
        &c.hints,
    )
}

pub fn conversion_record(c: &ConversionHook) -> EventRecord {
    crate::events::hint_record(
        &c.uid,
        CRD_API_VERSION,
        "CustomResourceDefinition",
        "",
        &c.name,
        "ConversionWebhook",
        worst_text(&c.hints, format!("{} -> {}", c.kind, c.backend.label())),
        &c.hints,
    )
}

pub fn apiservice_record(a: &ApiServiceHook) -> EventRecord {
    crate::events::hint_record(
        &a.uid,
        APISERVICE_API_VERSION,
        "APIService",
        "",
        &a.name,
        "APIService",
        worst_text(&a.hints, format!("{} -> {}", a.available_label(), a.backend.label())),
        &a.hints,
    )
}

pub fn hint_tone(level: HintLevel) -> LineColor {
    match level {
        HintLevel::Danger => LineColor::Err,
        HintLevel::Warn => LineColor::Warn,
        HintLevel::Info => LineColor::Info,
    }
}

// --- Break glass --------------------------------------------------------------------------------

/// Flip the `failurePolicy` of **one** webhook.
///
/// JSON patch, never merge: a merge patch on `webhooks` replaces the whole array, which is how the
/// other webhooks of a configuration get wiped by someone who only meant to touch one.
///
/// `add` rather than `replace`, because `failurePolicy` is optional and defaults to `Fail`: on a
/// webhook that does not spell it out the member does not exist, and `replace` would come back 422.
/// RFC 6902 says `add` on an object member sets it whether or not it was there.
///
/// The `test` op on the **name** is what makes the index safe: between the read and the write an
/// operator can have reordered `webhooks[]`, and a bare index would then flip the wrong hook.
pub fn failure_policy_patch(index: usize, webhook: &str, to: &str) -> serde_json::Value {
    serde_json::json!([
        { "op": "test", "path": format!("/webhooks/{}/name", index), "value": webhook },
        { "op": "add", "path": format!("/webhooks/{}/failurePolicy", index), "value": to },
    ])
}

/// The value to flip to, given what the hook is on now.
pub fn failure_policy_toggle(fail_closed: bool) -> &'static str {
    if fail_closed {
        "Ignore"
    } else {
        "Fail"
    }
}

/// Apply [`failure_policy_patch`] to a configuration.
///
/// Cluster-wide in effect, which is why the caller confirms it the way a deletion is confirmed.
pub async fn set_failure_policy(
    client: &Client,
    kind: WebhookKind,
    config: &str,
    index: usize,
    webhook: &str,
    to: &str,
) -> Result<(), String> {
    let api = crate::yaml::dynamic_api(client, ADMISSION_API_VERSION, kind.api_kind(), "").await?;
    let ops: json_patch::Patch = serde_json::from_value(failure_policy_patch(index, webhook, to))
        .map_err(|e| e.to_string())?;
    api.patch(
        config,
        &kube::api::PatchParams::default(),
        &kube::api::Patch::Json::<()>(ops),
    )
    .await
    .map_err(crate::edit::api_error_text)?;
    Ok(())
}

// --- Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{reads_as, EN};
    use serde_json::json;

    fn st() -> &'static Strings {
        crate::lang::t(crate::ai::AiLanguage::En)
    }

    fn vwc(value: serde_json::Value) -> ValidatingWebhookConfiguration {
        serde_json::from_value(value).expect("valid ValidatingWebhookConfiguration")
    }

    fn mwc(value: serde_json::Value) -> MutatingWebhookConfiguration {
        serde_json::from_value(value).expect("valid MutatingWebhookConfiguration")
    }

    fn crd(value: serde_json::Value) -> CustomResourceDefinition {
        serde_json::from_value(value).expect("valid CustomResourceDefinition")
    }

    fn apisvc(value: serde_json::Value) -> APIService {
        serde_json::from_value(value).expect("valid APIService")
    }

    // A webhook entry with everything the API server requires and nothing else, so each test only
    // has to spell out the field it is about.
    fn webhook(name: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "name": name,
            "sideEffects": "None",
            "admissionReviewVersions": ["v1"],
            "clientConfig": { "service": { "namespace": "ops", "name": "hook-svc", "port": 443 } },
            "rules": [{
                "apiGroups": ["apps"],
                "apiVersions": ["v1"],
                "resources": ["deployments"],
                "operations": ["CREATE", "UPDATE"],
            }],
        });
        let (serde_json::Value::Object(b), serde_json::Value::Object(e)) = (&mut base, extra) else {
            return base;
        };
        for (k, v) in e {
            b.insert(k, v);
        }
        base
    }

    fn config(name: &str, webhooks: serde_json::Value) -> serde_json::Value {
        json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": { "name": name },
            "webhooks": webhooks,
        })
    }

    fn hints_of(h: &AdmissionHook) -> Vec<Hint> {
        admission_hints(h, st())
    }

    fn said(hints: &[Hint], tpl: &str) -> bool {
        hints.iter().any(|h| reads_as(&h.text, tpl))
    }

    // À sévérité égale, la colonne porte le **premier** constat émis, parce que l'ordre d'émission
    // est un ordre d'importance : un service injoignable passe avant un caBundle absent, et c'est
    // la joignabilité qui dit quoi faire.
    #[test]
    fn two_findings_of_the_same_level_are_settled_by_the_order_they_were_written_in() {
        let c = vwc(config(
            "cfg",
            json!([webhook("w", json!({ "failurePolicy": "Ignore" }))]),
        ));
        let (_, mut hooks) = validating_rows(&c);
        hooks[0].reach = Reach::ServiceGone;
        let hints = admission_hints(&hooks[0], st());
        // Les deux sont des Warn : l'injoignabilité et le caBundle absent.
        assert!(said(&hints, EN.hk_dead_fail_open));
        assert!(said(&hints, EN.hk_ca_absent));
        assert!(reads_as(&worst_hint(&hints).unwrap().text, EN.hk_dead_fail_open));
    }

    #[test]
    fn a_configuration_yields_one_row_per_named_webhook() {
        let c = vwc(config(
            "kyverno-resource-validating-webhook-cfg",
            json!([
                webhook("validate.kyverno.svc-fail", json!({ "failurePolicy": "Fail" })),
                webhook("validate.kyverno.svc-ignore", json!({ "failurePolicy": "Ignore" })),
            ]),
        ));
        let (config, hooks) = validating_rows(&c);

        assert_eq!(config.hooks, 2);
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].name, "validate.kyverno.svc-fail");
        assert_eq!(hooks[1].name, "validate.kyverno.svc-ignore");
        // The two opposite policies of one object are what makes the entry the right grain.
        assert!(hooks[0].fail_closed);
        assert!(!hooks[1].fail_closed);
        // The index is what a patch addresses, so it follows declaration order.
        assert_eq!((hooks[0].index, hooks[1].index), (0, 1));
    }

    // Ce que `Ctrl-D` emporterait, et que le panneau annonce : le compte de la configuration, pas
    // l'index de l'entrée — les deux valent zéro sur un objet à un seul webhook, ce qui rend
    // l'erreur invisible partout ailleurs.
    #[test]
    fn every_webhook_of_a_configuration_knows_how_many_the_deletion_would_take() {
        let c = vwc(config(
            "cfg",
            json!([webhook("a", json!({})), webhook("b", json!({})), webhook("c", json!({}))]),
        ));
        let (config, hooks) = validating_rows(&c);
        assert_eq!(config.hooks, 3);
        assert!(hooks.iter().all(|h| h.siblings == 3));
        // Et l'index reste l'index : c'est ce qu'un patch adresse.
        assert_eq!(hooks.iter().map(|h| h.index).collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn an_absent_failure_policy_means_fail_closed_and_says_it_was_defaulted() {
        let c = vwc(config("cfg", json!([webhook("w", json!({}))])));
        let (_, hooks) = validating_rows(&c);
        assert!(hooks[0].fail_closed);
        assert!(hooks[0].failure_policy_defaulted);

        let c = vwc(config("cfg", json!([webhook("w", json!({ "failurePolicy": "Fail" }))])));
        let (_, hooks) = validating_rows(&c);
        assert!(hooks[0].fail_closed);
        assert!(!hooks[0].failure_policy_defaulted);
    }

    #[test]
    fn a_url_backend_is_never_judged_reachable_or_not() {
        let c = vwc(config(
            "cfg",
            json!([webhook(
                "w",
                json!({ "clientConfig": { "url": "https://hooks.example.test/validate" } })
            )]),
        ));
        let (_, mut hooks) = validating_rows(&c);
        assert!(matches!(hooks[0].backend, Backend::Url { .. }));
        assert_eq!(hooks[0].backend.service(), None);

        // What the probe would set for a URL backend, and what it must not turn into.
        hooks[0].reach = Reach::NotOurs;
        let hints = hints_of(&hooks[0]);
        assert!(said(&hints, EN.hk_url_backend));
        assert!(!said(&hints, EN.hk_dead_fail_closed));
        assert!(hints.iter().all(|h| h.level == HintLevel::Info || h.level == HintLevel::Warn));
    }

    #[test]
    fn a_service_that_cannot_be_queried_is_reported_unchecked_not_broken() {
        let c = vwc(config("cfg", json!([webhook("w", json!({ "failurePolicy": "Fail" }))])));
        let (_, mut hooks) = validating_rows(&c);
        hooks[0].reach = Reach::Unchecked;
        let hints = hints_of(&hooks[0]);

        assert!(said(&hints, EN.hk_unchecked));
        assert!(!said(&hints, EN.hk_dead_fail_closed));
        // The anti-invention rule made visible: it never colours the row.
        let level = hints.iter().filter(|h| reads_as(&h.text, EN.hk_unchecked)).map(|h| h.level).max();
        assert_eq!(level, Some(HintLevel::Info));
    }

    #[test]
    fn unchecked_is_not_a_fault_so_repair_keeps_ignoring_it() {
        assert_eq!(Reach::Unchecked.fault(), None);
        assert_eq!(Reach::Ready.fault(), None);
        assert_eq!(Reach::NotOurs.fault(), None);
        assert_eq!(Reach::NoEndpoints.fault(), Some(WebhookFault::NoEndpoints));
        assert_eq!(Reach::ServiceGone.fault(), Some(WebhookFault::ServiceGone));
        assert_eq!(Reach::NamespaceGone.fault(), Some(WebhookFault::NamespaceGone));
        assert!(!Reach::Unchecked.is_broken());
    }

    #[test]
    fn a_fail_closed_hook_on_a_dead_service_is_danger_and_a_fail_open_one_is_warn() {
        let c = vwc(config(
            "cfg",
            json!([
                webhook("closed", json!({ "failurePolicy": "Fail" })),
                webhook("open", json!({ "failurePolicy": "Ignore" })),
            ]),
        ));
        let (_, mut hooks) = validating_rows(&c);
        for h in hooks.iter_mut() {
            h.reach = Reach::NoEndpoints;
        }

        let closed = hints_of(&hooks[0]);
        assert!(said(&closed, EN.hk_dead_fail_closed));
        assert_eq!(
            closed.iter().filter(|h| reads_as(&h.text, EN.hk_dead_fail_closed)).map(|h| h.level).max(),
            Some(HintLevel::Danger)
        );

        let open = hints_of(&hooks[1]);
        assert!(said(&open, EN.hk_dead_fail_open));
        assert!(!said(&open, EN.hk_dead_fail_closed));
        assert_eq!(
            open.iter().filter(|h| reads_as(&h.text, EN.hk_dead_fail_open)).map(|h| h.level).max(),
            Some(HintLevel::Warn)
        );
    }

    #[test]
    fn a_star_star_star_rule_is_the_catch_all_and_a_named_group_is_not() {
        let catch_all = RuleScope {
            api_groups: vec!["*".into()],
            api_versions: vec!["*".into()],
            resources: vec!["*".into()],
            operations: vec!["*".into()],
            scope: "*".into(),
        };
        assert!(catch_all.is_catch_all());
        assert!(catch_all.covers_writes());

        let named = RuleScope {
            api_groups: vec!["apps".into()],
            api_versions: vec!["*".into()],
            resources: vec!["*".into()],
            operations: vec!["CREATE".into()],
            scope: "*".into(),
        };
        assert!(!named.is_catch_all());
        assert!(!named.covers_writes());
    }

    #[test]
    fn a_namespace_selector_that_excludes_kube_system_clears_the_system_hint() {
        let bare = vwc(config(
            "cfg",
            json!([webhook("w", json!({ "rules": [{
                "apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
                "operations": ["*"],
            }] }))]),
        ));
        let (_, mut hooks) = validating_rows(&bare);
        hooks[0].reach = Reach::Ready;
        assert!(said(&hints_of(&hooks[0]), EN.hk_catch_all_fail_closed));

        let guarded = vwc(config(
            "cfg",
            json!([webhook("w", json!({
                "rules": [{
                    "apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
                    "operations": ["*"],
                }],
                "namespaceSelector": { "matchExpressions": [{
                    "key": "kubernetes.io/metadata.name",
                    "operator": "NotIn",
                    "values": ["kube-system"],
                }] },
            }))]),
        ));
        let (_, mut hooks) = validating_rows(&guarded);
        hooks[0].reach = Reach::Ready;
        let hints = hints_of(&hooks[0]);
        assert!(hooks[0].namespace_selector.excludes_system);
        assert!(!said(&hints, EN.hk_catch_all_fail_closed));
        // Still worth saying that it stands in front of everything, just not that it takes
        // kube-system down with it.
        assert!(said(&hints, EN.hk_catch_all));
    }

    #[test]
    fn a_self_locking_hook_is_the_one_that_governs_its_own_namespace() {
        let own = vwc(config(
            "cfg",
            json!([webhook("w", json!({
                "clientConfig": { "service": { "namespace": "ops", "name": "hook-svc" } },
                "rules": [{
                    "apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
                    "operations": ["*"],
                }],
            }))]),
        ));
        let (_, mut hooks) = validating_rows(&own);
        hooks[0].reach = Reach::Ready;
        assert!(self_locking(&hooks[0]));
        assert!(said(&hints_of(&hooks[0]), EN.hk_self_locking));

        // With a namespaceSelector nothing is asserted: saying whether it excludes the backend's
        // own namespace would mean evaluating labels this module has not read.
        let selected = vwc(config(
            "cfg",
            json!([webhook("w", json!({
                "rules": [{
                    "apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
                    "operations": ["*"],
                }],
                "namespaceSelector": { "matchLabels": { "hooks": "on" } },
            }))]),
        ));
        let (_, hooks) = validating_rows(&selected);
        assert!(!self_locking(&hooks[0]));
    }

    #[test]
    fn a_mutating_webhook_carries_a_reinvocation_policy_and_a_validating_one_does_not() {
        let m = mwc(json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": { "name": "inject" },
            "webhooks": [webhook("w", json!({}))],
        }));
        let (cfg, hooks) = mutating_rows(&m);
        assert_eq!(cfg.kind, WebhookKind::Mutating);
        assert_eq!(cfg.kind.api_kind(), "MutatingWebhookConfiguration");
        // Absent in the manifest, but the API server's default is what runs.
        assert_eq!(hooks[0].reinvocation_policy.as_deref(), Some("Never"));

        let v = vwc(config("cfg", json!([webhook("w", json!({}))])));
        let (_, hooks) = validating_rows(&v);
        assert_eq!(hooks[0].reinvocation_policy, None);
    }

    #[test]
    fn side_effects_and_a_long_timeout_are_each_worth_a_warning() {
        let c = vwc(config(
            "cfg",
            json!([webhook("w", json!({ "sideEffects": "Unknown", "timeoutSeconds": 30 }))]),
        ));
        let (_, mut hooks) = validating_rows(&c);
        hooks[0].reach = Reach::Ready;
        let hints = hints_of(&hooks[0]);
        assert!(said(&hints, EN.hk_side_effects));
        assert!(said(&hints, EN.hk_timeout_long));
    }

    // --- caBundle ---------------------------------------------------------------------------

    fn cert(days: i64) -> CaCert {
        CaCert {
            subject_cn: "ca".into(),
            issuer_cn: "ca".into(),
            not_before: "2020-01-01".into(),
            not_after: "2030-01-01".into(),
            days_remaining: days,
            is_ca: true,
            self_signed: true,
        }
    }

    #[test]
    fn a_ca_bundle_chain_is_read_whole_and_the_soonest_expiry_decides() {
        let pem = include_str!("testdata/hooks_ca_chain.pem");
        let certs = parse_ca_chain(pem.as_bytes());
        // Two concatenated certificates: `parse_x509_pem` would have stopped at the first.
        assert_eq!(certs.len(), 2);
        assert!(certs.iter().all(|c| c.self_signed));

        let bundle = CaBundle::Parsed { bytes: pem.len(), certs: vec![cert(400), cert(12)] };
        assert_eq!(bundle.soonest().map(|c| c.days_remaining), Some(12));
    }

    #[test]
    fn an_expired_ca_bundle_outranks_an_expiring_one() {
        let mut out = Vec::new();
        ca_hints(&CaBundle::Parsed { bytes: 1, certs: vec![cert(-3)] }, st(), &mut out);
        assert!(said(&out, EN.hk_ca_expired));
        assert_eq!(out.iter().map(|h| h.level).max(), Some(HintLevel::Danger));

        let mut out = Vec::new();
        ca_hints(&CaBundle::Parsed { bytes: 1, certs: vec![cert(12)] }, st(), &mut out);
        assert!(said(&out, EN.hk_ca_expiring));
        assert_eq!(out.iter().map(|h| h.level).max(), Some(HintLevel::Warn));

        // Comfortably valid: nothing to say at all.
        let mut out = Vec::new();
        ca_hints(&CaBundle::Parsed { bytes: 1, certs: vec![cert(400)] }, st(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn an_undecodable_ca_bundle_says_opaque_rather_than_expired() {
        let meta = Default::default();
        let bundle = read_ca_bundle(Some(&k8s_openapi::ByteString(b"not a pem".to_vec())), &meta);
        assert!(matches!(bundle, CaBundle::Opaque { .. }));

        let mut out = Vec::new();
        ca_hints(&bundle, st(), &mut out);
        assert!(said(&out, EN.hk_ca_opaque));
        assert!(!said(&out, EN.hk_ca_expired));
    }

    #[test]
    fn an_absent_ca_bundle_with_an_injection_annotation_is_only_informational() {
        let c = vwc(json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {
                "name": "cfg",
                "annotations": { "cert-manager.io/inject-ca-from": "ops/hook-cert" },
            },
            "webhooks": [webhook("w", json!({}))],
        }));
        let (_, hooks) = validating_rows(&c);
        assert_eq!(hooks[0].ca, CaBundle::Absent { injector: Some("cert-manager".into()) });

        let mut out = Vec::new();
        ca_hints(&hooks[0].ca, st(), &mut out);
        assert!(said(&out, EN.hk_ca_injected));
        assert_eq!(out.iter().map(|h| h.level).max(), Some(HintLevel::Info));

        // Without the annotation nothing is going to fill it in, and that is a warning.
        let bare = vwc(config("cfg", json!([webhook("w", json!({}))])));
        let (_, hooks) = validating_rows(&bare);
        let mut out = Vec::new();
        ca_hints(&hooks[0].ca, st(), &mut out);
        assert!(said(&out, EN.hk_ca_absent));
        assert_eq!(out.iter().map(|h| h.level).max(), Some(HintLevel::Warn));
    }

    // --- conversion -------------------------------------------------------------------------

    fn conversion_crd(strategy: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut conversion = json!({ "strategy": strategy });
        if strategy == "Webhook" {
            conversion["webhook"] = json!({
                "conversionReviewVersions": ["v1"],
                "clientConfig": { "service": { "namespace": "cert-manager", "name": "webhook" } },
            });
        }
        let mut crd = json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.test" },
            "spec": {
                "group": "example.test",
                "scope": "Namespaced",
                "names": { "kind": "Widget", "plural": "widgets" },
                "conversion": conversion,
                "versions": [
                    { "name": "v1beta1", "served": true, "storage": false, "deprecated": true },
                    { "name": "v1", "served": true, "storage": true },
                ],
            },
        });
        if let (serde_json::Value::Object(spec), serde_json::Value::Object(e)) =
            (&mut crd["spec"], extra)
        {
            for (k, v) in e {
                spec.insert(k, v);
            }
        }
        crd
    }

    #[test]
    fn a_crd_with_strategy_none_is_not_a_conversion_hook() {
        assert!(conversion_from_crd(&crd(conversion_crd("None", json!({})))).is_none());
        assert!(conversion_from_crd(&crd(conversion_crd("Webhook", json!({})))).is_some());
    }

    #[test]
    fn the_storage_version_is_named_and_the_served_ones_keep_their_order() {
        let c = conversion_from_crd(&crd(conversion_crd("Webhook", json!({})))).unwrap();
        assert_eq!(c.storage_version, "v1");
        assert!(c.storage_version_served);
        assert_eq!(c.served_label(), "v1beta1,v1");
        assert_eq!(c.backend.short(), "cert-manager/webhook");

        let hints = conversion_hints(&c, st());
        assert!(said(&hints, EN.hk_conv_deprecated));
        assert!(!said(&hints, EN.hk_conv_storage_unserved));
    }

    #[test]
    fn a_storage_version_that_is_not_served_is_a_warning() {
        let c = conversion_from_crd(&crd(conversion_crd(
            "Webhook",
            json!({ "versions": [{ "name": "v1", "served": false, "storage": true }] }),
        )))
        .unwrap();
        assert!(!c.storage_version_served);
        assert!(said(&conversion_hints(&c, st()), EN.hk_conv_storage_unserved));
    }

    #[test]
    fn a_dead_conversion_webhook_says_that_reads_break_too() {
        let mut c = conversion_from_crd(&crd(conversion_crd("Webhook", json!({})))).unwrap();
        c.reach = Reach::ServiceGone;
        let hints = conversion_hints(&c, st());
        assert!(said(&hints, EN.hk_conv_dead));
        assert_eq!(hints.iter().map(|h| h.level).max(), Some(HintLevel::Danger));
    }

    // --- apiservice -------------------------------------------------------------------------

    #[test]
    fn a_local_apiservice_is_left_out_of_the_aggregated_list_but_counted() {
        let local = apisvc(json!({
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind": "APIService",
            "metadata": { "name": "v1." },
            "spec": { "groupPriorityMinimum": 18000, "versionPriority": 1 },
        }));
        assert!(apiservice_from(&local).is_none());

        let aggregated = apisvc(json!({
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind": "APIService",
            "metadata": { "name": "v1beta1.metrics.k8s.io" },
            "spec": {
                "group": "metrics.k8s.io", "version": "v1beta1",
                "groupPriorityMinimum": 100, "versionPriority": 100,
                "service": { "namespace": "kube-system", "name": "metrics-server", "port": 443 },
            },
        }));
        assert!(apiservice_from(&aggregated).is_some());
    }

    #[test]
    fn an_apiservice_available_false_carries_the_apiservers_own_reason_verbatim() {
        let a = apiservice_from(&apisvc(json!({
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind": "APIService",
            "metadata": { "name": "v1beta1.metrics.k8s.io" },
            "spec": {
                "group": "metrics.k8s.io", "version": "v1beta1",
                "groupPriorityMinimum": 100, "versionPriority": 100,
                "insecureSkipTLSVerify": true,
                "service": { "namespace": "kube-system", "name": "metrics-server", "port": 443 },
            },
            "status": { "conditions": [{
                "type": "Available", "status": "False",
                "reason": "FailedDiscoveryCheck",
                "message": "failing or missing response from https://10.0.0.1:443/apis",
            }] },
        })))
        .unwrap();

        assert_eq!(a.available.as_deref(), Some("False"));
        assert_eq!(a.reason, "FailedDiscoveryCheck");
        let hints = apiservice_hints(&a, st());
        assert!(said(&hints, EN.hk_apisvc_unavailable));
        // The reason is reproduced, not reworded: it is the only lead there is.
        assert!(hints.iter().any(|h| h.text.contains("FailedDiscoveryCheck")));
        assert!(said(&hints, EN.hk_apisvc_insecure));
    }

    // --- configuration rows, records, patch ---------------------------------------------------

    #[test]
    fn the_worst_hint_of_a_configuration_is_the_one_its_parent_row_carries() {
        let c = vwc(config(
            "cfg",
            json!([
                webhook("healthy", json!({ "failurePolicy": "Ignore" })),
                webhook("broken", json!({ "failurePolicy": "Fail" })),
            ]),
        ));
        let (mut config, mut hooks) = validating_rows(&c);
        hooks[0].reach = Reach::Ready;
        hooks[1].reach = Reach::NoEndpoints;
        for h in hooks.iter_mut() {
            h.hints = admission_hints(h, st());
        }
        config.hints = config_hints(&config, &hooks, st());
        assert_eq!(config.hints.iter().map(|h| h.level).max(), Some(HintLevel::Danger));
    }

    #[test]
    fn a_configuration_with_no_webhook_left_is_a_tombstone() {
        let c = vwc(config("cfg", json!([])));
        let (config, hooks) = validating_rows(&c);
        assert!(hooks.is_empty());
        assert_eq!(config.hooks, 0);
        assert!(said(&config_hints(&config, &hooks, st()), EN.hk_empty_config));

        // `webhooks: null` and `webhooks: []` are the same case.
        let null = vwc(json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": { "name": "cfg" },
        }));
        let (config, _) = validating_rows(&null);
        assert_eq!(config.hooks, 0);
    }

    #[test]
    fn an_admission_record_designates_the_configuration_though_the_row_shows_a_webhook() {
        let c = vwc(config("kyverno-cfg", json!([webhook("validate.kyverno.svc-fail", json!({}))])));
        let (_, hooks) = validating_rows(&c);
        let record = admission_record(&hooks[0]);

        // The row reads as the webhook; `y`, `e` and `Ctrl-D` act on the object that holds it.
        assert_eq!(hooks[0].name, "validate.kyverno.svc-fail");
        assert_eq!(record.kind, "ValidatingWebhookConfiguration");
        assert_eq!(record.name, "kyverno-cfg");
        assert_eq!(record.namespace, "");
        assert_eq!(record.api_version, ADMISSION_API_VERSION);
    }

    #[test]
    fn the_failure_policy_patch_tests_the_webhook_name_before_it_writes() {
        let patch = failure_policy_patch(3, "validate.kyverno.svc-fail", "Ignore");
        let ops = patch.as_array().expect("a JSON patch is an array");
        assert_eq!(ops.len(), 2);
        // Between the read and the write an operator can have reordered `webhooks[]`; a bare index
        // would then flip the wrong hook.
        assert_eq!(ops[0]["op"], "test");
        assert_eq!(ops[0]["path"], "/webhooks/3/name");
        assert_eq!(ops[0]["value"], "validate.kyverno.svc-fail");
    }

    #[test]
    fn the_failure_policy_patch_adds_rather_than_replaces_so_a_defaulted_field_takes_it() {
        let patch = failure_policy_patch(0, "w", "Ignore");
        let ops = patch.as_array().unwrap();
        // `replace` on a member that is not there comes back 422, and a webhook that relies on the
        // `Fail` default does not spell the field out.
        assert_eq!(ops[1]["op"], "add");
        assert_eq!(ops[1]["path"], "/webhooks/0/failurePolicy");
        assert_eq!(ops[1]["value"], "Ignore");
        assert!(serde_json::from_value::<json_patch::Patch>(patch).is_ok());

        assert_eq!(failure_policy_toggle(true), "Ignore");
        assert_eq!(failure_policy_toggle(false), "Fail");
    }

    #[test]
    fn the_counts_of_a_world_are_the_ones_its_title_shows() {
        let c = vwc(config(
            "cfg",
            json!([
                webhook("a", json!({ "failurePolicy": "Fail", "rules": [{
                    "apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
                    "operations": ["*"],
                }] })),
                webhook("b", json!({ "failurePolicy": "Ignore" })),
            ]),
        ));
        let (config, mut hooks) = validating_rows(&c);
        hooks[0].reach = Reach::NoEndpoints;
        hooks[1].reach = Reach::Ready;

        let state = HooksState { configs: vec![config], admission: hooks, ..Default::default() };
        let counts = state.counts(HookWorld::Admission);
        assert_eq!(counts.rows, 2);
        assert_eq!(counts.fail_closed, 1);
        assert_eq!(counts.broken, 1);
        assert_eq!(counts.catch_all, 1);
    }

    #[test]
    fn cycling_the_worlds_three_times_returns_to_admission() {
        let mut world = HookWorld::Admission;
        for _ in 0..3 {
            world = world.next();
        }
        assert_eq!(world, HookWorld::Admission);
    }
}
