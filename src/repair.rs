//! Naming — and undoing — the blockages that leave a GitOps engine stuck.
//!
//! A failing Kustomization or HelmRelease usually says *what* went wrong in its Ready condition, but
//! not *what to do about it*, and the counter-move is rarely another reconcile. The classic case: an
//! operator is uninstalled, its admission webhooks survive pointing at a service that no longer
//! exists, and from then on every apply the controller attempts is rejected by the API server. Flux
//! reports a webhook error forever; the fix is three namespaces away.
//!
//! The work splits in two on purpose. [`classify`] is pure: it reads the controller's own message
//! and produces [`Suspicion`]s — leads, not conclusions. [`probe`] then confirms each lead against
//! the live cluster, because a message naming a webhook proves nothing about whether that webhook is
//! actually broken. Only confirmed findings become [`Blocker`]s, and only a [`Blocker`] carries
//! [`Remedy`]s. As everywhere else in this codebase the findings are data, not sentences: the UI
//! localises them and decides how hard to make the confirmation.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::Client;
use serde_json::Value;

use crate::delete::Level;
use crate::yaml::dynamic_api;

// Label EndpointSlices carry to name the Service they back.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";
// Helm 3 stores the release state in the secret's labels, so the state of a release can be read
// without decompressing the release blob itself.
const HELM_OWNER_LABEL: &str = "owner=helm";

// Which of the two admission configurations a webhook lives in. They are separate cluster-scoped
// kinds with identical structure, and a repair has to name the right one to delete it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
}

// Why a webhook cannot be reached. The three cases are worth distinguishing because they say
// different things about whether the operator is coming back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WebhookFault {
    // The namespace the backing service lives in is gone: the operator was uninstalled.
    NamespaceGone,
    // The namespace is there but the Service is not.
    ServiceGone,
    // The Service exists and resolves, but nothing is behind it — the operator is scaled to zero or
    // crash-looping. This one may well fix itself, which is why it is not treated as an orphan.
    NoEndpoints,
}

// A lead extracted from the controller's message. Never shown as-is: a suspicion that the probe
// cannot confirm is dropped rather than reported, because a wrong diagnosis costs more than none.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Suspicion {
    // The API server could not reach an admission webhook. Carries the webhook name from the
    // message (e.g. `validate.kyverno.svc-fail`), which names a single webhook inside a
    // configuration object, not the configuration itself.
    WebhookUnreachable { webhook: String },
    // A webhook was reached and said no. Not a blockage to repair — a policy doing its job.
    AdmissionDenied { webhook: String },
    // Helm refuses to act because a previous operation never finished.
    HelmOperationInProgress,
    // The controller has given up retrying.
    RetriesExhausted,
    // Waiting on another Flux object.
    DependencyNotReady { reference: String },
    // The cluster has no such kind: a CRD has not been applied yet, or was removed.
    MissingKind { kind: String },
    // An apply tried to change a field the API server will not let it change.
    ImmutableField,
    // Objects cannot be created because their namespace is being deleted.
    NamespaceTerminating { namespace: String },
}

// A confirmed blockage, with the moves that address it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Blocker {
    // An admission configuration whose backing service is gone. Every apply matching its rules is
    // rejected while `failurePolicy` is Fail; with Ignore it is dead weight that still costs a
    // timeout on every matching request.
    OrphanWebhook {
        kind: WebhookKind,
        name: String,
        service: String,
        fail_closed: bool,
        fault: WebhookFault,
    },
    // A configuration with no webhook entries left: harmless, but it is the tombstone of an
    // uninstalled operator and it is what makes the operator's re-install behave oddly.
    EmptyWebhookConfig { kind: WebhookKind, name: String },
    // Deletion started and never finished, because a finalizer is waiting on a controller that is
    // not there any more.
    StuckTerminating {
        api_version: String,
        kind: String,
        namespace: String,
        name: String,
        finalizers: Vec<String>,
        // A Namespace holds a second lock in `spec.finalizers`, cleared only through the `finalize`
        // subresource. Reported so the panel does not promise a fix that leaves the object stuck.
        spec_finalizers: Vec<String>,
    },
    // A Helm release left mid-flight: helm-controller refuses every subsequent operation until the
    // pending state is cleared.
    HelmPending { namespace: String, name: String, state: String, version: String },
    // The controller has stopped retrying an install or upgrade.
    RetriesExhausted { namespace: String, name: String },
    // Blocked on another Flux object rather than on anything of its own.
    WaitingOnDependency { reference: String },
    // Reported for the record: nothing here can be repaired from a TUI.
    MissingKind { kind: String },
    ImmutableField,
    AdmissionDenied { webhook: String },
}

impl Blocker {
    pub fn level(&self) -> Level {
        match self {
            // A fail-closed orphan is actively breaking every matching apply.
            Blocker::OrphanWebhook { fail_closed: true, .. } => Level::Danger,
            Blocker::StuckTerminating { .. } | Blocker::HelmPending { .. } => Level::Danger,
            Blocker::OrphanWebhook { .. }
            | Blocker::RetriesExhausted { .. }
            | Blocker::ImmutableField
            | Blocker::MissingKind { .. } => Level::Warn,
            Blocker::EmptyWebhookConfig { .. }
            | Blocker::WaitingOnDependency { .. }
            | Blocker::AdmissionDenied { .. } => Level::Info,
        }
    }

    // The moves offered for this blockage, most conservative first — the panel presents them in
    // this order, so what the user reaches first should be what they can undo.
    pub fn remedies(&self) -> Vec<Remedy> {
        match self {
            Blocker::OrphanWebhook { kind, name, .. }
            | Blocker::EmptyWebhookConfig { kind, name } => {
                vec![Remedy::DeleteWebhookConfig { kind: *kind, name: name.clone() }]
            }
            Blocker::StuckTerminating { api_version, kind, namespace, name, finalizers, .. } => {
                vec![Remedy::RemoveFinalizers {
                    api_version: api_version.clone(),
                    kind: kind.clone(),
                    namespace: namespace.clone(),
                    name: name.clone(),
                    finalizers: finalizers.clone(),
                }]
            }
            // A pending release is cleared by asking helm-controller to redo the upgrade rather than
            // by touching Helm's own storage: deleting a release secret by hand loses the history
            // and leaves Helm's notion of the current revision inconsistent with the cluster.
            Blocker::HelmPending { .. } => vec![Remedy::ResetFailures, Remedy::ForceUpgrade],
            Blocker::RetriesExhausted { .. } => vec![Remedy::ResetFailures, Remedy::SuspendResume],
            Blocker::WaitingOnDependency { .. }
            | Blocker::MissingKind { .. }
            | Blocker::ImmutableField
            | Blocker::AdmissionDenied { .. } => Vec::new(),
        }
    }
}

// A counter-move. Everything here is executed against the API server by [`apply`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Remedy {
    // Cluster-scoped deletion: it removes admission control for everything the configuration
    // matched, not only for the object being unblocked.
    DeleteWebhookConfig { kind: WebhookKind, name: String },
    // Clears `metadata.finalizers` wholesale. Irreversible, and whatever cleanup the finalizer was
    // there to perform simply does not happen.
    RemoveFinalizers {
        api_version: String,
        kind: String,
        namespace: String,
        name: String,
        finalizers: Vec<String>,
    },
    // `reconcile.fluxcd.io/resetAt` — forgets the failure counters. Changes no desired state.
    ResetFailures,
    // `reconcile.fluxcd.io/forceAt` — replays the Helm upgrade even with an unchanged chart.
    ForceUpgrade,
    // Suspend then resume: the older way of making a controller rebuild its state machine.
    SuspendResume,
}

impl Remedy {
    // How much confirmation this move deserves. `Danger` routes the panel to the type-the-name
    // confirmation; the rest take the armed two-key path.
    pub fn level(&self) -> Level {
        match self {
            Remedy::DeleteWebhookConfig { .. } | Remedy::RemoveFinalizers { .. } => Level::Danger,
            Remedy::ForceUpgrade => Level::Warn,
            Remedy::ResetFailures | Remedy::SuspendResume => Level::Info,
        }
    }

    // The object name the user has to type through for a `Danger` remedy.
    pub fn confirm_target(&self) -> String {
        match self {
            Remedy::DeleteWebhookConfig { name, .. } => name.clone(),
            Remedy::RemoveFinalizers { name, .. } => name.clone(),
            _ => String::new(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct RepairState {
    // Identity of the object the findings belong to; a result whose key no longer matches the open
    // panel is dropped instead of overwriting it.
    pub key: String,
    pub loading: bool,
    // The probe could not run (RBAC, object gone). Reported rather than swallowed: an empty finding
    // list and a failed scan look the same on screen otherwise.
    pub error: Option<String>,
    pub blockers: Vec<Blocker>,
    // True when the findings come from the cluster-wide sweep rather than from the controller's own
    // message — meaning nothing here is proven to block the diagnosed resource. Worth stating: a
    // panel called "unblock" that lists leftovers reads as "these are stopping you", and a
    // fail-open webhook or an empty configuration is untidiness, not a blockage.
    pub swept: bool,
    pub applying: bool,
    pub done: Option<Result<String, String>>,
}

pub type SharedRepair = Arc<Mutex<RepairState>>;

pub fn new_repair_state() -> SharedRepair {
    Arc::new(Mutex::new(RepairState::default()))
}

// What the panel is diagnosing: the failing Flux object itself.
#[derive(Clone, Debug)]
pub struct Target {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Pure classification
// ---------------------------------------------------------------------------

// Reads the controller's Ready-condition message and returns the leads worth checking. Matching is
// on substrings rather than a grammar: these messages are assembled by several controllers and by
// the API server itself, and they get reworded between versions, so anchoring on the stable noun
// phrases survives upgrades better than parsing the sentence around them.
pub fn classify(message: &str) -> Vec<Suspicion> {
    let m = message.to_lowercase();
    let mut out = Vec::new();

    // Order matters: "admission webhook X denied the request" also contains "webhook", but a denial
    // means the webhook answered — the opposite of it being unreachable.
    if m.contains("denied the request") {
        if let Some(w) = quoted_after(message, "admission webhook") {
            out.push(Suspicion::AdmissionDenied { webhook: w });
        }
    } else if m.contains("failed calling webhook") || m.contains("failed to call webhook") {
        out.push(Suspicion::WebhookUnreachable {
            webhook: quoted_after(message, "webhook").unwrap_or_default(),
        });
    }

    if m.contains("another operation") && m.contains("in progress") {
        out.push(Suspicion::HelmOperationInProgress);
    }
    if m.contains("retries exhausted") {
        out.push(Suspicion::RetriesExhausted);
    }
    if m.contains("dependency") && m.contains("not ready") {
        out.push(Suspicion::DependencyNotReady {
            reference: quoted_single(message).unwrap_or_default(),
        });
    }
    if m.contains("no matches for kind") {
        out.push(Suspicion::MissingKind {
            kind: quoted_after(message, "no matches for kind").unwrap_or_default(),
        });
    }
    if m.contains("field is immutable") || m.contains("immutable field") {
        out.push(Suspicion::ImmutableField);
    }
    if m.contains("being terminated") {
        out.push(Suspicion::NamespaceTerminating {
            namespace: after_word(message, "namespace").unwrap_or_default(),
        });
    }
    out
}

// The first double-quoted run appearing after `marker`. Kubernetes quotes the names it complains
// about, which is the only reliable structure these messages have.
fn quoted_after(text: &str, marker: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let at = lower.find(&marker.to_lowercase())? + marker.len();
    let rest = text.get(at..)?;
    let start = rest.find('"')? + 1;
    let tail = rest.get(start..)?;
    let end = tail.find('"')?;
    let found = tail.get(..end)?.trim();
    (!found.is_empty()).then(|| found.to_string())
}

// The first single-quoted run: Flux quotes dependency references with single quotes.
fn quoted_single(text: &str) -> Option<String> {
    let start = text.find('\'')? + 1;
    let tail = text.get(start..)?;
    let end = tail.find('\'')?;
    let found = tail.get(..end)?.trim();
    (!found.is_empty()).then(|| found.to_string())
}

// The word following `marker`, stripped of the punctuation these messages trail it with.
fn after_word(text: &str, marker: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let at = lower.find(&marker.to_lowercase())? + marker.len();
    let word = text.get(at..)?.split_whitespace().next()?;
    let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

// ---------------------------------------------------------------------------
// Live probing
// ---------------------------------------------------------------------------

// Confirms the leads against the cluster and publishes the findings.
pub async fn probe(client: Client, target: Target, key: String, state: SharedRepair) {
    let result = run_probe(&client, &target).await;
    let mut s = state.lock().expect("repair state poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok((blockers, swept)) => {
            s.blockers = blockers;
            s.swept = swept;
            s.error = None;
        }
        Err(e) => {
            s.blockers.clear();
            s.swept = false;
            s.error = Some(e);
        }
    }
}

// Returns the findings and whether they came from the sweep (nothing implicated this resource).
async fn run_probe(client: &Client, target: &Target) -> Result<(Vec<Blocker>, bool), String> {
    let suspicions = classify(&target.message);
    let mut out: Vec<Blocker> = Vec::new();

    // The object's own deletion state is always worth checking: a HelmRelease that never finishes
    // terminating reports nothing useful in its Ready condition, so no suspicion would point here.
    if let Some(b) = terminating_blocker(client, target).await {
        out.push(b);
    }

    let mut scanned_webhooks = false;
    for s in &suspicions {
        match s {
            Suspicion::WebhookUnreachable { .. } => {
                if !scanned_webhooks {
                    out.extend(webhook_blockers(client).await?);
                    scanned_webhooks = true;
                }
            }
            Suspicion::HelmOperationInProgress => {
                if let Some(b) = helm_pending_blocker(client, target).await {
                    out.push(b);
                }
            }
            Suspicion::RetriesExhausted => out.push(Blocker::RetriesExhausted {
                namespace: target.namespace.clone(),
                name: target.name.clone(),
            }),
            Suspicion::DependencyNotReady { reference } => {
                out.push(Blocker::WaitingOnDependency { reference: reference.clone() })
            }
            Suspicion::MissingKind { kind } => {
                out.push(Blocker::MissingKind { kind: kind.clone() })
            }
            Suspicion::ImmutableField => out.push(Blocker::ImmutableField),
            Suspicion::AdmissionDenied { webhook } => {
                out.push(Blocker::AdmissionDenied { webhook: webhook.clone() })
            }
            // A namespace stuck terminating is almost always held by a finalizer, and the object
            // holding it is the namespace rather than the Flux resource being diagnosed.
            Suspicion::NamespaceTerminating { namespace } => {
                if let Some(b) = namespace_terminating_blocker(client, namespace).await {
                    out.push(b);
                }
            }
        }
    }

    // With no lead in the message there is nothing to confirm, so the webhook sweep runs as a last
    // resort: a fail-closed orphan is the one cluster-wide fault that breaks applies without ever
    // naming itself in the object it breaks. Everything it finds is reported, not just what is
    // already breaking — the sweep only ever returns configurations whose service is genuinely
    // dead, so it cannot be noisy, and "nothing is blocking this, but the cluster still carries
    // these leftovers" is the honest answer to someone who asked what was wrong.
    // Anything found before this point was implicated by the resource's own state or message.
    let implicated = !out.is_empty();
    let mut swept = false;
    if suspicions.is_empty() && !scanned_webhooks {
        let found = webhook_blockers(client).await?;
        swept = !implicated && !found.is_empty();
        out.extend(found);
    }

    out.sort_by_key(|b| std::cmp::Reverse(b.level()));
    Ok((out, swept))
}

// One webhook of a configuration, flattened: which Service backs it (absent for a URL-addressed
// webhook, which points outside the cluster and cannot be judged from here) and whether it fails
// closed.
struct WebhookEntry {
    service: Option<(String, String)>,
    fail_closed: bool,
}

// A configuration of either kind, reduced to what the orphan check needs.
struct WebhookConfig {
    kind: WebhookKind,
    name: String,
    hooks: Vec<WebhookEntry>,
}

// Every admission configuration whose backing service cannot serve. Both kinds are listed once and
// their distinct services resolved, rather than one lookup per webhook: a configuration commonly
// declares a dozen webhooks all pointing at the same service.
async fn webhook_blockers(client: &Client) -> Result<Vec<Blocker>, String> {
    let mut out = Vec::new();
    let mut checked: Vec<(String, String, Option<WebhookFault>)> = Vec::new();

    let validating: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    let mutating: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let (v, m) = futures::future::join(
        validating.list(&ListParams::default()),
        mutating.list(&ListParams::default()),
    )
    .await;

    // Both configurations reduced to the same shape, so the inspection below is written once
    // despite Validating and Mutating being distinct Rust types with no common trait.
    let mut configs: Vec<WebhookConfig> = Vec::new();
    for c in v.map_err(|e| e.to_string())?.items {
        configs.push(WebhookConfig {
            kind: WebhookKind::Validating,
            name: c.metadata.name.clone().unwrap_or_default(),
            hooks: c
                .webhooks
                .unwrap_or_default()
                .into_iter()
                .map(|w| WebhookEntry {
                    service: w.client_config.service.map(|s| (s.namespace, s.name)),
                    fail_closed: w.failure_policy.as_deref() != Some("Ignore"),
                })
                .collect(),
        });
    }
    for c in m.map_err(|e| e.to_string())?.items {
        configs.push(WebhookConfig {
            kind: WebhookKind::Mutating,
            name: c.metadata.name.clone().unwrap_or_default(),
            hooks: c
                .webhooks
                .unwrap_or_default()
                .into_iter()
                .map(|w| WebhookEntry {
                    service: w.client_config.service.map(|s| (s.namespace, s.name)),
                    fail_closed: w.failure_policy.as_deref() != Some("Ignore"),
                })
                .collect(),
        });
    }

    for WebhookConfig { kind, name, hooks } in configs {
        if hooks.is_empty() {
            out.push(Blocker::EmptyWebhookConfig { kind, name });
            continue;
        }
        // A configuration is reported once, on its worst webhook: deleting it takes them all.
        let mut worst: Option<(String, bool, WebhookFault)> = None;
        for WebhookEntry { service, fail_closed } in hooks {
            let Some((ns, svc_name)) = service else { continue };
            let fault = match checked.iter().find(|(n, s, _)| n == &ns && s == &svc_name) {
                Some((_, _, f)) => f.clone(),
                None => {
                    let f = service_fault(client, &ns, &svc_name).await;
                    checked.push((ns.clone(), svc_name.clone(), f.clone()));
                    f
                }
            };
            let Some(fault) = fault else { continue };
            let better = match &worst {
                // Fail-closed beats fail-open; among equals the first wins.
                Some((_, w_closed, _)) => fail_closed && !w_closed,
                None => true,
            };
            if better {
                worst = Some((format!("{}/{}", ns, svc_name), fail_closed, fault));
            }
        }
        if let Some((service, fail_closed, fault)) = worst {
            out.push(Blocker::OrphanWebhook { kind, name, service, fail_closed, fault });
        }
    }
    Ok(out)
}

// `None` when the service can serve. A lookup that fails for any reason other than a clean 404 is
// treated as healthy: being unable to ask is not evidence that the answer is bad, and inventing an
// orphan would push someone to delete working admission control.
async fn service_fault(client: &Client, ns: &str, name: &str) -> Option<WebhookFault> {
    let svc: Api<Service> = Api::namespaced(client.clone(), ns);
    match svc.get_opt(name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Distinguish "the operator is gone" from "this one service was removed".
            let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
            return match ns_api.get_opt(ns).await {
                Ok(None) => Some(WebhookFault::NamespaceGone),
                _ => Some(WebhookFault::ServiceGone),
            };
        }
        Err(_) => return None,
    }

    let slices: Api<EndpointSlice> = Api::namespaced(client.clone(), ns);
    let lp = ListParams::default().labels(&format!("{}={}", SERVICE_NAME_LABEL, name));
    let Ok(list) = slices.list(&lp).await else {
        return None;
    };
    let ready = list.items.iter().any(|s| {
        s.endpoints
            .iter()
            .any(|e| e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true))
    });
    (!ready).then_some(WebhookFault::NoEndpoints)
}

// The diagnosed object's own deletion state.
async fn terminating_blocker(client: &Client, target: &Target) -> Option<Blocker> {
    let api = dynamic_api(client, &target.api_version, &target.kind, &target.namespace)
        .await
        .ok()?;
    let obj = api.get_opt(&target.name).await.ok().flatten()?;
    let value = serde_json::to_value(&obj).ok()?;
    stuck_terminating(
        &value,
        &target.api_version,
        &target.kind,
        &target.namespace,
        &target.name,
    )
}

async fn namespace_terminating_blocker(client: &Client, namespace: &str) -> Option<Blocker> {
    if namespace.is_empty() {
        return None;
    }
    let api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let ns = api.get_opt(namespace).await.ok().flatten()?;
    let value = serde_json::to_value(&ns).ok()?;
    stuck_terminating(&value, "v1", "Namespace", "", namespace)
}

// Pure half of the terminating check, so the rule is testable without a cluster: an object with a
// deletionTimestamp and at least one lock still on it.
fn stuck_terminating(
    value: &Value,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Option<Blocker> {
    let meta = value.get("metadata")?;
    meta.get("deletionTimestamp")?.as_str()?;
    let finalizers = string_list(meta.get("finalizers"));
    let spec_finalizers = string_list(value.get("spec").and_then(|s| s.get("finalizers")));
    if finalizers.is_empty() && spec_finalizers.is_empty() {
        return None;
    }
    Some(Blocker::StuckTerminating {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        finalizers,
        spec_finalizers,
    })
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

// The Helm release backing a HelmRelease, read from the release secret's labels — Helm records the
// state there as well as inside the compressed blob, so the pending states are visible without
// decompressing anything.
async fn helm_pending_blocker(client: &Client, target: &Target) -> Option<Blocker> {
    let api: Api<Secret> = Api::namespaced(client.clone(), &target.namespace);
    let lp = ListParams::default().labels(HELM_OWNER_LABEL);
    let list = api.list(&lp).await.ok()?;
    let mut best: Option<(u32, String)> = None;
    for s in &list.items {
        let labels = s.metadata.labels.as_ref()?;
        if labels.get("name").map(String::as_str) != Some(target.name.as_str()) {
            continue;
        }
        let status = labels.get("status")?.clone();
        let version: u32 = labels.get("version").and_then(|v| v.parse().ok()).unwrap_or(0);
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, status));
        }
    }
    let (version, state) = best?;
    state.starts_with("pending").then(|| Blocker::HelmPending {
        namespace: target.namespace.clone(),
        name: target.name.clone(),
        state,
        version: version.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Applying a remedy
// ---------------------------------------------------------------------------

pub async fn apply(
    client: Client,
    remedy: Remedy,
    target: Target,
    key: String,
    state: SharedRepair,
) {
    let result = run_apply(&client, &remedy, &target).await;
    let mut s = state.lock().expect("repair state poisoned");
    if s.key != key {
        return;
    }
    s.applying = false;
    s.done = Some(result);
}

async fn run_apply(client: &Client, remedy: &Remedy, target: &Target) -> Result<String, String> {
    match remedy {
        Remedy::DeleteWebhookConfig { kind, name } => {
            let api = dynamic_api(client, "admissionregistration.k8s.io/v1", kind.api_kind(), "")
                .await?;
            api.delete(name, &DeleteParams::default())
                .await
                .map(|_| crate::lang::fill(crate::lang::active().rp_deleted, &[("name", name)]))
                .map_err(|e| e.to_string())
        }
        Remedy::RemoveFinalizers { api_version, kind, namespace, name, finalizers } => {
            let api = dynamic_api(client, api_version, kind, namespace).await?;
            // Merge-patch replaces an array wholesale, so an empty one clears every finalizer at
            // once. That is the intent here — the panel lists them before asking — but it does mean
            // this is not a way to drop a single lock and keep the others.
            let patch = serde_json::json!({ "metadata": { "finalizers": [] } });
            api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
                .map(|_| {
                    let st = crate::lang::active();
                    crate::lang::fill(
                        &st.plural(
                            finalizers.len(),
                            st.rp_finalizers_removed_one,
                            st.rp_finalizers_removed_many,
                        ),
                        &[("name", name)],
                    )
                })
                .map_err(|e| e.to_string())
        }
        Remedy::ResetFailures | Remedy::ForceUpgrade => {
            let scope = if matches!(remedy, Remedy::ForceUpgrade) {
                crate::flux::ReconcileScope::Force
            } else {
                crate::flux::ReconcileScope::Reset
            };
            crate::flux::reconcile_once(
                client,
                scope,
                &target.api_version,
                &target.kind,
                &target.namespace,
                &target.name,
            )
            .await
        }
        Remedy::SuspendResume => {
            crate::flux::suspend_cycle(
                client,
                &target.api_version,
                &target.kind,
                &target.namespace,
                &target.name,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreachable_webhook_is_named() {
        // The shape the API server produces when the backing service has gone away.
        let msg = "Internal error occurred: failed calling webhook \
                   \"validate.kyverno.svc-fail\": failed to call webhook: Post \
                   \"https://kyverno-svc.kyverno.svc:443/validate?timeout=10s\": no such host";
        assert_eq!(
            classify(msg),
            vec![Suspicion::WebhookUnreachable {
                webhook: "validate.kyverno.svc-fail".to_string()
            }]
        );
    }

    #[test]
    fn a_denial_is_not_an_unreachable_webhook() {
        // Both sentences contain "webhook", but a denial means it answered: offering to delete the
        // configuration here would remove a policy that is working as intended.
        let msg = "admission webhook \"validate.kyverno.svc-fail\" denied the request: \
                   validation error: runAsNonRoot is required";
        assert_eq!(
            classify(msg),
            vec![Suspicion::AdmissionDenied {
                webhook: "validate.kyverno.svc-fail".to_string()
            }]
        );
    }

    #[test]
    fn a_pending_helm_operation_is_recognised() {
        let msg = "Helm upgrade failed: another operation (install/upgrade/rollback) is in progress";
        assert_eq!(classify(msg), vec![Suspicion::HelmOperationInProgress]);
    }

    #[test]
    fn exhausted_retries_are_recognised() {
        assert_eq!(
            classify("upgrade retries exhausted"),
            vec![Suspicion::RetriesExhausted]
        );
    }

    #[test]
    fn a_dependency_reference_is_extracted() {
        assert_eq!(
            classify("dependency 'flux-system/infra-configs' is not ready"),
            vec![Suspicion::DependencyNotReady {
                reference: "flux-system/infra-configs".to_string()
            }]
        );
    }

    #[test]
    fn a_missing_crd_is_recognised() {
        assert_eq!(
            classify("no matches for kind \"Certificate\" in version \"cert-manager.io/v1\""),
            vec![Suspicion::MissingKind { kind: "Certificate".to_string() }]
        );
    }

    #[test]
    fn a_terminating_namespace_names_itself() {
        let msg = "unable to create new content in namespace kyverno because it is being terminated";
        assert_eq!(
            classify(msg),
            vec![Suspicion::NamespaceTerminating { namespace: "kyverno".to_string() }]
        );
    }

    #[test]
    fn a_healthy_message_yields_no_lead() {
        assert!(classify("Applied revision: main@sha256:abcd").is_empty());
        assert!(classify("").is_empty());
    }

    #[test]
    fn a_fail_closed_orphan_outranks_a_fail_open_one() {
        let closed = Blocker::OrphanWebhook {
            kind: WebhookKind::Mutating,
            name: "kyverno-policy-mutating-webhook-cfg".to_string(),
            service: "kyverno/kyverno-svc".to_string(),
            fail_closed: true,
            fault: WebhookFault::NamespaceGone,
        };
        let open = Blocker::OrphanWebhook {
            kind: WebhookKind::Mutating,
            name: "kyverno-verify-mutating-webhook-cfg".to_string(),
            service: "kyverno/kyverno-svc".to_string(),
            fail_closed: false,
            fault: WebhookFault::NamespaceGone,
        };
        assert_eq!(closed.level(), Level::Danger);
        assert_eq!(open.level(), Level::Warn);
    }

    #[test]
    fn deleting_a_webhook_config_demands_the_strict_confirmation() {
        let b = Blocker::EmptyWebhookConfig {
            kind: WebhookKind::Mutating,
            name: "kyverno-resource-mutating-webhook-cfg".to_string(),
        };
        let remedies = b.remedies();
        assert_eq!(remedies.len(), 1);
        assert_eq!(remedies[0].level(), Level::Danger);
        assert_eq!(
            remedies[0].confirm_target(),
            "kyverno-resource-mutating-webhook-cfg"
        );
    }

    #[test]
    fn a_terminating_object_with_a_finalizer_is_stuck() {
        let obj = serde_json::json!({
            "metadata": {
                "name": "kyverno",
                "deletionTimestamp": "2026-07-20T10:00:00Z",
                "finalizers": ["controller.cattle.io/namespace-auth"],
            },
            "spec": { "finalizers": ["kubernetes"] },
        });
        let b = stuck_terminating(&obj, "v1", "Namespace", "", "kyverno").expect("stuck");
        match &b {
            Blocker::StuckTerminating { finalizers, spec_finalizers, .. } => {
                assert_eq!(finalizers, &["controller.cattle.io/namespace-auth"]);
                // Surfaced separately: clearing metadata finalizers leaves this second lock on.
                assert_eq!(spec_finalizers, &["kubernetes"]);
            }
            other => panic!("unexpected blocker: {:?}", other),
        }
        assert_eq!(b.level(), Level::Danger);
    }

    #[test]
    fn an_object_merely_being_deleted_is_not_stuck() {
        // No finalizer means nothing is holding it: the deletion is simply in flight.
        let obj = serde_json::json!({
            "metadata": { "name": "web", "deletionTimestamp": "2026-07-20T10:00:00Z" },
        });
        assert!(stuck_terminating(&obj, "v1", "Pod", "default", "web").is_none());
    }

    #[test]
    fn a_live_object_is_not_stuck() {
        let obj = serde_json::json!({
            "metadata": { "name": "web", "finalizers": ["kubernetes.io/pvc-protection"] },
        });
        assert!(stuck_terminating(&obj, "v1", "Pod", "default", "web").is_none());
    }

    #[test]
    fn a_pending_release_is_repaired_without_touching_helm_storage() {
        let b = Blocker::HelmPending {
            namespace: "authentik".to_string(),
            name: "authentik".to_string(),
            state: "pending-upgrade".to_string(),
            version: "6".to_string(),
        };
        // Both moves go through the controller; neither deletes a release secret.
        assert_eq!(b.remedies(), vec![Remedy::ResetFailures, Remedy::ForceUpgrade]);
        assert!(b.remedies().iter().all(|r| r.level() != Level::Danger));
    }

    #[test]
    fn an_observation_offers_no_remedy() {
        // Nothing a TUI can do about these — they are reported so the panel is not silent.
        assert!(Blocker::ImmutableField.remedies().is_empty());
        assert!(Blocker::MissingKind { kind: "Certificate".to_string() }.remedies().is_empty());
        assert!(Blocker::WaitingOnDependency { reference: "a/b".to_string() }.remedies().is_empty());
    }
}
