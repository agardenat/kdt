//! Cluster-wide inventory of Kyverno: the policies, what they actually apply to, and what they
//! reject — read dynamically so the tool degrades cleanly on clusters without Kyverno, and on
//! clusters running only the older engine.
//!
//! The point of this module is the *join*. A `PolicyReport` names the policy that failed by a bare
//! string and nothing else; the rule that produced the result is a bare string too. To learn what
//! was actually checked you have to go and read the policy object, hop by hop, by hand. Here that
//! join is materialised once:
//!
//! ```text
//! ClusterPolicy / Policy / ValidatingPolicy …
//!    └─ rule (+ the autogen rules Kyverno derived from it)
//!        └─ the resources that fail it, from the PolicyReports
//! ```
//!
//! with, hanging off the policy itself, the PolicyExceptions that excuse one of its rules.
//!
//! Three things make that join harder than it looks, and each one is a silent wrong answer if
//! missed:
//!
//! 1. **The reports name autogen rules, not yours.** A rule matching `Pod` makes Kyverno generate
//!    `autogen-<rule>` for Deployment/StatefulSet/… and `autogen-cronjob-<rule>` for CronJob. Those
//!    are the names that appear in every report about a Deployment. Joining on `spec.rules` alone
//!    matches nothing on precisely the objects people look at. See [`parse_rules`].
//! 2. **The CEL engine reports readiness somewhere else entirely.** `kyverno.io/v1` policies carry
//!    `status.conditions[type=Ready]`; `policies.kyverno.io/v1` policies carry
//!    `status.conditionStatus.ready` with condition types `WebhookConfigured` and
//!    `RBACPermissionsGranted` — and no `Ready` condition at all. Reading conditions alone shows
//!    every CEL policy as Unknown. See [`parse_ready`].
//! 3. **An `Enforce` block leaves no report.** A resource refused at admission does not exist, so
//!    nothing describes it in any `PolicyReport`. The only trace is an Event whose reporting
//!    component is `kyverno-admission` and whose message carries `(blocked)`. Reading reports alone
//!    misses exactly the failures that woke someone up. The UI joins those events from the buffer it
//!    already holds; see [`is_admission_denial`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;
use futures::StreamExt;

use crate::events::{format_age, EventRecord, LineColor, Severity};
use crate::lang::Strings;

// (group, candidate versions newest-first, kind) probed via discovery until one resolves. Three
// generations coexist and a cluster may have any subset: the CEL engine (`policies.kyverno.io`)
// only exists from Kyverno 1.14, and its absence must not read as an error.
const CANDIDATES: &[(&str, &[&str], &str)] = &[
    ("kyverno.io", &["v1"], "ClusterPolicy"),
    ("kyverno.io", &["v1"], "Policy"),
    ("policies.kyverno.io", &["v1", "v1alpha1"], "ValidatingPolicy"),
    ("policies.kyverno.io", &["v1", "v1alpha1"], "MutatingPolicy"),
    ("policies.kyverno.io", &["v1", "v1alpha1"], "ImageValidatingPolicy"),
    ("policies.kyverno.io", &["v1", "v1alpha1"], "GeneratingPolicy"),
    ("policies.kyverno.io", &["v1", "v1alpha1"], "DeletingPolicy"),
    ("kyverno.io", &["v2"], "ClusterCleanupPolicy"),
    ("kyverno.io", &["v2"], "CleanupPolicy"),
    ("kyverno.io", &["v2"], "PolicyException"),
];

const KYVERNO_GROUP: &str = "kyverno.io";
const CEL_GROUP: &str = "policies.kyverno.io";
const REPORT_GROUP: &str = "wgpolicyk8s.io";
const REPORT_VERSIONS: &[&str] = &["v1alpha2"];
const KYVERNO_NS: &str = "kyverno";

// UpdateRequests are the queue Kyverno drains to apply `generate` and `mutateExisting` rules. When
// the background controller cannot keep up they stack up `Pending` and those rules quietly stop
// producing anything — a failure that leaves no PolicyReport and no admission denial, so nothing
// else in this view would show it.
const UR_VERSIONS: &[&str] = &["v2", "v1"];
// Intermediate per-resource reports awaiting aggregation into the PolicyReports; a large standing
// count means the reports controller is behind.
const EPHEMERAL_GROUP: &str = "reports.kyverno.io";
const EPHEMERAL_VERSIONS: &[&str] = &["v1"];

// Above this many stuck (Pending + Failed) requests the backlog is treated as an anomaly and shown
// in red with its worst offenders, rather than as an incidental count.
pub const UR_PILEUP: usize = 50;

// How many UpdateRequest deletions to run at once during a purge. Sequential deletes against a slow
// apiserver turned a ~900-request purge into minutes; a bounded fan-out keeps it to seconds without
// flooding the server.
const PURGE_CONCURRENCY: usize = 32;

// Per-resource reports are one object per scanned resource: a real cluster has thousands. Only the
// non-passing results are ever materialised as rows, but the cap bounds the parse itself.
const MAX_VIOLATIONS: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum KyKind {
    ClusterPolicy,
    Policy,
    ValidatingPolicy,
    MutatingPolicy,
    ImageValidatingPolicy,
    GeneratingPolicy,
    DeletingPolicy,
    ClusterCleanupPolicy,
    CleanupPolicy,
    PolicyException,
}

impl KyKind {
    pub fn parse(s: &str) -> Option<KyKind> {
        Some(match s {
            "ClusterPolicy" => KyKind::ClusterPolicy,
            "Policy" => KyKind::Policy,
            "ValidatingPolicy" => KyKind::ValidatingPolicy,
            "MutatingPolicy" => KyKind::MutatingPolicy,
            "ImageValidatingPolicy" => KyKind::ImageValidatingPolicy,
            "GeneratingPolicy" => KyKind::GeneratingPolicy,
            "DeletingPolicy" => KyKind::DeletingPolicy,
            "ClusterCleanupPolicy" => KyKind::ClusterCleanupPolicy,
            "CleanupPolicy" => KyKind::CleanupPolicy,
            "PolicyException" => KyKind::PolicyException,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            KyKind::ClusterPolicy => "ClusterPolicy",
            KyKind::Policy => "Policy",
            KyKind::ValidatingPolicy => "ValidatingPolicy",
            KyKind::MutatingPolicy => "MutatingPolicy",
            KyKind::ImageValidatingPolicy => "ImageValidatingPolicy",
            KyKind::GeneratingPolicy => "GeneratingPolicy",
            KyKind::DeletingPolicy => "DeletingPolicy",
            KyKind::ClusterCleanupPolicy => "ClusterCleanupPolicy",
            KyKind::CleanupPolicy => "CleanupPolicy",
            KyKind::PolicyException => "PolicyException",
        }
    }

    // Short label for the tree column, where the full kind eats too much width on nested rows.
    pub fn short(self) -> &'static str {
        match self {
            KyKind::ClusterPolicy => "ClusterPolicy",
            KyKind::Policy => "Policy",
            KyKind::ValidatingPolicy => "ValidatingPolicy",
            KyKind::MutatingPolicy => "MutatingPolicy",
            KyKind::ImageValidatingPolicy => "ImageValidPolicy",
            KyKind::GeneratingPolicy => "GeneratingPolicy",
            KyKind::DeletingPolicy => "DeletingPolicy",
            KyKind::ClusterCleanupPolicy => "ClusterCleanup",
            KyKind::CleanupPolicy => "Cleanup",
            KyKind::PolicyException => "PolicyException",
        }
    }

    // Whether this kind is part of the CEL engine (`policies.kyverno.io`), which reports its
    // readiness and its scope in an entirely different shape.
    pub fn is_cel(self) -> bool {
        matches!(
            self,
            KyKind::ValidatingPolicy
                | KyKind::MutatingPolicy
                | KyKind::ImageValidatingPolicy
                | KyKind::GeneratingPolicy
                | KyKind::DeletingPolicy
        )
    }

    // Cleanup policies delete on a schedule instead of guarding admission: no rules, no reports.
    pub fn is_cleanup(self) -> bool {
        matches!(self, KyKind::ClusterCleanupPolicy | KyKind::CleanupPolicy)
    }

    // The `source` string Kyverno stamps on the results this kind produces. It is what tells a
    // ClusterPolicy named `x` apart from a ValidatingPolicy also named `x`.
    fn report_source(self) -> &'static str {
        match self {
            KyKind::ValidatingPolicy => "KyvernoValidatingPolicy",
            KyKind::MutatingPolicy => "KyvernoMutatingPolicy",
            KyKind::ImageValidatingPolicy => "KyvernoImageValidatingPolicy",
            KyKind::GeneratingPolicy => "KyvernoGeneratingPolicy",
            KyKind::DeletingPolicy => "KyvernoDeletingPolicy",
            _ => "kyverno",
        }
    }
}

// What a failing validation actually does. `Deny` on the CEL engine and `Enforce` on the older one
// are the same posture under two names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KyAction {
    // Not a validating policy at all (mutate, generate, cleanup): nothing to block.
    None,
    Audit,
    Warn,
    Enforce,
}

impl KyAction {
    pub fn label(self) -> &'static str {
        match self {
            KyAction::None => "-",
            KyAction::Audit => "Audit",
            KyAction::Warn => "Warn",
            KyAction::Enforce => "Enforce",
        }
    }

    fn parse(s: &str) -> Option<KyAction> {
        Some(match s.trim() {
            "Enforce" | "Deny" => KyAction::Enforce,
            "Audit" => KyAction::Audit,
            "Warn" => KyAction::Warn,
            _ => return None,
        })
    }

    pub fn blocks(self) -> bool {
        self == KyAction::Enforce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KyReady {
    Ready,
    NotReady,
    Unknown,
}

// A single line of a PolicyReport. `Pass` and `Skip` are counted but never materialised as rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KyResult {
    Pass,
    Skip,
    Warn,
    Fail,
    // The rule could not be evaluated at all (bad CEL, missing context, failed API call). That is a
    // broken policy, not a non-compliant resource, and it outranks every `Fail`.
    Error,
}

impl KyResult {
    fn parse(s: &str) -> Option<KyResult> {
        Some(match s.trim() {
            "pass" => KyResult::Pass,
            "fail" => KyResult::Fail,
            "warn" => KyResult::Warn,
            "error" => KyResult::Error,
            "skip" => KyResult::Skip,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            KyResult::Pass => "pass",
            KyResult::Skip => "skip",
            KyResult::Warn => "warn",
            KyResult::Fail => "fail",
            KyResult::Error => "error",
        }
    }

    // Glyphs restricted to the font-safe list guarded by `ui::glyph_guard`; `!` stays ASCII.
    pub fn glyph(self) -> &'static str {
        match self {
            KyResult::Pass => "✓",
            KyResult::Skip => "·",
            KyResult::Warn => "!",
            KyResult::Fail => "✗",
            KyResult::Error => "×",
        }
    }

    pub fn is_problem(self) -> bool {
        matches!(self, KyResult::Fail | KyResult::Warn | KyResult::Error)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct KyCounts {
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
    pub skip: usize,
}

impl KyCounts {
    pub fn add_result(&mut self, r: KyResult) {
        match r {
            KyResult::Pass => self.pass += 1,
            KyResult::Fail => self.fail += 1,
            KyResult::Warn => self.warn += 1,
            KyResult::Error => self.error += 1,
            KyResult::Skip => self.skip += 1,
        }
    }

    fn merge(&mut self, o: &KyCounts) {
        self.pass += o.pass;
        self.fail += o.fail;
        self.warn += o.warn;
        self.error += o.error;
        self.skip += o.skip;
    }

    pub fn total(&self) -> usize {
        self.pass + self.fail + self.warn + self.error + self.skip
    }

    pub fn problems(&self) -> usize {
        self.fail + self.warn + self.error
    }

    // Compact "✗12 !3 ×1 ✓204" for the RÉSULTAT column, skipping the buckets that are empty.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.error > 0 {
            parts.push(format!("×{}", self.error));
        }
        if self.fail > 0 {
            parts.push(format!("✗{}", self.fail));
        }
        if self.warn > 0 {
            parts.push(format!("!{}", self.warn));
        }
        if self.pass > 0 {
            parts.push(format!("✓{}", self.pass));
        }
        parts.join(" ")
    }
}

// One rule of a policy, including the ones Kyverno generated itself.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KyRule {
    pub name: String,
    // validate | mutate | generate | verifyImages | cel — what the rule does, not what it matches.
    pub verb: String,
    // Derived by Kyverno from a Pod rule. These are the names the reports actually use.
    pub autogen: bool,
    pub action: KyAction,
    // "Pod, Deployment · ns prod,stage" — the answer to "applied to what?".
    pub match_summary: String,
    pub message: String,
    pub counts: KyCounts,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KyException {
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    // Rules of the target policy this exception excuses; empty means all of them.
    pub rules: Vec<String>,
    pub match_summary: String,
}

// A namespace-scoped override of the policy-wide posture (`spec.validationFailureActionOverrides`).
// Without it the ACTION column lies on every cluster that phases Enforce in namespace by namespace.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KyOverride {
    pub action: KyAction,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KyPolicy {
    pub kind: KyKind,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub title: String,
    // The strongest posture among the policy's rules: what it does at its most severe.
    pub action: KyAction,
    pub background: bool,
    pub admission: bool,
    pub ready: KyReady,
    pub ready_message: String,
    pub rules: Vec<KyRule>,
    pub exceptions: Vec<KyException>,
    pub overrides: Vec<KyOverride>,
    pub counts: KyCounts,
    // Cleanup policies only: the crontab that drives them.
    pub schedule: Option<String>,
    pub age: String,
}

impl KyPolicy {
    // Stable identifier, used to remember collapsed nodes and to restore the selection on refresh.
    pub fn uid(&self) -> String {
        ky_uid(self.kind.as_str(), &self.namespace, &self.name)
    }

    // Problems first: a policy that cannot evaluate outranks one that merely rejects things, which
    // outranks a healthy one — and within a bucket, blocking policies come before advisory ones.
    fn sort_key(&self) -> (u8, std::cmp::Reverse<u8>, &str, &str, &str) {
        let bucket = if self.ready == KyReady::NotReady {
            0
        } else if self.counts.error > 0 {
            1
        } else if self.counts.fail > 0 {
            2
        } else if self.counts.warn > 0 {
            3
        } else {
            4
        };
        (
            bucket,
            std::cmp::Reverse(self.action as u8),
            self.kind.as_str(),
            self.namespace.as_str(),
            self.name.as_str(),
        )
    }

    // True when the policy needs a human: it cannot run, or it is rejecting something.
    pub fn has_problem(&self) -> bool {
        self.ready == KyReady::NotReady || self.counts.problems() > 0
    }
}

pub fn ky_uid(kind: &str, ns: &str, name: &str) -> String {
    format!("{}|{}/{}", kind, ns, name)
}

// One non-passing result, resolved to the resource it is about. That resource reference is what
// makes `y`, `h` and `Ctrl-D` act on the offending object rather than on the policy.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KyViolation {
    // uid() of the policy this belongs to, or an empty string when no policy object matched.
    pub policy_uid: String,
    pub policy: String,
    pub rule: String,
    pub result: KyResult,
    pub severity: String,
    pub category: String,
    pub message: String,
    // The offending resource.
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    // "background scan" or "admission review request" — how the result was produced.
    pub process: String,
    pub age: String,
}

impl KyViolation {
    pub fn uid(&self) -> String {
        format!(
            "{}|{}|{}/{}|{}",
            self.policy, self.rule, self.namespace, self.name, self.kind
        )
    }

    fn sort_key(&self) -> (std::cmp::Reverse<u8>, &str, &str, &str) {
        (
            std::cmp::Reverse(self.result as u8),
            self.namespace.as_str(),
            self.kind.as_str(),
            self.name.as_str(),
        )
    }
}

// Is Kyverno actually doing anything? Four controllers, and the webhook counts that say whether
// admission is intercepted at all.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct KyHealth {
    pub version: String,
    // (component label, ready replicas, desired replicas), e.g. ("admission", 1, 1).
    pub controllers: Vec<(String, i32, i32)>,
    // Rules registered on `kyverno-resource-{validating,mutating}-webhook-cfg`. **Zero means
    // Kyverno intercepts nothing**: every controller can be green while no policy is enforced, and
    // this is the only place that shows it.
    pub validating_webhooks: usize,
    pub mutating_webhooks: usize,
    pub webhooks_known: bool,
    pub reports: usize,
}

impl KyHealth {
    pub fn controllers_ok(&self) -> bool {
        !self.controllers.is_empty() && self.controllers.iter().all(|(_, r, d)| r >= d && *d > 0)
    }

    // Green controllers with no registered webhook: nothing is being intercepted.
    pub fn silently_inactive(&self) -> bool {
        self.webhooks_known && self.validating_webhooks == 0 && self.mutating_webhooks == 0
    }
}

// The lifecycle state Kyverno stamps on an UpdateRequest (`status.state`). Only `Pending` and
// `Failed` are backlog; `Completed`/`Skip` are drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyRequestState {
    Pending,
    Failed,
    Completed,
    Skip,
    Other,
}

impl KyRequestState {
    fn parse(s: &str) -> KyRequestState {
        match s.trim() {
            "Pending" => KyRequestState::Pending,
            "Failed" => KyRequestState::Failed,
            "Completed" => KyRequestState::Completed,
            "Skip" => KyRequestState::Skip,
            _ => KyRequestState::Other,
        }
    }

    fn is_stuck(self) -> bool {
        matches!(self, KyRequestState::Pending | KyRequestState::Failed)
    }
}

// The generate/mutateExisting request queue, folded to what a human needs: how deep the backlog is,
// which policies own it, and how long the oldest one has been waiting.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct KyBacklog {
    // Whether the UpdateRequest CRD exists at all: absent Kyverno, or a build without generate.
    pub known: bool,
    pub total: usize,
    pub pending: usize,
    pub failed: usize,
    pub completed: usize,
    pub skip: usize,
    // (policy, stuck count) for the worst offenders, most first.
    pub by_policy: Vec<(String, usize)>,
    // Age of the oldest stuck request: a queue draining normally never shows an old one here.
    pub oldest_stuck: Option<String>,
    // Intermediate reports (`reports.kyverno.io`) still awaiting aggregation.
    pub ephemeral_reports: usize,
}

impl KyBacklog {
    pub fn stuck(&self) -> usize {
        self.pending + self.failed
    }

    // A backlog worth flagging: enough stuck requests that the controller is visibly not keeping up.
    pub fn has_pileup(&self) -> bool {
        self.stuck() >= UR_PILEUP
    }
}

#[derive(Default, Debug, Clone)]
pub struct KyvernoState {
    pub policies: Vec<KyPolicy>,
    pub violations: Vec<KyViolation>,
    pub backlog: KyBacklog,
    pub health: KyHealth,
    pub error: Option<String>,
    pub loading: bool,
    // Whether the core kyverno.io CRDs were found at all, as opposed to found-but-empty.
    pub installed: bool,
    // Whether the CEL engine group exists (absent before Kyverno 1.14).
    pub cel_installed: bool,
}

impl KyvernoState {
    // (policies, enforcing, not-ready, fail, warn, error) for the panel title.
    pub fn counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0, 0, 0);
        for p in &self.policies {
            c.0 += 1;
            if p.action.blocks() {
                c.1 += 1;
            }
            if p.ready == KyReady::NotReady {
                c.2 += 1;
            }
            c.3 += p.counts.fail;
            c.4 += p.counts.warn;
            c.5 += p.counts.error;
        }
        c
    }

}

pub type SharedKyverno = Arc<Mutex<KyvernoState>>;

pub fn new_kyverno_state() -> SharedKyverno {
    Arc::new(Mutex::new(KyvernoState::default()))
}

// List every Kyverno policy on the cluster, fold the PolicyReports into per-rule counts and a flat
// violation list, and probe the controllers. `installed` distinguishes "Kyverno is not deployed"
// from "deployed but no policy yet".
pub async fn fetch_kyverno(client: Client, state: SharedKyverno) {
    {
        let mut s = state.lock().expect("kyverno poisoned");
        s.loading = true;
        s.error = None;
    }

    // Twelve policy kinds plus two report kinds means fourteen discovery round-trips, and each one
    // is a full API hop. Done in sequence that is fifteen seconds of blank view on a remote
    // cluster, so the three independent halves of the fetch run as one wave instead.
    let (listed, reports, mut health, backlog) = futures::future::join4(
        list_policy_kinds(&client),
        list_reports(&client),
        fetch_health(&client),
        fetch_backlog(&client),
    )
    .await;

    let ListedPolicies { mut policies, exceptions, errors, installed, cel_installed } = listed;

    // A PolicyException names its target by policy name only, so it attaches to every policy of
    // that name — in practice there is one.
    for (exc, targets) in exceptions {
        for p in policies.iter_mut() {
            if targets.iter().any(|t| target_matches(t, p)) {
                p.exceptions.push(exc.clone());
            }
        }
    }

    let report_count = reports.len();
    let mut violations = attribute_reports(&reports, &mut policies);
    violations.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    policies.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    health.reports = report_count;

    let mut s = state.lock().expect("kyverno poisoned");
    s.loading = false;
    s.installed = installed;
    s.cel_installed = cel_installed;
    s.policies = policies;
    s.violations = violations;
    s.backlog = backlog;
    s.health = health;
    s.error = if !installed {
        Some(crate::lang::active().ky_crds_missing.to_string())
    } else if s.policies.is_empty() && !errors.is_empty() {
        Some(errors.join(" · "))
    } else {
        None
    };
}

// --- policies -----------------------------------------------------------------------------------

#[derive(Default)]
struct ListedPolicies {
    policies: Vec<KyPolicy>,
    exceptions: Vec<(KyException, Vec<String>)>,
    errors: Vec<String>,
    installed: bool,
    cel_installed: bool,
}

// Resolves every candidate kind concurrently, then lists the ones that exist — two waves of
// round-trips rather than two per kind. A kind that does not resolve is skipped in silence: a
// cluster on Kyverno 1.12 has no CEL engine, and that is not a failure.
async fn list_policy_kinds(client: &Client) -> ListedPolicies {
    let probes = CANDIDATES.iter().map(|(group, versions, _kind)| async move {
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, _kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
                return Some((ar, *v));
            }
        }
        None
    });
    let resolved = futures::future::join_all(probes).await;

    let mut out = ListedPolicies::default();
    let mut listings = Vec::new();
    for ((group, _versions, kind), r) in CANDIDATES.iter().zip(resolved) {
        let Some((ar, version)) = r else { continue };
        if *group == KYVERNO_GROUP {
            out.installed = true;
        } else if *group == CEL_GROUP {
            out.cel_installed = true;
        }
        let api_version = format!("{}/{}", group, version);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        listings.push(async move { (*kind, api_version, api.list(&ListParams::default()).await) });
    }

    for (kind, api_version, res) in futures::future::join_all(listings).await {
        match res {
            Ok(list) => {
                for obj in &list.items {
                    if kind == "PolicyException" {
                        if let Some((exc, targets)) = parse_exception(obj, &api_version) {
                            out.exceptions.push((exc, targets));
                        }
                    } else if let Some(p) = parse_policy(obj, kind, &api_version) {
                        out.policies.push(p);
                    }
                }
            }
            Err(e) => out.errors.push(format!("{}: {}", kind, e)),
        }
    }
    out
}

fn parse_policy(obj: &DynamicObject, kind: &str, api_version: &str) -> Option<KyPolicy> {
    let ky_kind = KyKind::parse(kind)?;
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    let (ready, ready_message) = parse_ready(ky_kind, status);
    let rules = parse_rules(ky_kind, spec, status);
    // The policy's posture is the strongest of its rules: one Enforce rule makes it a blocking
    // policy, whatever the others say.
    let action = rules.iter().map(|r| r.action).max().unwrap_or(KyAction::None);

    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    Some(KyPolicy {
        kind: ky_kind,
        api_version: api_version.to_string(),
        namespace,
        name,
        title: obj
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("policies.kyverno.io/title"))
            .cloned()
            .unwrap_or_default(),
        action,
        background: parse_background(ky_kind, spec),
        admission: spec
            .and_then(|s| s.get("admission"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        ready,
        ready_message,
        rules,
        exceptions: Vec::new(),
        overrides: parse_overrides(spec),
        counts: KyCounts::default(),
        schedule: spec
            .and_then(|s| s.get("schedule"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        age,
    })
}

// Readiness lives in two incompatible places. `kyverno.io/v1` uses the usual
// `status.conditions[type=Ready]`; the CEL engine uses `status.conditionStatus.ready` plus its own
// condition types (`WebhookConfigured`, `RBACPermissionsGranted`) and never emits a `Ready`
// condition — so a conditions-only read reports every CEL policy as Unknown.
fn parse_ready(kind: KyKind, status: Option<&Value>) -> (KyReady, String) {
    let Some(status) = status else {
        return (KyReady::Unknown, String::new());
    };

    if kind.is_cel() {
        let cs = status.get("conditionStatus");
        let ready = cs.and_then(|c| c.get("ready")).and_then(|v| v.as_bool());
        // The top-level message is empty when everything is fine; the failing condition carries the
        // reason worth showing.
        let msg = cs
            .and_then(|c| c.get("message"))
            .and_then(|v| v.as_str())
            .filter(|m| !m.is_empty())
            .map(|m| m.to_string())
            .or_else(|| {
                cs.and_then(|c| c.get("conditions"))
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter()
                            .find(|c| c.get("status").and_then(|v| v.as_str()) == Some("False"))
                            .map(condition_text)
                    })
            })
            .unwrap_or_default();
        return match ready {
            Some(true) => (KyReady::Ready, collapse_ws(&msg)),
            Some(false) => (KyReady::NotReady, collapse_ws(&msg)),
            None => (KyReady::Unknown, collapse_ws(&msg)),
        };
    }

    // Cleanup policies do carry a Ready condition; the older validating policies do too.
    let cond = status
        .get("conditions")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Ready"))
        });
    match cond {
        Some(c) => {
            let ok = c.get("status").and_then(|v| v.as_str()) == Some("True");
            // A healthy Kyverno policy reads "Succeeded: Ready", which says nothing the status
            // column does not already say. Only keep the text when it carries something else.
            let bare = c.get("message").and_then(|v| v.as_str()).unwrap_or("").trim();
            let msg = if ok && (bare.is_empty() || bare.eq_ignore_ascii_case("ready")) {
                String::new()
            } else {
                collapse_ws(&condition_text(c))
            };
            (if ok { KyReady::Ready } else { KyReady::NotReady }, msg)
        }
        None => (KyReady::Unknown, String::new()),
    }
}

fn condition_text(c: &Value) -> String {
    let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let message = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
    match (reason.is_empty(), message.is_empty()) {
        (false, false) if reason != message => format!("{}: {}", reason, message),
        (false, true) => reason.to_string(),
        _ => message.to_string(),
    }
}

// Background scanning is on by default; the CEL engine nests the switch under `evaluation`.
fn parse_background(kind: KyKind, spec: Option<&Value>) -> bool {
    let Some(spec) = spec else { return true };
    if kind.is_cel() {
        return spec
            .get("evaluation")
            .and_then(|e| e.get("background"))
            .and_then(|b| b.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
    }
    spec.get("background").and_then(|v| v.as_bool()).unwrap_or(true)
}

fn parse_overrides(spec: Option<&Value>) -> Vec<KyOverride> {
    spec.and_then(|s| s.get("validationFailureActionOverrides"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|o| {
                    let action = o
                        .get("action")
                        .and_then(|v| v.as_str())
                        .and_then(KyAction::parse)?;
                    Some(KyOverride {
                        action,
                        namespaces: str_list(o.get("namespaces")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// Every rule the reports can name: the authored ones plus `status.autogen.rules`. Kyverno derives
// the latter from any rule matching `Pod`, and they are the ones that appear in every report about
// a Deployment, DaemonSet, Job or CronJob — the objects people actually look at.
fn parse_rules(kind: KyKind, spec: Option<&Value>, status: Option<&Value>) -> Vec<KyRule> {
    if kind.is_cleanup() {
        return Vec::new();
    }
    if kind.is_cel() {
        return parse_cel_rules(spec);
    }

    let mut out: Vec<KyRule> = Vec::new();
    // The policy-wide posture of Kyverno <= 1.12, still the fallback when no rule sets its own.
    let policy_action = spec
        .and_then(|s| s.get("validationFailureAction"))
        .and_then(|v| v.as_str())
        .and_then(KyAction::parse);

    let push = |arr: Option<&Vec<Value>>, autogen: bool, out: &mut Vec<KyRule>| {
        for r in arr.into_iter().flatten() {
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let verb = rule_verb(r);
            let validate = r.get("validate");
            // Per-rule since 1.13, and the only form the autogen rules carry.
            let action = validate
                .and_then(|v| v.get("failureAction"))
                .and_then(|v| v.as_str())
                .and_then(KyAction::parse)
                .or(policy_action)
                // A validating rule with no stated posture audits; a mutate/generate rule blocks
                // nothing at all.
                .unwrap_or(if verb == "validate" { KyAction::Audit } else { KyAction::None });
            out.push(KyRule {
                name,
                verb,
                autogen,
                action,
                match_summary: match_summary(r.get("match"), r.get("exclude")),
                message: validate
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .map(collapse_ws)
                    .unwrap_or_default(),
                counts: KyCounts::default(),
            });
        }
    };

    push(spec.and_then(|s| s.get("rules")).and_then(|v| v.as_array()), false, &mut out);
    push(
        status
            .and_then(|s| s.get("autogen"))
            .and_then(|a| a.get("rules"))
            .and_then(|v| v.as_array()),
        true,
        &mut out,
    );
    out
}

// The CEL engine has no `rules` list: a policy is one implicit rule made of `validations`, scoped by
// `matchConstraints` and governed by `validationActions`.
fn parse_cel_rules(spec: Option<&Value>) -> Vec<KyRule> {
    let action = spec
        .and_then(|s| s.get("validationActions"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().filter_map(|a| a.as_str().and_then(KyAction::parse)).max())
        .unwrap_or(KyAction::Audit);
    let message = spec
        .and_then(|s| s.get("validations"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .map(collapse_ws)
        .unwrap_or_default();
    vec![KyRule {
        // Kyverno labels CEL results with this synthetic rule name.
        name: "evaluation".to_string(),
        verb: "cel".to_string(),
        autogen: false,
        action,
        match_summary: cel_match_summary(spec),
        message,
        counts: KyCounts::default(),
    }]
}

fn rule_verb(r: &Value) -> String {
    for key in ["validate", "mutate", "generate", "verifyImages"] {
        if r.get(key).is_some() {
            return key.to_string();
        }
    }
    "-".to_string()
}

// "Pod, Deployment · ns prod,stage · sauf kube-system" — condensed so the column answers
// "applied to what?" at a glance rather than needing the detail panel.
fn match_summary(match_: Option<&Value>, exclude: Option<&Value>) -> String {
    let (kinds, namespaces) = collect_resources(match_);
    let mut parts: Vec<String> = Vec::new();
    if kinds.is_empty() {
        parts.push("*".to_string());
    } else {
        parts.push(join_capped(&kinds, 3));
    }
    if !namespaces.is_empty() {
        parts.push(format!("ns {}", join_capped(&namespaces, 2)));
    }
    let (_, excluded_ns) = collect_resources(exclude);
    if !excluded_ns.is_empty() {
        parts.push(format!("sauf {}", join_capped(&excluded_ns, 2)));
    }
    parts.join(" · ")
}

// `match`/`exclude` accept `any`/`all` lists of selectors and, historically, a bare `resources`
// object. All three shapes appear on live clusters, including inside a single autogen rule.
fn collect_resources(sel: Option<&Value>) -> (Vec<String>, Vec<String>) {
    let mut kinds: Vec<String> = Vec::new();
    let mut namespaces: Vec<String> = Vec::new();
    let Some(sel) = sel else { return (kinds, namespaces) };

    let mut take = |res: Option<&Value>| {
        for k in str_list(res.and_then(|r| r.get("kinds"))) {
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
        for n in str_list(res.and_then(|r| r.get("namespaces"))) {
            if !namespaces.contains(&n) {
                namespaces.push(n);
            }
        }
    };

    for key in ["any", "all"] {
        for entry in sel.get(key).and_then(|v| v.as_array()).into_iter().flatten() {
            take(entry.get("resources"));
        }
    }
    take(sel.get("resources"));
    (kinds, namespaces)
}

// The CEL engine states its scope as admission-webhook resource rules (plural, lowercase) plus
// selectors — nothing like the older `match` block.
fn cel_match_summary(spec: Option<&Value>) -> String {
    let mc = spec.and_then(|s| s.get("matchConstraints"));
    let mut resources: Vec<String> = Vec::new();
    for r in mc
        .and_then(|m| m.get("resourceRules"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        for res in str_list(r.get("resources")) {
            if !resources.contains(&res) {
                resources.push(res);
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    parts.push(if resources.is_empty() { "*".to_string() } else { join_capped(&resources, 3) });
    // A namespaceSelector is how a CEL policy is scoped to namespaces; surface the plain-name form
    // that Kubernetes itself uses, since that is what people write.
    if let Some(ns) = mc
        .and_then(|m| m.get("namespaceSelector"))
        .and_then(|s| s.get("matchLabels"))
        .and_then(|l| l.get("kubernetes.io/metadata.name"))
        .and_then(|v| v.as_str())
    {
        parts.push(format!("ns {}", ns));
    } else if mc.and_then(|m| m.get("namespaceSelector")).is_some() {
        parts.push("ns (selector)".to_string());
    }
    parts.join(" · ")
}

// --- exceptions ---------------------------------------------------------------------------------

// Returns the exception and the policy names it excuses. Both generations are handled: the
// `kyverno.io/v2` form lists `spec.exceptions[].policyName`, the CEL form lists `spec.policyRefs[]`.
fn parse_exception(obj: &DynamicObject, api_version: &str) -> Option<(KyException, Vec<String>)> {
    let spec = obj.data.get("spec")?;
    let mut targets: Vec<String> = Vec::new();
    let mut rules: Vec<String> = Vec::new();

    for e in spec.get("exceptions").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(p) = e.get("policyName").and_then(|v| v.as_str()) {
            targets.push(p.to_string());
        }
        rules.extend(str_list(e.get("ruleNames")));
    }
    for r in spec.get("policyRefs").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(p) = r.get("name").and_then(|v| v.as_str()) {
            targets.push(p.to_string());
        }
    }

    Some((
        KyException {
            api_version: api_version.to_string(),
            namespace: obj.metadata.namespace.clone().unwrap_or_default(),
            name: obj.metadata.name.clone().unwrap_or_default(),
            rules,
            match_summary: match_summary(spec.get("match"), None),
        },
        targets,
    ))
}

// A target is written either as a bare name or as `namespace/name`.
fn target_matches(target: &str, p: &KyPolicy) -> bool {
    match target.split_once('/') {
        Some((ns, name)) => ns == p.namespace && name == p.name,
        None => target == p.name,
    }
}

// --- reports ------------------------------------------------------------------------------------

// Lists every PolicyReport on the cluster. Kept separate from the attribution below so it can run
// concurrently with the policy listing, which it does not depend on.
async fn list_reports(client: &Client) -> Vec<DynamicObject> {
    let probes = ["PolicyReport", "ClusterPolicyReport"].map(|kind| async move {
        for v in REPORT_VERSIONS {
            let gvk = GroupVersionKind::gvk(REPORT_GROUP, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
                let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
                return api.list(&ListParams::default()).await.ok();
            }
        }
        None
    });
    futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .flat_map(|list| list.items)
        .collect()
}

// Folds the reports into per-rule counts on the policies and a flat list of the non-passing
// results. Pure: everything it needs has already been fetched.
fn attribute_reports(reports: &[DynamicObject], policies: &mut [KyPolicy]) -> Vec<KyViolation> {
    // (source, policy name) -> policy index. The source is what tells a ClusterPolicy named `x`
    // apart from a ValidatingPolicy also named `x`.
    let mut by_key: HashMap<(String, String), usize> = HashMap::new();
    for (i, p) in policies.iter().enumerate() {
        by_key
            .entry((p.kind.report_source().to_string(), p.name.clone()))
            .or_insert(i);
    }

    let mut violations: Vec<KyViolation> = Vec::new();
    for obj in reports {
        read_report(obj, policies, &by_key, &mut violations);
    }

    // Roll the per-rule counts up to the policy.
    for p in policies.iter_mut() {
        let mut total = KyCounts::default();
        for r in &p.rules {
            total.merge(&r.counts);
        }
        p.counts = total;
    }

    violations
}

fn read_report(
    obj: &DynamicObject,
    policies: &mut [KyPolicy],
    by_key: &HashMap<(String, String), usize>,
    violations: &mut Vec<KyViolation>,
) {
    // Per-resource reports name their subject once, in `scope`; the ownerReference says the same
    // thing and covers the reports that predate `scope`. Aggregated reports instead repeat a
    // `resources` list on every result, so that is the last fallback, read per result below.
    let scope = obj.data.get("scope").and_then(resource_ref).or_else(|| {
        obj.metadata.owner_references.as_deref().and_then(|owners| {
            owners.first().map(|o| {
                (
                    o.api_version.clone(),
                    o.kind.clone(),
                    obj.metadata.namespace.clone().unwrap_or_default(),
                    o.name.clone(),
                )
            })
        })
    });

    for res in obj.data.get("results").and_then(|v| v.as_array()).into_iter().flatten() {
        let Some(result) = res
            .get("result")
            .and_then(|v| v.as_str())
            .and_then(KyResult::parse)
        else {
            continue;
        };
        let policy = res.get("policy").and_then(|v| v.as_str()).unwrap_or("");
        let rule = res.get("rule").and_then(|v| v.as_str()).unwrap_or("");
        let source = res.get("source").and_then(|v| v.as_str()).unwrap_or("kyverno");

        // A namespaced Policy is reported as `namespace/name`; only the name identifies the object.
        let bare = policy.rsplit('/').next().unwrap_or(policy);
        let idx = by_key
            .get(&(source.to_string(), bare.to_string()))
            .copied()
            // Older Kyverno stamped every result with `source: kyverno`, whatever the engine.
            .or_else(|| {
                by_key
                    .iter()
                    .find(|((_, n), _)| n == bare)
                    .map(|(_, i)| *i)
            });

        let policy_uid = match idx {
            Some(i) => {
                // The rule may be one Kyverno invented (`evaluation` on the CEL engine) or one that
                // has since been renamed: count it on the policy either way, never drop it.
                match policies[i].rules.iter_mut().find(|r| r.name == rule) {
                    Some(r) => r.counts.add_result(result),
                    None => {
                        if let Some(first) = policies[i].rules.first_mut() {
                            first.counts.add_result(result);
                        }
                    }
                }
                policies[i].uid()
            }
            None => String::new(),
        };

        if !result.is_problem() || violations.len() >= MAX_VIOLATIONS {
            continue;
        }

        let target = scope.clone().or_else(|| {
            res.get("resources")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(resource_ref)
        });
        let (api_version, kind, namespace, name) = target.unwrap_or_else(|| {
            (
                String::new(),
                String::new(),
                obj.metadata.namespace.clone().unwrap_or_default(),
                String::new(),
            )
        });

        let age = result_time(res).map(|t| format_age(&t)).unwrap_or_default();

        violations.push(KyViolation {
            policy_uid,
            policy: bare.to_string(),
            rule: rule.to_string(),
            result,
            severity: res.get("severity").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            category: res.get("category").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            message: res
                .get("message")
                .and_then(|v| v.as_str())
                .map(collapse_ws)
                .unwrap_or_default(),
            api_version,
            kind,
            namespace,
            name,
            process: res
                .get("properties")
                .and_then(|p| p.get("process"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            age,
        });
    }
}

fn resource_ref(v: &Value) -> Option<(String, String, String, String)> {
    let name = v.get("name").and_then(|x| x.as_str())?.to_string();
    Some((
        v.get("apiVersion").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        v.get("namespace").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        name,
    ))
}

// Result timestamps are `{seconds, nanos}`, not RFC3339 like everything else in the API.
fn result_time(res: &Value) -> Option<Timestamp> {
    let ts = res.get("timestamp")?;
    let secs = ts.get("seconds").and_then(|v| v.as_i64())?;
    let nanos = ts.get("nanos").and_then(|v| v.as_i64()).unwrap_or(0);
    Timestamp::new(secs, nanos as i32).ok()
}

// --- backlog ------------------------------------------------------------------------------------

// Resolve the newest available version of a kind and list it, or `None` if the kind does not exist
// on this cluster (older Kyverno, or a build without the generate/reports controllers).
async fn probe_list(
    client: &Client,
    group: &str,
    versions: &[&str],
    kind: &str,
) -> Option<Vec<DynamicObject>> {
    for v in versions {
        let gvk = GroupVersionKind::gvk(group, v, kind);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
            return api.list(&ListParams::default()).await.ok().map(|l| l.items);
        }
    }
    None
}

// Folds the UpdateRequest queue and the intermediate reports into the backlog summary. Kept apart
// from the policy and report listings so it rides the same concurrent wave.
async fn fetch_backlog(client: &Client) -> KyBacklog {
    let (urs, ephr, cephr) = futures::future::join3(
        probe_list(client, KYVERNO_GROUP, UR_VERSIONS, "UpdateRequest"),
        probe_list(client, EPHEMERAL_GROUP, EPHEMERAL_VERSIONS, "EphemeralReport"),
        probe_list(client, EPHEMERAL_GROUP, EPHEMERAL_VERSIONS, "ClusterEphemeralReport"),
    )
    .await;

    let mut b = KyBacklog {
        ephemeral_reports: ephr.map(|v| v.len()).unwrap_or(0)
            + cephr.map(|v| v.len()).unwrap_or(0),
        ..KyBacklog::default()
    };

    let Some(urs) = urs else { return b };
    b.known = true;
    fold_update_requests(&urs, &mut b);
    b
}

// Pure fold of the UpdateRequest list into `b`: state tallies, the worst offenders by stuck count,
// and the oldest stuck request's age.
fn fold_update_requests(urs: &[DynamicObject], b: &mut KyBacklog) {
    let mut stuck_by_policy: HashMap<String, usize> = HashMap::new();
    let mut oldest: Option<Timestamp> = None;

    for obj in urs {
        b.total += 1;
        let state = obj
            .data
            .get("status")
            .and_then(|s| s.get("state"))
            .and_then(|v| v.as_str())
            .map(KyRequestState::parse)
            .unwrap_or(KyRequestState::Other);
        match state {
            KyRequestState::Pending => b.pending += 1,
            KyRequestState::Failed => b.failed += 1,
            KyRequestState::Completed => b.completed += 1,
            KyRequestState::Skip => b.skip += 1,
            KyRequestState::Other => {}
        }
        if !state.is_stuck() {
            continue;
        }
        let policy = obj
            .data
            .get("spec")
            .and_then(|s| s.get("policy"))
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        *stuck_by_policy.entry(policy).or_default() += 1;
        if let Some(ts) = ur_created(obj) {
            if oldest.map(|o| ts < o).unwrap_or(true) {
                oldest = Some(ts);
            }
        }
    }

    let mut by_policy: Vec<(String, usize)> = stuck_by_policy.into_iter().collect();
    // Worst first, then by name so the order is stable across refreshes at equal depth.
    by_policy.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    b.by_policy = by_policy;
    b.oldest_stuck = oldest.map(|t| format_age(&t));
}

fn ur_created(obj: &DynamicObject) -> Option<Timestamp> {
    obj.metadata.creation_timestamp.as_ref().map(|t| t.0)
}

// Delete every stuck (Pending/Failed) UpdateRequest. This is the manual break in the feedback loop
// a jammed background controller cannot break on its own: the requests it can never drain are gone,
// and `synchronize: true` rules regenerate what is still needed on the next reconcile. Completed and
// Skip requests are left alone — they are not backlog. Returns the number actually deleted.
pub async fn purge_stuck_update_requests(client: Client) -> Result<usize, String> {
    let mut resolved = None;
    for v in UR_VERSIONS {
        let gvk = GroupVersionKind::gvk(KYVERNO_GROUP, v, "UpdateRequest");
        if let Ok((ar, _caps)) = discovery::pinned_kind(&client, &gvk).await {
            resolved = Some(ar);
            break;
        }
    }
    let ar = resolved.ok_or_else(|| crate::lang::active().ky_ur_missing.to_string())?;
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;

    // Resolve the targets first, then delete them in a bounded concurrent fan-out.
    let targets: Vec<(String, String)> = list
        .items
        .iter()
        .filter(|obj| {
            obj.data
                .get("status")
                .and_then(|s| s.get("state"))
                .and_then(|v| v.as_str())
                .map(KyRequestState::parse)
                .unwrap_or(KyRequestState::Other)
                .is_stuck()
        })
        .filter_map(|obj| {
            let name = obj.metadata.name.clone().unwrap_or_default();
            (!name.is_empty()).then(|| (obj.metadata.namespace.clone().unwrap_or_default(), name))
        })
        .collect();

    let outcomes: Vec<bool> = futures::stream::iter(targets.into_iter().map(|(ns, name)| {
        let client = client.clone();
        let ar = ar.clone();
        async move {
            let nsapi: Api<DynamicObject> = Api::namespaced_with(client, &ns, &ar);
            nsapi.delete(&name, &DeleteParams::background()).await.is_ok()
        }
    }))
    .buffer_unordered(PURGE_CONCURRENCY)
    .collect()
    .await;

    let deleted = outcomes.iter().filter(|ok| **ok).count();
    let errors = outcomes.len() - deleted;

    if errors > 0 {
        Err(crate::lang::fill(
            crate::lang::active().ky_purge_partial,
            &[("ok", &deleted.to_string()), ("ko", &errors.to_string())],
        ))
    } else {
        Ok(deleted)
    }
}

// --- health -------------------------------------------------------------------------------------

async fn fetch_health(client: &Client) -> KyHealth {
    let mut health = KyHealth::default();

    let deploys: Api<Deployment> = Api::namespaced(client.clone(), KYVERNO_NS);
    let params = ListParams::default().labels("app.kubernetes.io/part-of=kyverno");
    if let Ok(list) = deploys.list(&params).await {
        for d in &list.items {
            let name = d.metadata.name.clone().unwrap_or_default();
            let label = d
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("app.kubernetes.io/component"))
                .map(|c| c.trim_end_matches("-controller").to_string())
                .unwrap_or_else(|| name.clone());
            let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
            let ready = d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0);
            if health.version.is_empty() {
                if let Some(v) = d
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("app.kubernetes.io/version"))
                {
                    health.version = v.clone();
                }
            }
            health.controllers.push((label, ready, desired));
        }
        health.controllers.sort();
    }

    // The `kyverno-resource-*` configurations are the ones that intercept user workloads; the other
    // Kyverno webhooks only guard Kyverno's own CRDs and are always registered.
    let vw: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    let mw: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let (v, m) = futures::future::join(
        vw.get_opt("kyverno-resource-validating-webhook-cfg"),
        mw.get_opt("kyverno-resource-mutating-webhook-cfg"),
    )
    .await;
    if let Ok(v) = v {
        health.webhooks_known = true;
        health.validating_webhooks = v.and_then(|c| c.webhooks).map(|w| w.len()).unwrap_or(0);
    }
    if let Ok(m) = m {
        health.mutating_webhooks = m.and_then(|c| c.webhooks).map(|w| w.len()).unwrap_or(0);
    }

    health
}

// --- admission denials --------------------------------------------------------------------------

// Whether an event is Kyverno refusing a write at admission. Those refusals exist nowhere else: the
// rejected resource was never created, so no PolicyReport mentions it. Kyverno reports the
// component under `reportingComponent` rather than `source.component`, so a caller matching only on
// the latter finds nothing — hence the `(blocked)` marker as a second, message-level signal.
pub fn is_admission_denial(component: &str, message: &str) -> bool {
    component == "kyverno-admission" || message.contains("(blocked)")
}

// The Event's involvedObject is the *policy*, and the offending resource is named in the message as
// "Kind namespace/name: [rule] fail (blocked); …". Returns (resource, rule) for the detail panel.
pub fn parse_denial_message(message: &str) -> Option<(String, String)> {
    let (target, rest) = message.split_once(':')?;
    let rule = rest
        .split_once('[')
        .and_then(|(_, r)| r.split_once(']'))
        .map(|(r, _)| r.trim().to_string())
        .unwrap_or_default();
    Some((collapse_ws(target), rule))
}

// --- helpers ------------------------------------------------------------------------------------

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// "a, b, c +4" — keeps a column honest about how much it is not showing.
fn join_capped(items: &[String], max: usize) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!("{} +{}", items[..max].join(", "), items.len() - max)
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// --- What both interfaces share: verdicts, rows, records -----------------------------------------
//
// Everything below used to live in `ui.rs`. It moved here when kdt-web grew a kyverno view, for the
// reason every other view moved: a verdict written twice is a verdict that will diverge. The TUI and
// the browser now read the same tree, the same colours and the same synthetic records.

/// What the health band says about the installation itself, before any policy is read.
///
/// `Inactive` is the one that matters and the one nothing else on the cluster reports: every
/// controller green while no webhook is registered means Kyverno is intercepting nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KyHealthState {
    /// No controller Deployment was found at all — Kyverno is not deployed, or not readable.
    Unknown,
    /// A controller is short of replicas.
    Degraded,
    /// Controllers up, no `kyverno-resource-*` webhook registered: nothing is intercepted.
    Inactive,
    Ok,
}

impl KyHealth {
    pub fn state(&self) -> KyHealthState {
        if self.controllers.is_empty() {
            KyHealthState::Unknown
        } else if !self.controllers_ok() {
            KyHealthState::Degraded
        } else if self.silently_inactive() {
            KyHealthState::Inactive
        } else {
            KyHealthState::Ok
        }
    }
}

/// Which policies the view keeps.
///
/// `Problems` includes the policies that cannot evaluate, not only those rejecting something: a
/// policy that cannot run is silently protecting nothing, which is the worse of the two.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KyFilter {
    #[default]
    All,
    Problems,
    Enforce,
}

impl KyFilter {
    pub fn label(self) -> &'static str {
        match self {
            KyFilter::All => "ALL",
            KyFilter::Problems => "PROBLEMS",
            KyFilter::Enforce => "ENFORCE",
        }
    }

    pub fn matches(self, p: &KyPolicy) -> bool {
        match self {
            KyFilter::All => true,
            KyFilter::Problems => p.has_problem(),
            KyFilter::Enforce => p.action.blocks(),
        }
    }

    pub fn next(self) -> KyFilter {
        match self {
            KyFilter::All => KyFilter::Problems,
            KyFilter::Problems => KyFilter::Enforce,
            KyFilter::Enforce => KyFilter::All,
        }
    }
}

impl KyAction {
    /// The band a posture is painted in. `Enforce` is the only one that can break a deployment at
    /// 3am, so it reads as an alarm rather than as a label.
    pub fn tone(self) -> LineColor {
        match self {
            KyAction::Enforce => LineColor::Err,
            KyAction::Warn => LineColor::Warn,
            KyAction::Audit => LineColor::Info,
            KyAction::None => LineColor::Dim,
        }
    }
}

impl KyReady {
    pub fn label(self) -> &'static str {
        match self {
            KyReady::Ready => "Ready",
            KyReady::NotReady => "NotReady",
            KyReady::Unknown => "?",
        }
    }

    // Restricted to the font-safe glyph list guarded by `ui::glyph_guard`.
    pub fn glyph(self) -> &'static str {
        match self {
            KyReady::Ready => "✓",
            KyReady::NotReady => "✗",
            KyReady::Unknown => "·",
        }
    }

    pub fn tone(self) -> LineColor {
        match self {
            KyReady::Ready => LineColor::Ok,
            KyReady::NotReady => LineColor::Err,
            KyReady::Unknown => LineColor::Warn,
        }
    }
}

impl KyPolicy {
    /// A policy that needs a bed of its own: it cannot evaluate, or a rule is erroring. Both mean
    /// the policy is broken, as opposed to a resource being non-compliant.
    pub fn alarming(&self) -> bool {
        self.ready == KyReady::NotReady || self.counts.error > 0
    }

    /// What the policy applies to, taken from its authored rules — the autogen ones only restate
    /// the same match against the workload kinds Kyverno derived from it.
    pub fn scope(&self) -> String {
        if let Some(s) = self.schedule.as_ref() {
            return format!("cron {s}");
        }
        self.rules
            .iter()
            .find(|r| !r.autogen)
            .map(|r| r.match_summary.clone())
            .unwrap_or_default()
    }
}

impl KyViolation {
    /// The offending resource as one label. Cluster-scoped results carry no namespace.
    pub fn target(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.namespace, self.name)
        }
    }
}

// --- The join, laid out as a tree ----------------------------------------------------------------

/// One row of the kyverno tree, in either orientation.
///
/// The indices point into the **filtered** policy and violation lists the row builder was given:
/// rows and those lists travel together, and a row read against another list means another object.
#[derive(Debug, Clone)]
pub enum KyRow {
    Policy { idx: usize, collapsed: bool, has_children: bool },
    Rule { policy: usize, rule: usize, collapsed: bool, has_children: bool },
    Violation { idx: usize, depth: usize },
    Exception { policy: usize, exception: usize },
    Namespace { name: String, collapsed: bool, counts: KyCounts },
    Resource { kind: String, namespace: String, name: String, collapsed: bool, counts: KyCounts },
}

impl KyRow {
    pub fn depth(&self) -> usize {
        match self {
            KyRow::Policy { .. } | KyRow::Namespace { .. } => 0,
            KyRow::Rule { .. } | KyRow::Exception { .. } | KyRow::Resource { .. } => 1,
            KyRow::Violation { depth, .. } => *depth,
        }
    }

    pub fn has_children(&self) -> bool {
        match self {
            KyRow::Policy { has_children, .. } | KyRow::Rule { has_children, .. } => *has_children,
            // A namespace and a resource node are only ever emitted with children under them.
            KyRow::Namespace { .. } | KyRow::Resource { .. } => true,
            KyRow::Violation { .. } | KyRow::Exception { .. } => false,
        }
    }

    pub fn collapsed(&self) -> bool {
        match self {
            KyRow::Policy { collapsed, .. }
            | KyRow::Rule { collapsed, .. }
            | KyRow::Namespace { collapsed, .. }
            | KyRow::Resource { collapsed, .. } => *collapsed,
            KyRow::Violation { .. } | KyRow::Exception { .. } => false,
        }
    }

    /// The key this row folds under, or `None` for a leaf that cannot be folded.
    pub fn fold_key(&self, policies: &[KyPolicy]) -> Option<String> {
        match self {
            KyRow::Policy { idx, .. } => policies.get(*idx).map(|p| p.uid()),
            KyRow::Rule { policy, rule, .. } => {
                let p = policies.get(*policy)?;
                let r = p.rules.get(*rule)?;
                Some(ky_rule_uid(p, &r.name))
            }
            KyRow::Namespace { name, .. } => Some(format!("ns|{name}")),
            KyRow::Resource { kind, namespace, name, .. } => {
                Some(format!("res|{namespace}/{kind}/{name}"))
            }
            KyRow::Violation { .. } | KyRow::Exception { .. } => None,
        }
    }

    /// A stable identifier for the row, which is what lets a selection survive a refresh. It is not
    /// the fold key: a violation has an identity but nothing to fold.
    pub fn uid(&self, policies: &[KyPolicy], violations: &[KyViolation]) -> String {
        match self {
            KyRow::Violation { idx, .. } => violations
                .get(*idx)
                .map(|v| v.uid())
                .unwrap_or_else(|| format!("kyvio|{idx}")),
            KyRow::Exception { policy, exception } => policies
                .get(*policy)
                .and_then(|p| p.exceptions.get(*exception))
                .map(|e| format!("kyexc|{}/{}", e.namespace, e.name))
                .unwrap_or_else(|| format!("kyexc|{policy}|{exception}")),
            other => other.fold_key(policies).unwrap_or_default(),
        }
    }
}

/// The uid of a rule node. A rule is not an API object; it is identified by its policy plus its name.
pub fn ky_rule_uid(p: &KyPolicy, rule: &str) -> String {
    format!("{}|rule|{}", p.uid(), rule)
}

/// The tree, in the requested orientation, with the given nodes folded.
///
/// Prefix order, one row per node, each carrying its own depth: the callers only have to decide what
/// is folded. `by_resource` reads the same join from the other end — namespace, then resource, then
/// the policies it violates — which is the reading for "what is wrong here?" rather than "what does
/// this policy break?".
pub fn build_ky_rows(
    policies: &[KyPolicy],
    violations: &[KyViolation],
    by_resource: bool,
    collapsed: &std::collections::HashSet<String>,
) -> Vec<KyRow> {
    if by_resource {
        build_resource_rows(violations, collapsed)
    } else {
        build_policy_rows(policies, violations, collapsed)
    }
}

// Policy -> rule (+ the autogen ones) -> the resources that fail it, then the exceptions that excuse
// it. Answers "what does this policy do, and what is it breaking?".
fn build_policy_rows(
    policies: &[KyPolicy],
    violations: &[KyViolation],
    collapsed: &std::collections::HashSet<String>,
) -> Vec<KyRow> {
    let mut rows: Vec<KyRow> = Vec::new();
    for (pi, p) in policies.iter().enumerate() {
        let uid = p.uid();
        let folded = collapsed.contains(&uid);
        let has_children = !p.rules.is_empty() || !p.exceptions.is_empty();
        rows.push(KyRow::Policy { idx: pi, collapsed: folded, has_children });
        if folded {
            continue;
        }

        for (ri, r) in p.rules.iter().enumerate() {
            let ruid = ky_rule_uid(p, &r.name);
            let rule_violations: Vec<usize> = violations
                .iter()
                .enumerate()
                .filter(|(_, v)| v.policy_uid == uid && v.rule == r.name)
                .map(|(i, _)| i)
                .collect();
            let rfolded = collapsed.contains(&ruid);
            rows.push(KyRow::Rule {
                policy: pi,
                rule: ri,
                collapsed: rfolded,
                has_children: !rule_violations.is_empty(),
            });
            if rfolded {
                continue;
            }
            for vi in rule_violations {
                rows.push(KyRow::Violation { idx: vi, depth: 2 });
            }
        }

        for (ei, _) in p.exceptions.iter().enumerate() {
            rows.push(KyRow::Exception { policy: pi, exception: ei });
        }
    }
    rows
}

// Namespace -> resource -> the policies it violates.
fn build_resource_rows(
    violations: &[KyViolation],
    collapsed: &std::collections::HashSet<String>,
) -> Vec<KyRow> {
    // Preserve the violation ordering (worst result first) while grouping, so the namespace and the
    // resource that need attention stay at the top.
    let mut ns_order: Vec<String> = Vec::new();
    let mut by_ns: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, v) in violations.iter().enumerate() {
        let ns = v.namespace.clone();
        if !by_ns.contains_key(&ns) {
            ns_order.push(ns.clone());
        }
        by_ns.entry(ns).or_default().push(i);
    }

    let mut rows: Vec<KyRow> = Vec::new();
    for ns in ns_order {
        let idxs = &by_ns[&ns];
        let mut counts = KyCounts::default();
        for i in idxs {
            counts.add_result(violations[*i].result);
        }
        let nfolded = collapsed.contains(&format!("ns|{ns}"));
        rows.push(KyRow::Namespace { name: ns.clone(), collapsed: nfolded, counts });
        if nfolded {
            continue;
        }

        let mut res_order: Vec<(String, String)> = Vec::new();
        let mut by_res: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for i in idxs {
            let key = (violations[*i].kind.clone(), violations[*i].name.clone());
            if !by_res.contains_key(&key) {
                res_order.push(key.clone());
            }
            by_res.entry(key).or_default().push(*i);
        }

        for key in res_order {
            let vis = &by_res[&key];
            let mut rcounts = KyCounts::default();
            for i in vis {
                rcounts.add_result(violations[*i].result);
            }
            let rfolded = collapsed.contains(&format!("res|{}/{}/{}", ns, key.0, key.1));
            rows.push(KyRow::Resource {
                kind: key.0.clone(),
                namespace: ns.clone(),
                name: key.1.clone(),
                collapsed: rfolded,
                counts: rcounts,
            });
            if rfolded {
                continue;
            }
            for i in vis {
                rows.push(KyRow::Violation { idx: *i, depth: 2 });
            }
        }
    }
    rows
}

/// Whether kdt folds this node by default.
///
/// A healthy policy's rules are noise; a failing one's are the answer. The rule lives here so the
/// browser does not restate it: it receives the verdict per row and only remembers what a human
/// folded by hand.
pub fn ky_default_folded(row: &KyRow, policies: &[KyPolicy]) -> bool {
    match row {
        KyRow::Policy { idx, .. } => policies.get(*idx).is_none_or(|p| !p.has_problem()),
        KyRow::Rule { policy, rule, .. } => policies
            .get(*policy)
            .and_then(|p| p.rules.get(*rule))
            .is_none_or(|r| r.counts.problems() == 0),
        // Les regroupements par namespace et par ressource s'ouvrent : ils ne sont émis que
        // lorsqu'il y a quelque chose dessous, et ce quelque chose est toujours un constat.
        _ => false,
    }
}

/// Fold the healthy, open the failing — except where someone folded by hand.
///
/// A healthy policy's rules are noise; a failing one's are the answer. Recomputed on every refresh
/// so a policy that starts rejecting things opens itself, but never against a deliberate choice:
/// `user_toggled` holds the nodes whose state was decided by a human, and they are left alone.
pub fn ky_autofold(
    policies: &[KyPolicy],
    user_toggled: &std::collections::HashSet<String>,
    collapsed: &mut std::collections::HashSet<String>,
) {
    for (pi, p) in policies.iter().enumerate() {
        let uid = p.uid();
        let row = KyRow::Policy { idx: pi, collapsed: false, has_children: false };
        if !user_toggled.contains(&uid) {
            if ky_default_folded(&row, policies) {
                collapsed.insert(uid.clone());
            } else {
                collapsed.remove(&uid);
            }
        }
        for (ri, r) in p.rules.iter().enumerate() {
            let ruid = ky_rule_uid(p, &r.name);
            if user_toggled.contains(&ruid) {
                continue;
            }
            let row = KyRow::Rule { policy: pi, rule: ri, collapsed: false, has_children: false };
            if ky_default_folded(&row, policies) {
                collapsed.insert(ruid);
            } else {
                collapsed.remove(&ruid);
            }
        }
    }
}

// --- Synthetic records ---------------------------------------------------------------------------
//
// A Kyverno policy is an object, but a rule, a namespace grouping and a violation are not: they get
// a record pointing at the object a human would want to open. That is what gives this view the
// generic gestures — YAML, edit, touch, delete, Status, Related — without a line of its own.

pub fn synthetic_policy_record(p: &KyPolicy) -> EventRecord {
    let (severity, reason) = match p.ready {
        KyReady::Ready if p.counts.error > 0 => (Severity::Warning, "PolicyError".to_string()),
        KyReady::Ready if p.counts.fail > 0 => (Severity::Warning, "PolicyViolation".to_string()),
        KyReady::Ready => (Severity::Normal, "Ready".to_string()),
        KyReady::NotReady => (Severity::Warning, "NotReady".to_string()),
        KyReady::Unknown => (Severity::Normal, "Unknown".to_string()),
    };
    let message = if p.ready_message.is_empty() {
        format!("{} {} · {}", p.kind.as_str(), p.name, p.action.label())
    } else {
        p.ready_message.clone()
    };
    EventRecord {
        uid: format!("ky|{}", p.uid()),
        time: Timestamp::now(),
        severity,
        reason,
        api_version: p.api_version.clone(),
        kind: p.kind.as_str().to_string(),
        namespace: p.namespace.clone(),
        name: p.name.clone(),
        message,
        component: "kyverno".to_string(),
        host: String::new(),
        count: 1,
    }
}

// A rule is not an API object of its own: the record points at the policy, so the generic gestures
// open the thing that can actually be edited.
pub fn synthetic_rule_record(p: &KyPolicy, rule: &str, st: &'static Strings) -> EventRecord {
    EventRecord {
        uid: format!("kyrule|{}|{}", p.uid(), rule),
        reason: "Rule".to_string(),
        severity: Severity::Normal,
        message: crate::lang::fill(st.rec_rule, &[("policy", &p.name), ("rule", rule)]),
        ..synthetic_policy_record(p)
    }
}

pub fn synthetic_violation_record(v: &KyViolation) -> EventRecord {
    let severity = if v.result == KyResult::Warn { Severity::Normal } else { Severity::Warning };
    EventRecord {
        uid: format!("kyvio|{}", v.uid()),
        time: Timestamp::now(),
        severity,
        reason: v.result.label().to_string(),
        // Reports do not always name the apiVersion; the caller defaults it to v1, which is right
        // for the core kinds and harmless elsewhere since discovery resolves the kind.
        api_version: v.api_version.clone(),
        kind: v.kind.clone(),
        namespace: v.namespace.clone(),
        name: v.name.clone(),
        message: v.message.clone(),
        component: "kyverno".to_string(),
        host: String::new(),
        count: 1,
    }
}

pub fn synthetic_exception_record(e: &KyException, st: &'static Strings) -> EventRecord {
    EventRecord {
        uid: format!("kyexc|{}/{}", e.namespace, e.name),
        time: Timestamp::now(),
        severity: Severity::Normal,
        reason: "Exception".to_string(),
        api_version: e.api_version.clone(),
        kind: "PolicyException".to_string(),
        namespace: e.namespace.clone(),
        name: e.name.clone(),
        message: crate::lang::fill(st.ky_rec_excludes, &[("summary", &e.match_summary)]),
        component: "kyverno".to_string(),
        host: String::new(),
        count: 1,
    }
}

pub fn synthetic_namespace_record(ns: &str, counts: &KyCounts) -> EventRecord {
    EventRecord {
        uid: format!("kyns|{ns}"),
        time: Timestamp::now(),
        severity: if counts.fail + counts.error > 0 { Severity::Warning } else { Severity::Normal },
        reason: "Namespace".to_string(),
        api_version: "v1".to_string(),
        // The cluster-scoped bucket has no Namespace object behind it: leaving the kind empty is
        // what keeps the generic gestures from offering to open one.
        kind: if ns.is_empty() { String::new() } else { "Namespace".to_string() },
        namespace: String::new(),
        name: ns.to_string(),
        message: counts.summary(),
        component: "kyverno".to_string(),
        host: String::new(),
        count: 1,
    }
}

/// The record a row points at, so rows and records stay index-aligned by construction.
pub fn record_for_row(
    row: &KyRow,
    policies: &[KyPolicy],
    violations: &[KyViolation],
    st: &'static Strings,
) -> EventRecord {
    match row {
        KyRow::Policy { idx, .. } => policies
            .get(*idx)
            .map(synthetic_policy_record)
            .unwrap_or_else(|| synthetic_namespace_record("", &KyCounts::default())),
        KyRow::Rule { policy, rule, .. } => policies
            .get(*policy)
            .map(|p| {
                let name = p.rules.get(*rule).map(|r| r.name.as_str()).unwrap_or_default();
                synthetic_rule_record(p, name, st)
            })
            .unwrap_or_else(|| synthetic_namespace_record("", &KyCounts::default())),
        KyRow::Violation { idx, .. } => violations
            .get(*idx)
            .map(synthetic_violation_record)
            .unwrap_or_else(|| synthetic_namespace_record("", &KyCounts::default())),
        KyRow::Exception { policy, exception } => policies
            .get(*policy)
            .and_then(|p| p.exceptions.get(*exception))
            .map(|e| synthetic_exception_record(e, st))
            .unwrap_or_else(|| synthetic_namespace_record("", &KyCounts::default())),
        KyRow::Namespace { name, counts, .. } => synthetic_namespace_record(name, counts),
        // The resource node stands for the object itself: its record is that of its first violation,
        // which is the only place the apiVersion of the offending object is written down.
        KyRow::Resource { kind, namespace, name, .. } => violations
            .iter()
            .find(|v| &v.kind == kind && &v.namespace == namespace && &v.name == name)
            .map(synthetic_violation_record)
            .unwrap_or_else(|| synthetic_namespace_record(namespace, &KyCounts::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dynamic(kind: &str, name: &str, body: Value) -> DynamicObject {
        let mut obj: Value = json!({
            "apiVersion": "kyverno.io/v1",
            "kind": kind,
            "metadata": { "name": name },
        });
        for (k, v) in body.as_object().expect("objet attendu") {
            obj[k] = v.clone();
        }
        serde_json::from_value(obj).expect("DynamicObject")
    }

    // --- posture ---

    #[test]
    fn per_rule_failure_action_wins_over_policy_wide() {
        let spec = json!({
            "validationFailureAction": "Audit",
            "rules": [
                { "name": "a", "validate": { "failureAction": "Enforce", "message": "m" } },
                { "name": "b", "validate": { "message": "m" } },
            ]
        });
        let rules = parse_rules(KyKind::ClusterPolicy, Some(&spec), None);
        assert_eq!(rules[0].action, KyAction::Enforce);
        // Rule `b` states nothing, so it falls back to the policy-wide posture.
        assert_eq!(rules[1].action, KyAction::Audit);
    }

    #[test]
    fn validating_rule_without_any_action_audits() {
        let spec = json!({ "rules": [{ "name": "a", "validate": { "message": "m" } }] });
        let rules = parse_rules(KyKind::ClusterPolicy, Some(&spec), None);
        assert_eq!(rules[0].action, KyAction::Audit);
    }

    #[test]
    fn mutate_rule_blocks_nothing() {
        let spec = json!({ "rules": [{ "name": "a", "mutate": { "patchStrategicMerge": {} } }] });
        let rules = parse_rules(KyKind::ClusterPolicy, Some(&spec), None);
        assert_eq!(rules[0].verb, "mutate");
        assert_eq!(rules[0].action, KyAction::None);
    }

    #[test]
    fn cel_deny_is_enforce() {
        let spec = json!({ "validationActions": ["Audit", "Deny"] });
        let rules = parse_cel_rules(Some(&spec));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "evaluation");
        assert_eq!(rules[0].action, KyAction::Enforce);
    }

    #[test]
    fn cel_without_actions_audits() {
        let rules = parse_cel_rules(Some(&json!({})));
        assert_eq!(rules[0].action, KyAction::Audit);
    }

    #[test]
    fn policy_action_is_the_strongest_rule() {
        let obj = dynamic(
            "ClusterPolicy",
            "mixed",
            json!({ "spec": { "rules": [
                { "name": "a", "validate": { "failureAction": "Audit", "message": "m" } },
                { "name": "b", "validate": { "failureAction": "Enforce", "message": "m" } },
            ]}}),
        );
        let p = parse_policy(&obj, "ClusterPolicy", "kyverno.io/v1").expect("policy");
        assert_eq!(p.action, KyAction::Enforce);
    }

    #[test]
    fn namespace_overrides_are_kept() {
        let spec = json!({
            "validationFailureActionOverrides": [
                { "action": "Enforce", "namespaces": ["prod", "stage"] },
                { "action": "Audit", "namespaces": ["dev"] },
            ]
        });
        let ov = parse_overrides(Some(&spec));
        assert_eq!(ov.len(), 2);
        assert_eq!(ov[0].action, KyAction::Enforce);
        assert_eq!(ov[0].namespaces, vec!["prod", "stage"]);
    }

    // --- readiness ---

    #[test]
    fn v1_ready_condition_is_read() {
        let status = json!({ "conditions": [
            { "type": "Ready", "status": "False", "reason": "Failed", "message": "règle invalide" }
        ]});
        let (ready, msg) = parse_ready(KyKind::ClusterPolicy, Some(&status));
        assert_eq!(ready, KyReady::NotReady);
        assert_eq!(msg, "Failed: règle invalide");
    }

    #[test]
    fn v1_ready_true_drops_the_noise_message() {
        let status = json!({ "conditions": [
            { "type": "Ready", "status": "True", "reason": "Succeeded", "message": "Ready" }
        ]});
        let (ready, msg) = parse_ready(KyKind::ClusterPolicy, Some(&status));
        assert_eq!(ready, KyReady::Ready);
        assert_eq!(msg, "");
    }

    // The trap: the CEL engine emits no `Ready` condition at all. Reading conditions the usual way
    // would report every ValidatingPolicy as Unknown.
    #[test]
    fn cel_readiness_comes_from_condition_status() {
        let status = json!({ "conditionStatus": {
            "ready": true,
            "message": "",
            "conditions": [
                { "type": "WebhookConfigured", "status": "True", "reason": "Succeeded", "message": "Webhook configured." },
                { "type": "RBACPermissionsGranted", "status": "True", "reason": "Succeeded", "message": "ok" },
            ]
        }});
        assert_eq!(parse_ready(KyKind::ValidatingPolicy, Some(&status)).0, KyReady::Ready);
        // The same status read as a v1 policy finds nothing — which is why the kind matters.
        assert_eq!(parse_ready(KyKind::ClusterPolicy, Some(&status)).0, KyReady::Unknown);
    }

    #[test]
    fn cel_not_ready_surfaces_the_failing_condition() {
        let status = json!({ "conditionStatus": {
            "ready": false,
            "message": "",
            "conditions": [
                { "type": "WebhookConfigured", "status": "False", "reason": "Failed", "message": "compilation CEL" },
            ]
        }});
        let (ready, msg) = parse_ready(KyKind::ValidatingPolicy, Some(&status));
        assert_eq!(ready, KyReady::NotReady);
        assert_eq!(msg, "Failed: compilation CEL");
    }

    #[test]
    fn background_default_and_cel_nesting() {
        assert!(parse_background(KyKind::ClusterPolicy, Some(&json!({}))));
        assert!(!parse_background(
            KyKind::ClusterPolicy,
            Some(&json!({ "background": false }))
        ));
        assert!(!parse_background(
            KyKind::ValidatingPolicy,
            Some(&json!({ "evaluation": { "background": { "enabled": false } } }))
        ));
    }

    // --- scope ---

    #[test]
    fn match_summary_reads_any_and_exclude() {
        let m = json!({ "any": [{ "resources": { "kinds": ["Pod", "Deployment"], "namespaces": ["prod"] } }] });
        let e = json!({ "any": [{ "resources": { "namespaces": ["kube-system"] } }] });
        assert_eq!(
            match_summary(Some(&m), Some(&e)),
            "Pod, Deployment · ns prod · sauf kube-system"
        );
    }

    #[test]
    fn match_summary_reads_the_bare_resources_shape() {
        let m = json!({ "resources": { "kinds": ["Secret"] } });
        assert_eq!(match_summary(Some(&m), None), "Secret");
    }

    #[test]
    fn match_summary_without_kinds_is_a_wildcard() {
        assert_eq!(match_summary(Some(&json!({})), None), "*");
    }

    #[test]
    fn cel_scope_comes_from_match_constraints() {
        let spec = json!({ "matchConstraints": {
            "resourceRules": [{ "resources": ["deployments", "statefulsets"] }],
            "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "test" } }
        }});
        assert_eq!(cel_match_summary(Some(&spec)), "deployments, statefulsets · ns test");
    }

    #[test]
    fn long_kind_lists_are_capped() {
        let items: Vec<String> = ["a", "b", "c", "d", "e"].iter().map(|s| s.to_string()).collect();
        assert_eq!(join_capped(&items, 3), "a, b, c +2");
    }

    // --- autogen ---

    // The trap: reports about a Deployment name `autogen-*`, never the authored rule.
    #[test]
    fn autogen_rules_are_loaded_and_flagged() {
        let spec = json!({ "rules": [{ "name": "validate-resources", "validate": { "failureAction": "Enforce", "message": "m" } }] });
        let status = json!({ "autogen": { "rules": [
            { "name": "autogen-validate-resources",
              "match": { "any": [{ "resources": { "kinds": ["Deployment", "Job"] } }] },
              "validate": { "failureAction": "Enforce", "message": "m" } },
            { "name": "autogen-cronjob-validate-resources",
              "match": { "any": [{ "resources": { "kinds": ["CronJob"] } }] },
              "validate": { "failureAction": "Enforce", "message": "m" } },
        ]}});
        let rules = parse_rules(KyKind::ClusterPolicy, Some(&spec), Some(&status));
        assert_eq!(rules.len(), 3);
        assert!(!rules[0].autogen);
        assert!(rules[1].autogen && rules[2].autogen);
        assert_eq!(rules[1].name, "autogen-validate-resources");
        assert_eq!(rules[1].match_summary, "Deployment, Job");
    }

    // --- exceptions ---

    #[test]
    fn exception_v2_targets_policy_and_rules() {
        let obj = dynamic(
            "PolicyException",
            "legacy-allow",
            json!({ "spec": {
                "exceptions": [{ "policyName": "require-limits", "ruleNames": ["autogen-validate-resources"] }],
                "match": { "any": [{ "resources": { "kinds": ["Deployment"], "namespaces": ["legacy"] } }] }
            }}),
        );
        let (exc, targets) = parse_exception(&obj, "kyverno.io/v2").expect("exception");
        assert_eq!(targets, vec!["require-limits"]);
        assert_eq!(exc.rules, vec!["autogen-validate-resources"]);
        assert_eq!(exc.match_summary, "Deployment · ns legacy");
    }

    #[test]
    fn exception_cel_targets_policy_refs() {
        let obj = dynamic(
            "PolicyException",
            "cel-allow",
            json!({ "spec": { "policyRefs": [{ "name": "broken-cel-check" }] } }),
        );
        let (_, targets) = parse_exception(&obj, "policies.kyverno.io/v1").expect("exception");
        assert_eq!(targets, vec!["broken-cel-check"]);
    }

    #[test]
    fn namespaced_target_needs_the_namespace_to_match() {
        let mut p = parse_policy(
            &dynamic("Policy", "p", json!({ "spec": { "rules": [] } })),
            "Policy",
            "kyverno.io/v1",
        )
        .expect("policy");
        p.namespace = "prod".into();
        assert!(target_matches("p", &p));
        assert!(target_matches("prod/p", &p));
        assert!(!target_matches("dev/p", &p));
    }

    // --- reports ---

    fn policy(kind: KyKind, name: &str, rules: &[&str]) -> KyPolicy {
        KyPolicy {
            kind,
            api_version: "kyverno.io/v1".into(),
            namespace: String::new(),
            name: name.into(),
            title: String::new(),
            action: KyAction::Audit,
            background: true,
            admission: true,
            ready: KyReady::Ready,
            ready_message: String::new(),
            rules: rules
                .iter()
                .map(|r| KyRule {
                    name: r.to_string(),
                    verb: "validate".into(),
                    autogen: r.starts_with("autogen-"),
                    action: KyAction::Audit,
                    match_summary: String::new(),
                    message: String::new(),
                    counts: KyCounts::default(),
                })
                .collect(),
            exceptions: Vec::new(),
            overrides: Vec::new(),
            counts: KyCounts::default(),
            schedule: None,
            age: String::new(),
        }
    }

    fn report(scope_kind: &str, scope_name: &str, results: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "wgpolicyk8s.io/v1alpha2",
            "kind": "PolicyReport",
            "metadata": { "name": "r1", "namespace": "prod" },
            "scope": { "apiVersion": "apps/v1", "kind": scope_kind, "namespace": "prod", "name": scope_name },
            "results": results,
        }))
        .expect("DynamicObject")
    }

    fn read(policies: &mut [KyPolicy], obj: &DynamicObject) -> Vec<KyViolation> {
        attribute_reports(std::slice::from_ref(obj), policies)
    }

    #[test]
    fn results_are_counted_on_their_autogen_rule() {
        let mut policies = vec![policy(
            KyKind::ClusterPolicy,
            "require-limits",
            &["validate-resources", "autogen-validate-resources"],
        )];
        let obj = report(
            "Deployment",
            "bad-limits",
            json!([
                { "policy": "require-limits", "rule": "autogen-validate-resources", "result": "fail", "source": "kyverno", "message": "m" },
                { "policy": "require-limits", "rule": "validate-resources", "result": "pass", "source": "kyverno", "message": "m" },
            ]),
        );
        let vios = read(&mut policies, &obj);
        assert_eq!(policies[0].rules[1].counts.fail, 1);
        assert_eq!(policies[0].rules[0].counts.pass, 1);
        // Only the non-passing result becomes a row.
        assert_eq!(vios.len(), 1);
    }

    // The violation must point at the offending resource, not at the policy: that reference is what
    // `y`, `h` and `Ctrl-D` act on.
    #[test]
    fn violation_targets_the_scope_of_the_report() {
        let mut policies = vec![policy(KyKind::ClusterPolicy, "p", &["r"])];
        let obj = report(
            "Deployment",
            "bad-limits",
            json!([{ "policy": "p", "rule": "r", "result": "fail", "source": "kyverno", "message": "boom" }]),
        );
        let vios = read(&mut policies, &obj);
        assert_eq!(vios[0].kind, "Deployment");
        assert_eq!(vios[0].namespace, "prod");
        assert_eq!(vios[0].name, "bad-limits");
        assert_eq!(vios[0].api_version, "apps/v1");
        assert_eq!(vios[0].policy_uid, policies[0].uid());
    }

    // Aggregated reports have no `scope` and repeat the subject on each result instead.
    #[test]
    fn violation_falls_back_to_the_per_result_resource_list() {
        let mut policies = vec![policy(KyKind::ClusterPolicy, "p", &["r"])];
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "wgpolicyk8s.io/v1alpha2",
            "kind": "PolicyReport",
            "metadata": { "name": "polr-ns-prod", "namespace": "prod" },
            "results": [{
                "policy": "p", "rule": "r", "result": "fail", "source": "kyverno", "message": "m",
                "resources": [{ "apiVersion": "v1", "kind": "Pod", "namespace": "prod", "name": "web" }],
            }],
        }))
        .expect("DynamicObject");
        let vios = read(&mut policies, &obj);
        assert_eq!((vios[0].kind.as_str(), vios[0].name.as_str()), ("Pod", "web"));
    }

    // Two policies of different kinds may share a name; `source` is what tells them apart.
    #[test]
    fn source_disambiguates_policies_sharing_a_name() {
        let mut policies = vec![
            policy(KyKind::ClusterPolicy, "shared", &["r"]),
            policy(KyKind::ValidatingPolicy, "shared", &["evaluation"]),
        ];
        let obj = report(
            "Deployment",
            "d",
            json!([{ "policy": "shared", "rule": "evaluation", "result": "error",
                     "source": "KyvernoValidatingPolicy", "message": "index out of bounds" }]),
        );
        let vios = read(&mut policies, &obj);
        assert_eq!(policies[1].rules[0].counts.error, 1);
        assert_eq!(policies[0].counts.error, 0);
        assert_eq!(vios[0].policy_uid, policies[1].uid());
    }

    // A rule name Kyverno invented, or one renamed since the last scan, must still be counted.
    #[test]
    fn unknown_rule_name_still_counts_on_the_policy() {
        let mut policies = vec![policy(KyKind::ClusterPolicy, "p", &["r"])];
        let obj = report(
            "Deployment",
            "d",
            json!([{ "policy": "p", "rule": "disparue", "result": "fail", "source": "kyverno", "message": "m" }]),
        );
        read(&mut policies, &obj);
        assert_eq!(policies[0].rules[0].counts.fail, 1);
    }

    #[test]
    fn namespaced_policy_reported_with_its_namespace_prefix() {
        let mut policies = vec![policy(KyKind::Policy, "local", &["r"])];
        let obj = report(
            "Pod",
            "p",
            json!([{ "policy": "prod/local", "rule": "r", "result": "fail", "source": "kyverno", "message": "m" }]),
        );
        let vios = read(&mut policies, &obj);
        assert_eq!(vios[0].policy_uid, policies[0].uid());
    }

    #[test]
    fn result_timestamp_is_seconds_and_nanos() {
        let res = json!({ "timestamp": { "seconds": 1785056093, "nanos": 0 } });
        assert_eq!(result_time(&res).expect("timestamp").as_second(), 1785056093);
        assert!(result_time(&json!({})).is_none());
    }

    // --- ordering ---

    #[test]
    fn broken_policies_outrank_merely_failing_ones() {
        let mut not_ready = policy(KyKind::ClusterPolicy, "a", &[]);
        not_ready.ready = KyReady::NotReady;
        let mut erroring = policy(KyKind::ClusterPolicy, "b", &[]);
        erroring.counts.error = 1;
        let mut failing = policy(KyKind::ClusterPolicy, "c", &[]);
        failing.counts.fail = 9;
        let healthy = policy(KyKind::ClusterPolicy, "d", &[]);

        let mut all = [healthy, failing, erroring, not_ready];
        all.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn enforcing_policies_come_before_advisory_ones() {
        let mut audit = policy(KyKind::ClusterPolicy, "a-audit", &[]);
        audit.action = KyAction::Audit;
        let mut enforce = policy(KyKind::ClusterPolicy, "z-enforce", &[]);
        enforce.action = KyAction::Enforce;
        let mut all = [audit, enforce];
        all.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        assert_eq!(all[0].name, "z-enforce");
    }

    #[test]
    fn errors_sort_above_fails_in_the_violation_list() {
        let mk = |result: KyResult, name: &str| KyViolation {
            policy_uid: String::new(),
            policy: "p".into(),
            rule: "r".into(),
            result,
            severity: String::new(),
            category: String::new(),
            message: String::new(),
            api_version: String::new(),
            kind: "Pod".into(),
            namespace: "prod".into(),
            name: name.into(),
            process: String::new(),
            age: String::new(),
        };
        let mut all = [mk(KyResult::Warn, "w"), mk(KyResult::Fail, "f"), mk(KyResult::Error, "e")];
        all.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        let names: Vec<&str> = all.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["e", "f", "w"]);
    }

    // --- counters ---

    #[test]
    fn summary_skips_empty_buckets() {
        let c = KyCounts { pass: 204, fail: 12, warn: 0, error: 1, skip: 3 };
        assert_eq!(c.summary(), "×1 ✗12 ✓204");
        assert_eq!(c.problems(), 13);
        assert_eq!(KyCounts::default().summary(), "");
    }

    // --- health ---

    #[test]
    fn green_controllers_with_no_webhook_read_as_inactive() {
        let health = KyHealth {
            controllers: vec![("admission".into(), 1, 1), ("reports".into(), 1, 1)],
            webhooks_known: true,
            validating_webhooks: 0,
            mutating_webhooks: 0,
            ..Default::default()
        };
        assert!(health.controllers_ok());
        assert!(health.silently_inactive());
    }

    #[test]
    fn a_registered_webhook_clears_the_inactive_flag() {
        let health = KyHealth {
            controllers: vec![("admission".into(), 1, 1)],
            webhooks_known: true,
            validating_webhooks: 2,
            ..Default::default()
        };
        assert!(!health.silently_inactive());
    }

    #[test]
    fn a_controller_short_of_replicas_is_not_ok() {
        let health = KyHealth {
            controllers: vec![("admission".into(), 0, 1)],
            ..Default::default()
        };
        assert!(!health.controllers_ok());
    }

    // --- admission denials ---

    #[test]
    fn denial_recognised_by_component_or_marker() {
        assert!(is_admission_denial("kyverno-admission", ""));
        // Kyverno fills `reportingComponent`, not `source.component`: the marker is the fallback.
        assert!(is_admission_denial("", "Pod prod/x: [r] fail (blocked); nope"));
        assert!(!is_admission_denial("kyverno-scan", "Pod prod/x: [r] fail; nope"));
    }

    #[test]
    fn denial_message_yields_resource_and_rule() {
        let msg = "Pod kdt-kyverno-test/refused: [validate-resources] fail (blocked); validation error: …";
        let (target, rule) = parse_denial_message(msg).expect("message");
        assert_eq!(target, "Pod kdt-kyverno-test/refused");
        assert_eq!(rule, "validate-resources");
    }

    // --- backlog ---

    fn update_request(policy: &str, state: &str, created: &str) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "kyverno.io/v2",
            "kind": "UpdateRequest",
            "metadata": { "name": "ur-x", "namespace": "kyverno", "creationTimestamp": created },
            "spec": { "policy": policy, "requestType": "generate" },
            "status": { "state": state },
        }))
        .expect("UpdateRequest")
    }

    #[test]
    fn backlog_tallies_states_and_worst_offenders() {
        let urs = vec![
            update_request("gen-rbac", "Pending", "2026-08-06T00:00:00Z"),
            update_request("gen-rbac", "Pending", "2026-08-08T00:00:00Z"),
            update_request("gen-np", "Failed", "2026-08-09T00:00:00Z"),
            update_request("gen-np", "Completed", "2026-08-09T00:00:00Z"),
        ];
        let mut b = KyBacklog::default();
        fold_update_requests(&urs, &mut b);
        assert_eq!((b.total, b.pending, b.failed, b.completed), (4, 2, 1, 1));
        assert_eq!(b.stuck(), 3);
        // Only Pending and Failed are stuck; gen-rbac owns two of them, gen-np one.
        assert_eq!(b.by_policy, vec![("gen-rbac".into(), 2), ("gen-np".into(), 1)]);
        // A stuck request that has been waiting since 2026-08-06 has a non-empty age.
        assert!(b.oldest_stuck.is_some_and(|a| !a.is_empty()));
    }

    // A Completed request never counts as backlog, however old it is.
    #[test]
    fn completed_requests_are_not_backlog() {
        let urs = vec![
            update_request("gen-np", "Completed", "2020-01-01T00:00:00Z"),
            update_request("gen-np", "Skip", "2026-08-09T00:00:00Z"),
        ];
        let mut b = KyBacklog::default();
        fold_update_requests(&urs, &mut b);
        assert_eq!(b.stuck(), 0);
        assert!(b.by_policy.is_empty());
        assert!(b.oldest_stuck.is_none());
    }

    // A request whose status has not been written yet is `Other`, not stuck.
    #[test]
    fn missing_state_is_not_stuck() {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "kyverno.io/v2",
            "kind": "UpdateRequest",
            "metadata": { "name": "ur-x", "namespace": "kyverno" },
            "spec": { "policy": "gen-np", "requestType": "generate" },
        }))
        .expect("UpdateRequest");
        let mut b = KyBacklog::default();
        fold_update_requests(std::slice::from_ref(&obj), &mut b);
        assert_eq!(b.total, 1);
        assert_eq!(b.stuck(), 0);
    }

    #[test]
    fn pileup_threshold_gates_the_anomaly() {
        let below = KyBacklog { pending: UR_PILEUP - 1, ..KyBacklog::default() };
        let at = KyBacklog { pending: UR_PILEUP, ..KyBacklog::default() };
        assert!(!below.has_pileup());
        assert!(at.has_pileup());
    }
}
