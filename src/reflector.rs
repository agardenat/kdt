//! Reflector inventory for the `:reflector` view (emberstack/kubernetes-reflector).
//!
//! Reflector mirrors Secrets and ConfigMaps across namespaces from a single annotated source. The
//! point of this view is not to list the copies — `kubectl get secret -A` already does that — but
//! to say *why a mirror is not there, or no longer matches its source*, which is the part that
//! costs an afternoon. Reflector is almost entirely silent when it decides to do nothing: it skips
//! a namespace whose name is already taken, it never re-pushes a mirror whose recorded version
//! still matches, and it deletes mirrors that fall out of the automatic scope. None of that
//! produces an Event, a condition, or a status field — only a debug log line inside the controller.
//!
//! Everything the rules need is fetched in one pass — the objects themselves, the namespaces (with
//! their labels, for the selector annotations), and the pods and ServiceAccounts that consume them
//! — so the diagnosis comes from a single consistent view. The rules ([`diagnose`]) are pure
//! functions over that snapshot: no client, no I/O, testable.
//!
//! The scope arithmetic is reproduced from upstream rather than approximated, because the whole
//! view is an answer to "what will reflector actually do": see [`pattern_list_match`] and
//! [`selector_match`], which mirror `MirroringPropertiesExtensions.cs`. Where a source's scope
//! cannot be resolved (an unparsable selector), the view abstains from the "missing" and "blocked"
//! verdicts instead of inventing a target list.
//!
//! The only write this module offers is [`force_reflection`]: clearing a mirror's recorded version
//! so reflector pushes the source again. It touches one annotation, never the payload.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use crate::lang::{Strings, fill};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Pod, Secret, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::Client;

use crate::events::format_age;
use crate::rbac::{detect_provenance, Provenance};

// Annotation prefix and keys, verbatim from `Mirroring/Core/Annotations.cs`.
const PREFIX: &str = "reflector.v1.k8s.emberstack.com";
const A_ALLOWED: &str = "reflector.v1.k8s.emberstack.com/reflection-allowed";
const A_ALLOWED_NS: &str = "reflector.v1.k8s.emberstack.com/reflection-allowed-namespaces";
const A_ALLOWED_SEL: &str = "reflector.v1.k8s.emberstack.com/reflection-allowed-namespaces-selector";
const A_AUTO: &str = "reflector.v1.k8s.emberstack.com/reflection-auto-enabled";
const A_AUTO_NS: &str = "reflector.v1.k8s.emberstack.com/reflection-auto-namespaces";
const A_AUTO_SEL: &str = "reflector.v1.k8s.emberstack.com/reflection-auto-namespaces-selector";
const A_REFLECTS: &str = "reflector.v1.k8s.emberstack.com/reflects";
const A_AUTO_REFLECTS: &str = "reflector.v1.k8s.emberstack.com/auto-reflects";
pub const A_REFLECTED_VERSION: &str = "reflector.v1.k8s.emberstack.com/reflected-version";
const A_REFLECTED_AT: &str = "reflector.v1.k8s.emberstack.com/reflected-at";

// --- Diagnosis ----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HintLevel {
    Info,
    Warn,
    Danger,
}

#[derive(Debug, Clone)]
pub struct Hint {
    pub level: HintLevel,
    pub text: String,
}

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- Scope arithmetic ---------------------------------------------------------------------------

// Upstream `PatternListMatch`: a comma-separated list of *regexes*, each of which has to cover the
// whole namespace name to count. An empty list matches everything — which is why a source with
// `reflection-allowed` and no namespace list reaches every namespace in the cluster.
//
// A pattern that does not compile matches nothing here. Upstream `Regex.Match` would throw and take
// down the evaluation for every pattern in the list; matching nothing keeps the rest of the list
// meaningful and leaves the unmatched pattern visible to the "matches no namespace" rule.
pub fn pattern_list_match(pattern_list: &str, value: &str) -> bool {
    if pattern_list.is_empty() {
        return true;
    }
    pattern_list
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .any(|p| single_pattern_match(p.trim(), value))
}

fn single_pattern_match(pattern: &str, value: &str) -> bool {
    let Ok(re) = regex::Regex::new(pattern) else { return false };
    // `Regex.Match` finds the first match anywhere; upstream then requires it to span the whole
    // value. An anchored search would differ on patterns like `a|bb` against "bb".
    re.find(value).is_some_and(|m| m.len() == value.len())
}

// One requirement of a label selector, in the subset upstream accepts: equality, inequality,
// existence and set membership.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Requirement {
    Equals(String, String),
    NotEquals(String, String),
    Exists(String),
    NotExists(String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
}

// Parse a selector string into its requirements, or `None` when any of them is malformed. Upstream
// fails closed on a bad selector (it matches nothing); the caller here goes further and abstains
// from the scope verdicts entirely, because "matches nothing" and "we could not tell" would other-
// wise be reported to the user as the same thing.
fn parse_selector(raw: &str) -> Option<Vec<Requirement>> {
    if raw.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for req in split_requirements(raw) {
        out.push(parse_requirement(&req)?);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

// Split on commas that are not inside the parentheses of a set-based requirement.
fn split_requirements(selector: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in selector.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let part = selector[start..i].trim();
                if !part.is_empty() { out.push(part.to_string()); }
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    let last = selector[start..].trim();
    if !last.is_empty() { out.push(last.to_string()); }
    out
}

fn parse_requirement(req: &str) -> Option<Requirement> {
    // Set-based first: `key in (a, b)` / `key notin (a, b)`. Checked before the operators below so
    // a value containing `=` inside the parentheses cannot be mistaken for an equality.
    if let Some(open) = req.find('(') {
        if req.trim_end().ends_with(')') {
            let head = req[..open].trim();
            let close = req.rfind(')')?;
            let values: Vec<String> = req[open + 1..close]
                .split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            if values.is_empty() { return None; }
            if let Some(key) = head.strip_suffix("notin").map(str::trim) {
                return valid_key(key).then(|| Requirement::NotIn(key.to_string(), values));
            }
            if let Some(key) = head.strip_suffix("in").map(str::trim) {
                return valid_key(key).then(|| Requirement::In(key.to_string(), values));
            }
            return None;
        }
    }
    if let Some((k, v)) = req.split_once("!=") {
        let (k, v) = (k.trim(), v.trim());
        return (valid_key(k) && valid_value(v))
            .then(|| Requirement::NotEquals(k.to_string(), v.to_string()));
    }
    if let Some((k, v)) = req.split_once("==").or_else(|| req.split_once('=')) {
        let (k, v) = (k.trim(), v.trim());
        return (valid_key(k) && valid_value(v))
            .then(|| Requirement::Equals(k.to_string(), v.to_string()));
    }
    if let Some(key) = req.strip_prefix('!') {
        let key = key.trim();
        return valid_key(key).then(|| Requirement::NotExists(key.to_string()));
    }
    let key = req.trim();
    valid_key(key).then(|| Requirement::Exists(key.to_string()))
}

// Kubernetes label key: an optional DNS-subdomain prefix, then a 1-63 char name.
fn valid_key(key: &str) -> bool {
    let name = match key.split_once('/') {
        Some((prefix, name)) => {
            if prefix.is_empty() || prefix.len() > 253 { return false; }
            let dns_ok = prefix.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !l.starts_with('-')
                    && !l.ends_with('-')
            });
            if !dns_ok { return false; }
            name
        }
        None => key,
    };
    !name.is_empty() && name.len() <= 63 && valid_value(name)
}

// Kubernetes label value: up to 63 chars of alphanumerics, `_`, `.` and `-`, starting and ending on
// an alphanumeric. The empty value is legal.
fn valid_value(value: &str) -> bool {
    if value.is_empty() { return true; }
    if value.len() > 63 { return false; }
    let ok = |c: char| c.is_ascii_alphanumeric();
    let mid = |c: char| ok(c) || c == '_' || c == '.' || c == '-';
    value.starts_with(ok) && value.ends_with(ok) && value.chars().all(mid)
}

fn requirement_matches(req: &Requirement, labels: &BTreeMap<String, String>) -> bool {
    match req {
        Requirement::Equals(k, v) => labels.get(k).is_some_and(|l| l == v),
        Requirement::NotEquals(k, v) => labels.get(k).is_none_or(|l| l != v),
        Requirement::Exists(k) => labels.contains_key(k),
        Requirement::NotExists(k) => !labels.contains_key(k),
        Requirement::In(k, vs) => labels.get(k).is_some_and(|l| vs.contains(l)),
        Requirement::NotIn(k, vs) => labels.get(k).is_none_or(|l| !vs.contains(l)),
    }
}

// Evaluate a parsed selector against a namespace's labels. Requirements are ANDed.
fn selector_match(reqs: &[Requirement], labels: &BTreeMap<String, String>) -> bool {
    reqs.iter().all(|r| requirement_matches(r, labels))
}

// --- Parsed annotations -------------------------------------------------------------------------

// The reflector annotations of one object, in the shape upstream reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirroringProps {
    pub allowed: bool,
    pub allowed_ns: String,
    pub allowed_selector: String,
    pub auto_enabled: bool,
    pub auto_ns: String,
    pub auto_selector: String,
    // `(namespace, name)` of the source this object mirrors.
    pub reflects: Option<(String, String)>,
    pub auto_reflects: bool,
    pub reflected_version: String,
    // Whether the annotation key is there at all. Absent and present-but-empty read the same to
    // reflector, but a patch that has to *change* the object needs to know which one it faces.
    pub reflected_version_set: bool,
    pub reflected_at: String,
}

impl MirroringProps {
    // Upstream branches on `IsReflection` *first*: an object carrying `reflects` is handled as a
    // mirror even when it also carries `reflection-allowed`, so it never acts as a source.
    pub fn is_reflection(&self) -> bool {
        self.reflects.is_some()
    }

    pub fn is_source(&self) -> bool {
        self.allowed && !self.is_reflection()
    }
}

// .NET `bool.TryParse` is case-insensitive, and reflector writes `auto-reflects` with .NET's
// `ToString()` — which produces "True", not "true".
fn parse_bool(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("true")
}

pub fn parse_props(meta: &ObjectMeta) -> MirroringProps {
    let anns = meta.annotations.clone().unwrap_or_default();
    let get = |k: &str| anns.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
    MirroringProps {
        allowed: parse_bool(&get(A_ALLOWED)),
        allowed_ns: get(A_ALLOWED_NS),
        allowed_selector: get(A_ALLOWED_SEL),
        auto_enabled: parse_bool(&get(A_AUTO)),
        auto_ns: get(A_AUTO_NS),
        auto_selector: get(A_AUTO_SEL),
        reflects: anns.get(A_REFLECTS).and_then(|v| {
            let (ns, name) = v.trim().split_once('/')?;
            (!ns.is_empty() && !name.is_empty())
                .then(|| (ns.to_string(), name.to_string()))
        }),
        auto_reflects: parse_bool(&get(A_AUTO_REFLECTS)),
        reflected_version: get(A_REFLECTED_VERSION),
        reflected_version_set: anns.contains_key(A_REFLECTED_VERSION),
        reflected_at: get(A_REFLECTED_AT),
    }
}

// --- Rows ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReflKind {
    Secret,
    ConfigMap,
}

impl ReflKind {
    pub fn label(&self) -> &'static str {
        match self {
            ReflKind::Secret => "Secret",
            ReflKind::ConfigMap => "ConfigMap",
        }
    }
}

// One Secret or ConfigMap, normalized down to what the rules need. Built once per fetch, then only
// read: `diagnose` never talks to the cluster.
#[derive(Debug, Clone)]
pub struct ReflObject {
    pub kind: ReflKind,
    pub namespace: String,
    pub name: String,
    // Secret type (`kubernetes.io/dockerconfigjson`…); empty for a ConfigMap.
    pub type_: String,
    pub resource_version: String,
    pub age: String,
    pub provenance: Provenance,
    pub props: MirroringProps,
    // Hash of the payload. Reflector only compares recorded versions, so two objects that agree on
    // the version but not on this have drifted apart for good.
    pub fingerprint: u64,
    pub keys: Vec<String>,
}

// What a target namespace looks like for one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    // The mirror is there and records the source's current version.
    Synced,
    // The mirror records an older version: reflector has not caught up yet, or cannot.
    Stale,
    // The versions agree but the payloads do not — the mirror was edited by hand and reflector,
    // which compares versions only, will never correct it.
    Drifted,
    // `reflects` is set but nothing has been reflected yet.
    Pending,
    // In the automatic scope, and nothing is there.
    Missing,
    // Something else already holds the name: reflector skips the namespace, silently and for good.
    Blocked,
    // Allowed but outside the automatic scope: a mirror only exists if someone declares it.
    Manual,
}

impl TargetStatus {
    // Takes the table rather than reading the active language itself: this label also lands in a
    // table cell, and the whole view has to be drawn from one and the same language.
    pub fn label(&self, st: &'static Strings) -> &'static str {
        match self {
            TargetStatus::Synced => st.refl_st_synced,
            TargetStatus::Stale => st.refl_st_stale,
            TargetStatus::Drifted => st.refl_st_drifted,
            TargetStatus::Pending => st.refl_st_pending,
            TargetStatus::Missing => st.refl_st_missing,
            TargetStatus::Blocked => st.refl_st_blocked,
            TargetStatus::Manual => st.refl_st_manual,
        }
    }

    // Statuses that a forced re-reflection can actually move. On the others, clearing the recorded
    // version changes nothing — there is no mirror to push to, or the name is taken.
    pub fn forceable(&self) -> bool {
        matches!(
            self,
            TargetStatus::Synced | TargetStatus::Stale | TargetStatus::Drifted | TargetStatus::Pending
        )
    }
}

// The mirror sitting in a target namespace, as found.
#[derive(Debug, Clone)]
pub struct MirrorFacts {
    pub auto: bool,
    pub reflected_version: String,
    pub reflected_version_set: bool,
    pub reflected_at: String,
    // Human age derived from `reflected-at`, empty when it is absent or unparsable.
    pub reflected_age: String,
    pub age: String,
    pub provenance: Provenance,
    pub keys: Vec<String>,
}

// One (source, namespace) pair.
#[derive(Debug, Clone)]
pub struct ReflTarget {
    pub namespace: String,
    // In the automatic scope (reflector creates and maintains the mirror by itself).
    pub auto: bool,
    pub status: TargetStatus,
    pub mirror: Option<MirrorFacts>,
    // What occupies the name instead, when `status` is `Blocked`.
    pub blocker: Option<String>,
    // Workloads in this namespace that reference the object by name.
    pub consumers: Vec<String>,
    pub hints: Vec<Hint>,
}

impl ReflTarget {
    pub fn worst(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }
}

// An annotated source and everything it is meant to reach.
#[derive(Debug, Clone)]
pub struct ReflSource {
    pub kind: ReflKind,
    pub namespace: String,
    pub name: String,
    pub type_: String,
    pub resource_version: String,
    pub age: String,
    pub provenance: Provenance,
    pub props: MirroringProps,
    // The namespaces the annotations resolve to on today's cluster. `None` when a selector could
    // not be parsed: the scope is unknown, and the missing/blocked verdicts stay silent.
    pub scope_known: bool,
    pub targets: Vec<ReflTarget>,
    pub hints: Vec<Hint>,
}

impl ReflSource {
    // (synced, expected) for the table's summary column.
    pub fn tally(&self) -> (usize, usize) {
        let expected = self.targets.iter().filter(|t| t.auto).count();
        let synced = self
            .targets
            .iter()
            .filter(|t| t.auto && t.status == TargetStatus::Synced)
            .count();
        (synced, expected)
    }

    pub fn worst(&self) -> Option<HintLevel> {
        self.hints
            .iter()
            .map(|h| h.level)
            .chain(self.targets.iter().filter_map(|t| t.worst()))
            .max()
    }
}

// A mirror whose source cannot be resolved, or which no source claims any more. Kept apart from the
// sources because there is no tree to hang it under.
#[derive(Debug, Clone)]
pub struct ReflOrphan {
    pub kind: ReflKind,
    pub namespace: String,
    pub name: String,
    pub age: String,
    pub provenance: Provenance,
    pub props: MirroringProps,
    pub mirror: MirrorFacts,
    pub consumers: Vec<String>,
    pub hints: Vec<Hint>,
}

impl ReflOrphan {
    pub fn worst(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }
}

#[derive(Default, Debug, Clone)]
pub struct ReflectorState {
    pub sources: Vec<ReflSource>,
    pub orphans: Vec<ReflOrphan>,
    // Findings that belong to no single source (controller unreachable, consumers left stranded…).
    pub cluster_hints: Vec<Hint>,
    // `None` when the Deployment list failed: the view then says "introuvable", not "absent".
    pub controller_present: Option<bool>,
    // False when listing pods/ServiceAccounts failed. The "nobody is waiting for it" and "these
    // pods are waiting for it" rules stay silent rather than report an absence they cannot observe.
    pub consumers_known: bool,
    pub error: Option<String>,
    pub loading: bool,
}

impl ReflectorState {
    // (sources, mirrors, problems) for the table title.
    pub fn summary(&self) -> (usize, usize, usize) {
        let mirrors = self
            .sources
            .iter()
            .flat_map(|s| &s.targets)
            .filter(|t| t.mirror.is_some())
            .count()
            + self.orphans.len();
        let problems = self
            .sources
            .iter()
            .filter(|s| s.worst().is_some_and(|l| l >= HintLevel::Warn))
            .count()
            + self
                .orphans
                .iter()
                .filter(|o| o.worst().is_some_and(|l| l >= HintLevel::Warn))
                .count();
        (self.sources.len(), mirrors, problems)
    }
}

pub type SharedReflector = Arc<Mutex<ReflectorState>>;

pub fn new_reflector_state() -> SharedReflector {
    Arc::new(Mutex::new(ReflectorState::default()))
}

// --- Fetch --------------------------------------------------------------------------------------

// A namespace, reduced to what the scope arithmetic needs.
#[derive(Debug, Clone)]
pub struct NsInfo {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

// Which workloads in a namespace reference an object by name, keyed by (namespace, kind, name).
pub type ConsumerMap = HashMap<(String, ReflKind, String), Vec<String>>;

pub async fn fetch_reflector(client: Client, state: SharedReflector) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("reflector poisoned");
        s.loading = true;
        s.error = None;
    }

    let lp = ListParams::default();
    let secrets: Api<Secret> = Api::all(client.clone());
    let configmaps: Api<ConfigMap> = Api::all(client.clone());
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let pods: Api<Pod> = Api::all(client.clone());
    let sas: Api<ServiceAccount> = Api::all(client.clone());
    let deploys: Api<Deployment> = Api::all(client.clone());

    let (secrets, configmaps, nss, pods, sas, deploys) = tokio::join!(
        secrets.list(&lp),
        configmaps.list(&lp),
        namespaces.list(&lp),
        pods.list(&lp),
        sas.list(&lp),
        deploys.list(&lp),
    );

    // The objects are the subject of the view: without them there is nothing to say.
    let secrets = match secrets {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };
    let nss = match nss {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };

    let mut objects: Vec<ReflObject> = Vec::new();
    for s in &secrets.items {
        objects.push(secret_object(s));
    }
    // A ConfigMap list that fails only costs the ConfigMap half of the view: the Secret half stays
    // exact, so it is worth keeping rather than failing the whole fetch.
    if let Ok(list) = &configmaps {
        for c in &list.items {
            objects.push(configmap_object(c));
        }
    }

    let namespaces: Vec<NsInfo> = nss
        .items
        .iter()
        .map(|n| NsInfo {
            name: n.metadata.name.clone().unwrap_or_default(),
            labels: n
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect(),
        })
        .collect();

    let consumers_known = pods.is_ok() && sas.is_ok();
    let mut consumers: ConsumerMap = HashMap::new();
    if let Ok(list) = &pods {
        for p in &list.items {
            collect_pod_consumers(p, &mut consumers);
        }
    }
    if let Ok(list) = &sas {
        for sa in &list.items {
            collect_sa_consumers(sa, &mut consumers);
        }
    }

    let controller_present = match &deploys {
        Ok(list) => Some(list.items.iter().any(is_reflector_deployment)),
        Err(_) => None,
    };

    let mut diagnosed = diagnose(objects, &namespaces, &consumers, consumers_known, st);
    diagnosed.controller_present = controller_present;
    if controller_present == Some(false) && !diagnosed.sources.is_empty() {
        diagnosed.cluster_hints.push(danger(st.refl_no_controller.to_string()));
    } else if controller_present.is_none() {
        diagnosed.cluster_hints.push(info(st.refl_controller_unknown.to_string()));
    }

    let mut s = state.lock().expect("reflector poisoned");
    s.loading = false;
    s.error = None;
    s.sources = diagnosed.sources;
    s.orphans = diagnosed.orphans;
    s.cluster_hints = diagnosed.cluster_hints;
    s.controller_present = diagnosed.controller_present;
    s.consumers_known = diagnosed.consumers_known;
}

fn fail(state: &SharedReflector, msg: String) {
    let mut s = state.lock().expect("reflector poisoned");
    s.loading = false;
    s.error = Some(msg);
}

fn secret_object(s: &Secret) -> ReflObject {
    let data: Vec<(String, Vec<u8>)> = s
        .data
        .as_ref()
        .map(|d| d.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect())
        .unwrap_or_default();
    ReflObject {
        kind: ReflKind::Secret,
        namespace: s.metadata.namespace.clone().unwrap_or_default(),
        name: s.metadata.name.clone().unwrap_or_default(),
        type_: s.type_.clone().unwrap_or_default(),
        resource_version: s.metadata.resource_version.clone().unwrap_or_default(),
        age: meta_age(&s.metadata),
        provenance: detect_provenance(&s.metadata),
        props: parse_props(&s.metadata),
        fingerprint: fingerprint(&data),
        keys: data.into_iter().map(|(k, _)| k).collect(),
    }
}

fn configmap_object(c: &ConfigMap) -> ReflObject {
    let mut data: Vec<(String, Vec<u8>)> = c
        .data
        .as_ref()
        .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone().into_bytes())).collect())
        .unwrap_or_default();
    if let Some(bin) = &c.binary_data {
        data.extend(bin.iter().map(|(k, v)| (k.clone(), v.0.clone())));
    }
    data.sort_by(|a, b| a.0.cmp(&b.0));
    ReflObject {
        kind: ReflKind::ConfigMap,
        namespace: c.metadata.namespace.clone().unwrap_or_default(),
        name: c.metadata.name.clone().unwrap_or_default(),
        type_: String::new(),
        resource_version: c.metadata.resource_version.clone().unwrap_or_default(),
        age: meta_age(&c.metadata),
        provenance: detect_provenance(&c.metadata),
        props: parse_props(&c.metadata),
        fingerprint: fingerprint(&data),
        keys: data.into_iter().map(|(k, _)| k).collect(),
    }
}

fn meta_age(meta: &ObjectMeta) -> String {
    meta.creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default()
}

// Order-independent digest of the payload: reflector copies the data verbatim, so equal payloads
// have to hash equal whatever order the API server returned the keys in.
fn fingerprint(data: &[(String, Vec<u8>)]) -> u64 {
    let mut sorted: Vec<&(String, Vec<u8>)> = data.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = DefaultHasher::new();
    for (k, v) in sorted {
        k.hash(&mut h);
        v.hash(&mut h);
    }
    h.finish()
}

fn is_reflector_deployment(d: &Deployment) -> bool {
    let name = d.metadata.name.clone().unwrap_or_default();
    let labels = d.metadata.labels.clone().unwrap_or_default();
    labels.get("app.kubernetes.io/name").is_some_and(|v| v == "reflector")
        || name.contains("reflector")
}

fn push_consumer(map: &mut ConsumerMap, ns: &str, kind: ReflKind, name: &str, who: &str) {
    if name.is_empty() {
        return;
    }
    let entry = map.entry((ns.to_string(), kind, name.to_string())).or_default();
    if !entry.iter().any(|e| e == who) {
        entry.push(who.to_string());
    }
}

// Every way a pod can name a Secret or a ConfigMap. `imagePullSecrets` is the one that matters most
// here — a missing pull secret is an ImagePullBackOff with no explanation on the pod itself.
fn collect_pod_consumers(p: &Pod, map: &mut ConsumerMap) {
    let ns = p.metadata.namespace.clone().unwrap_or_default();
    let who = format!("Pod/{}", p.metadata.name.clone().unwrap_or_default());
    let Some(spec) = &p.spec else { return };

    for ips in spec.image_pull_secrets.iter().flatten() {
        push_consumer(map, &ns, ReflKind::Secret, &ips.name, &who);
    }
    for v in spec.volumes.iter().flatten() {
        if let Some(n) = v.secret.as_ref().and_then(|s| s.secret_name.as_deref()) {
            push_consumer(map, &ns, ReflKind::Secret, n, &who);
        }
        if let Some(c) = &v.config_map {
            push_consumer(map, &ns, ReflKind::ConfigMap, &c.name, &who);
        }
        for proj in v.projected.iter().flat_map(|p| p.sources.iter().flatten()) {
            if let Some(s) = &proj.secret {
                push_consumer(map, &ns, ReflKind::Secret, &s.name, &who);
            }
            if let Some(c) = &proj.config_map {
                push_consumer(map, &ns, ReflKind::ConfigMap, &c.name, &who);
            }
        }
    }
    // Ephemeral containers are left out on purpose: they are debug shells attached after the fact,
    // never the reason a namespace needs a reflected secret.
    for c in spec.containers.iter().chain(spec.init_containers.iter().flatten()) {
        for ef in c.env_from.iter().flatten() {
            if let Some(s) = &ef.secret_ref {
                push_consumer(map, &ns, ReflKind::Secret, &s.name, &who);
            }
            if let Some(cm) = &ef.config_map_ref {
                push_consumer(map, &ns, ReflKind::ConfigMap, &cm.name, &who);
            }
        }
        for e in c.env.iter().flatten() {
            let Some(src) = &e.value_from else { continue };
            if let Some(s) = &src.secret_key_ref {
                push_consumer(map, &ns, ReflKind::Secret, &s.name, &who);
            }
            if let Some(cm) = &src.config_map_key_ref {
                push_consumer(map, &ns, ReflKind::ConfigMap, &cm.name, &who);
            }
        }
    }
}

fn collect_sa_consumers(sa: &ServiceAccount, map: &mut ConsumerMap) {
    let ns = sa.metadata.namespace.clone().unwrap_or_default();
    let who = format!("ServiceAccount/{}", sa.metadata.name.clone().unwrap_or_default());
    for ips in sa.image_pull_secrets.iter().flatten() {
        push_consumer(map, &ns, ReflKind::Secret, &ips.name, &who);
    }
    // `ObjectReference.name` stays optional here, unlike the LocalObjectReference above.
    for n in sa.secrets.iter().flatten().filter_map(|s| s.name.as_deref()) {
        push_consumer(map, &ns, ReflKind::Secret, n, &who);
    }
}

// --- Diagnosis ----------------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
pub struct Diagnosed {
    pub sources: Vec<ReflSource>,
    pub orphans: Vec<ReflOrphan>,
    pub cluster_hints: Vec<Hint>,
    pub controller_present: Option<bool>,
    pub consumers_known: bool,
}

pub fn diagnose(
    objects: Vec<ReflObject>,
    namespaces: &[NsInfo],
    consumers: &ConsumerMap,
    consumers_known: bool,
    st: &'static Strings,
) -> Diagnosed {
    // Cluster-wide index: reflector's own `OnResourceWithNameList` looks objects up by name across
    // every namespace, so the conflict test has to see the whole cluster too.
    let by_id: HashMap<(ReflKind, String, String), &ReflObject> = objects
        .iter()
        .map(|o| ((o.kind, o.namespace.clone(), o.name.clone()), o))
        .collect();

    let source_objs: Vec<&ReflObject> = objects.iter().filter(|o| o.props.is_source()).collect();
    let source_ids: HashSet<(ReflKind, String, String)> = source_objs
        .iter()
        .map(|o| (o.kind, o.namespace.clone(), o.name.clone()))
        .collect();

    let mut sources: Vec<ReflSource> = Vec::new();
    // Mirrors accounted for by a source, so the orphan pass can skip them.
    let mut claimed: HashSet<(ReflKind, String, String)> = HashSet::new();

    for obj in &source_objs {
        let src = diagnose_source(obj, namespaces, &by_id, consumers, consumers_known, st);
        for t in &src.targets {
            if t.mirror.is_some() {
                claimed.insert((src.kind, t.namespace.clone(), src.name.clone()));
            }
        }
        sources.push(src);
    }

    // Orphans: anything carrying `reflects` that no source above accounted for.
    let mut orphans: Vec<ReflOrphan> = Vec::new();
    for obj in objects.iter().filter(|o| o.props.is_reflection()) {
        let key = (obj.kind, obj.namespace.clone(), obj.name.clone());
        if claimed.contains(&key) {
            continue;
        }
        orphans.push(diagnose_orphan(obj, &source_ids, &by_id, consumers, st));
    }

    let mut cluster_hints = Vec::new();
    // Pods elsewhere waiting on a name that some source publishes, in a namespace that source does
    // not reach: the ImagePullBackOff whose cause is three namespaces away.
    if consumers_known {
        cluster_hints.extend(stranded_consumers(&sources, &by_id, consumers, st));
    }

    sources.sort_by(|a, b| {
        b.worst()
            .cmp(&a.worst())
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });
    orphans.sort_by(|a, b| {
        b.worst()
            .cmp(&a.worst())
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });

    Diagnosed {
        sources,
        orphans,
        cluster_hints,
        controller_present: None,
        consumers_known,
    }
}

fn diagnose_source(
    obj: &ReflObject,
    namespaces: &[NsInfo],
    by_id: &HashMap<(ReflKind, String, String), &ReflObject>,
    consumers: &ConsumerMap,
    consumers_known: bool,
    st: &'static Strings,
) -> ReflSource {
    let p = &obj.props;
    let allowed_sel = parse_selector(&p.allowed_selector);
    let auto_sel = parse_selector(&p.auto_selector);
    let scope_known = allowed_sel.is_some() && auto_sel.is_some();

    let mut hints: Vec<Hint> = Vec::new();
    let mut targets: Vec<ReflTarget> = Vec::new();

    if !scope_known {
        let annotation = if allowed_sel.is_none() { A_ALLOWED_SEL } else { A_AUTO_SEL }
            .trim_start_matches(PREFIX)
            .trim_start_matches('/');
        hints.push(danger(fill(
            st.refl_bad_selector,
            &[("annotation", annotation)],
        )));
    }

    // The scope, resolved against the namespaces that exist right now.
    if let (Some(allowed_sel), Some(auto_sel)) = (&allowed_sel, &auto_sel) {
        for ns in namespaces {
            // Upstream never reflects into the source's own namespace.
            if ns.name == obj.namespace {
                continue;
            }
            if !match_scope(&p.allowed_ns, allowed_sel, ns) {
                continue;
            }
            let auto = p.auto_enabled && match_scope(&p.auto_ns, auto_sel, ns);
            targets.push(build_target(obj, ns, auto, by_id, consumers, consumers_known, st));
        }
        targets.sort_by(|a, b| a.namespace.cmp(&b.namespace));

        // A pattern that designates no existing namespace. Deliberate (the app is not deployed yet)
        // or a typo — either way the mirror everyone is waiting for will not appear, and the
        // annotation gives no hint of it.
        let unmatched = unmatched_patterns(&p.auto_ns, namespaces);
        if !unmatched.is_empty() && p.auto_enabled {
            hints.push(info(fill(
                &st.plural(unmatched.len(), st.refl_unmatched_one, st.refl_unmatched_many),
                &[("list", &unmatched.join(", "))],
            )));
        }
    }

    // Scope-shape rules. These read the annotations only, so they hold even when a selector failed
    // to parse.
    if p.allowed && p.allowed_ns.is_empty() && p.allowed_selector.is_empty() {
        hints.push(danger(st.plural(
            namespaces.len().saturating_sub(1),
            st.refl_allowed_everywhere_one,
            st.refl_allowed_everywhere_many,
        )));
    }
    if p.auto_enabled && p.auto_ns.is_empty() && p.auto_selector.is_empty() {
        hints.push(danger(st.plural(
            namespaces.len().saturating_sub(1),
            st.refl_auto_everywhere_one,
            st.refl_auto_everywhere_many,
        )));
    }
    if !p.auto_ns.is_empty() && !p.auto_enabled {
        hints.push(warn(st.refl_auto_list_decorative.to_string()));
    }

    // A mirror declared by hand in a namespace that is allowed but outside the automatic scope gets
    // *deleted* by the auto pass, which does not spare manual mirrors.
    if p.auto_enabled {
        let doomed: Vec<String> = targets
            .iter()
            .filter(|t| !t.auto && t.mirror.is_some())
            .map(|t| t.namespace.clone())
            .collect();
        if !doomed.is_empty() {
            hints.push(danger(fill(
                st.refl_manual_doomed,
                &[("namespaces", &doomed.join(", "))],
            )));
        }
    }

    hints.sort_by_key(|h| std::cmp::Reverse(h.level));
    ReflSource {
        kind: obj.kind,
        namespace: obj.namespace.clone(),
        name: obj.name.clone(),
        type_: obj.type_.clone(),
        resource_version: obj.resource_version.clone(),
        age: obj.age.clone(),
        provenance: obj.provenance.clone(),
        props: p.clone(),
        scope_known,
        targets,
        hints,
    }
}

// Upstream ORs the pattern list with the label selector, and an empty pair matches everything.
fn match_scope(patterns: &str, selector: &[Requirement], ns: &NsInfo) -> bool {
    let has_patterns = !patterns.is_empty();
    let has_selector = !selector.is_empty();
    if !has_patterns && !has_selector {
        return true;
    }
    (has_patterns && pattern_list_match(patterns, &ns.name))
        || (has_selector && selector_match(selector, &ns.labels))
}

// Patterns from a list that match none of the cluster's namespaces, reported verbatim.
fn unmatched_patterns(pattern_list: &str, namespaces: &[NsInfo]) -> Vec<String> {
    pattern_list
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter(|p| !namespaces.iter().any(|ns| single_pattern_match(p, &ns.name)))
        .map(String::from)
        .collect()
}

fn build_target(
    src: &ReflObject,
    ns: &NsInfo,
    auto: bool,
    by_id: &HashMap<(ReflKind, String, String), &ReflObject>,
    consumers: &ConsumerMap,
    consumers_known: bool,
    st: &'static Strings,
) -> ReflTarget {
    let here = by_id.get(&(src.kind, ns.name.clone(), src.name.clone())).copied();
    let waiting = consumers
        .get(&(ns.name.clone(), src.kind, src.name.clone()))
        .cloned()
        .unwrap_or_default();

    let mut hints: Vec<Hint> = Vec::new();
    let mut blocker = None;
    let mut mirror = None;
    // Whether the copy's payload actually equals the source's. Only meaningful once a mirror of this
    // source was found, which is why it starts as "no opinion".
    let mut content_matches = false;

    let status = match here {
        // Nothing on the spot.
        None => {
            if auto {
                TargetStatus::Missing
            } else {
                TargetStatus::Manual
            }
        }
        Some(obj) => match &obj.props.reflects {
            // A mirror of this very source.
            Some((rns, rname)) if *rns == src.namespace && *rname == src.name => {
                mirror = Some(mirror_facts(obj));
                content_matches = obj.fingerprint == src.fingerprint;
                if obj.props.reflected_version.is_empty() {
                    TargetStatus::Pending
                } else if obj.props.reflected_version != src.resource_version {
                    TargetStatus::Stale
                } else if obj.fingerprint != src.fingerprint {
                    TargetStatus::Drifted
                } else {
                    TargetStatus::Synced
                }
            }
            // The name is taken — by a mirror of something else, or by an unrelated object.
            Some((rns, rname)) => {
                blocker = Some(fill(
                    st.refl_blocker_mirror_of,
                    &[("ns", rns), ("name", rname)],
                ));
                TargetStatus::Blocked
            }
            None => {
                blocker = Some(format!(
                    "{} {} ({})",
                    obj.kind.label(),
                    if obj.type_.is_empty() { "".to_string() } else { obj.type_.clone() },
                    obj.provenance.label()
                )
                .replace("  ", " "));
                TargetStatus::Blocked
            }
        },
    };

    match status {
        TargetStatus::Blocked => {
            let who = blocker
                .clone()
                .unwrap_or_else(|| st.refl_blocker_unknown.to_string());
            hints.push(danger(fill(st.refl_blocked, &[("blocker", &who)])));
        }
        TargetStatus::Drifted => {
            hints.push(danger(st.refl_drifted.to_string()));
        }
        TargetStatus::Stale => {
            let age = mirror
                .as_ref()
                .map(|m| m.reflected_age.clone())
                .filter(|a| !a.is_empty())
                .map(|a| fill(st.refl_stale_age, &[("age", &a)]))
                .unwrap_or_default();
            let recorded =
                mirror.as_ref().map(|m| m.reflected_version.clone()).unwrap_or_default();
            hints.push(warn(fill(
                st.refl_stale,
                &[
                    ("mirror", &short_version(&recorded)),
                    ("source", &short_version(&src.resource_version)),
                    ("age", &age),
                ],
            )));
        }
        TargetStatus::Pending => {
            let passed = mirror.as_ref().is_some_and(|m| !m.reflected_at.is_empty());
            let age = mirror
                .as_ref()
                .map(|m| m.reflected_age.clone())
                .filter(|a| !a.is_empty())
                .map(|a| fill(st.refl_pending_age, &[("age", &a)]))
                .unwrap_or_default();
            hints.push(match (passed, content_matches) {
                // Reflector has been here and the copy is right; only its bookkeeping is blank. It
                // will re-send at the next event on the source, so this is untidy, not broken.
                (true, true) => info(fill(st.refl_pending_matches, &[("age", &age)])),
                (true, false) => warn(fill(st.refl_pending_differs, &[("age", &age)])),
                _ => warn(st.refl_pending_never.to_string()),
            });
        }
        TargetStatus::Missing => {
            hints.push(warn(st.refl_missing.to_string()));
        }
        TargetStatus::Manual => {
            hints.push(info(st.refl_manual.to_string()));
        }
        TargetStatus::Synced => {}
    }

    // Consumers turn an absence into an outage: say so, and name them.
    if consumers_known
        && !waiting.is_empty()
        && matches!(status, TargetStatus::Missing | TargetStatus::Blocked | TargetStatus::Manual)
    {
        hints.push(danger(fill(
            &st.plural(waiting.len(), st.refl_waiting_one, st.refl_waiting_many),
            &[("list", &waiting.join(", "))],
        )));
    }

    hints.sort_by_key(|h| std::cmp::Reverse(h.level));
    ReflTarget {
        namespace: ns.name.clone(),
        auto,
        status,
        mirror,
        blocker,
        consumers: waiting,
        hints,
    }
}

fn mirror_facts(obj: &ReflObject) -> MirrorFacts {
    MirrorFacts {
        auto: obj.props.auto_reflects,
        reflected_version: obj.props.reflected_version.clone(),
        reflected_version_set: obj.props.reflected_version_set,
        reflected_at: obj.props.reflected_at.clone(),
        reflected_age: reflected_age(&obj.props.reflected_at),
        age: obj.age.clone(),
        provenance: obj.provenance.clone(),
        keys: obj.keys.clone(),
    }
}

// Reflector writes `reflected-at` with .NET's round-trip format, which is RFC 3339 with a fractional
// second and an offset. An unparsable value yields an empty age rather than a wrong one.
fn reflected_age(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    raw.parse::<Timestamp>().map(|t| format_age(&t)).unwrap_or_default()
}

// resourceVersions are long and only ever compared, never read: the tail is enough to tell two
// apart on screen.
fn short_version(v: &str) -> String {
    if v.is_empty() {
        return "—".to_string();
    }
    if v.len() <= 8 {
        return v.to_string();
    }
    format!("…{}", &v[v.len() - 7..])
}

fn diagnose_orphan(
    obj: &ReflObject,
    source_ids: &HashSet<(ReflKind, String, String)>,
    by_id: &HashMap<(ReflKind, String, String), &ReflObject>,
    consumers: &ConsumerMap,
    st: &'static Strings,
) -> ReflOrphan {
    let (rns, rname) = obj.props.reflects.clone().unwrap_or_default();
    let key = (obj.kind, rns.clone(), rname.clone());
    let mut hints = Vec::new();

    if !by_id.contains_key(&key) {
        // An auto mirror in this state gets deleted the next time reflector looks at it; a manual
        // one simply stops being updated. Both are worth a red line, for different reasons.
        if obj.props.auto_reflects {
            hints.push(danger(fill(
                st.refl_orphan_source_gone_auto,
                &[("ns", &rns), ("name", &rname)],
            )));
        } else {
            hints.push(danger(fill(
                st.refl_orphan_source_gone_manual,
                &[("ns", &rns), ("name", &rname)],
            )));
        }
    } else if !source_ids.contains(&key) {
        hints.push(danger(fill(
            st.refl_orphan_not_a_source,
            &[("ns", &rns), ("name", &rname)],
        )));
    } else {
        // The source exists and is a source, yet this mirror was not attached to any of its targets
        // — the only way that happens is a namespace the source no longer permits.
        if obj.props.auto_reflects {
            hints.push(danger(fill(
                st.refl_orphan_out_of_scope_auto,
                &[("ns", &rns), ("name", &rname)],
            )));
        } else {
            hints.push(danger(fill(
                st.refl_orphan_out_of_scope_manual,
                &[("ns", &rns), ("name", &rname)],
            )));
        }
    }

    if obj.props.allowed {
        hints.push(warn(st.refl_orphan_both_annotations.to_string()));
    }

    let waiting = consumers
        .get(&(obj.namespace.clone(), obj.kind, obj.name.clone()))
        .cloned()
        .unwrap_or_default();

    hints.sort_by_key(|h| std::cmp::Reverse(h.level));
    ReflOrphan {
        kind: obj.kind,
        namespace: obj.namespace.clone(),
        name: obj.name.clone(),
        age: obj.age.clone(),
        provenance: obj.provenance.clone(),
        props: obj.props.clone(),
        mirror: mirror_facts(obj),
        consumers: waiting,
        hints,
    }
}

// Namespaces whose workloads name an object that a source publishes elsewhere, but which that
// source does not reach. This is the ImagePullBackOff whose cause lives three namespaces away.
fn stranded_consumers(
    sources: &[ReflSource],
    by_id: &HashMap<(ReflKind, String, String), &ReflObject>,
    consumers: &ConsumerMap,
    st: &'static Strings,
) -> Vec<Hint> {
    let mut out = Vec::new();
    for src in sources {
        let in_scope: HashSet<&str> = src.targets.iter().map(|t| t.namespace.as_str()).collect();
        let mut stranded: Vec<String> = Vec::new();
        for ((ns, kind, name), who) in consumers {
            if *kind != src.kind || *name != src.name || *ns == src.namespace {
                continue;
            }
            if in_scope.contains(ns.as_str()) {
                continue;
            }
            // Something with that name is on the spot: whatever it is, the workload finds it.
            if by_id.contains_key(&(src.kind, ns.clone(), name.clone())) {
                continue;
            }
            stranded.push(format!("{ns} ({})", who.join(", ")));
        }
        if !stranded.is_empty() {
            stranded.sort();
            out.push(danger(fill(
                &st.plural(stranded.len(), st.refl_stranded_one, st.refl_stranded_many),
                &[
                    ("kind", src.kind.label()),
                    ("name", &src.name),
                    ("ns", &src.namespace),
                    ("list", &stranded.join(", ")),
                ],
            )));
        }
    }
    out
}

// --- Write --------------------------------------------------------------------------------------

// Annotation kdt writes on a source to make it move. Its value is a timestamp, so the patch always
// changes the object and therefore always produces the watch event the re-reflection hangs on.
pub const A_KDT_FORCED_AT: &str = "kdt.io/reflect-forced-at";

// Which object a force has to write to, and what it writes there.
//
// Clearing the mirror's recorded version is only half the job, and on its own it is often no job at
// all. Reflector handles a change on a *direct* mirror by re-reflecting when the recorded version no
// longer matches (`ResourceMirror.cs:316-367`) — there, clearing works. But a change on an *auto*
// mirror only makes it check that its source still exists and still permits the namespace
// (`:370-415`); it explicitly leaves the copy for "when we hit the source". So an auto mirror is
// re-pushed only by an event on the source, whose auto pass re-sends every mirror whose recorded
// version differs (`:467-472`). Forcing an auto mirror therefore has to touch the source as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForceWrite {
    // Remove `reflected-version` from the mirror. Used when the key is present: removing it is what
    // guarantees the object actually changes, which setting an already-empty value would not.
    ClearMirror { kind: ReflKind, namespace: String, name: String },
    // Add `reflected-version: ""` to a mirror that does not carry the key at all.
    EmptyMirror { kind: ReflKind, namespace: String, name: String },
    // Stamp the source so reflector runs its auto pass over every mirror.
    TouchSource { kind: ReflKind, namespace: String, name: String },
    // Take the stamp back off. Flux owns the source and will not prune an annotation another field
    // manager added, so leaving it would litter the object for good. Removing it is itself a change
    // event, hence a second valid trigger for the same auto pass — whichever of the two reflector
    // sees first, the mirrors get re-sent, so the pair cannot race into doing nothing.
    UnstampSource { kind: ReflKind, namespace: String, name: String },
}

// The writes that forcing this mirror requires, in the order they must happen: the mirror first, so
// that when the source event arrives the recorded version already differs.
pub fn force_plan(
    kind: ReflKind,
    mirror_ns: &str,
    name: &str,
    reflected_version_set: bool,
    auto: bool,
    source_ns: &str,
) -> Vec<ForceWrite> {
    let mut plan = vec![if reflected_version_set {
        ForceWrite::ClearMirror {
            kind,
            namespace: mirror_ns.to_string(),
            name: name.to_string(),
        }
    } else {
        ForceWrite::EmptyMirror {
            kind,
            namespace: mirror_ns.to_string(),
            name: name.to_string(),
        }
    }];
    if auto {
        plan.push(ForceWrite::TouchSource {
            kind,
            namespace: source_ns.to_string(),
            name: name.to_string(),
        });
        plan.push(ForceWrite::UnstampSource {
            kind,
            namespace: source_ns.to_string(),
            name: name.to_string(),
        });
    }
    plan
}

// Apply one write. Merge patches on metadata only — never on the payload.
pub async fn apply_force(client: Client, write: ForceWrite) -> Result<(), String> {
    let (kind, namespace, name, patch) = match write {
        ForceWrite::ClearMirror { kind, namespace, name } => (
            kind,
            namespace,
            name,
            // `null` deletes the key in a JSON merge patch.
            serde_json::json!({ "metadata": { "annotations": { A_REFLECTED_VERSION: null } } }),
        ),
        ForceWrite::EmptyMirror { kind, namespace, name } => (
            kind,
            namespace,
            name,
            serde_json::json!({ "metadata": { "annotations": { A_REFLECTED_VERSION: "" } } }),
        ),
        ForceWrite::TouchSource { kind, namespace, name } => {
            let stamp = Timestamp::now().to_string();
            (
                kind,
                namespace,
                name,
                serde_json::json!({ "metadata": { "annotations": { A_KDT_FORCED_AT: stamp } } }),
            )
        }
        ForceWrite::UnstampSource { kind, namespace, name } => (
            kind,
            namespace,
            name,
            serde_json::json!({ "metadata": { "annotations": { A_KDT_FORCED_AT: null } } }),
        ),
    };
    let pp = PatchParams::default();
    match kind {
        ReflKind::Secret => {
            let api: Api<Secret> = Api::namespaced(client, &namespace);
            api.patch(&name, &pp, &Patch::Merge(&patch)).await.map(|_| ())
        }
        ReflKind::ConfigMap => {
            let api: Api<ConfigMap> = Api::namespaced(client, &namespace);
            api.patch(&name, &pp, &Patch::Merge(&patch)).await.map(|_| ())
        }
    }
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::FR;

    fn ns(name: &str) -> NsInfo {
        NsInfo { name: name.to_string(), labels: BTreeMap::new() }
    }

    fn ns_labelled(name: &str, pairs: &[(&str, &str)]) -> NsInfo {
        NsInfo {
            name: name.to_string(),
            labels: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn obj(kind: ReflKind, namespace: &str, name: &str, rv: &str, props: MirroringProps) -> ReflObject {
        ReflObject {
            kind,
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: String::new(),
            resource_version: rv.to_string(),
            age: "1d".to_string(),
            provenance: Provenance::Unmanaged,
            props,
            fingerprint: 42,
            keys: vec!["k".to_string()],
        }
    }

    fn source_props(allowed_ns: &str, auto_ns: &str) -> MirroringProps {
        MirroringProps {
            allowed: true,
            allowed_ns: allowed_ns.to_string(),
            auto_enabled: true,
            auto_ns: auto_ns.to_string(),
            ..MirroringProps::default()
        }
    }

    fn mirror_props(src_ns: &str, src_name: &str, version: &str) -> MirroringProps {
        MirroringProps {
            reflects: Some((src_ns.to_string(), src_name.to_string())),
            auto_reflects: true,
            reflected_version: version.to_string(),
            ..MirroringProps::default()
        }
    }

    // --- pattern matching ---

    #[test]
    fn empty_pattern_list_matches_everything() {
        // The footgun: reflection-allowed with no namespace list reaches the whole cluster.
        assert!(pattern_list_match("", "kube-system"));
        assert!(pattern_list_match("", "anything"));
    }

    #[test]
    fn patterns_must_span_the_whole_name() {
        // Upstream requires the match to cover the value, so a prefix is not enough.
        assert!(!pattern_list_match("qpool", "qpool-staging"));
        assert!(pattern_list_match("qpool", "qpool"));
        assert!(pattern_list_match("qpool.*", "qpool-staging"));
    }

    #[test]
    fn patterns_are_regexes_not_globs() {
        assert!(pattern_list_match("app-.*", "app-front"));
        assert!(pattern_list_match(r"team-\d+", "team-42"));
        assert!(!pattern_list_match(r"team-\d+", "team-x"));
    }

    #[test]
    fn pattern_list_splits_and_trims() {
        assert!(pattern_list_match("qpool, historik , wiki-mcp", "historik"));
        assert!(!pattern_list_match("qpool, historik", "tablet"));
    }

    #[test]
    fn alternation_still_has_to_cover_the_value() {
        // `Regex.Match` finds "bb" inside "bb" — length equal, so it counts.
        assert!(pattern_list_match("a|bb", "bb"));
        // But not inside "abb": the first match is "a", which is shorter than the value.
        assert!(!pattern_list_match("a|bb", "abb"));
    }

    #[test]
    fn uncompilable_pattern_matches_nothing() {
        assert!(!pattern_list_match("a[", "a["));
        // …and does not poison the rest of the list.
        assert!(pattern_list_match("a[,qpool", "qpool"));
    }

    // --- selectors ---

    #[test]
    fn selector_equality_and_existence() {
        let reqs = parse_selector("team=infra,tier").expect("valid selector");
        assert!(selector_match(&reqs, &ns_labelled("x", &[("team", "infra"), ("tier", "1")]).labels));
        assert!(!selector_match(&reqs, &ns_labelled("x", &[("team", "infra")]).labels));
        assert!(!selector_match(&reqs, &ns_labelled("x", &[("team", "apps"), ("tier", "1")]).labels));
    }

    #[test]
    fn selector_set_based_and_negations() {
        let reqs = parse_selector("env in (prod, staging),!legacy,team!=infra").expect("valid");
        assert!(selector_match(&reqs, &ns_labelled("x", &[("env", "prod"), ("team", "apps")]).labels));
        assert!(!selector_match(&reqs, &ns_labelled("x", &[("env", "dev")]).labels));
        assert!(!selector_match(
            &reqs,
            &ns_labelled("x", &[("env", "prod"), ("legacy", "y")]).labels
        ));
    }

    #[test]
    fn selector_notin_holds_when_the_label_is_absent() {
        let reqs = parse_selector("env notin (dev)").expect("valid");
        assert!(selector_match(&reqs, &BTreeMap::new()));
    }

    #[test]
    fn malformed_selector_is_rejected_rather_than_silently_empty() {
        assert!(parse_selector("=nope").is_none());
        assert!(parse_selector("env in ()").is_none());
        // An empty selector is legal and matches everything.
        assert_eq!(parse_selector(""), Some(Vec::new()));
    }

    // --- scope ---

    #[test]
    fn auto_scope_is_a_subset_of_allowed_scope() {
        // A namespace in auto-namespaces but not in allowed-namespaces is not a target at all:
        // `Allowed` gates everything upstream.
        let src = obj(ReflKind::Secret, "kube-system", "registry-pull", "100", source_props("qpool", "qpool,historik"));
        let namespaces = vec![ns("kube-system"), ns("qpool"), ns("historik")];
        let d = diagnose(vec![src], &namespaces, &HashMap::new(), true, &FR);
        let targets: Vec<&str> = d.sources[0].targets.iter().map(|t| t.namespace.as_str()).collect();
        assert_eq!(targets, vec!["qpool"]);
    }

    #[test]
    fn the_source_namespace_is_never_its_own_target() {
        let src = obj(ReflKind::Secret, "qpool", "s", "100", source_props("", ""));
        let namespaces = vec![ns("qpool"), ns("historik")];
        let d = diagnose(vec![src], &namespaces, &HashMap::new(), true, &FR);
        let targets: Vec<&str> = d.sources[0].targets.iter().map(|t| t.namespace.as_str()).collect();
        assert_eq!(targets, vec!["historik"]);
    }

    #[test]
    fn auto_disabled_leaves_targets_manual() {
        let props = MirroringProps { allowed: true, allowed_ns: "qpool".to_string(), ..Default::default() };
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", props);
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert!(!t.auto);
        assert_eq!(t.status, TargetStatus::Manual);
    }

    // --- statuses ---

    #[test]
    fn a_mirror_on_the_current_version_is_synced() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mut mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("kube-system", "s", "100"));
        mirror.fingerprint = 42; // same payload as the source
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.sources[0].targets[0].status, TargetStatus::Synced);
        assert!(d.orphans.is_empty());
    }

    #[test]
    fn an_older_recorded_version_is_stale() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "200", source_props("qpool", "qpool"));
        let mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("kube-system", "s", "100"));
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.sources[0].targets[0].status, TargetStatus::Stale);
    }

    #[test]
    fn same_version_but_different_payload_is_drift() {
        // The case reflector can never fix by itself: it compares recorded versions, not content.
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mut mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("kube-system", "s", "100"));
        mirror.fingerprint = 999;
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.status, TargetStatus::Drifted);
        assert_eq!(t.worst(), Some(HintLevel::Danger));
    }

    #[test]
    fn an_unrelated_object_of_the_same_name_blocks_the_namespace() {
        // The migration case: the app still ships its own copy, so reflector skips the namespace.
        let src = obj(ReflKind::Secret, "kube-system", "registry-pull", "100", source_props("qpool", "qpool"));
        let squatter = obj(ReflKind::Secret, "qpool", "registry-pull", "7", MirroringProps::default());
        let d = diagnose(vec![src, squatter], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.status, TargetStatus::Blocked);
        assert_eq!(t.worst(), Some(HintLevel::Danger));
        assert!(!t.status.forceable(), "forcer ne débloque pas un conflit de nom");
    }

    #[test]
    fn a_mirror_of_another_source_also_blocks() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let other = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("elsewhere", "s", "1"));
        let d = diagnose(vec![src, other], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.sources[0].targets[0].status, TargetStatus::Blocked);
    }

    #[test]
    fn a_namespace_in_scope_with_nothing_in_it_is_missing() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.status, TargetStatus::Missing);
        assert!(!t.status.forceable(), "il n'y a rien à forcer sans miroir");
    }

    // --- consumers ---

    #[test]
    fn consumers_turn_a_missing_mirror_into_an_outage() {
        let src = obj(ReflKind::Secret, "kube-system", "registry-pull", "100", source_props("qpool", "qpool"));
        let mut consumers: ConsumerMap = HashMap::new();
        consumers.insert(
            ("qpool".to_string(), ReflKind::Secret, "registry-pull".to_string()),
            vec!["Pod/web-1".to_string()],
        );
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &consumers, true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.worst(), Some(HintLevel::Danger));
        assert!(t.hints.iter().any(|h| h.text.contains("Pod/web-1")));
    }

    #[test]
    fn consumers_stay_silent_when_pods_could_not_be_listed() {
        let src = obj(ReflKind::Secret, "kube-system", "registry-pull", "100", source_props("qpool", "qpool"));
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), false, &FR);
        let t = &d.sources[0].targets[0];
        // Still missing, but nothing is claimed about who is waiting for it.
        assert_eq!(t.status, TargetStatus::Missing);
        assert_eq!(t.worst(), Some(HintLevel::Warn));
    }

    #[test]
    fn a_consumer_outside_the_scope_is_reported_at_cluster_level() {
        let src = obj(ReflKind::Secret, "kube-system", "registry-pull", "100", source_props("qpool", "qpool"));
        let mut consumers: ConsumerMap = HashMap::new();
        consumers.insert(
            ("tablet".to_string(), ReflKind::Secret, "registry-pull".to_string()),
            vec!["Pod/kiosk-0".to_string()],
        );
        let d = diagnose(
            vec![src],
            &[ns("kube-system"), ns("qpool"), ns("tablet")],
            &consumers,
            true,
            &FR,
        );
        assert!(d.cluster_hints.iter().any(|h| h.text.contains("tablet") && h.level == HintLevel::Danger));
    }

    // --- orphans ---

    #[test]
    fn a_mirror_without_a_source_is_an_orphan() {
        let mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("gone", "s", "1"));
        let d = diagnose(vec![mirror], &[ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.orphans.len(), 1);
        assert_eq!(d.orphans[0].worst(), Some(HintLevel::Danger));
    }

    #[test]
    fn a_mirror_whose_source_lost_its_annotation_is_an_orphan() {
        let ex_source = obj(ReflKind::Secret, "kube-system", "s", "100", MirroringProps::default());
        let mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("kube-system", "s", "100"));
        let d = diagnose(vec![ex_source, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.orphans.len(), 1);
        assert!(d.orphans[0].hints[0].text.contains("reflection-allowed"));
    }

    #[test]
    fn a_mirror_dropped_from_the_scope_is_an_orphan() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mirror = obj(ReflKind::Secret, "historik", "s", "7", mirror_props("kube-system", "s", "100"));
        let d = diagnose(
            vec![src, mirror],
            &[ns("kube-system"), ns("qpool"), ns("historik")],
            &HashMap::new(),
            true,
            &FR,
        );
        assert_eq!(d.orphans.len(), 1);
        assert!(d.orphans[0].hints[0].text.contains("ne permet plus"));
    }

    #[test]
    fn an_object_that_is_both_mirror_and_source_is_never_a_source() {
        let mut props = mirror_props("kube-system", "s", "100");
        props.allowed = true;
        let both = obj(ReflKind::Secret, "qpool", "s", "7", props);
        let d = diagnose(vec![both], &[ns("qpool")], &HashMap::new(), true, &FR);
        assert!(d.sources.is_empty(), "reflector branche sur reflects avant reflection-allowed");
        assert_eq!(d.orphans.len(), 1);
        assert!(d.orphans.iter().any(|o| o.hints.iter().any(|h| h.text == FR.refl_orphan_both_annotations)));
    }

    // --- scope-shape rules ---

    #[test]
    fn an_empty_allowed_list_is_flagged_as_cluster_wide() {
        let props = MirroringProps { allowed: true, ..Default::default() };
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", props);
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert!(d.sources[0]
            .hints
            .iter()
            .any(|h| h.level == HintLevel::Danger && h.text.contains("tous les namespaces")));
    }

    #[test]
    fn an_auto_list_without_auto_enabled_is_decorative() {
        let props = MirroringProps {
            allowed: true,
            allowed_ns: "qpool".to_string(),
            auto_ns: "qpool".to_string(),
            ..Default::default()
        };
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", props);
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert!(d.sources[0].hints.iter().any(|h| h.text == FR.refl_auto_list_decorative));
    }

    #[test]
    fn a_manual_mirror_outside_the_auto_scope_is_doomed() {
        // The auto pass deletes any mirror of the source whose namespace is outside auto scope —
        // it does not spare the ones a human declared.
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool,historik", "qpool"));
        let mirror = obj(ReflKind::Secret, "historik", "s", "7", MirroringProps {
            reflects: Some(("kube-system".to_string(), "s".to_string())),
            reflected_version: "100".to_string(),
            ..Default::default()
        });
        let d = diagnose(
            vec![src, mirror],
            &[ns("kube-system"), ns("qpool"), ns("historik")],
            &HashMap::new(),
            true,
            &FR,
        );
        assert!(d.sources[0]
            .hints
            .iter()
            .any(|h| h.level == HintLevel::Danger && h.text.contains("supprime")));
    }

    #[test]
    fn a_pattern_matching_no_namespace_is_reported() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool,tablet", "qpool,tablet"));
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert!(d.sources[0].hints.iter().any(|h| h.text.contains("tablet")));
    }

    #[test]
    fn an_unparsable_selector_suspends_the_scope_verdicts() {
        let props = MirroringProps {
            allowed: true,
            allowed_selector: "=nope".to_string(),
            ..Default::default()
        };
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", props);
        let d = diagnose(vec![src], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert!(!d.sources[0].scope_known);
        assert!(d.sources[0].targets.is_empty(), "aucune destination inventée");
    }

    // --- annotation parsing ---

    #[test]
    fn dotnet_capitalised_booleans_are_accepted() {
        // Reflector writes `auto-reflects` with .NET's ToString(): "True", not "true".
        let mut anns = std::collections::BTreeMap::new();
        anns.insert(A_AUTO_REFLECTS.to_string(), "True".to_string());
        anns.insert(A_ALLOWED.to_string(), "TRUE".to_string());
        anns.insert(A_REFLECTS.to_string(), "kube-system/s".to_string());
        let meta = ObjectMeta { annotations: Some(anns), ..Default::default() };
        let p = parse_props(&meta);
        assert!(p.auto_reflects);
        assert!(p.allowed);
        assert_eq!(p.reflects, Some(("kube-system".to_string(), "s".to_string())));
        assert!(p.is_reflection());
        assert!(!p.is_source());
    }

    // --- force plan ---

    #[test]
    fn forcing_an_auto_mirror_also_stamps_the_source() {
        // Reflector ignores a change on an auto mirror and only re-pushes when it sees the source,
        // so clearing the mirror alone would achieve nothing.
        let plan = force_plan(ReflKind::Secret, "qpool", "registry-pull", true, true, "kube-system");
        assert_eq!(
            plan,
            vec![
                ForceWrite::ClearMirror {
                    kind: ReflKind::Secret,
                    namespace: "qpool".to_string(),
                    name: "registry-pull".to_string(),
                },
                ForceWrite::TouchSource {
                    kind: ReflKind::Secret,
                    namespace: "kube-system".to_string(),
                    name: "registry-pull".to_string(),
                },
                // Flux owns the source and would never prune kdt's annotation: the plan takes it
                // back off itself rather than leaving a mark on someone else's object.
                ForceWrite::UnstampSource {
                    kind: ReflKind::Secret,
                    namespace: "kube-system".to_string(),
                    name: "registry-pull".to_string(),
                },
            ]
        );
    }

    #[test]
    fn forcing_a_manual_mirror_leaves_the_source_alone() {
        // A direct mirror *is* re-reflected on its own change event, so there is no reason to write
        // to the source.
        let plan = force_plan(ReflKind::Secret, "qpool", "s", true, false, "kube-system");
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0], ForceWrite::ClearMirror { .. }));
    }

    #[test]
    fn an_absent_annotation_is_added_rather_than_removed() {
        // Removing a key that is not there patches nothing, and a patch that changes nothing raises
        // no watch event — the force would be silently inert.
        let plan = force_plan(ReflKind::Secret, "qpool", "s", false, false, "kube-system");
        assert!(matches!(plan[0], ForceWrite::EmptyMirror { .. }));
    }

    #[test]
    fn an_empty_annotation_is_removed_rather_than_re_emptied() {
        // The historik case: `reflected-version: ""` is already there. Writing "" over "" is a
        // no-op, so the key has to be dropped instead for the object to actually change.
        let plan = force_plan(ReflKind::Secret, "historik", "s", true, true, "kube-system");
        assert!(matches!(plan[0], ForceWrite::ClearMirror { .. }));
    }

    // --- pending ---

    #[test]
    fn a_blank_version_with_matching_content_is_only_untidy() {
        // reflector passed, wrote no version, but the payload is right: usable, not broken.
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mut props = mirror_props("kube-system", "s", "");
        props.reflected_at = "2026-07-27T14:12:32.4166782+00:00".to_string();
        let mirror = obj(ReflKind::Secret, "qpool", "s", "7", props);
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.status, TargetStatus::Pending);
        assert_eq!(t.worst(), Some(HintLevel::Info), "ne pas crier au loup sur un miroir correct");
        assert!(t.status.forceable());
    }

    #[test]
    fn a_blank_version_with_diverging_content_is_a_warning() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mut props = mirror_props("kube-system", "s", "");
        props.reflected_at = "2026-07-27T14:12:32.4166782+00:00".to_string();
        let mut mirror = obj(ReflKind::Secret, "qpool", "s", "7", props);
        mirror.fingerprint = 999;
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        assert_eq!(d.sources[0].targets[0].worst(), Some(HintLevel::Warn));
    }

    #[test]
    fn a_blank_version_and_no_pass_at_all_stays_a_warning() {
        let src = obj(ReflKind::Secret, "kube-system", "s", "100", source_props("qpool", "qpool"));
        let mirror = obj(ReflKind::Secret, "qpool", "s", "7", mirror_props("kube-system", "s", ""));
        let d = diagnose(vec![src, mirror], &[ns("kube-system"), ns("qpool")], &HashMap::new(), true, &FR);
        let t = &d.sources[0].targets[0];
        assert_eq!(t.worst(), Some(HintLevel::Warn));
        assert!(t.hints[0].text == FR.refl_pending_never);
    }

    #[test]
    fn a_malformed_reflects_is_not_a_reflection() {
        let mut anns = std::collections::BTreeMap::new();
        anns.insert(A_REFLECTS.to_string(), "no-slash".to_string());
        let meta = ObjectMeta { annotations: Some(anns), ..Default::default() };
        assert!(!parse_props(&meta).is_reflection());
    }
}
