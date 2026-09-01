//! Cluster-wide inventory of cert-manager resources, read dynamically so the tool degrades cleanly on
//! clusters where cert-manager (or just its ACME half) is absent.
//!
//! The point of this module is the *chain*. A TLS Secret that is about to expire tells you nothing
//! about why: the answer lives in a lineage that has to be walked by hand with `kubectl`, one
//! `ownerReferences` hop at a time. Here that lineage is materialised once and reused everywhere:
//!
//! ```text
//! Issuer / ClusterIssuer  →  Certificate  →  CertificateRequest  →  Order  →  Challenge
//!                                    ↓ spec.secretName
//!                                  Secret  ←  Ingress
//! ```
//!
//! Parents come from `spec.issuerRef` for Certificates and from `ownerReferences` below that. The
//! produced Secret is deliberately *not* fetched here — the Secrets view already lists and decodes
//! every Secret ([`crate::secrets`]), so the UI joins on `(namespace, secretName)` instead of
//! duplicating the X.509 parsing.
//!
//! Readiness is the subtle part: Issuers, Certificates and CertificateRequests carry
//! `status.conditions`, but **Orders and Challenges carry a plain `status.state` string instead**.
//! Reading conditions alone would show every ACME object as Unknown — precisely the objects one opens
//! this view to look at. See [`parse_ready`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::lang::{Strings, fill};
use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;
use crate::flux::SharedReconcile;

// (group, candidate versions newest-first, kind) probed via discovery until one resolves. The ACME
// group is optional: a cluster issuing only from a CA or selfSigned issuer never installs it, and its
// absence must not read as an error.
const CANDIDATES: &[(&str, &[&str], &str)] = &[
    ("cert-manager.io", &["v1"], "ClusterIssuer"),
    ("cert-manager.io", &["v1"], "Issuer"),
    ("cert-manager.io", &["v1"], "Certificate"),
    ("cert-manager.io", &["v1"], "CertificateRequest"),
    ("acme.cert-manager.io", &["v1"], "Order"),
    ("acme.cert-manager.io", &["v1"], "Challenge"),
];

const CM_GROUP: &str = "cert-manager.io";
const CM_VERSIONS: &[&str] = &["v1"];

// A dns-01 challenge that has been pending longer than this is almost always a propagation problem
// (or a missing/incorrect TXT record) rather than normal latency.
const DNS_PROPAGATION_GRACE_SECS: i64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmReady {
    Ready,
    // Issuance in flight: not yet valid, but not a failure either.
    InProgress,
    Failed,
    Unknown,
}

// The six kinds that make up a cert-manager lineage, ordered from trust anchor to leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmKind {
    ClusterIssuer,
    Issuer,
    Certificate,
    CertificateRequest,
    Order,
    Challenge,
}

impl CmKind {
    pub fn from_str(s: &str) -> Option<CmKind> {
        Some(match s {
            "ClusterIssuer" => CmKind::ClusterIssuer,
            "Issuer" => CmKind::Issuer,
            "Certificate" => CmKind::Certificate,
            "CertificateRequest" => CmKind::CertificateRequest,
            "Order" => CmKind::Order,
            "Challenge" => CmKind::Challenge,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CmKind::ClusterIssuer => "ClusterIssuer",
            CmKind::Issuer => "Issuer",
            CmKind::Certificate => "Certificate",
            CmKind::CertificateRequest => "CertificateRequest",
            CmKind::Order => "Order",
            CmKind::Challenge => "Challenge",
        }
    }

    // Short label for the tree column, where the full kind eats too much width on deep rows.
    pub fn short(self) -> &'static str {
        match self {
            CmKind::ClusterIssuer => "ClusterIssuer",
            CmKind::Issuer => "Issuer",
            CmKind::Certificate => "Certificate",
            CmKind::CertificateRequest => "CertRequest",
            CmKind::Order => "Order",
            CmKind::Challenge => "Challenge",
        }
    }

    pub fn is_issuer(self) -> bool {
        matches!(self, CmKind::ClusterIssuer | CmKind::Issuer)
    }
}

// ACME-specific detail of a Challenge, surfaced so the detail panel can name the exact DNS record
// the validation is waiting on. The state and reason are not repeated here: `parse_ready` already
// folds them into `CmResource::ready` and `::message`.
#[derive(Debug, Clone, Default)]
pub struct ChallengeInfo {
    // "dns-01" or "http-01".
    pub type_: String,
    pub dns_name: String,
    // Whether the solver has actually published the record/route yet.
    pub presented: bool,
}

// Keystore formats cert-manager can add to the produced Secret, alongside `tls.crt`/`tls.key`.
// The file names are fixed by the controller (see the CRD documentation of `spec.keystores`), which
// is what makes "requested but absent" a checkable fact rather than a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreFormat {
    Jks,
    Pkcs12,
}

impl KeystoreFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            KeystoreFormat::Jks => "JKS",
            KeystoreFormat::Pkcs12 => "PKCS12",
        }
    }

    // The key holding the certificate + private key. Always written when `create: true`.
    pub fn keystore_key(self) -> &'static str {
        match self {
            KeystoreFormat::Jks => "keystore.jks",
            KeystoreFormat::Pkcs12 => "keystore.p12",
        }
    }

    // The key holding the issuing CA. Written *only* when the issuer returned a CA certificate, i.e.
    // its absence is a finding only when the Secret itself carries a `ca.crt`.
    pub fn truststore_key(self) -> &'static str {
        match self {
            KeystoreFormat::Jks => "truststore.jks",
            KeystoreFormat::Pkcs12 => "truststore.p12",
        }
    }
}

// One requested keystore, from `spec.keystores.{jks,pkcs12}` with `create: true`.
#[derive(Debug, Clone)]
pub struct KeystoreSpec {
    pub format: KeystoreFormat,
    // `passwordSecretRef` as (secret name, key). Namespace-local, like every cert-manager secret ref.
    // None when the password is given literally in `spec.keystores.*.password`, which is mutually
    // exclusive with the ref — nothing to resolve in that case, so nothing to report either.
    pub password_ref: Option<(String, String)>,
    // JKS only: `spec.keystores.jks.alias`, defaulting to `certificate` controller-side.
    pub alias: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CmResource {
    pub kind: CmKind,
    pub api_version: String,
    pub namespace: String,
    pub name: String,
    pub ready: CmReady,
    pub message: String,
    pub age: String,
    pub age_secs: i64,
    // (kind, name) of the owning object, from ownerReferences. Always namespace-local in
    // cert-manager: a Certificate owns its CertificateRequests, which own Orders, which own Challenges.
    pub owner: Option<(String, String)>,
    // (kind, name, namespace) of spec.issuerRef — namespace empty for a ClusterIssuer.
    pub issuer_ref: Option<(String, String, String)>,
    // Certificate.spec.secretName, or the CA Issuer's spec.ca.secretName (which is itself usually
    // produced by another Certificate — that is how a private PKI chains back to its root).
    pub secret_name: Option<String>,
    pub dns_names: Vec<String>,
    pub not_after: Option<String>,
    pub days_remaining: Option<i64>,
    // status.renewalTime: when cert-manager intends to start renewing.
    pub renewal_time: Option<String>,
    // For issuers: acme | ca | selfSigned | vault | venafi.
    pub issuer_type: Option<String>,
    pub challenge: Option<ChallengeInfo>,
    // Certificates only: keystores the spec asks cert-manager to add to the produced Secret.
    pub keystores: Vec<KeystoreSpec>,
}

impl CmResource {
    // Problems first, then in-flight, then unknown, then healthy — and within a bucket the soonest
    // expiry on top, so the rows that need a human are always at the head of the table.
    fn sort_key(&self) -> (u8, i64, &str, &str, &str) {
        let bucket = match self.ready {
            CmReady::Failed => 0,
            CmReady::InProgress => 1,
            CmReady::Unknown => 2,
            CmReady::Ready => 3,
        };
        (
            bucket,
            self.days_remaining.unwrap_or(i64::MAX),
            self.kind.as_str(),
            self.namespace.as_str(),
            self.name.as_str(),
        )
    }

    // Stable identifier, used to remember collapsed nodes and to land a cross-view jump.
    pub fn uid(&self) -> String {
        cert_tree_uid(self.kind.as_str(), &self.namespace, &self.name)
    }

    // True while this object represents issuance still in flight, i.e. something a retry would act on.
    pub fn in_flight(&self) -> bool {
        self.ready == CmReady::InProgress
    }
}

pub fn cert_tree_uid(kind: &str, ns: &str, name: &str) -> String {
    format!("{}|{}/{}", kind, ns, name)
}

#[derive(Default, Debug, Clone)]
pub struct CertState {
    pub resources: Vec<CmResource>,
    pub error: Option<String>,
    pub loading: bool,
    // Whether the core cert-manager.io CRDs were found at all, as opposed to found-but-empty.
    pub installed: bool,
    // Whether the acme.cert-manager.io group exists (absent on CA/selfSigned-only clusters).
    pub acme_installed: bool,
}

impl CertState {
    // (certificates, ready, failed, in-flight, expiring<30d) for the panel title. Counted over
    // Certificates only: the intermediate ACME objects are noise in a headline figure.
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0, 0);
        for r in &self.resources {
            if r.kind != CmKind::Certificate {
                continue;
            }
            c.0 += 1;
            match r.ready {
                CmReady::Ready => c.1 += 1,
                CmReady::Failed => c.2 += 1,
                CmReady::InProgress => c.3 += 1,
                CmReady::Unknown => {}
            }
            if matches!(r.days_remaining, Some(d) if d < 30) {
                c.4 += 1;
            }
        }
        c
    }
}

pub type SharedCerts = Arc<Mutex<CertState>>;

pub fn new_certs_state() -> SharedCerts {
    Arc::new(Mutex::new(CertState::default()))
}

// List every cert-manager object present on the cluster. `installed` distinguishes "cert-manager is
// not deployed" from "deployed but nothing issued yet", and `acme_installed` keeps a CA-only cluster
// from being reported as broken.
pub async fn fetch_certs(client: Client, state: SharedCerts) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("certs poisoned");
        s.loading = true;
        s.error = None;
    }

    let mut resources: Vec<CmResource> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut installed = false;
    let mut acme_installed = false;

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
        if *group == CM_GROUP {
            installed = true;
        } else {
            acme_installed = true;
        }
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                let api_version = format!("{}/{}", group, version);
                for obj in &list.items {
                    if let Some(r) = parse_cm(obj, kind, &api_version, st) {
                        resources.push(r);
                    }
                }
            }
            Err(e) => errors.push(format!("{}: {}", kind, e)),
        }
    }

    resources.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("certs poisoned");
    s.loading = false;
    s.installed = installed;
    s.acme_installed = acme_installed;
    s.resources = resources;
    s.error = if !installed {
        Some(st.cert_crds_missing.to_string())
    } else if s.resources.is_empty() && !errors.is_empty() {
        Some(errors.join(" · "))
    } else {
        None
    };
}

fn parse_cm(
    obj: &DynamicObject,
    kind: &str,
    api_version: &str,
    st: &'static Strings,
) -> Option<CmResource> {
    let cm_kind = CmKind::from_str(kind)?;
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    let (ready, message) = parse_ready(cm_kind, status, st);

    let owner = obj.metadata.owner_references.as_deref().and_then(lineage_owner);

    let issuer_ref = spec.and_then(|s| s.get("issuerRef")).and_then(|r| {
        let iname = r.get("name").and_then(|v| v.as_str())?.to_string();
        let ikind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("Issuer").to_string();
        // A ClusterIssuer is cluster-scoped; a plain Issuer always resolves in the referrer's own
        // namespace (cert-manager forbids cross-namespace Issuer references).
        let ins = if ikind == "ClusterIssuer" { String::new() } else { namespace.clone() };
        Some((ikind, iname, ins))
    });

    let secret_name = match cm_kind {
        CmKind::Certificate => spec
            .and_then(|s| s.get("secretName"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        // A CA issuer signs from a Secret that is itself usually produced by another Certificate,
        // which is what lets the tree chain a private PKI back to its root.
        CmKind::ClusterIssuer | CmKind::Issuer => spec
            .and_then(|s| s.get("ca"))
            .and_then(|c| c.get("secretName"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    };

    let dns_names = spec
        .and_then(|s| s.get("dnsNames"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let not_after = status
        .and_then(|s| s.get("notAfter"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let days_remaining = not_after.as_deref().and_then(days_until_rfc3339);
    let renewal_time = status
        .and_then(|s| s.get("renewalTime"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let issuer_type = if cm_kind.is_issuer() {
        spec.and_then(|s| s.as_object()).and_then(|m| {
            ["acme", "ca", "selfSigned", "vault", "venafi"]
                .iter()
                .find(|k| m.contains_key(**k))
                .map(|k| k.to_string())
        })
    } else {
        None
    };

    let challenge = if cm_kind == CmKind::Challenge {
        Some(ChallengeInfo {
            type_: spec
                .and_then(|s| s.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            dns_name: spec
                .and_then(|s| s.get("dnsName"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            presented: status
                .and_then(|s| s.get("presented"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
    } else {
        None
    };

    let keystores = if cm_kind == CmKind::Certificate {
        parse_keystores(spec.and_then(|s| s.get("keystores")))
    } else {
        Vec::new()
    };

    let (age, age_secs) = match obj.metadata.creation_timestamp.as_ref() {
        Some(t) => (
            format_age(&t.0),
            k8s_openapi::jiff::Timestamp::now().as_second() - t.0.as_second(),
        ),
        None => (String::new(), 0),
    };

    Some(CmResource {
        kind: cm_kind,
        api_version: api_version.to_string(),
        namespace,
        name,
        ready,
        message,
        age,
        age_secs,
        owner,
        issuer_ref,
        secret_name,
        dns_names,
        not_after,
        days_remaining,
        renewal_time,
        issuer_type,
        challenge,
        keystores,
    })
}

// `spec.keystores` → the formats actually requested. `create` is required by the CRD but explicitly
// settable to false, so only a true value counts: a `create: false` block asks for nothing and must
// not produce a badge, let alone a "missing file" finding.
fn parse_keystores(keystores: Option<&serde_json::Value>) -> Vec<KeystoreSpec> {
    let mut out = Vec::new();
    let Some(k) = keystores else { return out };
    for (field, format) in [("jks", KeystoreFormat::Jks), ("pkcs12", KeystoreFormat::Pkcs12)] {
        let Some(block) = k.get(field) else { continue };
        if block.get("create").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let password_ref = block.get("passwordSecretRef").and_then(|r| {
            let name = r.get("name").and_then(|v| v.as_str())?.to_string();
            let key = r.get("key").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            Some((name, key))
        });
        let alias = block
            .get("alias")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        out.push(KeystoreSpec { format, password_ref, alias });
    }
    out
}

// The ownerReference that actually describes the lineage.
//
// cert-manager objects carry more than one owner: a Challenge is owned by its Order *and* by the
// issuer that will validate it. Taking the first reference is a coin flip — picking the issuer would
// hang the Challenge off the trust anchor instead of its Order, i.e. exactly the wrong chain. The
// controller reference is the authoritative one.
//
// When the controller owner is deleted, Kubernetes' garbage collector strips that reference and
// leaves the others behind, so a stale Challenge can end up with an issuer reference alone. That is
// an orphan, not a child of the issuer: return None and let it surface at the root.
fn lineage_owner(refs: &[k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference])
    -> Option<(String, String)>
{
    let usable = |kind: &str| {
        matches!(
            CmKind::from_str(kind),
            Some(CmKind::Certificate | CmKind::CertificateRequest | CmKind::Order)
        )
    };
    refs.iter()
        .find(|r| r.controller.unwrap_or(false))
        .or_else(|| refs.iter().find(|r| usable(&r.kind)))
        .map(|r| (r.kind.clone(), r.name.clone()))
}

// Readiness, from whichever place the kind actually publishes it.
//
// Issuers, Certificates and CertificateRequests use `status.conditions`. Orders and Challenges use a
// bare `status.state` string and have no conditions at all — reading conditions alone would leave
// every ACME object Unknown.
fn parse_ready(
    kind: CmKind,
    status: Option<&serde_json::Value>,
    st: &'static Strings,
) -> (CmReady, String) {
    match kind {
        CmKind::Order | CmKind::Challenge => {
            let state = status
                .and_then(|s| s.get("state"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason = status
                .and_then(|s| s.get("reason"))
                .and_then(|v| v.as_str())
                .map(collapse_ws)
                .unwrap_or_default();
            let ready = acme_state_ready(state);
            let msg = match (state.is_empty(), reason.is_empty()) {
                (true, true) => st.cert_no_state.to_string(),
                (false, true) => state.to_string(),
                (true, false) => reason,
                (false, false) => format!("{state}: {reason}"),
            };
            (ready, msg)
        }
        CmKind::CertificateRequest => {
            // A denied or malformed request never reaches a Ready=False condition, so those two
            // conditions have to be checked before falling back to Ready.
            for (ty, label) in [
                ("Denied", st.cert_denied),
                ("InvalidRequest", st.cert_invalid_request),
            ] {
                if let Some(c) = condition(status, ty) {
                    if c.0 == "True" {
                        let m = join_reason(&c.1, &c.2);
                        return (CmReady::Failed, if m.is_empty() { label.to_string() } else { m });
                    }
                }
            }
            match condition(status, "Ready") {
                Some((state, reason, msg)) => cond_to_ready(&state, &reason, &msg),
                // Approval is a distinct gate: an unapproved request sits with no Ready condition at
                // all, which is pending rather than unknown.
                None if condition(status, "Approved").is_none() => (
                    CmReady::InProgress,
                    st.cert_awaiting_approval.to_string(),
                ),
                None => (CmReady::Unknown, st.cert_no_ready_condition.to_string()),
            }
        }
        CmKind::Certificate => {
            // Issuing=True means a renewal is under way; it must not read as a failure even while
            // Ready is False (the previous certificate is usually still valid and in use).
            let issuing =
                matches!(condition(status, "Issuing"), Some((state, _, _)) if state == "True");
            match condition(status, "Ready") {
                Some((state, reason, msg)) => {
                    let (r, m) = cond_to_ready(&state, &reason, &msg);
                    if issuing && r != CmReady::Ready {
                        (CmReady::InProgress, if m.is_empty() { st.cert_issuing.to_string() } else { m })
                    } else {
                        (r, m)
                    }
                }
                None if issuing => (CmReady::InProgress, st.cert_issuing.to_string()),
                None => (CmReady::Unknown, st.cert_no_ready_condition.to_string()),
            }
        }
        CmKind::Issuer | CmKind::ClusterIssuer => match condition(status, "Ready") {
            Some((state, reason, msg)) => cond_to_ready(&state, &reason, &msg),
            None => (CmReady::Unknown, st.cert_no_ready_condition.to_string()),
        },
    }
}

// cert-manager's ACME state machine, shared by Order and Challenge.
fn acme_state_ready(state: &str) -> CmReady {
    match state {
        "valid" | "ready" => CmReady::Ready,
        "pending" | "processing" => CmReady::InProgress,
        "invalid" | "expired" | "errored" => CmReady::Failed,
        _ => CmReady::Unknown,
    }
}

// (status, reason, message) of the named condition.
fn condition(
    status: Option<&serde_json::Value>,
    ty: &str,
) -> Option<(String, String, String)> {
    let c = status?
        .get("conditions")?
        .as_array()?
        .iter()
        .find(|c| c.get("type").and_then(|v| v.as_str()) == Some(ty))?;
    Some((
        c.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
        c.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        c.get("message").and_then(|v| v.as_str()).map(collapse_ws).unwrap_or_default(),
    ))
}

fn cond_to_ready(st: &str, reason: &str, msg: &str) -> (CmReady, String) {
    let ready = match st {
        "True" => CmReady::Ready,
        "False" if is_progressing_reason(reason) => CmReady::InProgress,
        "False" => CmReady::Failed,
        _ => CmReady::Unknown,
    };
    let text = if ready == CmReady::Ready {
        msg.to_string()
    } else {
        join_reason(reason, msg)
    };
    (ready, text)
}

fn join_reason(reason: &str, msg: &str) -> String {
    match (reason.is_empty(), msg.is_empty()) {
        (true, true) => String::new(),
        (false, true) => reason.to_string(),
        (true, false) => msg.to_string(),
        (false, false) => format!("{reason}: {msg}"),
    }
}

// Ready=False reasons that mean "still working", not "failed".
fn is_progressing_reason(reason: &str) -> bool {
    matches!(reason, "Pending" | "InProgress" | "Issuing" | "Requested" | "DoesNotExist")
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn days_until_rfc3339(ts: &str) -> Option<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    Some((t.timestamp() - chrono::Utc::now().timestamp()).div_euclid(86_400))
}

fn is_past_rfc3339(ts: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.timestamp() < chrono::Utc::now().timestamp())
        .unwrap_or(false)
}

// --- Tree ---------------------------------------------------------------------------------------

// Parent of every resource (None = root), shared by the tree builder and the chain walkers so all
// three agree on the lineage.
//
// Issuers are roots. A Certificate hangs off its `issuerRef`; everything below it hangs off its
// `ownerReferences`. A reference that resolves to nothing leaves the node at the root rather than
// hiding it — an orphaned CertificateRequest is exactly the kind of thing worth seeing.
pub fn parent_map(resources: &[CmResource]) -> Vec<Option<usize>> {
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for (i, r) in resources.iter().enumerate() {
        by_key.insert(cert_tree_uid(r.kind.as_str(), &r.namespace, &r.name), i);
    }

    let mut parent: Vec<Option<usize>> = vec![None; resources.len()];
    for (i, r) in resources.iter().enumerate() {
        if r.kind.is_issuer() {
            continue;
        }
        let by_owner = r.owner.as_ref().and_then(|(okind, oname)| {
            by_key.get(&cert_tree_uid(okind, &r.namespace, oname)).copied()
        });
        let by_issuer = r.issuer_ref.as_ref().and_then(|(ikind, iname, ins)| {
            by_key.get(&cert_tree_uid(ikind, ins, iname)).copied()
        });
        // A Certificate is defined by its issuer; the ACME objects below are defined by their owner.
        parent[i] = match r.kind {
            CmKind::Certificate => by_issuer.or(by_owner),
            _ => by_owner.or(by_issuer),
        };
        if parent[i] == Some(i) {
            parent[i] = None;
        }
    }
    parent
}

// Builds the display tree, honouring `collapsed` (a collapsed node's descendants are omitted).
// Reuses `FlatTreeNode` from the Flux view: the two trees have the same shape and the same renderer
// conventions.
pub fn build_cert_tree(
    resources: &[CmResource],
    collapsed: &HashSet<String>,
) -> Vec<crate::flux::FlatTreeNode> {
    let parent = parent_map(resources);
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); resources.len()];
    let mut roots: Vec<usize> = Vec::new();
    for (i, p) in parent.iter().enumerate() {
        match p {
            Some(p) => children[*p].push(i),
            None => roots.push(i),
        }
    }

    // Reachability ignoring `collapsed`, so a node hidden under a folded parent is not mistaken for
    // an unreachable one. Whatever the roots cannot reach at all is caught in a reference cycle.
    let mut reachable = vec![false; resources.len()];
    let mut stack: Vec<usize> = roots.clone();
    while let Some(i) = stack.pop() {
        if reachable[i] {
            continue;
        }
        reachable[i] = true;
        stack.extend(children[i].iter().copied());
    }

    let mut out = Vec::new();
    let mut visited = vec![false; resources.len()];
    for r in roots {
        push_subtree(r, 0, resources, &children, collapsed, &mut visited, &mut out);
    }
    // Cycle members have no root above them and would otherwise vanish from the view entirely.
    for (i, ok) in reachable.iter().enumerate() {
        if !ok {
            push_subtree(i, 0, resources, &children, collapsed, &mut visited, &mut out);
        }
    }
    out
}

fn push_subtree(
    idx: usize,
    depth: usize,
    resources: &[CmResource],
    children: &[Vec<usize>],
    collapsed: &HashSet<String>,
    visited: &mut [bool],
    out: &mut Vec<crate::flux::FlatTreeNode>,
) {
    if visited[idx] {
        return;
    }
    visited[idx] = true;
    let has_children = !children[idx].is_empty();
    let is_collapsed = collapsed.contains(&resources[idx].uid());
    out.push(crate::flux::FlatTreeNode {
        idx,
        depth,
        has_children,
        collapsed: is_collapsed,
        // The certificate tree folds nothing away that the Flux badge would count.
        hidden_failed: 0,
        hidden_reconciling: 0,
    });
    if has_children && !is_collapsed {
        for &c in &children[idx] {
            push_subtree(c, depth + 1, resources, children, collapsed, visited, out);
        }
    }
}

// Ancestors of `idx`, root first, ending with `idx` itself. This is the "remonter la chaîne" walk.
pub fn chain_path(idx: usize, resources: &[CmResource]) -> Vec<usize> {
    let parent = parent_map(resources);
    let mut path = vec![idx];
    let mut seen: HashSet<usize> = HashSet::from([idx]);
    let mut cur = idx;
    // `seen` stops a malformed reference cycle from looping forever without truncating a legitimate
    // lineage, however deep.
    while let Some(p) = parent[cur] {
        if !seen.insert(p) {
            break;
        }
        path.push(p);
        cur = p;
    }
    path.reverse();
    path
}

// Everything below `idx`, each paired with its depth *relative to `idx`*, excluding `idx` itself.
// Siblings share a depth — the detail panel indents from this, so getting it wrong turns a fan-out
// into a fake ladder.
pub fn chain_subtree(idx: usize, resources: &[CmResource]) -> Vec<(usize, usize)> {
    let parent = parent_map(resources);
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::from([(idx, 0usize)]);
    let mut seen: HashSet<usize> = HashSet::from([idx]);
    while let Some((cur, depth)) = queue.pop_front() {
        for (i, p) in parent.iter().enumerate() {
            if *p == Some(cur) && seen.insert(i) {
                out.push((i, depth + 1));
                queue.push_back((i, depth + 1));
            }
        }
    }
    out
}

// Everything below `idx`, excluding `idx`.
pub fn chain_descendants(idx: usize, resources: &[CmResource]) -> Vec<usize> {
    chain_subtree(idx, resources).into_iter().map(|(i, _)| i).collect()
}

// Nearest Certificate at or above `idx` — the object the renew/retry actions operate on, whichever
// row of the chain the cursor happens to be sitting on.
pub fn owning_certificate(idx: usize, resources: &[CmResource]) -> Option<usize> {
    chain_path(idx, resources)
        .into_iter()
        .rev()
        .find(|&i| resources[i].kind == CmKind::Certificate)
}

// The in-flight CertificateRequest under a Certificate, if any. Deleting it is what restarts a stuck
// ACME cycle: the Order and its Challenges are owned by it and go with it.
pub fn in_flight_request(cert_idx: usize, resources: &[CmResource]) -> Option<usize> {
    chain_descendants(cert_idx, resources)
        .into_iter()
        .filter(|&i| resources[i].kind == CmKind::CertificateRequest)
        .find(|&i| resources[i].in_flight() || has_in_flight_acme(i, resources))
}

fn has_in_flight_acme(idx: usize, resources: &[CmResource]) -> bool {
    chain_descendants(idx, resources)
        .into_iter()
        .any(|i| matches!(resources[i].kind, CmKind::Order | CmKind::Challenge) && resources[i].in_flight())
}

// --- Diagnostics --------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// What the Secrets view knows about the Secret a Certificate targets. Passed in rather than fetched
// so this module never duplicates `secrets.rs`, and so the rules stay pure and testable.
#[derive(Debug, Clone, Default)]
pub struct SecretFacts {
    pub found: bool,
    pub days_remaining: Option<i64>,
    pub ingress_refs: usize,
    // Data keys of the produced Secret. Empty means "not known", never "the Secret is empty": the
    // keystore rules stay silent on an empty list rather than claim a file is missing.
    pub data_keys: Vec<String>,
    // Resolution of each `passwordSecretRef`, in `CmResource::keystores` order. Absent entries mean
    // the reference could not be looked up.
    pub password_refs: Vec<PasswordRef>,
}

// Whether a keystore password reference actually resolves. Both flags false is the common failure:
// the Secret named by `passwordSecretRef` does not exist in the Certificate's namespace.
#[derive(Debug, Clone, Default)]
pub struct PasswordRef {
    pub secret_found: bool,
    pub key_found: bool,
}

// True when the failure is an ACME rate limit. Retrying here does not help and actively burns the
// remaining quota (Let's Encrypt allows 5 duplicate certificates per week), so the retry action
// refuses to run while this holds.
pub fn is_rate_limited(idx: usize, resources: &[CmResource]) -> bool {
    let mut scope = chain_descendants(idx, resources);
    scope.push(idx);
    scope.extend(chain_path(idx, resources));
    scope.iter().any(|&i| {
        let m = resources[i].message.to_lowercase();
        m.contains("too many certificates")
            || m.contains("rate limit")
            || m.contains("ratelimited")
            || m.contains("too many failed authorizations")
    })
}

// Reads the whole chain around the selected row and explains what is actually wrong. This is the
// difference between this view and `kubectl get challenges`.
pub fn chain_hints(
    idx: usize,
    resources: &[CmResource],
    secret: Option<&SecretFacts>,
    st: &'static Strings,
) -> Vec<Hint> {
    let mut out: Vec<Hint> = Vec::new();
    let warn = |t: String| Hint { level: HintLevel::Warn, text: t };
    let danger = |t: String| Hint { level: HintLevel::Danger, text: t };

    let mut scope = chain_path(idx, resources);
    scope.extend(chain_descendants(idx, resources));

    for &i in &scope {
        let r = &resources[i];
        match r.kind {
            // 1. A dns-01 challenge stuck past the grace period is a propagation or record problem.
            CmKind::Challenge => {
                if let Some(c) = &r.challenge {
                    if r.ready == CmReady::InProgress
                        && c.type_ == "dns-01"
                        && r.age_secs > DNS_PROPAGATION_GRACE_SECS
                    {
                        out.push(warn(fill(
                            st.cert_dns_slow,
                            &[
                                ("min", &(r.age_secs / 60).to_string()),
                                ("dns", &c.dns_name),
                            ],
                        )));
                    }
                    if r.ready == CmReady::InProgress && c.type_ == "http-01" && !c.presented {
                        out.push(warn(fill(
                            st.cert_http01_not_presented,
                            &[("dns", &c.dns_name)],
                        )));
                    }
                }
            }
            // 3. An invalid Order carries the authorization failure that explains everything above it.
            CmKind::Order if r.ready == CmReady::Failed => {
                out.push(danger(fill(
                    st.cert_order_failed,
                    &[("name", &r.name), ("message", &r.message)],
                )));
            }
            // 7. A broken issuer dooms every issuance under it — worth saying once, loudly.
            CmKind::Issuer | CmKind::ClusterIssuer if r.ready != CmReady::Ready => {
                out.push(danger(fill(
                    st.cert_issuer_not_ready,
                    &[
                        ("kind", r.kind.as_str()),
                        ("name", &r.name),
                        ("message", &r.message),
                    ],
                )));
            }
            _ => {}
        }
    }

    // 2. Rate limit: checked over the whole chain, and it overrides the advice to retry.
    if is_rate_limited(idx, resources) {
        out.push(danger(st.cert_rate_limited.to_string()));
    }

    if let Some(cert_idx) = owning_certificate(idx, resources) {
        let cert = &resources[cert_idx];

        // 4. Renewal due but nothing in flight means the controller is not reacting.
        if let Some(rt) = &cert.renewal_time {
            if is_past_rfc3339(rt) && in_flight_request(cert_idx, resources).is_none() {
                out.push(warn(fill(
                    st.cert_renewal_late,
                    &[("date", &rt[..rt.len().min(10)])],
                )));
            }
        }

        if let (Some(sn), Some(facts)) = (&cert.secret_name, secret) {
            // 5. Ready with no Secret is the one case where the certificate is useless despite
            //    looking healthy.
            if !facts.found {
                out.push(danger(fill(
                    st.cert_secret_missing,
                    &[("ns", &cert.namespace), ("name", sn)],
                )));
            } else if let (Some(sd), Some(cd)) = (facts.days_remaining, cert.days_remaining) {
                // 6. A Secret that disagrees with the Certificate means consumers are serving an
                //    older certificate than the control plane believes.
                if (sd - cd).abs() > 1 {
                    out.push(warn(fill(
                        st.cert_secret_desynced,
                        &[("secret", &sd.to_string()), ("cert", &cd.to_string())],
                    )));
                }
            }
            // 8. A keystore that was asked for but never landed in the Secret: cert-manager keeps the
            //    Certificate Ready, so nothing else in the cluster says the Java consumers have no
            //    keystore to mount. Only checked once the Secret's keys are actually known.
            if facts.found && !facts.data_keys.is_empty() {
                let has = |k: &str| facts.data_keys.iter().any(|d| d == k);
                for ks in &cert.keystores {
                    if !has(ks.format.keystore_key()) {
                        out.push(danger(fill(
                            st.cert_keystore_missing,
                            &[("format", ks.format.as_str()), ("key", ks.format.keystore_key())],
                        )));
                    } else if !has(ks.format.truststore_key()) {
                        // The truststore is written only when the issuer returned a CA. With a
                        // `ca.crt` in hand and no truststore, the omission is real; without one it is
                        // the documented behaviour, and saying so beats saying nothing.
                        if has("ca.crt") {
                            out.push(danger(fill(
                                st.cert_truststore_missing,
                                &[
                                    ("format", ks.format.as_str()),
                                    ("key", ks.format.truststore_key()),
                                ],
                            )));
                        } else {
                            out.push(Hint {
                                level: HintLevel::Info,
                                text: fill(
                                    st.cert_truststore_no_ca,
                                    &[
                                        ("format", ks.format.as_str()),
                                        ("key", ks.format.truststore_key()),
                                    ],
                                ),
                            });
                        }
                    }
                }
            }

            // 9. The password reference is the usual reason a requested keystore never appears.
            for (ks, pw) in cert.keystores.iter().zip(facts.password_refs.iter()) {
                let Some((sname, skey)) = &ks.password_ref else { continue };
                if !pw.secret_found {
                    out.push(warn(fill(
                        st.cert_keystore_pw_secret_missing,
                        &[
                            ("format", ks.format.as_str()),
                            ("ns", &cert.namespace),
                            ("name", sname),
                        ],
                    )));
                } else if !pw.key_found && !skey.is_empty() {
                    out.push(warn(fill(
                        st.cert_keystore_pw_key_missing,
                        &[
                            ("format", ks.format.as_str()),
                            ("key", skey),
                            ("name", sname),
                        ],
                    )));
                }
            }

            if facts.found && facts.ingress_refs == 0 && cert.ready == CmReady::Ready {
                out.push(Hint {
                    level: HintLevel::Info,
                    text: fill(
                        st.cert_no_ingress_ref,
                        &[("ns", &cert.namespace), ("name", sn)],
                    ),
                });
            }
        }
    }

    out.dedup_by(|a, b| a.text == b.text);
    out
}

// --- Actions ------------------------------------------------------------------------------------

// Forces re-issuance, the way `cmctl renew` does: set the `Issuing` condition to True on the
// Certificate's status subresource.
//
// The condition has to be merged into the existing array by hand. A JSON merge patch **replaces**
// an array wholesale, so patching `{"conditions":[Issuing]}` would drop `Ready` and every other
// condition cert-manager relies on. Hence read-modify-write, sending the complete list back.
pub async fn renew(
    client: Client,
    api_version: String,
    namespace: String,
    name: String,
    status: SharedReconcile,
) {
    let st = crate::lang::active();
    let msg = match run_renew(&client, &api_version, &namespace, &name, st).await {
        Ok(m) => m,
        Err(e) => fill(st.cert_renew_failed, &[("e", &e)]),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((std::time::Instant::now(), msg));
    }
}

async fn run_renew(
    client: &Client,
    api_version: &str,
    namespace: &str,
    name: &str,
    st: &'static Strings,
) -> Result<String, String> {
    let version = api_version.split_once('/').map(|(_, v)| v).unwrap_or("v1");
    let ar = resolve_ar(client, CM_GROUP, &[version], "Certificate").await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let obj = api
        .get(name)
        .await
        .map_err(|e| format!("Certificate/{} : {}", name, e))?;

    let now = chrono::Utc::now().to_rfc3339();
    let issuing = serde_json::json!({
        "type": "Issuing",
        "status": "True",
        "reason": "ManuallyTriggered",
        // Written onto the Kubernetes object, not shown in the UI: it stays in one language so a
        // reader of `kubectl describe` sees the same text whatever kdt was set to.
        "message": "Renouvellement déclenché manuellement depuis kdt",
        "lastTransitionTime": now,
    });

    // Keep every other condition, replacing only Issuing.
    let mut conditions: Vec<serde_json::Value> = obj
        .data
        .get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.get("type").and_then(|v| v.as_str()) != Some("Issuing"))
        .collect();
    conditions.push(issuing);

    let patch = serde_json::json!({ "status": { "conditions": conditions } });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| format!("Certificate/{} : {}", name, e))?;
    Ok(fill(st.cert_renew_ok, &[("name", name)]))
}

// Restarts a stuck ACME cycle by deleting the in-flight CertificateRequest. Deleting the Challenge
// alone achieves nothing — its Order recreates it identically. The Order and its Challenges are
// owned by the request, so they are garbage-collected with it and cert-manager issues a fresh one.
pub async fn retry_acme(
    client: Client,
    api_version: String,
    namespace: String,
    name: String,
    status: SharedReconcile,
) {
    let st = crate::lang::active();
    let msg = match run_retry_acme(&client, &api_version, &namespace, &name, st).await {
        Ok(m) => m,
        Err(e) => fill(st.cert_acme_retry_failed, &[("e", &e)]),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((std::time::Instant::now(), msg));
    }
}

async fn run_retry_acme(
    client: &Client,
    api_version: &str,
    namespace: &str,
    name: &str,
    st: &'static Strings,
) -> Result<String, String> {
    let version = api_version.split_once('/').map(|(_, v)| v).unwrap_or("v1");
    let ar = resolve_ar(client, CM_GROUP, &[version], "CertificateRequest").await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    api.delete(name, &kube::api::DeleteParams::default())
        .await
        .map_err(|e| format!("CertificateRequest/{} : {}", name, e))?;
    Ok(fill(st.cert_acme_retry_ok, &[("name", name)]))
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
    // Fall back to the canonical version when the caller passed one the cluster does not serve.
    for v in CM_VERSIONS {
        let gvk = GroupVersionKind::gvk(group, v, kind);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            return Ok(ar);
        }
    }
    Err(format!("{} introuvable sur le cluster", kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{FR, reads_as};

    fn res(kind: CmKind, ns: &str, name: &str) -> CmResource {
        CmResource {
            kind,
            api_version: "cert-manager.io/v1".into(),
            namespace: ns.into(),
            name: name.into(),
            ready: CmReady::Ready,
            message: String::new(),
            age: String::new(),
            age_secs: 0,
            owner: None,
            issuer_ref: None,
            secret_name: None,
            dns_names: vec![],
            not_after: None,
            days_remaining: None,
            renewal_time: None,
            issuer_type: None,
            challenge: None,
            keystores: vec![],
        }
    }

    // ClusterIssuer → Certificate → CertificateRequest → Order → Challenge, the nominal lineage.
    fn full_chain() -> Vec<CmResource> {
        let mut ci = res(CmKind::ClusterIssuer, "", "letsencrypt");
        ci.issuer_type = Some("acme".into());
        let mut cert = res(CmKind::Certificate, "mon", "grafana-tls");
        cert.issuer_ref = Some(("ClusterIssuer".into(), "letsencrypt".into(), String::new()));
        cert.secret_name = Some("grafana-tls".into());
        let mut cr = res(CmKind::CertificateRequest, "mon", "grafana-tls-2");
        cr.owner = Some(("Certificate".into(), "grafana-tls".into()));
        let mut order = res(CmKind::Order, "mon", "grafana-tls-2-289");
        order.owner = Some(("CertificateRequest".into(), "grafana-tls-2".into()));
        let mut ch = res(CmKind::Challenge, "mon", "grafana-tls-2-289-186");
        ch.owner = Some(("Order".into(), "grafana-tls-2-289".into()));
        vec![ci, cert, cr, order, ch]
    }

    #[test]
    fn tree_nests_the_full_lineage() {
        let all = full_chain();
        let rows = build_cert_tree(&all, &HashSet::new());
        let shape: Vec<(usize, &str)> =
            rows.iter().map(|n| (n.depth, all[n.idx].kind.as_str())).collect();
        assert_eq!(
            shape,
            [
                (0, "ClusterIssuer"),
                (1, "Certificate"),
                (2, "CertificateRequest"),
                (3, "Order"),
                (4, "Challenge"),
            ]
        );
    }

    #[test]
    fn collapsing_hides_descendants_only() {
        let all = full_chain();
        let mut collapsed = HashSet::new();
        collapsed.insert(all[1].uid());
        let rows = build_cert_tree(&all, &collapsed);
        let kinds: Vec<&str> = rows.iter().map(|n| all[n.idx].kind.as_str()).collect();
        assert_eq!(kinds, ["ClusterIssuer", "Certificate"]);
        assert!(rows[1].has_children && rows[1].collapsed);
    }

    #[test]
    fn orphans_stay_visible_at_the_root() {
        // A CertificateRequest whose Certificate is gone, and a Certificate whose issuer is missing:
        // both must still be listed rather than silently dropped.
        let mut cr = res(CmKind::CertificateRequest, "mon", "orphan-1");
        cr.owner = Some(("Certificate".into(), "disparu".into()));
        let mut cert = res(CmKind::Certificate, "mon", "sans-issuer");
        cert.issuer_ref = Some(("Issuer".into(), "absent".into(), "mon".into()));
        let all = vec![cr, cert];
        let rows = build_cert_tree(&all, &HashSet::new());
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|n| n.depth == 0));
    }

    #[test]
    fn reference_cycle_does_not_drop_rows_or_hang() {
        let mut a = res(CmKind::Order, "mon", "a");
        a.owner = Some(("Order".into(), "b".into()));
        let mut b = res(CmKind::Order, "mon", "b");
        b.owner = Some(("Order".into(), "a".into()));
        let all = vec![a, b];
        let rows = build_cert_tree(&all, &HashSet::new());
        assert_eq!(rows.len(), 2);
        assert_eq!(chain_path(0, &all).len(), 2);
    }

    #[test]
    fn self_reference_is_treated_as_a_root() {
        let mut a = res(CmKind::Order, "mon", "a");
        a.owner = Some(("Order".into(), "a".into()));
        let all = vec![a];
        assert_eq!(parent_map(&all)[0], None);
        assert_eq!(build_cert_tree(&all, &HashSet::new()).len(), 1);
    }

    fn owner_ref(kind: &str, name: &str, controller: bool)
        -> k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference
    {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "cert-manager.io/v1".into(),
            kind: kind.into(),
            name: name.into(),
            uid: "u".into(),
            controller: Some(controller),
            block_owner_deletion: Some(true),
        }
    }

    #[test]
    fn lineage_owner_prefers_the_controller_over_the_issuer() {
        // Observed on a live cluster: a Challenge is owned by both its Order and the ClusterIssuer.
        // Taking the first reference would hang it off the trust anchor instead of its Order.
        let refs = [
            owner_ref("ClusterIssuer", "letsencrypt", false),
            owner_ref("Order", "cert-1-999", true),
        ];
        assert_eq!(lineage_owner(&refs), Some(("Order".into(), "cert-1-999".into())));

        // Controller missing but a usable lineage kind present (GC has not caught up yet).
        let refs = [owner_ref("Order", "cert-1-999", false)];
        assert_eq!(lineage_owner(&refs), Some(("Order".into(), "cert-1-999".into())));

        // Only the issuer left: the controller owner was deleted, so this is an orphan. It must not
        // be adopted by the issuer — it belongs at the root where it is visible as such.
        let refs = [owner_ref("ClusterIssuer", "letsencrypt", false)];
        assert_eq!(lineage_owner(&refs), None);

        assert_eq!(lineage_owner(&[]), None);
    }

    #[test]
    fn subtree_depths_keep_siblings_level() {
        // Two Certificates under one issuer are siblings, not a ladder: both sit at depth 1, and the
        // request under one of them at depth 2.
        let mut ci = res(CmKind::ClusterIssuer, "", "le");
        ci.issuer_type = Some("acme".into());
        let mut c1 = res(CmKind::Certificate, "a", "one");
        c1.issuer_ref = Some(("ClusterIssuer".into(), "le".into(), String::new()));
        let mut c2 = res(CmKind::Certificate, "a", "two");
        c2.issuer_ref = Some(("ClusterIssuer".into(), "le".into(), String::new()));
        let mut cr = res(CmKind::CertificateRequest, "a", "one-1");
        cr.owner = Some(("Certificate".into(), "one".into()));
        let all = vec![ci, c1, c2, cr];

        let mut sub = chain_subtree(0, &all);
        sub.sort_unstable();
        assert_eq!(sub, [(1, 1), (2, 1), (3, 2)]);
    }

    #[test]
    fn chain_path_walks_from_the_trust_anchor_down() {
        let all = full_chain();
        let path = chain_path(4, &all);
        let kinds: Vec<&str> = path.iter().map(|&i| all[i].kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["ClusterIssuer", "Certificate", "CertificateRequest", "Order", "Challenge"]
        );
        // Reachable from any row of the chain, not just the leaf.
        assert_eq!(owning_certificate(4, &all), Some(1));
        assert_eq!(owning_certificate(0, &all), None);
    }

    #[test]
    fn acme_objects_read_their_state_not_their_conditions() {
        // The trap: Orders and Challenges have no conditions at all. A conditions-only parser would
        // report every one of them as Unknown.
        let st = serde_json::json!({ "state": "pending", "reason": "waiting for DNS" });
        assert_eq!(parse_ready(CmKind::Order, Some(&st), &FR).0, CmReady::InProgress);
        let st = serde_json::json!({ "state": "invalid", "reason": "NXDOMAIN" });
        let (r, m) = parse_ready(CmKind::Challenge, Some(&st), &FR);
        assert_eq!(r, CmReady::Failed);
        assert_eq!(m, "invalid: NXDOMAIN");
        let st = serde_json::json!({ "state": "valid" });
        assert_eq!(parse_ready(CmKind::Order, Some(&st), &FR).0, CmReady::Ready);
    }

    #[test]
    fn certificate_issuing_is_progress_not_failure() {
        let st = serde_json::json!({ "conditions": [
            { "type": "Ready", "status": "False", "reason": "DoesNotExist", "message": "issuing" },
            { "type": "Issuing", "status": "True", "reason": "Renewing" },
        ]});
        assert_eq!(parse_ready(CmKind::Certificate, Some(&st), &FR).0, CmReady::InProgress);

        let st = serde_json::json!({ "conditions": [
            { "type": "Ready", "status": "False", "reason": "Failed", "message": "order errored" },
        ]});
        assert_eq!(parse_ready(CmKind::Certificate, Some(&st), &FR).0, CmReady::Failed);

        let st = serde_json::json!({ "conditions": [
            { "type": "Ready", "status": "True", "reason": "Ready", "message": "up to date" },
        ]});
        assert_eq!(parse_ready(CmKind::Certificate, Some(&st), &FR).0, CmReady::Ready);
    }

    #[test]
    fn certificate_request_denial_beats_the_ready_condition() {
        let st = serde_json::json!({ "conditions": [
            { "type": "Ready", "status": "False", "reason": "Pending", "message": "waiting" },
            { "type": "Denied", "status": "True", "reason": "Denied", "message": "policy refuse" },
        ]});
        let (r, m) = parse_ready(CmKind::CertificateRequest, Some(&st), &FR);
        assert_eq!(r, CmReady::Failed);
        assert_eq!(m, "Denied: policy refuse");

        // Not yet approved: no Ready condition at all, which is pending rather than unknown.
        let st = serde_json::json!({ "conditions": [] });
        assert_eq!(
            parse_ready(CmKind::CertificateRequest, Some(&st), &FR).0,
            CmReady::InProgress
        );
    }

    #[test]
    fn sort_puts_failures_then_soonest_expiry_first() {
        let mut ok_far = res(CmKind::Certificate, "a", "far");
        ok_far.days_remaining = Some(300);
        let mut ok_soon = res(CmKind::Certificate, "a", "soon");
        ok_soon.days_remaining = Some(3);
        let mut failed = res(CmKind::Certificate, "a", "broken");
        failed.ready = CmReady::Failed;
        let mut progress = res(CmKind::Certificate, "a", "issuing");
        progress.ready = CmReady::InProgress;

        let mut v = [ok_far, ok_soon, failed, progress];
        v.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        let order: Vec<&str> = v.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, ["broken", "issuing", "soon", "far"]);
    }

    #[test]
    fn rate_limit_is_detected_anywhere_in_the_chain() {
        let mut all = full_chain();
        all[2].message = "Failed: acme: urn:ietf:params:acme:error:rateLimited: too many certificates already issued".into();
        // Detected from the Challenge at the bottom as well as from the Certificate above.
        assert!(is_rate_limited(4, &all));
        assert!(is_rate_limited(1, &all));

        let clean = full_chain();
        assert!(!is_rate_limited(4, &clean));
    }

    #[test]
    fn slow_dns_challenge_is_flagged_only_past_the_grace_period() {
        let mut all = full_chain();
        all[4].ready = CmReady::InProgress;
        all[4].challenge = Some(ChallengeInfo {
            type_: "dns-01".into(),
            dns_name: "grafana.exemple.fr".into(),
            presented: true,
        });

        all[4].age_secs = 60;
        assert!(chain_hints(4, &all, None, &FR).is_empty());

        all[4].age_secs = 1_800;
        let hints = chain_hints(4, &all, None, &FR);
        assert!(hints.iter().any(|h| h.text.contains("_acme-challenge.grafana.exemple.fr")));
    }

    #[test]
    fn missing_and_desynced_secrets_are_reported() {
        let all = full_chain();
        let missing = SecretFacts { found: false, ..SecretFacts::default() };
        let hints = chain_hints(1, &all, Some(&missing), &FR);
        assert!(hints.iter().any(|h| reads_as(&h.text, FR.cert_secret_missing) && h.level == HintLevel::Danger));

        let mut synced = full_chain();
        synced[1].days_remaining = Some(60);
        let facts = SecretFacts {
            found: true,
            days_remaining: Some(12),
            ingress_refs: 1,
            ..SecretFacts::default()
        };
        let hints = chain_hints(1, &synced, Some(&facts), &FR);
        assert!(hints.iter().any(|h| reads_as(&h.text, FR.cert_secret_desynced)));

        let facts = SecretFacts {
            found: true,
            days_remaining: Some(60),
            ingress_refs: 1,
            ..SecretFacts::default()
        };
        let hints = chain_hints(1, &synced, Some(&facts), &FR);
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_secret_desynced)));
    }

    fn jks_chain(password_ref: Option<(&str, &str)>) -> Vec<CmResource> {
        let mut all = full_chain();
        all[1].keystores = vec![KeystoreSpec {
            format: KeystoreFormat::Jks,
            password_ref: password_ref.map(|(n, k)| (n.to_string(), k.to_string())),
            alias: None,
        }];
        all
    }

    fn keys(list: &[&str]) -> SecretFacts {
        SecretFacts {
            found: true,
            data_keys: list.iter().map(|s| s.to_string()).collect(),
            ..SecretFacts::default()
        }
    }

    #[test]
    fn requested_keystore_absent_from_the_secret_is_reported() {
        let all = jks_chain(None);
        let facts = keys(&["tls.crt", "tls.key", "ca.crt"]);
        let hints = chain_hints(1, &all, Some(&facts), &FR);
        assert!(hints
            .iter()
            .any(|h| reads_as(&h.text, FR.cert_keystore_missing) && h.level == HintLevel::Danger));

        let complete = keys(&["tls.crt", "tls.key", "ca.crt", "keystore.jks", "truststore.jks"]);
        let hints = chain_hints(1, &all, Some(&complete), &FR);
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_missing)));
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_truststore_missing)));
    }

    // A missing truststore means two different things depending on whether the issuer returned a CA,
    // and only one of them is a problem.
    #[test]
    fn missing_truststore_is_a_finding_only_when_a_ca_is_present() {
        let all = jks_chain(None);
        let with_ca = keys(&["tls.crt", "tls.key", "ca.crt", "keystore.jks"]);
        let hints = chain_hints(1, &all, Some(&with_ca), &FR);
        assert!(hints
            .iter()
            .any(|h| reads_as(&h.text, FR.cert_truststore_missing) && h.level == HintLevel::Danger));

        let without_ca = keys(&["tls.crt", "tls.key", "keystore.jks"]);
        let hints = chain_hints(1, &all, Some(&without_ca), &FR);
        assert!(hints
            .iter()
            .any(|h| reads_as(&h.text, FR.cert_truststore_no_ca) && h.level == HintLevel::Info));
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_truststore_missing)));
    }

    // An unknown key list must stay silent: "we did not read the Secret" is not "the file is gone".
    #[test]
    fn unknown_secret_keys_report_nothing() {
        let all = jks_chain(None);
        let facts = SecretFacts { found: true, ..SecretFacts::default() };
        let hints = chain_hints(1, &all, Some(&facts), &FR);
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_missing)));
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_truststore_no_ca)));
    }

    #[test]
    fn unresolvable_keystore_password_is_reported() {
        let all = jks_chain(Some(("jks-password", "keystore-pass")));
        let mut facts = keys(&["tls.crt", "tls.key", "ca.crt", "keystore.jks", "truststore.jks"]);

        facts.password_refs = vec![PasswordRef { secret_found: false, key_found: false }];
        let hints = chain_hints(1, &all, Some(&facts), &FR);
        assert!(hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_pw_secret_missing)));

        facts.password_refs = vec![PasswordRef { secret_found: true, key_found: false }];
        let hints = chain_hints(1, &all, Some(&facts), &FR);
        assert!(hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_pw_key_missing)));

        facts.password_refs = vec![PasswordRef { secret_found: true, key_found: true }];
        let hints = chain_hints(1, &all, Some(&facts), &FR);
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_pw_secret_missing)));
        assert!(!hints.iter().any(|h| reads_as(&h.text, FR.cert_keystore_pw_key_missing)));
    }

    #[test]
    fn keystores_are_parsed_only_when_creation_is_enabled() {
        let spec = serde_json::json!({
            "jks": {
                "create": true,
                "alias": "cassandra",
                "passwordSecretRef": { "name": "jks-password", "key": "keystore-pass" }
            },
            "pkcs12": { "create": false }
        });
        let parsed = parse_keystores(Some(&spec));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].format, KeystoreFormat::Jks);
        assert_eq!(parsed[0].alias.as_deref(), Some("cassandra"));
        assert_eq!(
            parsed[0].password_ref,
            Some(("jks-password".to_string(), "keystore-pass".to_string()))
        );
        assert!(parse_keystores(None).is_empty());
    }

    #[test]
    fn broken_issuer_is_reported_from_a_descendant() {
        let mut all = full_chain();
        all[0].ready = CmReady::Failed;
        all[0].message = "ACME account registration failed".into();
        let hints = chain_hints(4, &all, None, &FR);
        assert!(hints
            .iter()
            .any(|h| h.text.contains("letsencrypt") && h.level == HintLevel::Danger));
    }

    #[test]
    fn in_flight_request_is_found_via_its_pending_challenge() {
        let mut all = full_chain();
        // The request itself looks settled; the pending Challenge underneath is what makes the
        // cycle live, and it is that cycle the retry action restarts.
        all[4].ready = CmReady::InProgress;
        assert_eq!(in_flight_request(1, &all), Some(2));

        let settled = full_chain();
        assert_eq!(in_flight_request(1, &settled), None);
    }

    #[test]
    fn counts_only_tally_certificates() {
        let mut all = full_chain();
        all[1].days_remaining = Some(12);
        let s = CertState { resources: all, ..Default::default() };
        assert_eq!(s.counts(), (1, 1, 0, 0, 1));
    }
}
