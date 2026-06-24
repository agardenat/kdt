//! Secrets view: lists every Secret in the cluster and, for `kubernetes.io/tls` secrets, decodes the
//! embedded X.509 certificate so the table can surface the expiry date (coloured by urgency) and the
//! detail panel can show the certificate's subject/issuer/SAN/validity.
//!
//! Only the leaf certificate (`tls.crt`) is parsed — never the private key, which is read past. The
//! optional CA bundle (`ca.crt`) is decoded just for its CN and expiry. Decoding is best effort: a
//! malformed or non-PEM `tls.crt` keeps the row but flags it "certificat illisible" instead of being
//! dropped.
//!
//! Consumers are resolved in a second pass so the detail panel can answer "who uses this secret / what
//! issues it": Ingresses referencing the secret via `spec.tls[].secretName`, and the cert-manager
//! `Certificate` that produces it (when cert-manager is installed). Reads follow the same Shared-state
//! + dynamic-discovery pattern as `flux.rs`/`rbac.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;
use crate::rbac::{detect_provenance, Provenance};

const TLS_TYPE: &str = "kubernetes.io/tls";
const CRT_KEY: &str = "tls.crt";
const CA_KEY: &str = "ca.crt";

// cert-manager Certificate CRD: discovered dynamically and treated as optional (the view degrades to
// "no issuer info" when cert-manager is not installed).
const CM_GROUP: &str = "cert-manager.io";
const CM_VERSIONS: &[&str] = &["v1"];
const CM_KIND: &str = "Certificate";

// Expiry urgency band of a TLS certificate, derived from the days left until `notAfter`. Drives both
// the table colour and the sort order (most urgent first). Thresholds: <0 expired, <15 critical,
// <30 warning, otherwise healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Expiry {
    Expired,
    Critical,
    Warn,
    Ok,
}

impl Expiry {
    pub fn from_days(days: i64) -> Expiry {
        if days < 0 {
            Expiry::Expired
        } else if days < 15 {
            Expiry::Critical
        } else if days < 30 {
            Expiry::Warn
        } else {
            Expiry::Ok
        }
    }
}

// CN + expiry of the CA found in the bundle (`ca.crt`), shown alongside the leaf for chain context.
#[derive(Debug, Clone)]
pub struct CaBundle {
    pub subject_cn: String,
    pub not_after: String,
    pub days_remaining: i64,
}

// Decoded leaf certificate of a TLS secret. All fields are owned so the borrowed parser output can be
// dropped immediately after decoding.
#[derive(Debug, Clone)]
pub struct TlsCert {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub self_signed: bool,
    pub is_ca: bool,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub expiry: Expiry,
    pub serial: String,
    pub key_algo: String,
    pub ca_bundle: Option<CaBundle>,
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub namespace: String,
    pub name: String,
    pub type_: String,
    pub data_keys: Vec<String>,
    // Raw (already base64-decoded by the API) value of every data key, sorted by key. Held so the
    // detail panel can reveal the content on demand, in base64 or decoded form.
    pub data: Vec<(String, Vec<u8>)>,
    pub age: String,
    pub provenance: Provenance,
    // `Some` for a `kubernetes.io/tls` secret whose certificate decoded successfully.
    pub tls: Option<TlsCert>,
    // `Some` for a TLS-typed secret whose certificate could not be decoded (the human reason).
    pub tls_error: Option<String>,
    // "ns/name" of every Ingress referencing this secret in `spec.tls[].secretName`.
    pub ingress_refs: Vec<String>,
    // Name of the cert-manager Certificate that owns/produces this secret, when found.
    pub cert_manager: Option<String>,
    // Full object serialized to YAML (managedFields stripped), for "copy manifest".
    pub manifest: String,
}

impl SecretInfo {
    pub fn is_tls(&self) -> bool {
        self.type_ == TLS_TYPE
    }

    // TLS secrets first, ordered by urgency (fewest days left on top), then undecodable TLS, then the
    // rest alphabetically. Keeps the certs about to expire at the very top of the table.
    fn sort_key(&self) -> (u8, i64, String, String) {
        match (&self.tls, self.is_tls()) {
            (Some(c), _) => (0, c.days_remaining, self.namespace.clone(), self.name.clone()),
            (None, true) => (1, 0, self.namespace.clone(), self.name.clone()),
            (None, false) => (2, 0, self.namespace.clone(), self.name.clone()),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct SecretsState {
    pub secrets: Vec<SecretInfo>,
    pub error: Option<String>,
    pub loading: bool,
    // Whether the cert-manager CRD was present on the last fetch (drives the issuer column hint).
    pub cert_manager_present: bool,
}

impl SecretsState {
    // (total, tls, expired, expiring<30) for the table title.
    pub fn summary(&self) -> (usize, usize, usize, usize) {
        let mut s = (self.secrets.len(), 0, 0, 0);
        for sec in &self.secrets {
            if let Some(c) = &sec.tls {
                s.1 += 1;
                match c.expiry {
                    Expiry::Expired => s.2 += 1,
                    Expiry::Critical | Expiry::Warn => s.3 += 1,
                    Expiry::Ok => {}
                }
            }
        }
        s
    }
}

pub type SharedSecrets = Arc<Mutex<SecretsState>>;

pub fn new_secrets_state() -> SharedSecrets {
    Arc::new(Mutex::new(SecretsState::default()))
}

pub async fn fetch_secrets(client: Client, state: SharedSecrets) {
    {
        let mut s = state.lock().expect("secrets poisoned");
        s.loading = true;
        s.error = None;
    }

    let secret_api: Api<Secret> = Api::all(client.clone());
    let ingress_api: Api<Ingress> = Api::all(client.clone());
    let lp = ListParams::default();

    let (secrets, ingresses) = tokio::join!(secret_api.list(&lp), ingress_api.list(&lp));

    let secrets = match secrets {
        Ok(l) => l,
        Err(e) => return fail(&state, e.to_string()),
    };

    // (namespace, secretName) → Ingresses consuming it. Ingress TLS references are namespace-local.
    let mut ingress_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    if let Ok(list) = ingresses {
        for ing in &list.items {
            let ns = ing.metadata.namespace.clone().unwrap_or_default();
            let name = ing.metadata.name.clone().unwrap_or_default();
            let tls = ing.spec.as_ref().and_then(|s| s.tls.as_ref());
            for t in tls.into_iter().flatten() {
                if let Some(sn) = &t.secret_name {
                    ingress_map
                        .entry((ns.clone(), sn.clone()))
                        .or_default()
                        .push(format!("{ns}/{name}"));
                }
            }
        }
    }

    // (namespace, secretName) → cert-manager Certificate name. Optional: absent CRD just skips it.
    let (cm_map, cm_present) = fetch_cert_manager_map(&client).await;

    let mut out: Vec<SecretInfo> = Vec::with_capacity(secrets.items.len());
    for sec in &secrets.items {
        out.push(build_secret_info(sec, &ingress_map, &cm_map));
    }
    out.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut s = state.lock().expect("secrets poisoned");
    s.loading = false;
    s.error = None;
    s.cert_manager_present = cm_present;
    s.secrets = out;
}

fn build_secret_info(
    sec: &Secret,
    ingress_map: &HashMap<(String, String), Vec<String>>,
    cm_map: &HashMap<(String, String), String>,
) -> SecretInfo {
    let namespace = sec.metadata.namespace.clone().unwrap_or_default();
    let name = sec.metadata.name.clone().unwrap_or_default();
    let type_ = sec.type_.clone().unwrap_or_default();
    let mut data: Vec<(String, Vec<u8>)> = sec
        .data
        .as_ref()
        .map(|d| d.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect())
        .unwrap_or_default();
    data.sort_by(|a, b| a.0.cmp(&b.0));
    let data_keys: Vec<String> = data.iter().map(|(k, _)| k.clone()).collect();

    let (tls, tls_error) = if type_ == TLS_TYPE {
        let crt = sec.data.as_ref().and_then(|d| d.get(CRT_KEY)).map(|b| b.0.as_slice());
        let ca = sec.data.as_ref().and_then(|d| d.get(CA_KEY)).map(|b| b.0.as_slice());
        match crt {
            Some(bytes) => match parse_tls_cert(bytes, ca) {
                Ok(c) => (Some(c), None),
                Err(e) => (None, Some(e)),
            },
            None => (None, Some(format!("clé {CRT_KEY} absente"))),
        }
    } else {
        (None, None)
    };

    let key = (namespace.clone(), name.clone());
    SecretInfo {
        namespace,
        name,
        type_,
        data_keys,
        data,
        manifest: manifest_yaml(sec),
        age: sec
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
        provenance: detect_provenance(&sec.metadata),
        tls,
        tls_error,
        ingress_refs: ingress_map.get(&key).cloned().unwrap_or_default(),
        cert_manager: cm_map.get(&key).cloned(),
    }
}

// Discover cert-manager Certificates and index them by the secret they target (spec.secretName).
// Returns the map plus whether the CRD was present at all.
async fn fetch_cert_manager_map(
    client: &Client,
) -> (HashMap<(String, String), String>, bool) {
    let mut map: HashMap<(String, String), String> = HashMap::new();
    let mut ar = None;
    for v in CM_VERSIONS {
        let gvk = GroupVersionKind::gvk(CM_GROUP, v, CM_KIND);
        if let Ok((a, _caps)) = discovery::pinned_kind(client, &gvk).await {
            ar = Some(a);
            break;
        }
    }
    let Some(ar) = ar else {
        return (map, false);
    };
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    if let Ok(list) = api.list(&ListParams::default()).await {
        for obj in &list.items {
            let ns = obj.metadata.namespace.clone().unwrap_or_default();
            let name = obj.metadata.name.clone().unwrap_or_default();
            if let Some(sn) = obj
                .data
                .get("spec")
                .and_then(|s| s.get("secretName"))
                .and_then(|v| v.as_str())
            {
                map.insert((ns, sn.to_string()), name);
            }
        }
    }
    (map, true)
}

// Decode the leaf certificate from a PEM `tls.crt`, plus the CA's CN/expiry from `ca.crt` when given.
// Every returned field is owned so the borrowed parser buffers can be dropped on return.
fn parse_tls_cert(crt: &[u8], ca: Option<&[u8]>) -> Result<TlsCert, String> {
    use x509_parser::prelude::*;

    let (_, pem) = parse_x509_pem(crt).map_err(|e| format!("PEM invalide: {e:?}"))?;
    let cert = pem.parse_x509().map_err(|e| format!("X.509 invalide: {e:?}"))?;

    let subject_cn = first_cn(cert.subject());
    let issuer_cn = first_cn(cert.issuer());
    let self_signed = cert.subject() == cert.issuer();
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|b| b.value.ca)
        .unwrap_or(false);

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().map(general_name).collect())
        .unwrap_or_default();

    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();
    let days_remaining = days_until(not_after_ts);

    Ok(TlsCert {
        subject_cn,
        issuer_cn,
        self_signed,
        is_ca,
        sans,
        not_before: fmt_date(not_before_ts),
        not_after: fmt_date(not_after_ts),
        days_remaining,
        expiry: Expiry::from_days(days_remaining),
        serial: cert.raw_serial_as_string(),
        key_algo: key_algo(&cert),
        ca_bundle: ca.and_then(parse_ca_bundle),
    })
}

fn parse_ca_bundle(ca: &[u8]) -> Option<CaBundle> {
    use x509_parser::prelude::*;
    let (_, pem) = parse_x509_pem(ca).ok()?;
    let cert = pem.parse_x509().ok()?;
    let not_after_ts = cert.validity().not_after.timestamp();
    Some(CaBundle {
        subject_cn: first_cn(cert.subject()),
        not_after: fmt_date(not_after_ts),
        days_remaining: days_until(not_after_ts),
    })
}

fn first_cn(name: &x509_parser::x509::X509Name) -> String {
    name.iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string())
}

fn general_name(gn: &x509_parser::extensions::GeneralName) -> String {
    use x509_parser::extensions::GeneralName;
    match gn {
        GeneralName::DNSName(s) => s.to_string(),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("uri:{s}"),
        GeneralName::IPAddress(b) => match b.len() {
            4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            16 => <[u8; 16]>::try_from(*b)
                .map(|a| std::net::Ipv6Addr::from(a).to_string())
                .unwrap_or_else(|_| "ip?".to_string()),
            _ => "ip?".to_string(),
        },
        other => format!("{other:?}"),
    }
}

fn key_algo(cert: &x509_parser::certificate::X509Certificate) -> String {
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
        Ok(PublicKey::EC(_)) => "EC".to_string(),
        Ok(PublicKey::DSA(_)) => "DSA".to_string(),
        Ok(_) => "autre".to_string(),
        Err(_) => "?".to_string(),
    }
}

fn days_until(ts: i64) -> i64 {
    let now = chrono::Utc::now().timestamp();
    (ts - now).div_euclid(86_400)
}

fn fmt_date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "?".to_string())
}

// Serialize the live object to a kubectl-like YAML manifest, dropping the noisy managedFields.
fn manifest_yaml(sec: &Secret) -> String {
    let mut m = sec.clone();
    m.metadata.managed_fields = None;
    serde_yaml::to_string(&m).unwrap_or_default()
}

fn fail(state: &SharedSecrets, msg: String) {
    let mut s = state.lock().expect("secrets poisoned");
    s.loading = false;
    s.error = Some(msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_bands() {
        assert_eq!(Expiry::from_days(-1), Expiry::Expired);
        assert_eq!(Expiry::from_days(0), Expiry::Critical);
        assert_eq!(Expiry::from_days(14), Expiry::Critical);
        assert_eq!(Expiry::from_days(20), Expiry::Warn);
        assert_eq!(Expiry::from_days(45), Expiry::Ok);
    }

    fn info(ns: &str, name: &str, tls_days: Option<i64>, tls_typed: bool) -> SecretInfo {
        let tls = tls_days.map(|d| TlsCert {
            subject_cn: String::new(),
            issuer_cn: String::new(),
            self_signed: false,
            is_ca: false,
            sans: vec![],
            not_before: String::new(),
            not_after: String::new(),
            days_remaining: d,
            expiry: Expiry::from_days(d),
            serial: String::new(),
            key_algo: String::new(),
            ca_bundle: None,
        });
        SecretInfo {
            namespace: ns.into(),
            name: name.into(),
            type_: if tls_typed { TLS_TYPE.into() } else { "Opaque".into() },
            data_keys: vec![],
            data: vec![],
            age: String::new(),
            provenance: Provenance::Unmanaged,
            tls,
            tls_error: None,
            ingress_refs: vec![],
            cert_manager: None,
            manifest: String::new(),
        }
    }

    #[test]
    fn sort_puts_urgent_tls_first_then_others() {
        let mut v = vec![
            info("a", "opaque", None, false),
            info("a", "broken-tls", None, true),
            info("a", "fresh", Some(300), true),
            info("a", "urgent", Some(2), true),
        ];
        v.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        let order: Vec<&str> = v.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(order, ["urgent", "fresh", "broken-tls", "opaque"]);
    }
}
