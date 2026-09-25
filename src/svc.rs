//! Network inventory for the Services/Ingress view. Two object worlds share one fetch and one shared
//! state so the UI can toggle between them with a single refresh path. In the Services world each
//! Service is listed with the backing endpoints (pods) discovered from its EndpointSlices, so the view
//! can nest live endpoints under their Service the way pods nest under a workload. In the Ingress world
//! each Ingress is listed alongside the IngressClasses, so the view can group ingresses under their
//! class (the class row also surfaces the controller that serves it).
//!
//! Nothing here writes to the cluster: the view inspects (Status/Related tabs reuse the generic
//! detail machinery via the real apiVersion/kind/namespace/name of each row), and its one action —
//! the port-forward of [`crate::portfwd`] — opens a local socket rather than changing an object.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::{format_age, EventRecord, LineColor, Severity};
use crate::lang::{fill, Strings};
use crate::netpol::{list_netpols, NetPolResource};
use crate::secrets::TlsCert;

// The standard label EndpointSlices carry to point back at the Service they belong to.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";
// Annotation marking the cluster's default IngressClass.
const DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";
// How long a read TLS secret is trusted before being read again. The list refreshes every 5 s and a
// certificate does not change that often; a secret that is missing or unreadable is re-read sooner,
// so the fix shows up while the user is still looking.
const TLS_CERT_TTL: Duration = Duration::from_secs(60);
const TLS_PROBLEM_TTL: Duration = Duration::from_secs(15);
const TLS_READ_CONCURRENCY: usize = 8;

// A Service row (parent in the grouped Services view, or a flat row when grouping is off).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceResource {
    pub namespace: String,
    pub name: String,
    pub type_: String,
    pub cluster_ip: String,
    pub external_ip: String,
    pub ports: String,
    pub age: String,
    pub uid: String,
    // Readiness summed across the Service's EndpointSlices, for an "ENDPOINTS" column (ready/total).
    pub endpoints_ready: usize,
    pub endpoints_total: usize,
    // The spec ports, kept structured next to the display string: the port-forward popup has to
    // offer them one by one, and a formatted "80:31234/TCP,443/TCP" cannot be picked from.
    pub port_specs: Vec<SvcPortSpec>,
    // An ExternalName Service is a DNS alias with nothing behind it in the cluster — nothing to
    // forward to, and the popup says so instead of offering ports.
    pub external_name: bool,
}

// One port of a Service spec, as the port-forward popup reads it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SvcPortSpec {
    pub name: Option<String>,
    pub port: i32,
    pub protocol: String,
    // `targetPort` as written: a number, or the container port name it points at.
    pub target: String,
}

// One backing endpoint of a Service (typically a Pod), nested under its Service row when grouping is on.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointRow {
    // Which Service this endpoint backs (used to nest it under the right parent row).
    pub service_namespace: String,
    pub service_name: String,
    pub target_name: String,
    pub target_kind: String,
    pub address: String,
    pub node: String,
    pub ready: bool,
    pub uid: String,
}

// An Ingress row: hosts and host/path → service:port routes flattened to display strings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngressResource {
    pub namespace: String,
    pub name: String,
    pub class: Option<String>,
    pub hosts: String,
    pub rules: String,
    pub tls: Vec<IngressTls>,
    pub address: String,
    pub age: String,
    pub uid: String,
}

// One `spec.tls[]` entry: the Secret the controller serves for these hosts, and what it holds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngressTls {
    pub secret: Option<String>,
    pub hosts: Vec<String>,
    pub state: TlsSecretState,
}

// What the Secret named by a `spec.tls[]` entry holds, as read from the cluster.
// Serialised as `{"kind": "missing"}`, `{"kind": "cert", "detail": {…}}`: kdt-web paints the state
// the TUI computed instead of guessing it back from a label.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "lowercase")]
pub enum TlsSecretState {
    // The entry names no secret: the controller answers these hosts with its default certificate.
    Default,
    // Not read (RBAC refusal, API error): nothing is claimed about it.
    Unchecked(String),
    Missing,
    // The secret exists but has no `tls.crt`.
    NoCert,
    Unreadable(String),
    Cert(Box<TlsCert>),
}

impl IngressTls {
    // Hosts of the entry that no DNS SAN of the served certificate matches. Empty unless a
    // certificate was read: an unread one proves nothing either way.
    pub fn uncovered_hosts(&self) -> Vec<&str> {
        let TlsSecretState::Cert(c) = &self.state else { return Vec::new() };
        self.hosts
            .iter()
            .filter(|h| !c.sans.iter().any(|san| san_matches(san, h)))
            .map(|h| h.as_str())
            .collect()
    }

    pub fn tone(&self) -> LineColor {
        match &self.state {
            TlsSecretState::Default | TlsSecretState::Unchecked(_) => LineColor::Dim,
            TlsSecretState::Missing | TlsSecretState::NoCert | TlsSecretState::Unreadable(_) => LineColor::Err,
            TlsSecretState::Cert(c) => {
                if self.uncovered_hosts().is_empty() {
                    c.expiry.tone()
                } else {
                    worse(c.expiry.tone(), LineColor::Warn)
                }
            }
        }
    }

    // What the TLS column shows for this entry.
    pub fn label(&self, st: &Strings) -> String {
        self.secret.clone().unwrap_or_else(|| st.ing_tls_default_short.to_string())
    }
}

// A DNS SAN matches a host exactly (case-insensitively), or as a wildcard covering exactly one
// leftmost label: `*.example.com` covers `a.example.com`, not `example.com` nor `a.b.example.com`.
fn san_matches(san: &str, host: &str) -> bool {
    if san.eq_ignore_ascii_case(host) {
        return true;
    }
    match (san.strip_prefix("*."), host.split_once('.')) {
        (Some(suffix), Some((label, rest))) => !label.is_empty() && label != "*" && rest.eq_ignore_ascii_case(suffix),
        _ => false,
    }
}

fn tone_rank(c: LineColor) -> u8 {
    match c {
        LineColor::Err => 3,
        LineColor::Warn => 2,
        LineColor::Ok => 1,
        LineColor::Plain | LineColor::Info | LineColor::Dim => 0,
    }
}

pub fn worse(a: LineColor, b: LineColor) -> LineColor {
    if tone_rank(b) > tone_rank(a) { b } else { a }
}

impl IngressResource {
    // The worst tone across the TLS entries; `None` for a plain-HTTP Ingress.
    pub fn tls_tone(&self) -> Option<LineColor> {
        self.tls.iter().map(IngressTls::tone).reduce(worse)
    }

    // The first Secret named in `spec.tls`, where `s` lands.
    pub fn first_tls_secret(&self) -> Option<&str> {
        self.tls.iter().find_map(|t| t.secret.as_deref())
    }
}

// An IngressClass row (cluster-scoped): the controller that serves it and whether it is the default.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngressClassResource {
    pub name: String,
    pub controller: String,
    pub is_default: bool,
    pub age: String,
    pub uid: String,
}

#[derive(Default, Debug, Clone)]
pub struct NetworkState {
    pub services: Vec<ServiceResource>,
    pub endpoints: Vec<EndpointRow>,
    pub ingresses: Vec<IngressResource>,
    pub ingress_classes: Vec<IngressClassResource>,
    pub netpols: Vec<NetPolResource>,
    pub tls_cache: TlsCache,
    pub error: Option<String>,
    pub endpoints_error: Option<String>,
    // Error listing native NetworkPolicies; kept apart from `error` so the netpol world shows its own
    // failure without blanking the Services/Ingress worlds (and vice versa).
    pub netpol_error: Option<String>,
    pub loading: bool,
}

pub type SharedNetwork = Arc<Mutex<NetworkState>>;

pub fn new_network_state() -> SharedNetwork {
    Arc::new(Mutex::new(NetworkState::default()))
}

// Does endpoint `e` back service `s` (so it nests under it in the grouped view)?
pub fn endpoint_belongs_to(e: &EndpointRow, s: &ServiceResource) -> bool {
    e.service_namespace == s.namespace && e.service_name == s.name
}

impl ServiceResource {
    // The ENDPOINTS cell. An ExternalName Service is a DNS alias and has no endpoints by design, and
    // unread EndpointSlices say nothing either way: neither gets a count that would read as zero.
    pub fn endpoints_label(&self, known: bool) -> String {
        if self.external_name {
            "—".to_string()
        } else if !known {
            "?".to_string()
        } else {
            format!("{}/{}", self.endpoints_ready, self.endpoints_total)
        }
    }

    pub fn endpoints_tone(&self, known: bool) -> LineColor {
        if self.external_name || !known {
            LineColor::Dim
        } else if self.endpoints_total == 0 {
            LineColor::Err
        } else if self.endpoints_ready < self.endpoints_total {
            LineColor::Warn
        } else {
            LineColor::Ok
        }
    }
}

impl EndpointRow {
    pub fn ready_label(&self) -> &'static str {
        if self.ready { "✓ ready" } else { "✗ notready" }
    }

    pub fn ready_tone(&self) -> LineColor {
        if self.ready { LineColor::Ok } else { LineColor::Err }
    }

    // An endpoint with a `targetRef` stands for a real object (a Pod, almost always); one without is
    // a bare address, which no generic gesture can act on.
    pub fn addressable(&self) -> bool {
        self.target_kind != "Address"
    }
}

// TLS secrets already read, keyed by (namespace, name), with the time of the read.
pub type TlsCache = HashMap<(String, String), (Instant, TlsSecretState)>;

pub struct ServicesInventory {
    pub services: Vec<ServiceResource>,
    pub endpoints: Vec<EndpointRow>,
    // Listing EndpointSlices failed: the Services are still listed, but their ENDPOINTS say nothing.
    pub endpoints_error: Option<String>,
}

// Every Service of `namespace` (None = all namespaces) with the endpoints discovered from its
// EndpointSlices. Only the Services themselves are a hard dependency.
pub async fn services_inventory(client: &Client, namespace: &Option<String>) -> Result<ServicesInventory, String> {
    // Endpoints are enrichment (the ready/total column and the nested rows): if listing EndpointSlices
    // fails — e.g. the role can't read discovery.k8s.io — degrade to no endpoints rather than blanking
    // the whole Services list, which only needs the Services themselves.
    let (endpoints, ep_summary, endpoints_error) = match list_endpoints(client, namespace).await {
        Ok((rows, summary)) => (rows, summary, None),
        Err(e) => (Vec::new(), EndpointSummary::new(), Some(e)),
    };
    let services = list_services(client, namespace, &ep_summary).await?;
    Ok(ServicesInventory { services, endpoints, endpoints_error })
}

pub struct IngressInventory {
    pub ingresses: Vec<IngressResource>,
    pub classes: Vec<IngressClassResource>,
    // IngressClasses are cluster-scoped: a namespaced role often cannot list them, and the ingresses
    // are then shown without their class rows rather than not at all.
    pub classes_error: Option<String>,
}

// Every Ingress of `namespace` with the state of each TLS Secret it names, plus the (cluster-wide)
// IngressClasses. `cache` spares the secrets read recently; pass an empty one to read them all.
pub async fn ingress_inventory(
    client: &Client,
    namespace: &Option<String>,
    cache: &mut TlsCache,
) -> Result<IngressInventory, String> {
    let mut ingresses = list_ingresses(client, namespace).await?;
    resolve_tls(client, &mut ingresses, cache).await;
    let (classes, classes_error) = match list_ingress_classes(client).await {
        Ok(v) => (v, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    Ok(IngressInventory { ingresses, classes, classes_error })
}

// List every Service + its backing endpoints, plus every Ingress and (cluster-scoped) IngressClass
// in `namespace` (None = all namespaces). One fetch feeds both worlds so the UI toggles without a
// reload; IngressClasses are always cluster-wide regardless of the namespace scope.
pub async fn fetch_network(client: Client, namespace: Option<String>, state: SharedNetwork) {
    {
        let mut s = state.lock().expect("network poisoned");
        s.loading = true;
        s.error = None;
    }

    let svc = match services_inventory(&client, &namespace).await {
        Ok(v) => v,
        Err(e) => {
            let mut s = state.lock().expect("network poisoned");
            s.loading = false;
            s.error = Some(e);
            return;
        }
    };

    let mut cache = state.lock().expect("network poisoned").tls_cache.clone();
    let ing = ingress_inventory(&client, &namespace, &mut cache).await.unwrap_or(IngressInventory {
        ingresses: Vec::new(),
        classes: Vec::new(),
        classes_error: None,
    });
    let (netpols, netpol_error) = list_netpols(&client, &namespace).await;

    let mut s = state.lock().expect("network poisoned");
    s.loading = false;
    s.error = None;
    s.services = svc.services;
    s.endpoints = svc.endpoints;
    s.endpoints_error = svc.endpoints_error;
    s.ingresses = ing.ingresses;
    s.ingress_classes = ing.classes;
    s.tls_cache = cache;
    s.netpols = netpols;
    s.netpol_error = netpol_error;
}

// The EventRecord each network row stands for, so the shared Status/Related tabs and the generic
// gestures act on the real apiVersion/kind/namespace/name. An endpoint stands for its backing Pod,
// so selecting one yields that pod's status/related/logs just like in the pods view.
pub fn service_record(s: &ServiceResource) -> EventRecord {
    EventRecord {
        uid: format!("net|{}", s.uid),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: Severity::Normal,
        reason: "Service".to_string(),
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        namespace: s.namespace.clone(),
        name: s.name.clone(),
        message: format!(
            "{} clusterIP={} extIP={} ports={} endpoints={}/{}",
            s.type_, s.cluster_ip, s.external_ip, s.ports, s.endpoints_ready, s.endpoints_total
        ),
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

pub fn endpoint_record(e: &EndpointRow) -> EventRecord {
    EventRecord {
        uid: format!("net|{}", e.uid),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: if e.ready { Severity::Normal } else { Severity::Warning },
        reason: if e.ready { "Ready".to_string() } else { "NotReady".to_string() },
        api_version: "v1".to_string(),
        kind: e.target_kind.clone(),
        namespace: e.service_namespace.clone(),
        name: e.target_name.clone(),
        message: format!("address={} node={} ready={}", e.address, e.node, e.ready),
        component: String::new(),
        host: e.node.clone(),
        count: 1,
    }
}

pub fn ingress_record(i: &IngressResource, st: &Strings) -> EventRecord {
    EventRecord {
        uid: format!("net|{}", i.uid),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: if i.tls_tone() == Some(LineColor::Err) { Severity::Warning } else { Severity::Normal },
        reason: "Ingress".to_string(),
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "Ingress".to_string(),
        namespace: i.namespace.clone(),
        name: i.name.clone(),
        message: format!(
            "class={} hosts={} tls={} {}",
            i.class.clone().unwrap_or_else(|| "—".to_string()),
            i.hosts,
            if i.tls.is_empty() {
                "—".to_string()
            } else {
                i.tls.iter().map(|t| t.label(st)).collect::<Vec<_>>().join(",")
            },
            i.rules
        ),
        component: String::new(),
        host: i.address.clone(),
        count: 1,
    }
}

pub fn ingress_class_record(c: &IngressClassResource) -> EventRecord {
    EventRecord {
        uid: format!("net|{}", c.uid),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: Severity::Normal,
        reason: "IngressClass".to_string(),
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "IngressClass".to_string(),
        namespace: String::new(),
        name: c.name.clone(),
        message: format!("controller={}{}", c.controller, if c.is_default { " (default)" } else { "" }),
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

// (ready, total) endpoint counts keyed by (namespace, service name).
type EndpointSummary = HashMap<(String, String), (usize, usize)>;

// Read EndpointSlices once: build the per-Service ready/total summary and the flat endpoint rows.
async fn list_endpoints(
    client: &Client,
    namespace: &Option<String>,
) -> Result<(Vec<EndpointRow>, EndpointSummary), String> {
    let api: Api<EndpointSlice> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?;

    let mut rows: Vec<EndpointRow> = Vec::new();
    let mut summary: EndpointSummary = HashMap::new();
    for slice in &list.items {
        let svc_ns = slice.metadata.namespace.clone().unwrap_or_default();
        let Some(svc_name) = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))
            .cloned()
        else {
            continue;
        };
        for ep in &slice.endpoints {
            let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
            let address = ep.addresses.first().cloned().unwrap_or_default();
            let node = ep.node_name.clone().unwrap_or_default();
            let (target_kind, target_name) = match ep.target_ref.as_ref() {
                Some(r) => (
                    r.kind.clone().unwrap_or_else(|| "?".to_string()),
                    r.name.clone().unwrap_or_else(|| address.clone()),
                ),
                None => ("Address".to_string(), address.clone()),
            };
            let entry = summary.entry((svc_ns.clone(), svc_name.clone())).or_insert((0, 0));
            entry.1 += 1;
            if ready {
                entry.0 += 1;
            }
            rows.push(EndpointRow {
                uid: format!("endpoint|{}/{}|{}", svc_ns, svc_name, target_name),
                service_namespace: svc_ns.clone(),
                service_name: svc_name.clone(),
                target_name,
                target_kind,
                address,
                node,
                ready,
            });
        }
    }
    rows.sort_by(|a, b| {
        (&a.service_namespace, &a.service_name, &a.target_name)
            .cmp(&(&b.service_namespace, &b.service_name, &b.target_name))
    });
    Ok((rows, summary))
}

async fn list_services(
    client: &Client,
    namespace: &Option<String>,
    ep_summary: &EndpointSummary,
) -> Result<Vec<ServiceResource>, String> {
    let api: Api<Service> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?;

    let mut out: Vec<ServiceResource> = list.items.iter().map(|s| service_resource(s, ep_summary)).collect();
    out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    Ok(out)
}

fn service_resource(s: &Service, ep_summary: &EndpointSummary) -> ServiceResource {
    let namespace = s.metadata.namespace.clone().unwrap_or_default();
    let name = s.metadata.name.clone().unwrap_or_default();
    let spec = s.spec.as_ref();
    let type_ = spec.and_then(|sp| sp.type_.clone()).unwrap_or_else(|| "ClusterIP".to_string());
    let cluster_ip = spec
        .and_then(|sp| sp.cluster_ip.clone())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| "None".to_string());
    let external_ip = service_external_ip(s);
    let ports = service_ports(s);
    let age = s
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();
    let (endpoints_ready, endpoints_total) = ep_summary
        .get(&(namespace.clone(), name.clone()))
        .copied()
        .unwrap_or((0, 0));
    let port_specs = spec
        .and_then(|sp| sp.ports.as_ref())
        .map(|ports| {
            ports
                .iter()
                .map(|p| SvcPortSpec {
                    name: p.name.clone(),
                    port: p.port,
                    protocol: p.protocol.clone().unwrap_or_else(|| "TCP".to_string()),
                    target: crate::portfwd::target_port_label(p.target_port.as_ref(), p.port),
                })
                .collect()
        })
        .unwrap_or_default();
    let external_name = spec.and_then(|sp| sp.external_name.as_ref()).is_some();
    ServiceResource {
        uid: format!("service|{}/{}", namespace, name),
        namespace,
        name,
        type_,
        cluster_ip,
        external_ip,
        ports,
        age,
        endpoints_ready,
        endpoints_total,
        port_specs,
        external_name,
    }
}

// External address as kubectl shows it: LoadBalancer ingress IP/hostname, an ExternalName target, or
// explicit externalIPs; "<none>" / "<pending>" otherwise.
fn service_external_ip(s: &Service) -> String {
    if let Some(name) = s.spec.as_ref().and_then(|sp| sp.external_name.clone()) {
        return name;
    }
    let lb: Vec<String> = s
        .status
        .as_ref()
        .and_then(|st| st.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|ing| {
            ing.iter()
                .filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone()))
                .collect()
        })
        .unwrap_or_default();
    if !lb.is_empty() {
        return lb.join(",");
    }
    if let Some(ext) = s.spec.as_ref().and_then(|sp| sp.external_ips.as_ref()) {
        if !ext.is_empty() {
            return ext.join(",");
        }
    }
    let is_lb = s.spec.as_ref().and_then(|sp| sp.type_.as_deref()) == Some("LoadBalancer");
    if is_lb { "<pending>".to_string() } else { "<none>".to_string() }
}

// Ports column matching kubectl: "port[:nodePort]/protocol" entries joined by commas.
fn service_ports(s: &Service) -> String {
    let Some(ports) = s.spec.as_ref().and_then(|sp| sp.ports.as_ref()) else {
        return String::new();
    };
    ports
        .iter()
        .map(|p| {
            let proto = p.protocol.clone().unwrap_or_else(|| "TCP".to_string());
            match p.node_port {
                Some(np) => format!("{}:{}/{}", p.port, np, proto),
                None => format!("{}/{}", p.port, proto),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

// Fill the state of every `spec.tls[]` entry, reading only the secrets whose cached read is stale.
// The cache is pruned to what is still referenced, so a deleted Ingress does not keep its secret.
async fn resolve_tls(client: &Client, ingresses: &mut [IngressResource], cache: &mut TlsCache) {
    let mut wanted: Vec<(String, String)> = Vec::new();
    for i in ingresses.iter() {
        for t in &i.tls {
            if let Some(sn) = &t.secret {
                let key = (i.namespace.clone(), sn.clone());
                if !wanted.contains(&key) {
                    wanted.push(key);
                }
            }
        }
    }
    cache.retain(|k, _| wanted.contains(k));
    let stale: Vec<(String, String)> = wanted
        .into_iter()
        .filter(|k| match cache.get(k) {
            Some((at, TlsSecretState::Cert(_))) => at.elapsed() >= TLS_CERT_TTL,
            Some((at, _)) => at.elapsed() >= TLS_PROBLEM_TTL,
            None => true,
        })
        .collect();
    let read: Vec<((String, String), TlsSecretState)> = futures::stream::iter(stale)
        .map(|(ns, name)| async move {
            let st = read_tls_secret(client, &ns, &name).await;
            ((ns, name), st)
        })
        .buffer_unordered(TLS_READ_CONCURRENCY)
        .collect()
        .await;
    let now = Instant::now();
    for (k, st) in read {
        cache.insert(k, (now, st));
    }
    for i in ingresses.iter_mut() {
        for t in i.tls.iter_mut() {
            if let Some(sn) = &t.secret {
                if let Some((_, st)) = cache.get(&(i.namespace.clone(), sn.clone())) {
                    t.state = st.clone();
                }
            }
        }
    }
}

pub async fn read_tls_secret(client: &Client, namespace: &str, name: &str) -> TlsSecretState {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    match api.get(name).await {
        Ok(sec) => match crate::secrets::leaf_cert(&sec) {
            None => TlsSecretState::NoCert,
            Some(Ok(c)) => TlsSecretState::Cert(Box::new(c)),
            Some(Err(e)) => TlsSecretState::Unreadable(e),
        },
        Err(kube::Error::Api(e)) if e.code == 404 => TlsSecretState::Missing,
        Err(e) => TlsSecretState::Unchecked(crate::edit::api_error_text(e)),
    }
}

// The Status tab of an Ingress: its class and address, then each TLS entry with the Secret behind
// it, read now rather than taken from the list's cache.
pub async fn ingress_status_lines(
    client: &Client,
    namespace: &str,
    name: &str,
    st: &'static Strings,
) -> Result<Vec<(LineColor, String)>, String> {
    let api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    let ing = api.get(name).await.map_err(|e| e.to_string())?;
    let mut res = ingress_resource(&ing);
    for t in res.tls.iter_mut() {
        if let Some(sn) = &t.secret {
            t.state = read_tls_secret(client, namespace, sn).await;
        }
    }
    let mut out: Vec<(LineColor, String)> = vec![(LineColor::Info, format!("Ingress {}/{}", namespace, name))];
    if let Some(t) = &ing.metadata.creation_timestamp {
        out.push((LineColor::Dim, format!("Created: {}", t.0)));
    }
    if let Some(c) = &res.class {
        out.push((LineColor::Plain, format!("ingressClassName: {}", c)));
    }
    if !res.address.is_empty() {
        out.push((LineColor::Plain, format!("address: {}", res.address)));
    }
    out.extend(format_ingress_tls(&res.tls, st));
    Ok(out)
}

pub fn format_ingress_tls(tls: &[IngressTls], st: &Strings) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = vec![(LineColor::Plain, String::new())];
    if tls.is_empty() {
        out.push((LineColor::Dim, st.ing_tls_none.to_string()));
        return out;
    }
    out.push((LineColor::Info, format!("TLS ({})", tls.len())));
    for t in tls {
        let head = match &t.secret {
            Some(sn) => format!("▸ Secret {}", sn),
            None => format!("▸ {}", st.ing_tls_default_short),
        };
        let head = if t.hosts.is_empty() {
            head
        } else {
            format!("{} → {}", head, t.hosts.join(", "))
        };
        out.push((t.tone(), head));
        let sub = |s: String| format!("  └ {}", s);
        match &t.state {
            TlsSecretState::Default => out.push((LineColor::Dim, sub(st.ing_tls_default.to_string()))),
            TlsSecretState::Unchecked(e) => out.push((LineColor::Dim, sub(fill(st.ing_tls_unchecked, &[("err", e)])))),
            TlsSecretState::Missing => out.push((LineColor::Err, sub(st.ing_tls_missing.to_string()))),
            TlsSecretState::NoCert => out.push((
                LineColor::Err,
                sub(fill(st.sec_crt_key_missing, &[("key", "tls.crt")])),
            )),
            TlsSecretState::Unreadable(e) => out.push((LineColor::Err, sub(e.clone()))),
            TlsSecretState::Cert(c) => {
                let issuer = if c.self_signed {
                    fill(st.sec_self_signed, &[("issuer", &c.issuer_cn)])
                } else {
                    c.issuer_cn.clone()
                };
                out.push((LineColor::Plain, sub(format!("CN {} · {}", c.subject_cn, issuer))));
                let expiry = if c.days_remaining < 0 {
                    fill(st.sec_expired_since, &[("date", &c.not_after), ("n", &(-c.days_remaining).to_string())])
                } else {
                    fill(st.sec_days_left, &[("date", &c.not_after), ("n", &c.days_remaining.to_string())])
                };
                out.push((c.expiry.tone(), sub(format!("{} {}", st.sec_lbl_expires_on, expiry))));
                for h in t.uncovered_hosts() {
                    out.push((LineColor::Warn, sub(fill(st.ing_tls_host_uncovered, &[("host", h)]))));
                }
            }
        }
    }
    out
}

async fn list_ingresses(
    client: &Client,
    namespace: &Option<String>,
) -> Result<Vec<IngressResource>, String> {
    let api: Api<Ingress> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?;
    let mut out: Vec<IngressResource> = list.items.iter().map(ingress_resource).collect();
    out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    Ok(out)
}

fn ingress_resource(i: &Ingress) -> IngressResource {
    let namespace = i.metadata.namespace.clone().unwrap_or_default();
    let name = i.metadata.name.clone().unwrap_or_default();
    let spec = i.spec.as_ref();
    let class = spec.and_then(|s| s.ingress_class_name.clone());

    let mut hosts: Vec<String> = Vec::new();
    let mut rules: Vec<String> = Vec::new();
    if let Some(rs) = spec.and_then(|s| s.rules.as_ref()) {
        for r in rs {
            let host = r.host.clone().unwrap_or_else(|| "*".to_string());
            if !hosts.contains(&host) {
                hosts.push(host.clone());
            }
            if let Some(http) = r.http.as_ref() {
                for p in &http.paths {
                    let path = p.path.clone().unwrap_or_else(|| "/".to_string());
                    let backend = p
                        .backend
                        .service
                        .as_ref()
                        .map(|svc| {
                            let port = svc
                                .port
                                .as_ref()
                                .map(|p| p.number.map(|n| n.to_string()).or_else(|| p.name.clone()).unwrap_or_default())
                                .unwrap_or_default();
                            if port.is_empty() {
                                svc.name.clone()
                            } else {
                                format!("{}:{}", svc.name, port)
                            }
                        })
                        .unwrap_or_else(|| "—".to_string());
                    rules.push(format!("{}{} → {}", host, path, backend));
                }
            }
        }
    }
    let tls: Vec<IngressTls> = spec
        .and_then(|s| s.tls.as_ref())
        .into_iter()
        .flatten()
        .map(|t| {
            let secret = t.secret_name.clone().filter(|s| !s.is_empty());
            IngressTls {
                state: if secret.is_some() {
                    TlsSecretState::Unchecked(String::new())
                } else {
                    TlsSecretState::Default
                },
                secret,
                hosts: t.hosts.clone().unwrap_or_default(),
            }
        })
        .collect();
    let address = i
        .status
        .as_ref()
        .and_then(|st| st.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|ing| {
            ing.iter()
                .filter_map(|x| x.ip.clone().or_else(|| x.hostname.clone()))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let age = i
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();
    IngressResource {
        uid: format!("ingress|{}/{}", namespace, name),
        namespace,
        name,
        class,
        hosts: hosts.join(","),
        rules: rules.join("  ·  "),
        tls,
        address,
        age,
    }
}

async fn list_ingress_classes(client: &Client) -> Result<Vec<IngressClassResource>, String> {
    let api: Api<IngressClass> = Api::all(client.clone());
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?;
    let mut out: Vec<IngressClassResource> = list.items.iter().map(ingress_class_resource).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn ingress_class_resource(c: &IngressClass) -> IngressClassResource {
    let name = c.metadata.name.clone().unwrap_or_default();
    let controller = c
        .spec
        .as_ref()
        .and_then(|s| s.controller.clone())
        .unwrap_or_default();
    let is_default = c
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(DEFAULT_CLASS_ANNOTATION))
        .map(|v| v == "true")
        .unwrap_or(false);
    let age = c
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();
    IngressClassResource {
        uid: format!("ingressclass|{}", name),
        name,
        controller,
        is_default,
        age,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{EN, FR};
    use crate::secrets::Expiry;

    fn cert(sans: &[&str], days: i64) -> TlsSecretState {
        TlsSecretState::Cert(Box::new(TlsCert {
            subject_cn: "a.example.com".into(),
            issuer_cn: "R11".into(),
            self_signed: false,
            is_ca: false,
            sans: sans.iter().map(|s| s.to_string()).collect(),
            not_before: "2026-01-01".into(),
            not_after: "2026-12-01".into(),
            days_remaining: days,
            expiry: Expiry::from_days(days),
            serial: String::new(),
            key_algo: "EC".into(),
            ca_bundle: None,
        }))
    }

    fn entry(secret: Option<&str>, hosts: &[&str], state: TlsSecretState) -> IngressTls {
        IngressTls {
            secret: secret.map(|s| s.to_string()),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            state,
        }
    }

    #[test]
    fn wildcard_san_covers_exactly_one_label() {
        assert!(san_matches("*.example.com", "a.example.com"));
        assert!(san_matches("*.Example.com", "A.example.COM"));
        assert!(!san_matches("*.example.com", "example.com"));
        assert!(!san_matches("*.example.com", "a.b.example.com"));
        assert!(san_matches("*.example.com", "*.example.com"));
        assert!(san_matches("a.example.com", "a.example.com"));
    }

    #[test]
    fn a_host_outside_the_sans_lowers_a_healthy_cert_to_warn() {
        let ok = entry(Some("t"), &["a.example.com"], cert(&["a.example.com"], 80));
        assert_eq!(ok.tone(), LineColor::Ok);
        assert!(ok.uncovered_hosts().is_empty());
        let off = entry(Some("t"), &["a.example.com", "b.other.com"], cert(&["*.example.com"], 80));
        assert_eq!(off.uncovered_hosts(), vec!["b.other.com"]);
        assert_eq!(off.tone(), LineColor::Warn);
        let expired = entry(Some("t"), &["b.other.com"], cert(&["a.example.com"], -3));
        assert_eq!(expired.tone(), LineColor::Err);
    }

    #[test]
    fn only_a_read_secret_gets_a_verdict() {
        assert_eq!(entry(Some("t"), &[], TlsSecretState::Missing).tone(), LineColor::Err);
        assert_eq!(entry(Some("t"), &[], TlsSecretState::NoCert).tone(), LineColor::Err);
        assert_eq!(entry(Some("t"), &[], TlsSecretState::Unchecked("forbidden".into())).tone(), LineColor::Dim);
        assert_eq!(entry(None, &["a"], TlsSecretState::Default).tone(), LineColor::Dim);
        let unread = entry(Some("t"), &["zzz"], TlsSecretState::Unchecked(String::new()));
        assert!(unread.uncovered_hosts().is_empty());
    }

    #[test]
    fn the_worst_entry_colours_the_ingress() {
        let mut ing = IngressResource {
            namespace: "ns".into(),
            name: "web".into(),
            class: None,
            hosts: String::new(),
            rules: String::new(),
            tls: Vec::new(),
            address: String::new(),
            age: String::new(),
            uid: String::new(),
        };
        assert_eq!(ing.tls_tone(), None);
        assert_eq!(ing.first_tls_secret(), None);
        ing.tls = vec![
            entry(None, &["x"], TlsSecretState::Default),
            entry(Some("good"), &["a.example.com"], cert(&["a.example.com"], 80)),
            entry(Some("gone"), &["b.example.com"], TlsSecretState::Missing),
        ];
        assert_eq!(ing.tls_tone(), Some(LineColor::Err));
        assert_eq!(ing.first_tls_secret(), Some("good"));
    }

    #[test]
    fn detail_names_each_secret_and_what_it_holds() {
        let tls = vec![
            entry(Some("web-tls"), &["a.example.com", "b.other.com"], cert(&["a.example.com"], 80)),
            entry(Some("gone-tls"), &["c.example.com"], TlsSecretState::Missing),
            entry(None, &["d.example.com"], TlsSecretState::Default),
        ];
        for st in [&FR, &EN] {
            let lines = format_ingress_tls(&tls, st);
            let text: Vec<&str> = lines.iter().map(|(_, t)| t.as_str()).collect();
            assert!(text.contains(&"TLS (3)"));
            assert!(text.contains(&"▸ Secret web-tls → a.example.com, b.other.com"));
            assert!(text.contains(&"▸ Secret gone-tls → c.example.com"));
            let uncovered = format!("  └ {}", fill(st.ing_tls_host_uncovered, &[("host", "b.other.com")]));
            assert!(lines.contains(&(LineColor::Warn, uncovered)));
            assert!(lines.contains(&(LineColor::Err, format!("  └ {}", st.ing_tls_missing))));
            assert!(text.contains(&format!("▸ {} → d.example.com", st.ing_tls_default_short).as_str()));
        }
        let none = format_ingress_tls(&[], &EN);
        assert_eq!(none.last().map(|(_, t)| t.as_str()), Some(EN.ing_tls_none));
    }
}
