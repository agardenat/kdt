//! Network inventory for the Services/Ingress view. Two object worlds share one fetch and one shared
//! state so the UI can toggle between them with a single refresh path. In the Services world each
//! Service is listed with the backing endpoints (pods) discovered from its EndpointSlices, so the view
//! can nest live endpoints under their Service the way pods nest under a workload. In the Ingress world
//! each Ingress is listed alongside the IngressClasses, so the view can group ingresses under their
//! class (the class row also surfaces the controller that serves it).
//!
//! Everything is read-only: this view has no actions, only inspection (Status/Related tabs reuse the
//! generic detail machinery via the real apiVersion/kind/namespace/name of each row).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::api::{Api, ListParams};
use kube::Client;

use crate::events::format_age;

// The standard label EndpointSlices carry to point back at the Service they belong to.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";
// Annotation marking the cluster's default IngressClass.
const DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

// A Service row (parent in the grouped Services view, or a flat row when grouping is off).
#[derive(Debug, Clone)]
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
}

// One backing endpoint of a Service (typically a Pod), nested under its Service row when grouping is on.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct IngressResource {
    pub namespace: String,
    pub name: String,
    pub class: Option<String>,
    pub hosts: String,
    pub rules: String,
    pub tls: bool,
    pub address: String,
    pub age: String,
    pub uid: String,
}

// An IngressClass row (cluster-scoped): the controller that serves it and whether it is the default.
#[derive(Debug, Clone)]
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
    pub error: Option<String>,
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

// List every Service + its backing endpoints, plus every Ingress and (cluster-scoped) IngressClass
// in `namespace` (None = all namespaces). One fetch feeds both worlds so the UI toggles without a
// reload; IngressClasses are always cluster-wide regardless of the namespace scope.
pub async fn fetch_network(client: Client, namespace: Option<String>, state: SharedNetwork) {
    {
        let mut s = state.lock().expect("network poisoned");
        s.loading = true;
        s.error = None;
    }

    // Endpoints are enrichment (the ready/total column and the nested rows): if listing EndpointSlices
    // fails — e.g. the role can't read discovery.k8s.io — degrade to no endpoints rather than blanking
    // the whole Services list, which only needs the Services themselves.
    let (endpoints, ep_summary) = list_endpoints(&client, &namespace).await.unwrap_or_default();

    let services = match list_services(&client, &namespace, &ep_summary).await {
        Ok(v) => v,
        Err(e) => {
            let mut s = state.lock().expect("network poisoned");
            s.loading = false;
            s.error = Some(e);
            return;
        }
    };

    let ingresses = list_ingresses(&client, &namespace).await.unwrap_or_default();
    let ingress_classes = list_ingress_classes(&client).await.unwrap_or_default();

    let mut s = state.lock().expect("network poisoned");
    s.loading = false;
    s.error = None;
    s.services = services;
    s.endpoints = endpoints;
    s.ingresses = ingresses;
    s.ingress_classes = ingress_classes;
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
    let tls = spec.and_then(|s| s.tls.as_ref()).map(|t| !t.is_empty()).unwrap_or(false);
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
