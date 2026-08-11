//! Network policy inventory for the network view's third world. Two policy worlds coexist in one list:
//! the native Kubernetes `NetworkPolicy` (fully typed, with a real posture verdict computed from its
//! well-defined semantics) and the CNI-specific CRDs — Cilium's `CiliumNetworkPolicy` /
//! `CiliumClusterwideNetworkPolicy` and Calico's `NetworkPolicy` / `GlobalNetworkPolicy`. The CRDs are
//! discovered (probed, so an absent CNI simply yields nothing) and rendered factually: their selector
//! and rule counts, but no ingress/egress *verdict*, because each engine's default-allow/deny semantics
//! differ from the native ones and asserting them would be guessing.
//!
//! Everything is read-only: rows stand in for their real object via apiVersion/kind/namespace/name so
//! the shared Status/Related/YAML machinery works unchanged.

use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};

use crate::events::format_age;

// Which controller owns a policy row. Drives the KIND badge and whether a posture verdict is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetPolEngine {
    K8s,
    Cilium,
    Calico,
}

impl NetPolEngine {
    pub fn label(&self) -> &'static str {
        match self {
            NetPolEngine::K8s => "k8s",
            NetPolEngine::Cilium => "cilium",
            NetPolEngine::Calico => "calico",
        }
    }
}

// The posture of one direction (ingress or egress) for the pods a *native* policy selects. Only the
// native engine sets anything other than `Unknown`: its semantics are specified, the CNIs' are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirEffect {
    // The policy does not affect this direction (not in policyTypes): traffic is left to other policies.
    Unaffected,
    // Direction is governed but no rule allows anything: the selected pods are isolated (default-deny).
    Deny,
    // A rule allows every peer (empty `from`/`to`): the direction is wide open for the selected pods.
    AllowAll,
    // At least one rule with explicit peers: selective allow.
    Selective,
    // CRD engines: the direction exists but its effect is engine-specific and not asserted here.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NetPolResource {
    pub engine: NetPolEngine,
    pub kind: String,
    pub api_version: String,
    // Empty for cluster-scoped policies (CiliumClusterwide, Calico GlobalNetworkPolicy).
    pub namespace: String,
    pub name: String,
    // The pods/endpoints the policy applies to ("all pods" when the selector is empty).
    pub target: String,
    // Native only: the resolved policyTypes ("Ingress", "Egress", "Ingress,Egress"). Empty for CRDs.
    pub types: String,
    pub ingress: String,
    pub egress: String,
    pub ingress_effect: DirEffect,
    pub egress_effect: DirEffect,
    pub age: String,
    pub uid: String,
}

impl NetPolResource {
    pub fn sort_key(&self) -> (u8, String, String) {
        // Native policies first, then by namespace/name; keeps the engine grouping stable in the list.
        let engine_order = match self.engine {
            NetPolEngine::K8s => 0,
            NetPolEngine::Cilium => 1,
            NetPolEngine::Calico => 2,
        };
        (engine_order, self.namespace.clone(), self.name.clone())
    }
}

// CRD policy kinds probed via discovery: (group, versions newest-first, kind, cluster_scoped).
const CRD_CANDIDATES: &[(&str, &[&str], &str, bool)] = &[
    ("cilium.io", &["v2"], "CiliumNetworkPolicy", false),
    ("cilium.io", &["v2"], "CiliumClusterwideNetworkPolicy", true),
    ("crd.projectcalico.org", &["v1"], "NetworkPolicy", false),
    ("crd.projectcalico.org", &["v1"], "GlobalNetworkPolicy", true),
];

// List every network policy in scope: native NetworkPolicies plus any discovered CNI CRDs. `namespace`
// None means all namespaces. Discovery failures for a CRD (CNI not installed) are silently skipped —
// the native list is the floor. Returns (policies, native_list_error): a native error is surfaced,
// CRD errors are not (their absence is normal).
pub async fn list_netpols(
    client: &Client,
    namespace: &Option<String>,
) -> (Vec<NetPolResource>, Option<String>) {
    let mut out: Vec<NetPolResource> = Vec::new();
    let mut native_err = None;

    match list_native(client, namespace).await {
        Ok(mut v) => out.append(&mut v),
        Err(e) => native_err = Some(e),
    }

    for (group, versions, kind, cluster_scoped) in CRD_CANDIDATES {
        let mut resolved = None;
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
                resolved = Some((ar, *v));
                break;
            }
        }
        let Some((ar, version)) = resolved else { continue };
        // Clusterwide CRDs are cluster-scoped; namespaced CRDs honor the current scope.
        let api: Api<DynamicObject> = if *cluster_scoped {
            Api::all_with(client.clone(), &ar)
        } else {
            match namespace {
                Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
                None => Api::all_with(client.clone(), &ar),
            }
        };
        let engine = if group.starts_with("cilium") {
            NetPolEngine::Cilium
        } else {
            NetPolEngine::Calico
        };
        let api_version = format!("{}/{}", group, version);
        if let Ok(list) = api.list(&ListParams::default()).await {
            for obj in &list.items {
                out.push(parse_crd(obj, engine, kind, &api_version));
            }
        }
    }

    out.sort_by_key(|a| a.sort_key());
    (out, native_err)
}

async fn list_native(
    client: &Client,
    namespace: &Option<String>,
) -> Result<Vec<NetPolResource>, String> {
    let api: Api<NetworkPolicy> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| e.to_string())?;
    Ok(list.items.iter().map(native_resource).collect())
}

fn native_resource(p: &NetworkPolicy) -> NetPolResource {
    let namespace = p.metadata.namespace.clone().unwrap_or_default();
    let name = p.metadata.name.clone().unwrap_or_default();
    let spec = p.spec.as_ref();

    let target = spec
        .map(|s| format_selector(s.pod_selector.as_ref()))
        .unwrap_or_else(|| "all pods".to_string());

    // Resolve which directions the policy governs. When policyTypes is omitted the API defaults it:
    // Ingress is always governed; Egress is governed only if egress rules are present.
    let (affects_ing, affects_eg) = match spec.and_then(|s| s.policy_types.as_ref()) {
        Some(t) => (
            t.iter().any(|x| x == "Ingress"),
            t.iter().any(|x| x == "Egress"),
        ),
        None => (
            true,
            spec.and_then(|s| s.egress.as_ref()).map(|e| !e.is_empty()).unwrap_or(false),
        ),
    };

    let mut types: Vec<&str> = Vec::new();
    if affects_ing {
        types.push("Ingress");
    }
    if affects_eg {
        types.push("Egress");
    }

    let (ingress, ingress_effect) = direction_summary(
        affects_ing,
        spec.and_then(|s| s.ingress.as_ref()).map(|rules| {
            rules
                .iter()
                .map(|r| (r.from.as_ref(), r.ports.as_ref()))
                .collect::<Vec<_>>()
        }),
    );
    let (egress, egress_effect) = direction_summary(
        affects_eg,
        spec.and_then(|s| s.egress.as_ref()).map(|rules| {
            rules
                .iter()
                .map(|r| (r.to.as_ref(), r.ports.as_ref()))
                .collect::<Vec<_>>()
        }),
    );

    let age = p
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    NetPolResource {
        engine: NetPolEngine::K8s,
        kind: "NetworkPolicy".to_string(),
        api_version: "networking.k8s.io/v1".to_string(),
        uid: format!("netpol|k8s|{}/{}", namespace, name),
        namespace,
        name,
        target,
        types: types.join(","),
        ingress,
        egress,
        ingress_effect,
        egress_effect,
        age,
    }
}

// Render one native direction: its display string and its posture. `rules` is None when the spec has
// no such section (distinct from Some(empty), though both deny when the direction is governed).
type NativeRule<'a> = (Option<&'a Vec<NetworkPolicyPeer>>, Option<&'a Vec<NetworkPolicyPort>>);

fn direction_summary(affects: bool, rules: Option<Vec<NativeRule<'_>>>) -> (String, DirEffect) {
    if !affects {
        return ("—".to_string(), DirEffect::Unaffected);
    }
    let rules = rules.unwrap_or_default();
    if rules.is_empty() {
        return ("deny all".to_string(), DirEffect::Deny);
    }
    let mut allow_all = false;
    let mut parts: Vec<String> = Vec::new();
    for (peers, ports) in &rules {
        let peer_txt = match peers {
            // Empty or absent peer list = every source/destination is allowed by this rule.
            None => {
                allow_all = true;
                "all".to_string()
            }
            Some(v) if v.is_empty() => {
                allow_all = true;
                "all".to_string()
            }
            Some(v) => v.iter().map(format_peer).collect::<Vec<_>>().join(", "),
        };
        let port_txt = format_ports(*ports);
        if port_txt.is_empty() {
            parts.push(peer_txt);
        } else {
            parts.push(format!("{}:{}", peer_txt, port_txt));
        }
    }
    let effect = if allow_all {
        DirEffect::AllowAll
    } else {
        DirEffect::Selective
    };
    (parts.join(" | "), effect)
}

fn format_ports(ports: Option<&Vec<NetworkPolicyPort>>) -> String {
    let Some(ports) = ports else { return String::new() };
    ports
        .iter()
        .map(|p| {
            let proto = p.protocol.clone().unwrap_or_else(|| "TCP".to_string());
            let port = p
                .port
                .as_ref()
                .map(|p| match p {
                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(i) => i.to_string(),
                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s) => s.clone(),
                })
                .unwrap_or_else(|| "*".to_string());
            match p.end_port {
                Some(end) => format!("{}/{}-{}", proto, port, end),
                None => format!("{}/{}", proto, port),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_peer(p: &NetworkPolicyPeer) -> String {
    if let Some(b) = &p.ip_block {
        return match &b.except {
            Some(ex) if !ex.is_empty() => format!("ip:{}\\{}", b.cidr, ex.join(",")),
            _ => format!("ip:{}", b.cidr),
        };
    }
    let ns = p
        .namespace_selector
        .as_ref()
        .map(|s| format!("ns({})", format_selector(Some(s))));
    let pod = p
        .pod_selector
        .as_ref()
        .map(|s| format!("pod({})", format_selector(Some(s))));
    match (ns, pod) {
        (Some(n), Some(p)) => format!("{}/{}", n, p),
        (Some(n), None) => n,
        (None, Some(p)) => p,
        (None, None) => "?".to_string(),
    }
}

// A LabelSelector as "k=v,k2=v2". An empty selector (no matchLabels, no matchExpressions) selects
// everything → "all pods". matchExpressions are summarized as "+Nexpr" rather than expanded here.
fn format_selector(sel: Option<&LabelSelector>) -> String {
    let Some(sel) = sel else { return "all pods".to_string() };
    let labels: Vec<String> = sel
        .match_labels
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
        .unwrap_or_default();
    let expr_n = sel.match_expressions.as_ref().map(|e| e.len()).unwrap_or(0);
    if labels.is_empty() && expr_n == 0 {
        return "all pods".to_string();
    }
    let mut out = labels.join(",");
    if expr_n > 0 {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("+{}expr", expr_n));
    }
    out
}

// A CNI CRD policy rendered from its raw JSON: best-effort selector and rule counts, but no posture
// verdict — each engine's default-allow/deny model differs from the native one, so effects stay Unknown.
fn parse_crd(
    obj: &DynamicObject,
    engine: NetPolEngine,
    kind: &str,
    api_version: &str,
) -> NetPolResource {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let spec = obj.data.get("spec");

    let target = crd_target(engine, spec);
    let (ingress, ingress_effect) = crd_direction(engine, spec, true);
    let (egress, egress_effect) = crd_direction(engine, spec, false);

    let age = obj
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();

    NetPolResource {
        engine,
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        uid: format!("netpol|{}|{}/{}", engine.label(), namespace, name),
        namespace,
        name,
        target,
        types: String::new(),
        ingress,
        egress,
        ingress_effect,
        egress_effect,
        age,
    }
}

fn crd_target(engine: NetPolEngine, spec: Option<&serde_json::Value>) -> String {
    let Some(spec) = spec else { return "—".to_string() };
    match engine {
        // Cilium selects endpoints via endpointSelector.matchLabels, or nodes via nodeSelector.
        NetPolEngine::Cilium => {
            if let Some(sel) = spec.get("endpointSelector") {
                let s = json_match_labels(sel);
                return if s.is_empty() { "all endpoints".to_string() } else { s };
            }
            if let Some(sel) = spec.get("nodeSelector") {
                let s = json_match_labels(sel);
                return if s.is_empty() { "all nodes".to_string() } else { format!("node:{}", s) };
            }
            "—".to_string()
        }
        // Calico selects via a `selector` expression string (its own DSL), "all()" when empty.
        NetPolEngine::Calico => spec
            .get("selector")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("all()")
            .to_string(),
        NetPolEngine::K8s => "—".to_string(),
    }
}

// Rule count for a CRD direction: engine-specific field names, always DirEffect::Unknown so no verdict
// is implied. "N rules" / "—" when the section is absent.
fn crd_direction(
    engine: NetPolEngine,
    spec: Option<&serde_json::Value>,
    ingress: bool,
) -> (String, DirEffect) {
    let Some(spec) = spec else { return ("—".to_string(), DirEffect::Unknown) };
    let key = if ingress { "ingress" } else { "egress" };
    // Cilium and Calico both use `ingress`/`egress` arrays of rules.
    let n = spec.get(key).and_then(|v| v.as_array()).map(|a| a.len());
    // Cilium also has deny variants; surface them so a deny-only policy isn't shown as empty.
    let deny_key = if ingress { "ingressDeny" } else { "egressDeny" };
    let deny_n = if engine == NetPolEngine::Cilium {
        spec.get(deny_key).and_then(|v| v.as_array()).map(|a| a.len())
    } else {
        None
    };
    match (n, deny_n) {
        (None, None) | (Some(0), None) | (None, Some(0)) | (Some(0), Some(0)) => {
            ("—".to_string(), DirEffect::Unknown)
        }
        (allow, deny) => {
            let a = allow.unwrap_or(0);
            let d = deny.unwrap_or(0);
            let txt = if d > 0 {
                format!("{} allow · {} deny", a, d)
            } else {
                format!("{} rules", a)
            };
            (txt, DirEffect::Unknown)
        }
    }
}

fn json_match_labels(sel: &serde_json::Value) -> String {
    let Some(m) = sel.get("matchLabels").and_then(|v| v.as_object()) else {
        return String::new();
    };
    m.iter()
        .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn native(spec: serde_json::Value) -> NetPolResource {
        let np: NetworkPolicy =
            serde_json::from_value(json!({ "metadata": { "name": "p", "namespace": "ns" }, "spec": spec }))
                .unwrap();
        native_resource(&np)
    }

    #[test]
    fn default_deny_all_ingress() {
        // Empty podSelector + Ingress in policyTypes + no ingress rules = every pod isolated (deny-all).
        let r = native(json!({ "podSelector": {}, "policyTypes": ["Ingress"] }));
        assert_eq!(r.target, "all pods");
        assert_eq!(r.types, "Ingress");
        assert_eq!(r.ingress_effect, DirEffect::Deny);
        assert_eq!(r.ingress, "deny all");
        // Egress isn't in policyTypes: this policy leaves it to others.
        assert_eq!(r.egress_effect, DirEffect::Unaffected);
        assert_eq!(r.egress, "—");
    }

    #[test]
    fn allow_all_ingress() {
        // A rule with an empty `from` opens ingress to every source.
        let r = native(json!({ "podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}] }));
        assert_eq!(r.ingress_effect, DirEffect::AllowAll);
        assert_eq!(r.ingress, "all");
    }

    #[test]
    fn selective_ingress_from_peers() {
        let r = native(json!({
            "podSelector": { "matchLabels": { "app": "api" } },
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [
                    { "namespaceSelector": { "matchLabels": { "team": "x" } } },
                    { "podSelector": { "matchLabels": { "role": "web" } } },
                    { "ipBlock": { "cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"] } }
                ],
                "ports": [{ "protocol": "TCP", "port": 8080 }]
            }]
        }));
        assert_eq!(r.target, "app=api");
        assert_eq!(r.ingress_effect, DirEffect::Selective);
        assert_eq!(
            r.ingress,
            "ns(team=x), pod(role=web), ip:10.0.0.0/8\\10.1.0.0/16:TCP/8080"
        );
    }

    #[test]
    fn egress_defaulted_from_rules_when_types_absent() {
        // policyTypes omitted: Ingress is always governed; Egress governed because egress rules exist.
        let r = native(json!({
            "podSelector": {},
            "egress": [{ "to": [{ "ipBlock": { "cidr": "0.0.0.0/0" } }] }]
        }));
        assert_eq!(r.types, "Ingress,Egress");
        // No ingress section but Ingress is governed → deny-all ingress.
        assert_eq!(r.ingress_effect, DirEffect::Deny);
        assert_eq!(r.egress_effect, DirEffect::Selective);
        assert_eq!(r.egress, "ip:0.0.0.0/0");
    }

    #[test]
    fn cilium_crd_target_and_counts() {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": { "name": "c", "namespace": "ns" },
            "spec": {
                "endpointSelector": { "matchLabels": { "app": "db" } },
                "ingress": [{}, {}],
                "egressDeny": [{}]
            }
        }))
        .unwrap();
        let r = parse_crd(&obj, NetPolEngine::Cilium, "CiliumNetworkPolicy", "cilium.io/v2");
        assert_eq!(r.engine, NetPolEngine::Cilium);
        assert_eq!(r.target, "app=db");
        // CRDs carry rule counts, never a native-style verdict.
        assert_eq!(r.ingress, "2 rules");
        assert_eq!(r.ingress_effect, DirEffect::Unknown);
        assert_eq!(r.egress, "0 allow · 1 deny");
        assert_eq!(r.egress_effect, DirEffect::Unknown);
    }

    #[test]
    fn calico_crd_selector_expression() {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "crd.projectcalico.org/v1",
            "kind": "GlobalNetworkPolicy",
            "metadata": { "name": "g" },
            "spec": { "selector": "role == 'frontend'", "ingress": [{}] }
        }))
        .unwrap();
        let r = parse_crd(&obj, NetPolEngine::Calico, "GlobalNetworkPolicy", "crd.projectcalico.org/v1");
        assert_eq!(r.target, "role == 'frontend'");
        assert_eq!(r.ingress, "1 rules");
        assert!(r.namespace.is_empty());
    }
}
