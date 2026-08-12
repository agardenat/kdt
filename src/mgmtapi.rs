//! Cassandra's own operational state, read through the apiserver's proxy subresource.
//!
//! The `:k8ssandra` view needs answers that no CRD carries: which nodes the ring actually sees, is
//! the schema in agreement, are the thread pools backing up. `nodetool` is the usual way to ask, and
//! it is the wrong tool here — a shell-out would need a binary in `$PATH`, a TTY, and on a k8ssandra
//! cluster it does not even connect: JMX is behind SSL (`rmi_registry_ssl`), so a bare
//! `nodetool status` inside the container fails with `non-JRMP server at remote endpoint` before it
//! reaches Cassandra.
//!
//! The `cassandra` container is a `cass-management-api` server, and cass-operator drives it over
//! plain HTTP on port 8080. The apiserver will proxy to that port for us:
//!
//! ```text
//! GET /api/v1/namespaces/{ns}/pods/{pod}:8080/proxy/api/v0/metadata/endpoints
//! ```
//!
//! which is the same raw-request mechanism [`crate::diagnostic`] already uses for `/livez`. No
//! port-forward, no `kubectl`, no exec, and the answer arrives as JSON instead of a table to
//! re-parse. Reaper is reached the same way through its Service.
//!
//! Everything here is a transport: it fetches and shapes, it does not judge. The rules live in
//! [`crate::k8ssandra`]. Every call is fallible in a way the caller is expected to survive — a
//! management API that does not answer costs a column, never the view.

use std::collections::BTreeMap;
use std::time::Duration;

use http::Request;
use kube::Client;
use serde_json::Value;

// Long enough for a busy node to answer, short enough that a wedged pod does not hold the panel.
const TIMEOUT: Duration = Duration::from_secs(8);

// The management API port, as cass-operator itself addresses it, and the metrics port used when
// `telemetry.prometheus` is on. MCAC (9103) is a third possibility and is deliberately not tried:
// when `mcac.enabled` is false the port is closed and the proxy answers 502, which is a four-second
// wait for nothing.
const MGMT_PORT: u16 = 8080;
const METRICS_PORT: u16 = 9000;

// --- Ring ---------------------------------------------------------------------------------------

/// One endpoint as the contacted node sees it — `nodetool status` and `nodetool describecluster`
/// come out of this single call.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Endpoint {
    pub ip: String,
    pub host_id: String,
    pub datacenter: String,
    pub rack: String,
    // `NORMAL`, `LEAVING`, `JOINING`, `MOVING`: the word before the token in the raw `STATUS`.
    pub state: String,
    pub alive: bool,
    pub local: bool,
    pub load_bytes: Option<f64>,
    pub tokens: usize,
    pub release_version: String,
    pub schema: String,
    pub partitioner: String,
    pub cluster_name: String,
    pub rpc_ready: bool,
}

impl Endpoint {
    /// The two-letter status `nodetool status` prints: up/down, then the ring state.
    pub fn status_code(&self) -> String {
        let up = if self.alive { 'U' } else { 'D' };
        let state = match self.state.as_str() {
            "NORMAL" => 'N',
            "LEAVING" => 'L',
            "JOINING" => 'J',
            "MOVING" => 'M',
            _ => '?',
        };
        format!("{up}{state}")
    }
}

/// Read the ring from one pod. Every value in the management API's payload is a string, including
/// the booleans and the load, so each field is converted rather than deserialised.
pub async fn endpoints(client: &Client, namespace: &str, pod: &str) -> Result<Vec<Endpoint>, String> {
    let body = get_text(client, &pod_proxy(namespace, pod, MGMT_PORT, "/api/v0/metadata/endpoints")).await?;
    parse_endpoints(&body)
}

pub fn parse_endpoints(body: &str) -> Result<Vec<Endpoint>, String> {
    let root: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let entity = root
        .get("entity")
        .and_then(Value::as_array)
        .ok_or_else(|| "entity absent".to_string())?;
    let mut out: Vec<Endpoint> = entity.iter().map(parse_endpoint).collect();
    // The ring has no inherent order; sorting by DC then rack then address keeps a node on the same
    // line between two refreshes, which is what makes the panel readable while it changes.
    out.sort_by(|a, b| {
        (&a.datacenter, &a.rack, &a.ip).cmp(&(&b.datacenter, &b.rack, &b.ip))
    });
    Ok(out)
}

fn parse_endpoint(v: &Value) -> Endpoint {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let b = |k: &str| v.get(k).and_then(Value::as_str) == Some("true");
    // `STATUS` is `NORMAL,-1048540984083913893`: the state, then the first token. Only the state is
    // meaningful here — the tokens are listed in full in their own field.
    let raw_status = s("STATUS");
    let state = raw_status.split(',').next().unwrap_or_default().to_string();
    // The load is a Java double rendered into a string, scientific notation included
    // (`2.723922667075E12`). `f64::from_str` accepts that form; anything else is left as unknown
    // rather than defaulted to zero, which would read as an empty node.
    let load_bytes = v
        .get("LOAD")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<f64>().ok());
    let tokens = v
        .get("TOKENS")
        .and_then(Value::as_str)
        .map(|t| t.split(',').filter(|s| !s.trim().is_empty()).count())
        .unwrap_or(0);
    Endpoint {
        ip: s("ENDPOINT_IP"),
        host_id: s("HOST_ID"),
        datacenter: s("DC"),
        rack: s("RACK"),
        state,
        alive: b("IS_ALIVE"),
        local: b("IS_LOCAL"),
        load_bytes,
        tokens,
        release_version: s("RELEASE_VERSION"),
        schema: s("SCHEMA"),
        partitioner: s("PARTITIONER"),
        cluster_name: s("CLUSTER_NAME"),
        rpc_ready: b("RPC_READY"),
    }
}

/// The schema versions in play, per Cassandra cluster. Disagreement inside one cluster is what
/// `nodetool describecluster` is read for, and it is invisible from any CRD.
///
/// Grouped by `CLUSTER_NAME` and not over the whole list: two k8ssandra clusters in one Kubernetes
/// cluster have no reason to share a schema, and comparing across them reports a disagreement on
/// every cluster that has a neighbour.
pub fn schema_versions_by_cluster(
    endpoints: &[Endpoint],
) -> BTreeMap<String, Vec<(String, Vec<String>)>> {
    let mut per_cluster: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for e in endpoints.iter().filter(|e| !e.schema.is_empty()) {
        per_cluster
            .entry(e.cluster_name.clone())
            .or_default()
            .entry(e.schema.clone())
            .or_default()
            .push(e.ip.clone());
    }
    per_cluster
        .into_iter()
        .map(|(cluster, by_schema)| (cluster, by_schema.into_iter().collect()))
        .collect()
}

// --- Streams ------------------------------------------------------------------------------------

/// Active streaming sessions (`nodetool netstats`). The payload's per-session shape is not modelled:
/// on every cluster reachable here `entity` has been empty, and inventing fields for sessions that
/// were never observed is exactly the kind of guess this codebase refuses. The entries are returned
/// as flat key/value pairs so the detail panel can show whatever the node reports.
pub async fn streams(
    client: &Client,
    namespace: &str,
    pod: &str,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let body = get_text(client, &pod_proxy(namespace, pod, MGMT_PORT, "/api/v0/ops/node/streaminfo")).await?;
    parse_entity_pairs(&body)
}

fn parse_entity_pairs(body: &str) -> Result<Vec<Vec<(String, String)>>, String> {
    let root: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let entity = root
        .get("entity")
        .and_then(Value::as_array)
        .ok_or_else(|| "entity absent".to_string())?;
    Ok(entity
        .iter()
        .map(|v| match v.as_object() {
            Some(map) => map
                .iter()
                .map(|(k, val)| (k.clone(), scalar_text(val)))
                .collect(),
            None => vec![(String::new(), scalar_text(v))],
        })
        .collect())
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

// --- Metrics ------------------------------------------------------------------------------------

/// One thread pool line of `nodetool tpstats`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ThreadPool {
    pub name: String,
    pub kind: String,
    pub active: f64,
    pub pending: f64,
    pub completed: f64,
    pub blocked: f64,
    pub all_time_blocked: f64,
}

/// What `nodetool tpstats` and `nodetool compactionstats` report, for a single node.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeMetrics {
    pub pools: Vec<ThreadPool>,
    // Only the message types actually dropped: a list of ~30 zeroes is noise, and the reader is
    // looking for the non-zero one.
    pub dropped: Vec<(String, f64)>,
    pub pending_compactions: Option<f64>,
    pub completed_compactions: Option<f64>,
    pub bytes_compacted: Option<f64>,
}

// The families worth keeping out of the exposition. The endpoint answers with ~29 000 lines, most
// of them per-table histograms, so the filter is applied while parsing and the rest is never held.
const F_POOL_ACTIVE: &str = "org_apache_cassandra_metrics_thread_pools_active_tasks";
const F_POOL_PENDING: &str = "org_apache_cassandra_metrics_thread_pools_pending_tasks";
const F_POOL_COMPLETED: &str = "org_apache_cassandra_metrics_thread_pools_completed_tasks";
const F_POOL_BLOCKED: &str = "org_apache_cassandra_metrics_thread_pools_currently_blocked_tasks";
const F_POOL_ALL_BLOCKED: &str = "org_apache_cassandra_metrics_thread_pools_total_blocked_tasks";
const F_DROPPED: &str = "org_apache_cassandra_metrics_dropped_message_dropped_total";
const F_PENDING_COMPACTIONS: &str = "org_apache_cassandra_metrics_table_pending_compactions_all";
const F_COMPLETED_COMPACTIONS: &str = "org_apache_cassandra_metrics_compaction_completed_tasks";
const F_BYTES_COMPACTED: &str = "org_apache_cassandra_metrics_compaction_bytes_compacted";

/// Read the thread pools and compaction counters of one node.
///
/// The response is large and slow to produce, so this is called on demand for the selected pod and
/// never from the refresh ticker.
pub async fn metrics(client: &Client, namespace: &str, pod: &str) -> Result<NodeMetrics, String> {
    let body = get_text(client, &pod_proxy(namespace, pod, METRICS_PORT, "/metrics")).await?;
    Ok(parse_metrics(&body))
}

pub fn parse_metrics(body: &str) -> NodeMetrics {
    let mut pools: BTreeMap<(String, String), ThreadPool> = BTreeMap::new();
    let mut out = NodeMetrics::default();

    for line in body.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some((family, labels, value)) = split_sample(line) else { continue };
        match family {
            F_POOL_ACTIVE | F_POOL_PENDING | F_POOL_COMPLETED | F_POOL_BLOCKED
            | F_POOL_ALL_BLOCKED => {
                let name = labels.get("pool_name").cloned().unwrap_or_default();
                let kind = labels.get("pool_type").cloned().unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let pool = pools.entry((kind.clone(), name.clone())).or_insert_with(|| ThreadPool {
                    name,
                    kind,
                    ..ThreadPool::default()
                });
                match family {
                    F_POOL_ACTIVE => pool.active = value,
                    F_POOL_PENDING => pool.pending = value,
                    F_POOL_COMPLETED => pool.completed = value,
                    F_POOL_BLOCKED => pool.blocked = value,
                    _ => pool.all_time_blocked = value,
                }
            }
            F_DROPPED if value > 0.0 => {
                if let Some(kind) = labels.get("message_type") {
                    out.dropped.push((kind.clone(), value));
                }
            }
            F_PENDING_COMPACTIONS => out.pending_compactions = Some(value),
            F_COMPLETED_COMPACTIONS => out.completed_compactions = Some(value),
            F_BYTES_COMPACTED => out.bytes_compacted = Some(value),
            _ => {}
        }
    }

    out.pools = pools.into_values().collect();
    // Busiest first: a pool with pending work is the reason the panel was opened, and the twenty
    // idle ones below it are context.
    out.pools.sort_by(|a, b| {
        b.pending
            .total_cmp(&a.pending)
            .then(b.active.total_cmp(&a.active))
            .then(a.name.cmp(&b.name))
    });
    out.dropped.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

// One exposition line into (family, labels, value). Written against the format the management API
// actually emits — labels always present, always closed by a trailing comma
// (`…node_name="x",} 0.0`) — and tolerant of the plain `family value` form.
fn split_sample(line: &str) -> Option<(&str, BTreeMap<String, String>, f64)> {
    let (head, rest) = match line.find('{') {
        Some(i) => {
            let close = line.rfind('}')?;
            if close < i {
                return None;
            }
            (&line[..i], Some(&line[i + 1..close]))
        }
        None => (line.split(' ').next()?, None),
    };
    let value: f64 = line.rsplit(' ').next()?.trim().parse().ok()?;
    let labels = rest.map(parse_labels).unwrap_or_default();
    Some((head, labels, value))
}

fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else { continue };
        out.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
    }
    out
}

// --- Reaper -------------------------------------------------------------------------------------

/// A session against Reaper's REST API. Reaper 3.x has authentication on by default
/// (`REAPER_AUTH_ENABLED`), so every call carries a bearer token obtained from `/login` with the UI
/// credentials — which are read from the Secret the Reaper object names in
/// `spec.uiUserSecretRef`, never from a name guessed off the cluster name.
#[derive(Debug, Clone)]
pub struct ReaperSession {
    pub namespace: String,
    pub service: String,
    pub token: String,
}

/// Exchange the UI credentials for a JWT.
///
/// The token is the whole point of the returned value and must be treated like the Secret it came
/// from: it is never rendered, logged, or copied to the clipboard.
pub async fn reaper_login(
    client: &Client,
    namespace: &str,
    service: &str,
    username: &str,
    password: &str,
) -> Result<ReaperSession, String> {
    let path = svc_proxy(namespace, service, MGMT_PORT, "/login");
    let body = format!(
        "username={}&password={}",
        form_encode(username),
        form_encode(password)
    );
    let req = Request::post(&path)
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.into_bytes())
        .map_err(|e| e.to_string())?;
    let token = send_text(client, req).await?.trim().to_string();
    if token.is_empty() {
        return Err("login sans jeton".to_string());
    }
    Ok(ReaperSession {
        namespace: namespace.to_string(),
        service: service.to_string(),
        token,
    })
}

pub async fn reaper_get(session: &ReaperSession, client: &Client, path: &str) -> Result<String, String> {
    let full = svc_proxy(&session.namespace, &session.service, MGMT_PORT, path);
    let req = Request::get(&full)
        .header(http::header::AUTHORIZATION, format!("Bearer {}", session.token))
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    send_text(client, req).await
}

// --- Transport ----------------------------------------------------------------------------------

/// Path of the apiserver's proxy subresource for a port of a pod. The `:port` form is required —
/// without it the apiserver proxies to 80.
pub fn pod_proxy(namespace: &str, pod: &str, port: u16, path: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod}:{port}/proxy{path}")
}

/// The same for a Service, used to reach Reaper, which is a Deployment behind one.
pub fn svc_proxy(namespace: &str, service: &str, port: u16, path: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/services/{service}:{port}/proxy{path}")
}

async fn get_text(client: &Client, path: &str) -> Result<String, String> {
    let req = Request::get(path).body(Vec::new()).map_err(|e| e.to_string())?;
    send_text(client, req).await
}

// A proxied call fails in ways the plain client does not — the pod is gone, the port is closed, the
// service has no endpoint — and `kube::Error`'s Display keeps the useful half in its source chain.
// The timeout is ours: without it a pod that accepts the connection and never answers holds the
// panel for as long as the client's own deadline, which is minutes.
async fn send_text(client: &Client, req: Request<Vec<u8>>) -> Result<String, String> {
    match tokio::time::timeout(TIMEOUT, client.request_text(req)).await {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(e)) => Err(error_chain(&e)),
        Err(_) => Err(crate::lang::fill(
            crate::lang::active().k8c_mgmt_timeout,
            &[("n", &TIMEOUT.as_secs().to_string())],
        )),
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        src = s.source();
    }
    out
}

// `application/x-www-form-urlencoded`, for the two fields the Reaper login takes. A password is
// arbitrary bytes and goes through a form field, so it is escaped rather than trusted to be
// alphanumeric.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINTS: &str = r#"{"entity":[
      {"CLUSTER_NAME":"cassandracluster","DC":"dc1","ENDPOINT_IP":"10.244.19.20",
       "HOST_ID":"6a540fad-7723-4cca-ace8-a875f44fb9bd","IS_ALIVE":"true","IS_LOCAL":"false",
       "LOAD":"2.723922667075E12","PARTITIONER":"org.apache.cassandra.dht.Murmur3Partitioner",
       "RACK":"default","RELEASE_VERSION":"3.11.15","RPC_READY":"true",
       "SCHEMA":"247d3ebb-f742-38f5-8590-1a1420624d81","STATUS":"NORMAL,-1048540984083913893",
       "TOKENS":"-1048540984083913893,-1049741563546568863,-107014925353016814"},
      {"CLUSTER_NAME":"cassandracluster","DC":"dc1","ENDPOINT_IP":"10.244.6.124",
       "HOST_ID":"65a449eb-c271-4e78-80b7-4e71b2f466d5","IS_ALIVE":"false","IS_LOCAL":"true",
       "LOAD":"not-a-number","PARTITIONER":"org.apache.cassandra.dht.Murmur3Partitioner",
       "RACK":"default","RELEASE_VERSION":"3.11.15","RPC_READY":"true",
       "SCHEMA":"aaaaaaaa-f742-38f5-8590-1a1420624d81","STATUS":"LEAVING,42","TOKENS":""}
    ]}"#;

    #[test]
    fn the_ring_is_read_out_of_the_management_api_payload() {
        let eps = parse_endpoints(ENDPOINTS).expect("parse");
        assert_eq!(eps.len(), 2);
        // Sorted by dc/rack/ip: 10.244.19.20 sorts before 10.244.6.124 as text, which is what the
        // panel shows and what keeps a node on its line between refreshes.
        assert_eq!(eps[0].ip, "10.244.19.20");
        assert_eq!(eps[0].state, "NORMAL");
        assert_eq!(eps[0].status_code(), "UN");
        assert_eq!(eps[0].tokens, 3);
        assert_eq!(eps[0].load_bytes, Some(2.723922667075E12));
        assert_eq!(eps[1].status_code(), "DL");
    }

    #[test]
    fn an_unreadable_load_is_unknown_rather_than_zero() {
        // Zero would read as an empty node, which is a different and much more alarming fact.
        let eps = parse_endpoints(ENDPOINTS).expect("parse");
        assert_eq!(eps[1].load_bytes, None);
        assert_eq!(eps[1].tokens, 0);
    }

    #[test]
    fn a_schema_disagreement_is_visible_as_two_groups() {
        let eps = parse_endpoints(ENDPOINTS).expect("parse");
        let by_cluster = schema_versions_by_cluster(&eps);
        assert_eq!(by_cluster.len(), 1, "both endpoints belong to the same cluster");
        assert_eq!(by_cluster["cassandracluster"].len(), 2, "and they disagree on the schema");
    }

    #[test]
    fn two_clusters_side_by_side_do_not_disagree_with_each_other() {
        // Two k8ssandra clusters in one Kubernetes cluster: comparing their schemas across the
        // boundary reported a disagreement on both, every time, on a perfectly healthy pair.
        let eps = vec![
            Endpoint {
                ip: "10.0.0.1".into(),
                schema: "aaa".into(),
                cluster_name: "one".into(),
                ..Endpoint::default()
            },
            Endpoint {
                ip: "10.0.0.2".into(),
                schema: "bbb".into(),
                cluster_name: "two".into(),
                ..Endpoint::default()
            },
        ];
        let by_cluster = schema_versions_by_cluster(&eps);
        assert_eq!(by_cluster.len(), 2);
        assert!(by_cluster.values().all(|v| v.len() == 1), "each cluster agrees with itself");
    }

    const METRICS: &str = concat!(
        "# HELP org_apache_cassandra_metrics_thread_pools_pending_tasks \n",
        "# TYPE org_apache_cassandra_metrics_thread_pools_pending_tasks gauge\n",
        "org_apache_cassandra_metrics_thread_pools_pending_tasks{pod_name=\"sts-0\",pool_type=\"internal\",pool_name=\"CompactionExecutor\",} 7.0\n",
        "org_apache_cassandra_metrics_thread_pools_active_tasks{pod_name=\"sts-0\",pool_type=\"internal\",pool_name=\"CompactionExecutor\",} 2.0\n",
        "org_apache_cassandra_metrics_thread_pools_pending_tasks{pod_name=\"sts-0\",pool_type=\"internal\",pool_name=\"GossipStage\",} 0.0\n",
        "org_apache_cassandra_metrics_dropped_message_dropped_total{message_type=\"MUTATION\",} 3.0\n",
        "org_apache_cassandra_metrics_dropped_message_dropped_total{message_type=\"BATCH_STORE\",} 0.0\n",
        "org_apache_cassandra_metrics_table_pending_compactions_all{pod_name=\"sts-0\",} 4.0\n",
        "org_apache_cassandra_metrics_compaction_bytes_compacted{pod_name=\"sts-0\",} 3.33174098666286E14\n",
        "org_apache_cassandra_metrics_table_range_latency_bucket{keyspace=\"system\",le=\"35\",} 0.0\n",
    );

    #[test]
    fn only_the_families_the_panel_shows_survive_the_parse() {
        let m = parse_metrics(METRICS);
        // Two pools, and not one of the 29 000 per-table histogram lines.
        assert_eq!(m.pools.len(), 2);
        assert_eq!(m.pools[0].name, "CompactionExecutor", "busiest pool first");
        assert_eq!(m.pools[0].pending, 7.0);
        assert_eq!(m.pools[0].active, 2.0);
        assert_eq!(m.pending_compactions, Some(4.0));
        assert_eq!(m.bytes_compacted, Some(3.33174098666286E14));
    }

    #[test]
    fn a_message_type_that_dropped_nothing_is_not_listed() {
        let m = parse_metrics(METRICS);
        assert_eq!(m.dropped, vec![("MUTATION".to_string(), 3.0)]);
    }

    #[test]
    fn the_proxy_paths_carry_the_port() {
        assert_eq!(
            pod_proxy("ns", "sts-0", 8080, "/api/v0/metadata/endpoints"),
            "/api/v1/namespaces/ns/pods/sts-0:8080/proxy/api/v0/metadata/endpoints"
        );
        assert_eq!(
            svc_proxy("ns", "reaper-service", 8080, "/login"),
            "/api/v1/namespaces/ns/services/reaper-service:8080/proxy/login"
        );
    }

    #[test]
    fn a_password_is_escaped_before_it_reaches_the_form() {
        assert_eq!(form_encode("a b&c=d"), "a+b%26c%3Dd");
        assert_eq!(form_encode("plain-1_2.3~"), "plain-1_2.3~");
    }

    #[test]
    fn an_empty_entity_list_is_a_valid_answer() {
        // What every cluster tried so far returns for streaminfo: no streams, not a failure.
        let pairs = parse_entity_pairs(r#"{"entity":[],"variant":null}"#).expect("parse");
        assert!(pairs.is_empty());
    }
}
