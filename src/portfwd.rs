//! Port-forward on a Service, done in-process.
//!
//! Unlike the shell of [`crate::exec`], this one does not hand the terminal to `kubectl`: a forward
//! is a background task, not a foreground program, and a TUI that suspends itself for the lifetime
//! of a tunnel would be a TUI nobody can use while the tunnel is up. kube-rs already speaks the
//! `portforward` subresource over the same websocket upgrade `kubectl` uses, so kdt binds the local
//! socket itself and keeps the forwards in its own process — they live and die with kdt, and there
//! is no orphaned child left listening on a port after it exits.
//!
//! A Service is not what the API server forwards to: it forwards to a Pod. Resolving one to the
//! other is the whole subtlety of this module, and it is done off the EndpointSlices rather than
//! off the Service selector — the slices already carry the *resolved* target port for each named
//! Service port, and they say which endpoints are ready. Forwarding to a pod that is not ready is
//! how a port-forward ends up "working" against a container that is still starting.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, ListParams};
use kube::Client;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::lang;

// The standard label EndpointSlices carry to point back at the Service they belong to.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

// What the user asked for: a Service port, and the local port to expose it on. `local_port` 0 means
// "any free port" — the loopback bind then picks one and the entry is updated with it.
#[derive(Debug, Clone)]
pub struct PfRequest {
    pub namespace: String,
    pub service: String,
    pub service_port: i32,
    pub port_name: Option<String>,
    pub local_port: u16,
}

// Where a forward stands. `Starting` covers both the resolution and the bind: neither is instant,
// and a row that showed "listening" before the socket exists would be a row that lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfState {
    Starting,
    Listening,
    Failed(String),
}

// One forward, as the views read it. The `JoinHandle` is not part of it: stopping goes through
// [`stop`], which is the only thing allowed to take the task down.
#[derive(Debug, Clone)]
pub struct PfRow {
    pub id: u64,
    pub namespace: String,
    pub service: String,
    pub service_port: i32,
    pub port_name: Option<String>,
    pub local_port: u16,
    pub pod: String,
    pub remote_port: u16,
    pub state: PfState,
    // Connections currently open through the tunnel, and how many it has served since it started.
    pub open: usize,
    pub served: u64,
    // Last per-connection failure. Kept apart from `state`: a refused connection does not stop the
    // listener, so the forward is still live and still worth showing as such.
    pub last_error: Option<String>,
}

impl PfRow {
    // How the local end is reached, once there is one.
    pub fn local_address(&self) -> String {
        format!("127.0.0.1:{}", self.local_port)
    }
}

struct PfEntry {
    row: PfRow,
    handle: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub struct Forwards {
    entries: Vec<PfEntry>,
    next_id: u64,
    // Sentences the background tasks want the footer to say (started, bound, failed). Drained by
    // the UI tick into the toast — the tasks have no other way to speak.
    events: Vec<String>,
}

pub type SharedForwards = Arc<Mutex<Forwards>>;

pub fn new_forwards() -> SharedForwards {
    Arc::new(Mutex::new(Forwards::default()))
}

fn lock(shared: &SharedForwards) -> std::sync::MutexGuard<'_, Forwards> {
    shared.lock().expect("forwards poisoned")
}

/// Every forward, in the order they were started.
pub fn rows(shared: &SharedForwards) -> Vec<PfRow> {
    lock(shared).entries.iter().map(|e| e.row.clone()).collect()
}

/// The live forward on this Service port, if there is one.
pub fn find(shared: &SharedForwards, namespace: &str, service: &str, service_port: i32) -> Option<PfRow> {
    lock(shared)
        .entries
        .iter()
        .find(|e| {
            e.row.namespace == namespace && e.row.service == service && e.row.service_port == service_port
        })
        .map(|e| e.row.clone())
}

pub fn count(shared: &SharedForwards) -> usize {
    lock(shared).entries.len()
}

/// Take what the tasks have to say since the last call.
pub fn drain_events(shared: &SharedForwards) -> Vec<String> {
    std::mem::take(&mut lock(shared).events)
}

fn say(shared: &SharedForwards, msg: String) {
    lock(shared).events.push(msg);
}

fn update(shared: &SharedForwards, id: u64, f: impl FnOnce(&mut PfRow)) {
    if let Some(e) = lock(shared).entries.iter_mut().find(|e| e.row.id == id) {
        f(&mut e.row);
    }
}

/// Register the forward and start it. Returns straight away with the id of a row already in
/// `Starting`: resolving the pod and binding the socket are both network work, and the view has to
/// have something to show while they happen.
pub fn start(client: Client, req: PfRequest, shared: &SharedForwards) -> u64 {
    let id = {
        let mut g = lock(shared);
        g.next_id += 1;
        let id = g.next_id;
        g.entries.push(PfEntry {
            row: PfRow {
                id,
                namespace: req.namespace.clone(),
                service: req.service.clone(),
                service_port: req.service_port,
                port_name: req.port_name.clone(),
                local_port: req.local_port,
                pod: String::new(),
                remote_port: 0,
                state: PfState::Starting,
                open: 0,
                served: 0,
                last_error: None,
            },
            handle: None,
        });
        id
    };

    let shared_task = shared.clone();
    let handle = tokio::spawn(async move {
        run(client, req, id, shared_task).await;
    });
    if let Some(e) = lock(shared).entries.iter_mut().find(|e| e.row.id == id) {
        e.handle = Some(handle);
    }
    id
}

/// Stop a forward and forget it: the task is aborted, which drops the listener and, with it, every
/// connection it was carrying. Returns the row that was stopped.
pub fn stop(shared: &SharedForwards, id: u64) -> Option<PfRow> {
    let mut g = lock(shared);
    let idx = g.entries.iter().position(|e| e.row.id == id)?;
    let entry = g.entries.remove(idx);
    if let Some(h) = entry.handle {
        h.abort();
    }
    Some(entry.row)
}

/// Stop everything (kdt is leaving). The tasks would die with the process anyway; doing it here
/// closes the sockets before the terminal is handed back.
pub fn stop_all(shared: &SharedForwards) {
    let mut g = lock(shared);
    for entry in g.entries.drain(..) {
        if let Some(h) = entry.handle {
            h.abort();
        }
    }
}

// Resolve the target, bind the local socket, then serve until aborted.
async fn run(client: Client, req: PfRequest, id: u64, shared: SharedForwards) {
    let st = lang::active();
    let target = match resolve(&client, &req).await {
        Ok(t) => t,
        Err(e) => {
            update(&shared, id, |r| r.state = PfState::Failed(e.clone()));
            say(&shared, lang::fill(st.pf_failed, &[("d", &format!("{}/{}", req.namespace, req.service)), ("e", &e)]));
            return;
        }
    };

    let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, req.local_port))).await {
        Ok(l) => l,
        Err(e) => {
            // The state carries the bare cause and the toast the whole sentence: the row shows the
            // cause under a "failed" of its own, and reading "failed: ✗ port-forward: …" twice over
            // is what happens when the two are the same string.
            let cause = lang::fill(
                st.pf_bind_cause,
                &[("p", &req.local_port.to_string()), ("e", &e.to_string())],
            );
            update(&shared, id, |r| r.state = PfState::Failed(cause.clone()));
            say(&shared, lang::fill(st.pf_failed, &[("d", &format!("{}/{}", req.namespace, req.service)), ("e", &cause)]));
            return;
        }
    };
    // With `local_port` 0 the kernel chose the port: the row has to learn which one, or the forward
    // is listening somewhere nobody can name.
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(req.local_port);
    update(&shared, id, |r| {
        r.local_port = bound;
        r.pod = target.pod.clone();
        r.remote_port = target.port;
        r.state = PfState::Listening;
    });
    say(
        &shared,
        lang::fill(
            st.pf_started,
            &[
                ("l", &format!("127.0.0.1:{}", bound)),
                ("d", &format!("{}/{}:{}", req.namespace, req.service, req.service_port)),
                ("p", &target.pod),
            ],
        ),
    );

    serve(client, target, listener, id, shared).await;
}

// Which pod, and which port on it.
#[derive(Debug, Clone)]
struct Target {
    namespace: String,
    pod: String,
    port: u16,
}

// Accept loop. Each accepted connection gets its own websocket to the pod: that is how `kubectl`
// does it too, and it keeps one broken connection from taking the tunnel down. The connection
// tasks are held in a `JoinSet` owned by this future, so aborting it drops them with it.
async fn serve(client: Client, target: Target, listener: TcpListener, id: u64, shared: SharedForwards) {
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let sock = match accepted {
                    Ok((sock, _)) => sock,
                    Err(e) => {
                        let msg = e.to_string();
                        update(&shared, id, |r| r.last_error = Some(msg));
                        continue;
                    }
                };
                update(&shared, id, |r| { r.open += 1; r.served += 1; });
                let client = client.clone();
                let target = target.clone();
                let shared = shared.clone();
                conns.spawn(async move {
                    let outcome = pump(client, &target, sock).await;
                    update(&shared, id, |r| {
                        r.open = r.open.saturating_sub(1);
                        r.last_error = outcome.err();
                    });
                });
            }
            // Reaping finished connections. On an empty set `join_next` resolves to `None`, the
            // pattern fails and the branch is simply disabled for this round — the accept branch
            // keeps waiting.
            Some(_) = conns.join_next() => {}
        }
    }
}

// One connection: open the forward, splice the two halves, then read whatever the API server had to
// say about it. The error channel is the only place a "connection refused" on the pod side shows
// up — the stream itself just closes.
async fn pump(client: Client, target: &Target, mut sock: TcpStream) -> Result<(), String> {
    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, &target.namespace);
    let mut pf = pods
        .portforward(&target.pod, &[target.port])
        .await
        .map_err(|e| e.to_string())?;
    let error = pf.take_error(target.port);
    let mut upstream = pf
        .take_stream(target.port)
        .ok_or_else(|| lang::active().pf_no_stream.to_string())?;

    let copied = copy_bidirectional(&mut sock, &mut upstream).await;
    drop(upstream);
    // `join` reports the websocket's own failures; the per-port error channel reports the ones the
    // API server refused the connection with.
    let joined = pf.join().await.map_err(|e| e.to_string());
    if let Some(fut) = error {
        if let Some(msg) = fut.await {
            return Err(msg);
        }
    }
    copied.map_err(|e| e.to_string())?;
    joined
}

// Service → (pod, port on the pod). Everything that can be missing is named, because "port-forward
// failed" on a Service that has no ready endpoint and one that is an ExternalName are two entirely
// different problems.
async fn resolve(client: &Client, req: &PfRequest) -> Result<Target, String> {
    let st = lang::active();
    let api: Api<Service> = Api::namespaced(client.clone(), &req.namespace);
    let svc = api.get(&req.service).await.map_err(|e| e.to_string())?;
    let spec = svc.spec.as_ref();

    if spec.and_then(|s| s.external_name.as_ref()).is_some() {
        return Err(st.pf_external_name.to_string());
    }
    let port = spec
        .and_then(|s| s.ports.as_ref())
        .and_then(|ports| ports.iter().find(|p| p.port == req.service_port))
        .ok_or_else(|| lang::fill(st.pf_port_gone, &[("p", &req.service_port.to_string())]))?;
    let protocol = port.protocol.clone().unwrap_or_else(|| "TCP".to_string());
    if protocol != "TCP" {
        return Err(lang::fill(st.pf_not_tcp, &[("d", &protocol)]));
    }

    let slices: Api<EndpointSlice> = Api::namespaced(client.clone(), &req.namespace);
    let list = slices
        .list(&ListParams::default().labels(&format!("{}={}", SERVICE_NAME_LABEL, req.service)))
        .await
        .map_err(|e| e.to_string())?;

    // Ready endpoints first, and only them: forwarding onto a pod the Service itself would not send
    // traffic to turns "the app answers" into a coin toss.
    for slice in &list.items {
        let Some(target_port) = slice_target_port(slice, port.name.as_deref()) else { continue };
        for ep in &slice.endpoints {
            let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
            if !ready {
                continue;
            }
            let Some(reference) = ep.target_ref.as_ref() else { continue };
            if reference.kind.as_deref() != Some("Pod") {
                continue;
            }
            let Some(pod) = reference.name.clone() else { continue };
            return Ok(Target {
                namespace: reference.namespace.clone().unwrap_or_else(|| req.namespace.clone()),
                pod,
                port: target_port,
            });
        }
    }

    // No slice usable: say which of the two reasons it was. A Service whose endpoints exist but are
    // all not-ready is a workload problem; one with no endpoint at all is a selector problem.
    let has_endpoint = list.items.iter().any(|s| !s.endpoints.is_empty());
    if has_endpoint {
        Err(st.pf_no_ready_endpoint.to_string())
    } else {
        Err(st.pf_no_endpoint.to_string())
    }
}

// The port on the pod, for the Service port named `name`. EndpointSlices carry the target port
// already resolved — including when the Service names it as a string, which is the case a plain
// read of `spec.targetPort` cannot follow.
fn slice_target_port(slice: &EndpointSlice, name: Option<&str>) -> Option<u16> {
    let ports = slice.ports.as_ref()?;
    // An unnamed Service port matches the unnamed slice port; a single-port slice is taken as that
    // port whatever it is called, which is what a single-port Service always produces.
    let matched = ports
        .iter()
        .find(|p| p.name.as_deref() == name)
        .or_else(|| if ports.len() == 1 { ports.first() } else { None })?;
    u16::try_from(matched.port?).ok()
}

/// The Service ports a forward can be started on, with the target port spelled out. Read straight
/// off the spec: this is what the popup offers before anything is resolved.
pub fn target_port_label(target: Option<&IntOrString>, service_port: i32) -> String {
    match target {
        Some(IntOrString::Int(i)) => i.to_string(),
        Some(IntOrString::String(s)) => s.clone(),
        None => service_port.to_string(),
    }
}

/// Default local port for a Service port: the same number, which is what one expects to type into a
/// browser. Ports the process cannot bind (below 1024, unless it is root) are left as they are —
/// the bind error names the problem better than a silently different port would.
pub fn default_local_port(service_port: i32) -> u16 {
    u16::try_from(service_port).unwrap_or(0)
}

/// Forwards keyed by Service, for the column of the services table.
pub fn by_service(shared: &SharedForwards) -> HashMap<(String, String), Vec<PfRow>> {
    let mut out: HashMap<(String, String), Vec<PfRow>> = HashMap::new();
    for row in rows(shared) {
        out.entry((row.namespace.clone(), row.service.clone())).or_default().push(row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::discovery::v1::EndpointPort;

    fn slice(ports: Vec<(Option<&str>, i32)>) -> EndpointSlice {
        EndpointSlice {
            ports: Some(
                ports
                    .into_iter()
                    .map(|(name, port)| EndpointPort {
                        name: name.map(|n| n.to_string()),
                        port: Some(port),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn a_named_service_port_takes_the_slice_port_of_the_same_name() {
        let s = slice(vec![(Some("http"), 8080), (Some("metrics"), 9090)]);
        assert_eq!(slice_target_port(&s, Some("http")), Some(8080));
        assert_eq!(slice_target_port(&s, Some("metrics")), Some(9090));
        // A name the slice does not carry is not silently swapped for another port.
        assert_eq!(slice_target_port(&s, Some("grpc")), None);
    }

    #[test]
    fn a_single_port_service_needs_no_name_to_match() {
        // What a one-port Service produces: the slice port is unnamed, and so is the Service port.
        assert_eq!(slice_target_port(&slice(vec![(None, 8080)]), None), Some(8080));
        // kubectl-created Services sometimes name the single port anyway; the lone port still wins.
        assert_eq!(slice_target_port(&slice(vec![(Some("http"), 8080)]), None), Some(8080));
    }

    #[test]
    fn a_named_target_port_is_read_from_the_slice_not_the_spec() {
        // `targetPort: http` is a string in the Service; only the slice knows it resolved to 8080.
        assert_eq!(target_port_label(Some(&IntOrString::String("http".into())), 80), "http");
        assert_eq!(slice_target_port(&slice(vec![(Some("http"), 8080)]), Some("http")), Some(8080));
    }

    #[test]
    fn the_local_port_defaults_to_the_service_port() {
        assert_eq!(default_local_port(8080), 8080);
        assert_eq!(target_port_label(None, 8080), "8080");
        assert_eq!(target_port_label(Some(&IntOrString::Int(9090)), 8080), "9090");
    }
}
