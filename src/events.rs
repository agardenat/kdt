//! Cluster data access layer: the live event watcher plus on-demand fetchers for pod logs,
//! object status, namespaces, nodes, and per-node resource usage. Each fetcher writes into a
//! shared, mutex-guarded state struct that the UI polls.

use kube::api::DynamicObject;
use kube::core::GroupVersionKind;
use kube::discovery::{self, Scope};
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::{ListParams, LogParams};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k8s_openapi::jiff::Timestamp;

use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Event as K8sEvent;
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Client};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Normal,
    Warning,
}

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub uid: String,
    pub time: Timestamp,
    pub severity: Severity,
    pub reason: String,
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub message: String,
    pub component: String,
    pub host: String,
    pub count: i32,
}

impl EventRecord {
    pub fn node_name(&self) -> Option<String> {
        if self.kind == "Node" && !self.name.is_empty() {
            return Some(self.name.clone());
        }
        if !self.host.is_empty() {
            return Some(self.host.clone());
        }
        None
    }
}

impl EventRecord {
    // Flatten a Kubernetes Event into our display record, picking the most precise timestamp
    // available (eventTime > lastTimestamp > firstTimestamp > creationTimestamp > now).
    pub fn from_k8s(ev: K8sEvent) -> Self {
        let uid = ev.metadata.uid.clone().unwrap_or_default();
        let time = ev
            .event_time
            .map(|t| t.0)
            .or_else(|| ev.last_timestamp.map(|t| t.0))
            .or_else(|| ev.first_timestamp.map(|t| t.0))
            .or_else(|| ev.metadata.creation_timestamp.map(|t| t.0))
            .unwrap_or_else(Timestamp::now);

            let severity = match ev.type_.as_deref() {
            Some("Warning") => Severity::Warning,
            _ => Severity::Normal,
        };

        let obj = ev.involved_object;
        let (component, host) = ev
            .source
            .map(|s| (s.component.unwrap_or_default(), s.host.unwrap_or_default()))
            .unwrap_or_default();
        Self {
            uid,
            time,
            severity,
            reason: ev.reason.unwrap_or_default(),
            api_version: obj.api_version.unwrap_or_default(),
            kind: obj.kind.unwrap_or_default(),
            namespace: obj.namespace.unwrap_or_default(),
            name: obj.name.unwrap_or_default(),
            message: ev.message.unwrap_or_default(),
            component,
            host,
            count: ev.count.unwrap_or(1),
        }
    }
}

pub type SharedBuffer = Arc<Mutex<VecDeque<EventRecord>>>;

pub fn new_buffer() -> SharedBuffer {
    Arc::new(Mutex::new(VecDeque::new()))
}

// Spawn a background task that watches Events and maintains a bounded ring buffer (`capacity`).
// On reconnect the watcher re-emits objects, so an existing record with the same uid is replaced
// in place to keep counts/messages fresh. The outer loop restarts the stream after any error.
pub fn spawn_watcher(
    client: Client,
    namespace: Option<String>,
    buffer: SharedBuffer,
    capacity: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let api: Api<K8sEvent> = match namespace {
            Some(ns) => Api::namespaced(client, &ns),
            None => Api::all(client),
        };

        loop {
            let stream = watcher(api.clone(), watcher::Config::default())
                .default_backoff()
                .applied_objects();
            tokio::pin!(stream);

            loop {
                match stream.try_next().await {
                    Ok(Some(ev)) => {
                        let rec = EventRecord::from_k8s(ev);
                        let mut buf = buffer.lock().expect("buffer poisoned");
                        if !rec.uid.is_empty() {
                            if let Some(pos) = buf.iter().rposition(|r| r.uid == rec.uid) {
                                buf.remove(pos);
                            }
                        }
                        if buf.len() >= capacity {
                            buf.pop_front();
                        }
                        buf.push_back(rec);
                    }                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "watcher stream error, backing off");
                        break;
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}

#[derive(Default, Debug, Clone)]
pub struct LogState {
    pub current_key: Option<String>,
    pub lines: Vec<String>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedLog = Arc<Mutex<LogState>>;

pub fn new_log_state() -> SharedLog {
    Arc::new(Mutex::new(LogState::default()))
}

// Fetch recent logs for every container (init + regular) of a pod. The `tail` budget is split
// across containers when there is more than one. `key` guards against a stale write (see AiState).
pub async fn fetch_logs(
    client: Client,
    namespace: String,
    pod: String,
    key: String,
    state: SharedLog,
    tail: i64,
) {
    let api: Api<Pod> = Api::namespaced(client, &namespace);

    let containers: Vec<(String, bool)> = match api.get(&pod).await {
        Ok(p) => {
            let mut names = Vec::new();
            if let Some(spec) = p.spec.as_ref() {
                if let Some(inits) = &spec.init_containers {
                    for c in inits {
                        names.push((c.name.clone(), true));
                    }
                }
                for c in &spec.containers {
                    names.push((c.name.clone(), false));
                }
            }
            names
        }
        Err(e) => {
            let mut s = state.lock().expect("log state poisoned");
            if s.current_key.as_deref() != Some(&key) { return; }
            s.loading = false;
            s.lines.clear();
            s.error = Some(format!("get pod: {}", e));
            return;
        }
    };

    if containers.is_empty() {
        let mut s = state.lock().expect("log state poisoned");
        if s.current_key.as_deref() != Some(&key) { return; }
        s.loading = false;
        s.lines.clear();
        s.error = Some("aucun container trouvé sur ce pod".to_string());
        return;
    }

    let multi = containers.len() > 1;
    let per_container_tail = if multi { tail.max(1) / containers.len() as i64 } else { tail };
    let per_container_tail = per_container_tail.max(50);
    let mut all_lines: Vec<String> = Vec::new();

    for (cname, is_init) in &containers {
        if multi {
            let kind = if *is_init { "init container" } else { "container" };
            all_lines.push(format!("══ {}: {} ══", kind, cname));
        }
        let lp = LogParams {
            tail_lines: Some(per_container_tail),
            container: Some(cname.clone()),
            ..Default::default()
        };
        match api.logs(&pod, &lp).await {
            Ok(text) => {
                let lines = text.lines();
                let mut count = 0;
                for line in lines {
                    all_lines.push(line.to_string());
                    count += 1;
                }
                if multi && count == 0 {
                    all_lines.push("(aucun log)".to_string());
                }
            }
            Err(e) => {
                all_lines.push(format!("(échec récupération logs de {}: {})", cname, e));
            }
        }
        if multi { all_lines.push(String::new()); }
    }

    let mut s = state.lock().expect("log state poisoned");
    if s.current_key.as_deref() != Some(&key) { return; }
    s.loading = false;
    s.lines = all_lines;
    s.error = None;
}

// Fetch logs from the Flux controllers in flux-system. Controllers emit one JSON object per line
// (level/ts/msg + the reconciled object's namespace/name); when `filter` is set we keep only the
// lines about that object, otherwise we aggregate everything (global view). Pods are matched by
// name prefix to avoid depending on a specific label scheme. Lines are sorted by timestamp.
pub async fn fetch_flux_logs(
    client: Client,
    controllers: Vec<String>,
    filter: Option<(String, String)>,
    key: String,
    state: SharedLog,
    tail: i64,
) {
    let api: Api<Pod> = Api::namespaced(client, "flux-system");
    let pods = match api.list(&ListParams::default()).await {
        Ok(l) => l.items,
        Err(e) => {
            let mut s = state.lock().expect("log state poisoned");
            if s.current_key.as_deref() != Some(&key) { return; }
            s.loading = false;
            s.lines.clear();
            s.error = Some(format!("flux-system introuvable: {}", e));
            return;
        }
    };

    let mut collected: Vec<(String, String)> = Vec::new();
    for p in &pods {
        let Some(pod_name) = p.metadata.name.as_deref() else { continue };
        let Some(ctrl) = controllers.iter().find(|c| pod_name.starts_with(c.as_str())) else { continue };
        let lp = LogParams { tail_lines: Some(tail), ..Default::default() };
        let Ok(text) = api.logs(pod_name, &lp).await else { continue };
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if let Some((ns, name)) = &filter {
                if !flux_log_matches(&v, ns, name) { continue; }
            }
            collected.push((flux_log_ts(&v), format_flux_log_line(&v, ctrl, filter.is_none())));
        }
    }

    collected.sort_by(|a, b| a.0.cmp(&b.0));
    let lines: Vec<String> = collected.into_iter().map(|(_, l)| l).collect();

    let mut s = state.lock().expect("log state poisoned");
    if s.current_key.as_deref() != Some(&key) { return; }
    s.loading = false;
    s.error = if lines.is_empty() {
        Some("(aucune ligne de log correspondante)".to_string())
    } else {
        None
    };
    s.lines = lines;
}

// True if a controller log line refers to the given object, either via top-level name/namespace
// fields or a nested object (e.g. {"Kustomization": {"name":…, "namespace":…}}).
fn flux_log_matches(v: &serde_json::Value, ns: &str, name: &str) -> bool {
    let hit = |obj: &serde_json::Value| {
        obj.get("name").and_then(|x| x.as_str()) == Some(name)
            && obj.get("namespace").and_then(|x| x.as_str()) == Some(ns)
    };
    if hit(v) {
        return true;
    }
    if let Some(map) = v.as_object() {
        for val in map.values() {
            if val.is_object() && hit(val) {
                return true;
            }
        }
    }
    false
}

fn flux_log_ts(v: &serde_json::Value) -> String {
    v.get("ts")
        .map(|t| match t {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

// Render a controller log line as "HH:MM:SS [controller] LEVEL — msg"; in the global view the
// object's namespace/name is appended to keep entries distinguishable.
fn format_flux_log_line(v: &serde_json::Value, ctrl: &str, global: bool) -> String {
    let ts = flux_log_ts(v);
    let hms = ts
        .split_once('T')
        .map(|(_, t)| t.get(..8).unwrap_or(t).to_string())
        .unwrap_or(ts);
    let level = v.get("level").and_then(|x| x.as_str()).unwrap_or("info");
    let msg = v.get("msg").and_then(|x| x.as_str()).unwrap_or("");
    let mut out = format!("{} [{}] {} — {}", hms, ctrl, level, msg);
    if global {
        let ns = v.get("namespace").and_then(|x| x.as_str()).unwrap_or("");
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
        if !name.is_empty() {
            out.push_str(&format!("  ({}/{})", ns, name));
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
pub enum LineColor { Plain, Ok, Warn, Err, Info, Dim }

#[derive(Default, Debug, Clone)]
pub struct StatusState {
    pub current_key: Option<String>,
    pub lines: Vec<(LineColor, String)>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedStatus = Arc<Mutex<StatusState>>;

pub fn new_status_state() -> SharedStatus {
    Arc::new(Mutex::new(StatusState::default()))
}

pub async fn fetch_status(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    key: String,
    state: SharedStatus,
) {
    let result: Result<Vec<(LineColor, String)>, String> = if kind == "Pod" {
        let api: Api<Pod> = Api::namespaced(client, &namespace);
        match api.get(&name).await {
            Ok(p) => Ok(format_pod_status(&p)),
            Err(e) => Err(e.to_string()),
        }
    } else if kind == "Node" {
        let node_api: Api<Node> = Api::all(client.clone());
        match node_api.get(&name).await {
            Ok(n) => {
                let mut lines = format_node_status(&n);
                let pod_api: Api<Pod> = Api::all(client.clone());
                let lp = ListParams::default().fields(&format!("spec.nodeName={}", name));
                match pod_api.list(&lp).await {
                    Ok(list) => {
                        lines.extend(format_node_reserved(&list.items, &n));
                        lines.extend(format_node_oom_history(&list.items));
                    }
                    Err(e) => {
                        lines.push((LineColor::Plain, String::new()));
                        lines.push((LineColor::Warn, format!("(impossible de lister les pods du noeud: {})", e)));
                    }
                }
                Ok(lines)
            }
            Err(e) => Err(e.to_string()),
        }
    } else {
        fetch_dynamic(client, &api_version, &kind, &namespace, &name).await
    };

    let mut s = state.lock().expect("status state poisoned");
    if s.current_key.as_deref() != Some(&key) {
        return;
    }
    s.loading = false;
    match result {
        Ok(lines) => {
            s.lines = lines;
            s.error = None;
        }
        Err(e) => {
            s.lines.clear();
            s.error = Some(e);
        }
    }
}

// Fetch an arbitrary object by GVK (via discovery) and render a generic status summary for kinds
// without a dedicated formatter.
async fn fetch_dynamic(
    client: Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<Vec<(LineColor, String)>, String> {
    if kind.is_empty() {
        return Err("involvedObject has no kind".into());
    }
    let gvk = if let Some((g, v)) = api_version.split_once('/') {
        GroupVersionKind::gvk(g, v, kind)
    } else {
        GroupVersionKind::gvk("", api_version, kind)
    };
    let (ar, caps) = discovery::pinned_kind(&client, &gvk)
        .await
        .map_err(|e| format!("discovery failed for {}/{}: {}", api_version, kind, e))?;
    let api: Api<DynamicObject> = if caps.scope == Scope::Cluster {
        Api::all_with(client, &ar)
    } else {
        Api::namespaced_with(client, namespace, &ar)
    };
    let obj = api.get(name).await.map_err(|e| e.to_string())?;
    Ok(format_dynamic_status(&obj, kind))
}

fn format_dynamic_status(obj: &DynamicObject, kind: &str) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = Vec::new();
    let ns = obj.metadata.namespace.as_deref().unwrap_or("");
    let name = obj.metadata.name.as_deref().unwrap_or("?");
    let header = if ns.is_empty() {
        format!("{} {}", kind, name)
    } else {
        format!("{} {}/{}", kind, ns, name)
    };
    out.push((LineColor::Info, header));

    if let Some(t) = &obj.metadata.creation_timestamp {
        out.push((LineColor::Dim, format!("Created: {}", t.0)));
    }

    let status = obj.data.get("status");
    if let Some(phase) = status.and_then(|s| s.get("phase")).and_then(|p| p.as_str()) {
        let color = match phase {
            "Running" | "Succeeded" | "Bound" | "Active" | "Available" => LineColor::Ok,
            "Pending" | "Reconciling" => LineColor::Warn,
            "Failed" | "Lost" | "Released" | "Error" => LineColor::Err,
            _ => LineColor::Plain,
        };
        out.push((color, format!("Phase: {}", phase)));
    }
    if let Some(reason) = status.and_then(|s| s.get("reason")).and_then(|p| p.as_str()) {
        out.push((LineColor::Err, format!("Reason: {}", reason)));
    }
    if let Some(message) = status.and_then(|s| s.get("message")).and_then(|p| p.as_str()) {
        out.push((LineColor::Err, format!("Message: {}", message)));
    }

    if let Some(conds) = status.and_then(|s| s.get("conditions")).and_then(|c| c.as_array()) {
        if !conds.is_empty() {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, format!("Conditions ({})", conds.len())));
            for c in conds {
                let typ = c.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                let st = c.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                let message = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
                let color = match (st, condition_true_is_good(typ)) {
                    ("True", true) => LineColor::Ok,
                    ("True", false) => LineColor::Err,
                    ("False", true) => LineColor::Err,
                    ("False", false) => LineColor::Ok,
                    _ => LineColor::Warn,
                };
                let mut line = format!("  {} = {}", typ, st);
                if !reason.is_empty() {
                    line.push_str(&format!("  ({})", reason));
                }
                out.push((color, line));
                if !message.is_empty() {
                    out.push((LineColor::Dim, format!("    {}", message)));
                }
            }
        }
    }

    if kind == "ClusterPolicy" || kind == "Policy" {
        let spec = obj.data.get("spec");
        if let Some(action) = spec.and_then(|s| s.get("validationFailureAction")).and_then(|v| v.as_str()) {
            let color = match action {
                "Enforce" | "enforce" => LineColor::Err,
                "Audit" | "audit" => LineColor::Warn,
                _ => LineColor::Plain,
            };
            out.push((color, format!("validationFailureAction: {}", action)));
        }
        if let Some(bg) = spec.and_then(|s| s.get("background")).and_then(|v| v.as_bool()) {
            out.push((LineColor::Dim, format!("background: {}", bg)));
        }
        if let Some(rules) = spec.and_then(|s| s.get("rules")).and_then(|r| r.as_array()) {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, format!("Rules ({})", rules.len())));
            for r in rules {
                let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                out.push((LineColor::Plain, format!("  {}", n)));
            }
        }
    }

    if out.len() <= 2 {
        out.push((LineColor::Warn, "No status fields exposed".into()));
    }
    out
}

// Decide whether status=True is healthy for a given condition type: most conditions are positive
// (Ready/Available…) but pressure/failure/unavailable conditions invert that meaning.
fn condition_true_is_good(typ: &str) -> bool {
    if typ.ends_with("Pressure")
        || typ.ends_with("Unavailable")
        || typ.ends_with("Failure")
        || typ == "NetworkUnavailable"
        || typ == "ReplicaFailure"
    {
        return false;
    }
    matches!(
        typ,
        "Ready" | "Available" | "ContainersReady" | "Initialized" | "PodScheduled"
        | "Healthy" | "Synced" | "Reconciling" | "Established"
        | "Progressing" | "Bound" | "Active"
    ) || typ.ends_with("Ready") || typ.ends_with("Available")
}

#[derive(Default, Debug, Clone)]
pub struct NsListState {
    pub namespaces: Vec<String>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedNsList = Arc<Mutex<NsListState>>;

pub fn new_ns_list_state() -> SharedNsList {
    Arc::new(Mutex::new(NsListState::default()))
}

pub async fn fetch_namespaces(client: Client, state: SharedNsList) {
    {
        let mut s = state.lock().expect("ns list poisoned");
        s.loading = true;
        s.namespaces.clear();
        s.error = None;
    }
    let api: Api<Namespace> = Api::all(client);
    match api.list(&Default::default()).await {
        Ok(list) => {
            let mut names: Vec<String> = list.items.into_iter()
                .filter_map(|n| n.metadata.name)
                .collect();
            names.sort();
            let mut s = state.lock().expect("ns list poisoned");
            s.loading = false;
            s.namespaces = names;
        }
        Err(e) => {
            let mut s = state.lock().expect("ns list poisoned");
            s.loading = false;
            s.error = Some(e.to_string());
        }
    }
}

fn format_pod_status(pod: &Pod) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = Vec::new();
    let meta = &pod.metadata;
    let spec = pod.spec.as_ref();
    let status = pod.status.as_ref();

    out.push((LineColor::Info, format!(
        "Pod {}/{}",
        meta.namespace.as_deref().unwrap_or("?"),
        meta.name.as_deref().unwrap_or("?"),
    )));

    if let Some(s) = status {
        let phase_color = match s.phase.as_deref() {
            Some("Running") | Some("Succeeded") => LineColor::Ok,
            Some("Pending") => LineColor::Warn,
            Some("Failed") | Some("Unknown") => LineColor::Err,
            _ => LineColor::Plain,
        };
        out.push((phase_color, format!("Phase: {}", s.phase.as_deref().unwrap_or("?"))));
        if let Some(reason) = &s.reason {
            out.push((LineColor::Err, format!("Reason: {}", reason)));
        }
        if let Some(message) = &s.message {
            out.push((LineColor::Err, format!("Message: {}", message)));
        }
        if let Some(node) = spec.and_then(|sp| sp.node_name.as_deref()) {
            out.push((LineColor::Dim, format!("Node: {}", node)));
        }
        if let Some(ip) = &s.pod_ip {
            out.push((LineColor::Dim, format!("PodIP: {}", ip)));
        }
        if let Some(qos) = &s.qos_class {
            out.push((LineColor::Dim, format!("QoS: {}", qos)));
        }

        if let Some(conds) = &s.conditions {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, "Conditions:".into()));
            for c in conds {
                let color = if c.status == "True" { LineColor::Ok } else { LineColor::Warn };
                let msg = c.message.clone().unwrap_or_default();
                out.push((color, format!("  {} = {}  {}", c.type_, c.status, msg)));
            }
        }

        if let Some(cs) = &s.container_statuses {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, "Containers:".into()));
            for c in cs {
                let ready_color = if c.ready { LineColor::Ok } else { LineColor::Err };
                let restart_color = if c.restart_count >= 5 { LineColor::Err }
                    else if c.restart_count >= 1 { LineColor::Warn }
                    else { ready_color };
                out.push((restart_color, format!(
                    "  {} ready={} restarts={} image={}",
                    c.name, c.ready, c.restart_count, c.image,
                )));
                if let Some(state) = &c.state {
                    if state.running.is_some() {
                        out.push((LineColor::Ok, "    state: Running".into()));
                    }
                    if let Some(w) = &state.waiting {
                        let reason = w.reason.as_deref().unwrap_or("");
                        let color = if reason.contains("BackOff") || reason.contains("Err") || reason.contains("Failed") {
                            LineColor::Err
                        } else {
                            LineColor::Warn
                        };
                        out.push((color, format!(
                            "    state: Waiting ({}): {}",
                            reason,
                            w.message.as_deref().unwrap_or(""),
                        )));
                    }
                    if let Some(t) = &state.terminated {
                        let oom = t.reason.as_deref() == Some("OOMKilled");
                        out.push((LineColor::Err, format!(
                            "    state: Terminated ({}, exit={}){}",
                            t.reason.as_deref().unwrap_or(""),
                            t.exit_code,
                            if oom { "  ⚠ OOMKILLED" } else { "" },
                        )));
                    }
                }
                if let Some(last) = &c.last_state {
                    if let Some(t) = &last.terminated {
                        let oom = t.reason.as_deref() == Some("OOMKilled");
                        let color = if oom { LineColor::Err } else { LineColor::Dim };
                        out.push((color, format!(
                            "    last: Terminated ({}, exit={}){}",
                            t.reason.as_deref().unwrap_or(""),
                            t.exit_code,
                            if oom { "  ⚠ OOMKILLED précédemment" } else { "" },
                        )));
                    }
                }
            }
        }

        if let Some(ics) = &s.init_container_statuses {
            if !ics.is_empty() {
                out.push((LineColor::Plain, String::new()));
                out.push((LineColor::Info, "Init containers:".into()));
                for c in ics {
                    let ready_color = if c.ready { LineColor::Ok } else { LineColor::Warn };
                    out.push((ready_color, format!(
                        "  {} ready={} restarts={}",
                        c.name, c.ready, c.restart_count,
                    )));
                }
            }
        }

        let oom_count = count_oom(s);
        if oom_count > 0 {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Err, format!("⚠ OOMKilled détecté sur {} container(s)", oom_count)));
        }
    } else {
        out.push((LineColor::Warn, "No status available".into()));
    }

    if let Some(spec) = spec {
        let mut any = false;
        for c in &spec.containers {
            if c.resources.as_ref().map(|r| r.requests.is_some() || r.limits.is_some()).unwrap_or(false) {
                any = true; break;
            }
        }
        if any {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, "Resources :".into()));
            for c in &spec.containers {
                if let Some(r) = &c.resources {
                    let req = format_resource_map(r.requests.as_ref());
                    let lim = format_resource_map(r.limits.as_ref());
                    out.push((LineColor::Plain, format!("  {} requests={} limits={}", c.name, req, lim)));
                }
            }
        }
    }
    out
}

fn count_oom(s: &k8s_openapi::api::core::v1::PodStatus) -> usize {
    let mut n = 0;
    if let Some(cs) = &s.container_statuses {
        for c in cs {
            if let Some(state) = &c.state {
                if let Some(t) = &state.terminated {
                    if t.reason.as_deref() == Some("OOMKilled") { n += 1; }
                }
            }
            if let Some(last) = &c.last_state {
                if let Some(t) = &last.terminated {
                    if t.reason.as_deref() == Some("OOMKilled") { n += 1; }
                }
            }
        }
    }
    n
}

fn format_resource_map(m: Option<&BTreeMap<String, Quantity>>) -> String {
    let Some(m) = m else { return "—".to_string() };
    if m.is_empty() { return "—".to_string(); }
    let mut parts: Vec<String> = m.iter().map(|(k, v)| format!("{}={}", k, v.0)).collect();
    parts.sort();
    parts.join(",")
}

pub fn format_node_status(node: &Node) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = Vec::new();
    let meta = &node.metadata;
    out.push((LineColor::Info, format!("Node {}", meta.name.as_deref().unwrap_or("?"))));
    if let Some(t) = &meta.creation_timestamp {
        out.push((LineColor::Dim, format!("Created: {}  (age: {})", t.0, format_age(&t.0))));
    }

    if let Some(roles) = node_roles(meta.labels.as_ref()) {
        out.push((LineColor::Dim, format!("Roles: {}", roles)));
    }

    if let Some(spec) = node.spec.as_ref() {
        if spec.unschedulable.unwrap_or(false) {
            out.push((LineColor::Err, "⚠ Unschedulable (cordoned)".into()));
        }
        if let Some(taints) = &spec.taints {
            if !taints.is_empty() {
                out.push((LineColor::Plain, String::new()));
                out.push((LineColor::Info, format!("Taints ({}) :", taints.len())));
                for t in taints {
                    let color = match t.effect.as_str() {
                        "NoSchedule" | "NoExecute" => LineColor::Warn,
                        _ => LineColor::Plain,
                    };
                    out.push((color, format!(
                        "  {}={} : {}",
                        t.key,
                        t.value.as_deref().unwrap_or(""),
                        t.effect,
                    )));
                }
            }
        }
    }

    let status = node.status.as_ref();

    if let Some(s) = status {
        if let Some(conds) = &s.conditions {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, "Conditions :".into()));
            for c in conds {
                let typ = c.type_.as_str();
                let bad = match typ {
                    "Ready" => c.status != "True",
                    _ => c.status == "True",
                };
                let color = if bad { LineColor::Err } else if typ == "Ready" { LineColor::Ok } else { LineColor::Dim };
                let mut line = format!("  {} = {}", typ, c.status);
                if let Some(reason) = &c.reason {
                    if !reason.is_empty() { line.push_str(&format!("  ({})", reason)); }
                }
                out.push((color, line));
                if let Some(message) = &c.message {
                    if !message.is_empty() {
                        out.push((LineColor::Dim, format!("    {}", message)));
                    }
                }
            }
        }

        out.push((LineColor::Plain, String::new()));
        out.push((LineColor::Info, "Capacity / Allocatable (limites du noeud, pas l'usage) :".into()));
        let cap = s.capacity.as_ref();
        let alloc = s.allocatable.as_ref();
        for key in ["cpu", "memory", "ephemeral-storage", "pods"] {
            let c = cap.and_then(|m| m.get(key)).map(|q| q.0.clone()).unwrap_or_else(|| "?".into());
            let a = alloc.and_then(|m| m.get(key)).map(|q| q.0.clone()).unwrap_or_else(|| "?".into());
            let abnormal = c == "?" || a == "?";
            let color = if abnormal { LineColor::Warn } else { LineColor::Plain };
            out.push((color, format!("  {:<22} capacity={}  allocatable={}", key, c, a)));
        }
        if let Some(cap) = cap {
            for (k, v) in cap.iter() {
                if matches!(k.as_str(), "cpu" | "memory" | "ephemeral-storage" | "pods") { continue; }
                out.push((LineColor::Dim, format!("  {:<22} capacity={}", k, v.0)));
            }
        }

        if let Some(info) = &s.node_info {
            out.push((LineColor::Plain, String::new()));
            out.push((LineColor::Info, "System info :".into()));
            out.push((LineColor::Dim, format!("  kubelet: {}", info.kubelet_version)));
            out.push((LineColor::Dim, format!("  containerd: {}", info.container_runtime_version)));
            out.push((LineColor::Dim, format!("  OS: {} ({})", info.operating_system, info.os_image)));
            out.push((LineColor::Dim, format!("  kernel: {}", info.kernel_version)));
            out.push((LineColor::Dim, format!("  arch: {}", info.architecture)));
        }

        if let Some(addrs) = &s.addresses {
            if !addrs.is_empty() {
                out.push((LineColor::Plain, String::new()));
                out.push((LineColor::Info, "Addresses :".into()));
                for a in addrs {
                    out.push((LineColor::Dim, format!("  {:<14} {}", a.type_, a.address)));
                }
            }
        }
    } else {
        out.push((LineColor::Warn, "No status available".into()));
    }
    out
}

fn node_roles(labels: Option<&BTreeMap<String, String>>) -> Option<String> {
    let labels = labels?;
    let mut roles: Vec<String> = labels.keys()
        .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    roles.sort();
    if roles.is_empty() { None } else { Some(roles.join(",")) }
}

pub fn format_age(t: &Timestamp) -> String {
    let now_s = Timestamp::now().as_second();
    let then_s = t.as_second();
    let secs = (now_s - then_s).max(0) as u64;
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m", secs / 60) }
    else if secs < 86400 { format!("{}h", secs / 3600) }
    else { format!("{}d", secs / 86400) }
}

#[derive(Debug, Clone)]
pub struct NodeSummary {
    pub name: String,
    pub ready: String,
    pub roles: String,
    pub age: String,
    pub version: String,
    pub schedulable: bool,
    pub abnormal: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub struct NodeListState {
    pub nodes: Vec<NodeSummary>,
    pub error: Option<String>,
    pub loading: bool,
}

pub type SharedNodeList = Arc<Mutex<NodeListState>>;

pub fn new_node_list_state() -> SharedNodeList {
    Arc::new(Mutex::new(NodeListState::default()))
}

pub async fn fetch_nodes(client: Client, state: SharedNodeList) {
    {
        let mut s = state.lock().expect("node list poisoned");
        s.loading = true;
        s.error = None;
    }
    let api: Api<Node> = Api::all(client);
    match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut nodes: Vec<NodeSummary> = list.items.iter().map(node_summary).collect();
            nodes.sort_by(|a, b| a.name.cmp(&b.name));
            let mut s = state.lock().expect("node list poisoned");
            s.loading = false;
            s.nodes = nodes;
        }
        Err(e) => {
            let mut s = state.lock().expect("node list poisoned");
            s.loading = false;
            s.error = Some(e.to_string());
        }
    }
}

fn node_summary(n: &Node) -> NodeSummary {
    let name = n.metadata.name.clone().unwrap_or_default();
    let ready = n.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .map(|c| c.status.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let roles = node_roles(n.metadata.labels.as_ref()).unwrap_or_else(|| "<none>".to_string());
    let age = n.metadata.creation_timestamp.as_ref()
        .map(|t| format_age(&t.0))
        .unwrap_or_default();
    let version = n.status.as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.kubelet_version.clone())
        .unwrap_or_default();
    let schedulable = !n.spec.as_ref()
        .and_then(|s| s.unschedulable)
        .unwrap_or(false);
    let abnormal: Vec<String> = n.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|cs| cs.iter().filter_map(|c| {
            let bad = match c.type_.as_str() {
                "Ready" => c.status != "True",
                _ => c.status == "True",
            };
            if bad { Some(c.type_.clone()) } else { None }
        }).collect())
        .unwrap_or_default();
    NodeSummary { name, ready, roles, age, version, schedulable, abnormal }
}

pub fn format_node_oom_history(pods: &[Pod]) -> Vec<(LineColor, String)> {
    let mut entries: Vec<(Option<Timestamp>, String)> = Vec::new();
    for p in pods {
        let ns = p.metadata.namespace.as_deref().unwrap_or("");
        let pod_name = p.metadata.name.as_deref().unwrap_or("");
        let Some(status) = &p.status else { continue };
        let collect = |container: &str, terminated: &k8s_openapi::api::core::v1::ContainerStateTerminated, current: bool, out: &mut Vec<(Option<Timestamp>, String)>| {
            if terminated.reason.as_deref() != Some("OOMKilled") { return; }
            let when = terminated.finished_at.as_ref().map(|t| t.0);
            let when_label = when
                .as_ref()
                .map(|t| format!("{} ({})", t, format_age(t)))
                .unwrap_or_else(|| "?".to_string());
            let tag = if current { "current" } else { "previous" };
            out.push((
                when,
                format!(
                    "  {}/{}  container={}  exit={}  [{}]  {}",
                    ns, pod_name, container, terminated.exit_code, tag, when_label,
                ),
            ));
        };
        if let Some(cs) = &status.container_statuses {
            for c in cs {
                if let Some(t) = c.state.as_ref().and_then(|s| s.terminated.as_ref()) {
                    collect(&c.name, t, true, &mut entries);
                }
                if let Some(t) = c.last_state.as_ref().and_then(|s| s.terminated.as_ref()) {
                    collect(&c.name, t, false, &mut entries);
                }
            }
        }
        if let Some(ics) = &status.init_container_statuses {
            for c in ics {
                if let Some(t) = c.state.as_ref().and_then(|s| s.terminated.as_ref()) {
                    collect(&c.name, t, true, &mut entries);
                }
                if let Some(t) = c.last_state.as_ref().and_then(|s| s.terminated.as_ref()) {
                    collect(&c.name, t, false, &mut entries);
                }
            }
        }
    }
    let mut out: Vec<(LineColor, String)> = Vec::new();
    if entries.is_empty() {
        return out;
    }
    entries.sort_by(|a, b| match (a.0.as_ref(), b.0.as_ref()) {
        (Some(x), Some(y)) => y.cmp(x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    out.push((LineColor::Plain, String::new()));
    out.push((
        LineColor::Err,
        format!("⚠ Récents OOMKilled sur ce noeud ({}) :", entries.len()),
    ));
    for (_, line) in entries.iter().take(10) {
        out.push((LineColor::Err, line.clone()));
    }
    if entries.len() > 10 {
        out.push((LineColor::Dim, format!("  ... ({} de plus)", entries.len() - 10)));
    }
    out
}

// Sum container requests/limits across active pods on a node and express them as a percentage of
// the node's allocatable capacity (reservation for requests, over-commit for limits).
pub fn format_node_reserved(pods: &[Pod], node: &Node) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = Vec::new();
    let mut cpu_req = 0_i64; let mut cpu_lim = 0_i64;
    let mut mem_req = 0_i64; let mut mem_lim = 0_i64;
    let mut active = 0usize; let mut total = 0usize;
    for p in pods {
        total += 1;
        if let Some(s) = &p.status {
            if let Some(phase) = &s.phase {
                if phase == "Succeeded" || phase == "Failed" { continue; }
            }
        }
        active += 1;
        if let Some(spec) = &p.spec {
            for c in &spec.containers {
                if let Some(r) = &c.resources {
                    if let Some(reqs) = &r.requests {
                        if let Some(q) = reqs.get("cpu") { cpu_req += parse_quantity_cpu_milli(&q.0).unwrap_or(0); }
                        if let Some(q) = reqs.get("memory") { mem_req += parse_quantity_memory_bytes(&q.0).unwrap_or(0); }
                    }
                    if let Some(lims) = &r.limits {
                        if let Some(q) = lims.get("cpu") { cpu_lim += parse_quantity_cpu_milli(&q.0).unwrap_or(0); }
                        if let Some(q) = lims.get("memory") { mem_lim += parse_quantity_memory_bytes(&q.0).unwrap_or(0); }
                    }
                }
            }
        }
    }
    let alloc_cpu = node.status.as_ref().and_then(|s| s.allocatable.as_ref())
        .and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0);
    let alloc_mem = node.status.as_ref().and_then(|s| s.allocatable.as_ref())
        .and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)).unwrap_or(0);
    out.push((LineColor::Plain, String::new()));
    out.push((LineColor::Info, format!(
        "Réservé par les pods (somme des requests/limits sur {} pods actifs / {} total ; le ratio est sur l'allocatable du noeud) :",
        active, total,
    )));
    out.push((color_for_pct(pct(cpu_req, alloc_cpu)), format!("  cpu  requests sum : {:>10}  /  allocatable {:<10} ({}% reserved)",
        format_cpu_milli(cpu_req), format_cpu_milli(alloc_cpu), pct(cpu_req, alloc_cpu))));
    out.push((color_for_pct(pct(cpu_lim, alloc_cpu)), format!("  cpu  limits   sum : {:>10}  /  allocatable {:<10} ({}% over-commit)",
        format_cpu_milli(cpu_lim), format_cpu_milli(alloc_cpu), pct(cpu_lim, alloc_cpu))));
    out.push((color_for_pct(pct(mem_req, alloc_mem)), format!("  mem  requests sum : {:>10}  /  allocatable {:<10} ({}% reserved)",
        format_memory_bytes(mem_req), format_memory_bytes(alloc_mem), pct(mem_req, alloc_mem))));
    out.push((color_for_pct(pct(mem_lim, alloc_mem)), format!("  mem  limits   sum : {:>10}  /  allocatable {:<10} ({}% over-commit)",
        format_memory_bytes(mem_lim), format_memory_bytes(alloc_mem), pct(mem_lim, alloc_mem))));
    out
}

fn pct(v: i64, total: i64) -> i64 {
    if total > 0 { v.saturating_mul(100) / total } else { 0 }
}

fn color_for_pct(p: i64) -> LineColor {
    if p >= 100 { LineColor::Err }
    else if p >= 80 { LineColor::Warn }
    else if p >= 50 { LineColor::Info }
    else { LineColor::Plain }
}

// Parse a Kubernetes CPU quantity into millicores (e.g. "500m"->500, "2"->2000, "1500000n"->1).
pub fn parse_quantity_cpu_milli(q: &str) -> Option<i64> {
    let q = q.trim();
    if let Some(s) = q.strip_suffix('m') { s.parse::<f64>().ok().map(|v| v as i64) }
    else if let Some(s) = q.strip_suffix('n') { s.parse::<f64>().ok().map(|v| (v / 1_000_000.0) as i64) }
    else if let Some(s) = q.strip_suffix('u') { s.parse::<f64>().ok().map(|v| (v / 1_000.0) as i64) }
    else { q.parse::<f64>().ok().map(|v| (v * 1000.0) as i64) }
}

// Parse a Kubernetes memory quantity into bytes, honoring both binary (Ki/Mi/Gi…) and decimal
// (K/M/G…) suffixes.
pub fn parse_quantity_memory_bytes(q: &str) -> Option<i64> {
    let q = q.trim();
    let suffixes: &[(&str, i64)] = &[
        ("Ei", 1024_i64.pow(6)), ("Pi", 1024_i64.pow(5)), ("Ti", 1024_i64.pow(4)),
        ("Gi", 1024_i64.pow(3)), ("Mi", 1024 * 1024), ("Ki", 1024),
        ("E", 1_000_000_000_000_000_000), ("P", 1_000_000_000_000_000),
        ("T", 1_000_000_000_000), ("G", 1_000_000_000),
        ("M", 1_000_000), ("K", 1_000),
    ];
    for (suf, mult) in suffixes {
        if let Some(s) = q.strip_suffix(suf) {
            return s.parse::<f64>().ok().map(|v| (v * *mult as f64) as i64);
        }
    }
    q.parse::<f64>().ok().map(|v| v as i64)
}

pub fn format_cpu_milli(m: i64) -> String {
    if m == 0 { "0".to_string() }
    else if m < 1000 { format!("{}m", m) }
    else if m % 1000 == 0 { format!("{}", m / 1000) }
    else { format!("{:.2}", m as f64 / 1000.0) }
}

pub fn format_memory_bytes(b: i64) -> String {
    if b == 0 { return "0".to_string(); }
    const GI: i64 = 1024 * 1024 * 1024;
    const MI: i64 = 1024 * 1024;
    const KI: i64 = 1024;
    if b >= GI { format!("{:.1}Gi", b as f64 / GI as f64) }
    else if b >= MI { format!("{:.0}Mi", b as f64 / MI as f64) }
    else if b >= KI { format!("{:.0}Ki", b as f64 / KI as f64) }
    else { format!("{}", b) }
}

#[derive(Debug, Clone, Default)]
pub struct PodUsageRow {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub cpu_req: Option<i64>,
    pub cpu_lim: Option<i64>,
    pub cpu_use: Option<i64>,
    pub mem_req: Option<i64>,
    pub mem_lim: Option<i64>,
    pub mem_use: Option<i64>,
    pub _phase: String, // captured for completeness; currently not displayed (underscore-prefixed)
    pub ready: bool,
    pub restarts: i32,
    pub is_system: bool,
}

// Heuristic: namespaces managed by Kubernetes itself or common platform add-ons (cloud CNI/CSI,
// service mesh, Rancher…), used to separate "system" from "user" workloads in usage views.
pub fn is_system_namespace(ns: &str) -> bool {
    ns.starts_with("kube-")
        || ns.starts_with("cattle-")
        || ns.starts_with("gke-")
        || ns == "gmp-system"
        || ns.starts_with("aks-")
        || ns.starts_with("azure-")
        || ns == "azuredisk-csi-driver"
        || ns == "azurefile-csi-driver"
        || ns == "secrets-store-csi-driver"
        || ns.starts_with("eks-")
        || ns.starts_with("tigera-")
        || ns.starts_with("calico-")
        || ns.starts_with("cilium-")
        || ns.starts_with("vmware-system-")
        || ns == "linkerd"
        || ns == "istio-system"
        || ns == "openshift-monitoring"
        || ns.starts_with("openshift-")
}

#[derive(Default, Debug, Clone)]
pub struct NodeUsageState {
    pub current_node: Option<String>,
    pub rows: Vec<PodUsageRow>,
    pub loading: bool,
    pub error: Option<String>,
    pub metrics_available: bool,
    pub alloc_cpu_milli: i64,
    pub alloc_mem_bytes: i64,
}

pub type SharedNodeUsage = Arc<Mutex<NodeUsageState>>;

pub fn new_node_usage_state() -> SharedNodeUsage {
    Arc::new(Mutex::new(NodeUsageState::default()))
}

// Build the per-container usage table for one node: join pod specs (requests/limits) with live
// metrics from metrics-server (optional) keyed by (namespace, pod, container). Completed pods
// (Succeeded/Failed) are skipped. `metrics_available` is false when metrics-server is absent.
pub async fn fetch_node_usage(client: Client, node_name: String, state: SharedNodeUsage) {
    {
        let mut s = state.lock().expect("node usage poisoned");
        s.current_node = Some(node_name.clone());
        s.rows.clear();
        s.error = None;
        s.loading = true;
        s.metrics_available = false;
    }

    let node_api: Api<Node> = Api::all(client.clone());
    let (alloc_cpu, alloc_mem) = match node_api.get(&node_name).await {
        Ok(n) => {
            let cpu = n.status.as_ref().and_then(|s| s.allocatable.as_ref())
                .and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0);
            let mem = n.status.as_ref().and_then(|s| s.allocatable.as_ref())
                .and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)).unwrap_or(0);
            (cpu, mem)
        }
        Err(_) => (0, 0),
    };

    let pod_api: Api<Pod> = Api::all(client.clone());
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    let pods = match pod_api.list(&lp).await {
        Ok(l) => l.items,
        Err(e) => {
            let mut s = state.lock().expect("node usage poisoned");
            if s.current_node.as_deref() != Some(&node_name) { return; }
            s.loading = false;
            s.error = Some(format!("liste des pods: {}", e));
            return;
        }
    };

    let usage_map = fetch_pod_metrics_map(&client).await.unwrap_or_default();
    let metrics_available = !usage_map.is_empty();

    let mut rows = Vec::new();
    for p in pods {
        let ns = p.metadata.namespace.clone().unwrap_or_default();
        let pod_name = p.metadata.name.clone().unwrap_or_default();
        let phase = p.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
        if phase == "Succeeded" || phase == "Failed" { continue; }
        let cs_list = p.status.as_ref().and_then(|s| s.container_statuses.clone()).unwrap_or_default();

        if let Some(spec) = &p.spec {
            let priority_class = spec.priority_class_name.clone().unwrap_or_default();
            let is_system = is_system_namespace(&ns)
                || priority_class == "system-cluster-critical"
                || priority_class == "system-node-critical";
            for c in &spec.containers {
                let (cpu_req, cpu_lim, mem_req, mem_lim) = if let Some(r) = &c.resources {
                    (
                        r.requests.as_ref().and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)),
                        r.limits.as_ref().and_then(|m| m.get("cpu")).and_then(|q| parse_quantity_cpu_milli(&q.0)),
                        r.requests.as_ref().and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)),
                        r.limits.as_ref().and_then(|m| m.get("memory")).and_then(|q| parse_quantity_memory_bytes(&q.0)),
                    )
                } else { (None, None, None, None) };
                let (cpu_use, mem_use) = match usage_map.get(&(ns.clone(), pod_name.clone(), c.name.clone())) {
                    Some(&(c, m)) => (Some(c), Some(m)),
                    None => (None, None),
                };
                let cs = cs_list.iter().find(|cs| cs.name == c.name);
                let ready = cs.map(|cs| cs.ready).unwrap_or(false);
                let restarts = cs.map(|cs| cs.restart_count).unwrap_or(0);
                rows.push(PodUsageRow {
                    namespace: ns.clone(),
                    pod: pod_name.clone(),
                    container: c.name.clone(),
                    cpu_req, cpu_lim, cpu_use,
                    mem_req, mem_lim, mem_use,
                    _phase: phase.clone(),
                    ready,
                    restarts,
                    is_system,
                });
            }
        }
    }
    rows.sort_by(|a, b|
        a.is_system.cmp(&b.is_system)
            .then(a.namespace.cmp(&b.namespace))
            .then(a.pod.cmp(&b.pod))
            .then(a.container.cmp(&b.container))
    );

    let mut s = state.lock().expect("node usage poisoned");
    if s.current_node.as_deref() != Some(&node_name) { return; }
    s.loading = false;
    s.rows = rows;
    s.metrics_available = metrics_available;
    s.alloc_cpu_milli = alloc_cpu;
    s.alloc_mem_bytes = alloc_mem;
}

#[derive(Default, Debug, Clone)]
pub struct ClusterInfo {
    pub server_version: Option<String>,
    pub node_count: usize,
    pub nodes_ready: usize,
    pub cpu_alloc_milli: i64,
    pub cpu_use_milli: i64,
    pub mem_alloc_bytes: i64,
    pub mem_use_bytes: i64,
    pub metrics_available: bool,
    pub loaded: bool,
}

pub type SharedClusterInfo = Arc<Mutex<ClusterInfo>>;

pub fn new_cluster_info_state() -> SharedClusterInfo {
    Arc::new(Mutex::new(ClusterInfo::default()))
}

pub async fn fetch_cluster_info(client: Client, state: SharedClusterInfo) {
    let version = client
        .apiserver_version()
        .await
        .ok()
        .map(|i| i.git_version);

    let node_api: Api<Node> = Api::all(client.clone());
    let (mut cpu_alloc, mut mem_alloc, mut count, mut ready) = (0_i64, 0_i64, 0_usize, 0_usize);
    if let Ok(list) = node_api.list(&ListParams::default()).await {
        count = list.items.len();
        for n in &list.items {
            if let Some(alloc) = n.status.as_ref().and_then(|s| s.allocatable.as_ref()) {
                cpu_alloc += alloc.get("cpu").and_then(|q| parse_quantity_cpu_milli(&q.0)).unwrap_or(0);
                mem_alloc += alloc.get("memory").and_then(|q| parse_quantity_memory_bytes(&q.0)).unwrap_or(0);
            }
            let is_ready = n.status.as_ref()
                .and_then(|s| s.conditions.as_ref())
                .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
                .map(|c| c.status == "True")
                .unwrap_or(false);
            if is_ready { ready += 1; }
        }
    }

    let (cpu_use, mem_use, metrics_available) = match fetch_node_metrics_total(&client).await {
        Some((c, m)) => (c, m, true),
        None => (0, 0, false),
    };

    let mut s = state.lock().expect("cluster info poisoned");
    s.server_version = version;
    s.node_count = count;
    s.nodes_ready = ready;
    s.cpu_alloc_milli = cpu_alloc;
    s.mem_alloc_bytes = mem_alloc;
    s.cpu_use_milli = cpu_use;
    s.mem_use_bytes = mem_use;
    s.metrics_available = metrics_available;
    s.loaded = true;
}

// Sum CPU/memory usage across all nodes from metrics-server (metrics.k8s.io). None if unavailable.
async fn fetch_node_metrics_total(client: &Client) -> Option<(i64, i64)> {
    let gvk = GroupVersionKind::gvk("metrics.k8s.io", "v1beta1", "NodeMetrics");
    let (ar, _) = discovery::pinned_kind(client, &gvk).await.ok()?;
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    let list = api.list(&ListParams::default()).await.ok()?;
    let mut cpu = 0_i64;
    let mut mem = 0_i64;
    for item in list.items {
        let usage = item.data.get("usage");
        cpu += usage.and_then(|u| u.get("cpu")).and_then(|v| v.as_str()).and_then(parse_quantity_cpu_milli).unwrap_or(0);
        mem += usage.and_then(|u| u.get("memory")).and_then(|v| v.as_str()).and_then(parse_quantity_memory_bytes).unwrap_or(0);
    }
    Some((cpu, mem))
}

async fn fetch_pod_metrics_map(client: &Client) -> Option<std::collections::HashMap<(String, String, String), (i64, i64)>> {
    let gvk = GroupVersionKind::gvk("metrics.k8s.io", "v1beta1", "PodMetrics");
    let (ar, _) = discovery::pinned_kind(client, &gvk).await.ok()?;
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    let list = api.list(&ListParams::default()).await.ok()?;
    let mut map = std::collections::HashMap::new();
    for item in list.items {
        let ns = item.metadata.namespace.clone().unwrap_or_default();
        let pod = item.metadata.name.clone().unwrap_or_default();
        if let Some(containers) = item.data.get("containers").and_then(|v| v.as_array()) {
            for c in containers {
                let cname = c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let usage = c.get("usage");
                let cpu = usage.and_then(|u| u.get("cpu")).and_then(|v| v.as_str()).and_then(parse_quantity_cpu_milli);
                let mem = usage.and_then(|u| u.get("memory")).and_then(|v| v.as_str()).and_then(parse_quantity_memory_bytes);
                if let (Some(c), Some(m)) = (cpu, mem) {
                    map.insert((ns.clone(), pod.clone(), cname), (c, m));
                }
            }
        }
    }
    Some(map)
}