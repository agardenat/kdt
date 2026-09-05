//! Cluster health diagnostic: a fixed sequence of read-only `check_*` steps (API health, nodes,
//! kube-system, DNS/CNI, webhooks, Rancher, problem pods, PVs, recent warnings). Each step pushes
//! a "Running" entry, then finishes it with a status and detail lines for the UI/PDF.
//!
//! `run_id` is bumped on every run so results from a superseded run are discarded.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use http::Request;
use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Event as K8sEvent, Namespace, Node, PersistentVolume, Pod};
use crate::lang::{active, fill};
use kube::api::{DynamicObject, ListParams, LogParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Api, Client};

use crate::events::LineColor;

use crate::certmanager::{fetch_certs, new_certs_state, CmKind, CmReady};
use crate::flux::{fetch_flux, new_flux_state, FluxReady};
use crate::kyverno::{fetch_kyverno, new_kyverno_state};
use crate::velero::{age_of, fetch_velero, new_velero_state};
use crate::storage::{fetch_storage, new_storage_state};
use crate::capacity::{fetch_capacity, new_capacity_state};
use crate::rbac::{critical_namespaces, fetch_rbac, new_rbac_state, Severity};
use crate::argocd::{fetch_argocd, new_argo_state};
use crate::identity::{fetch_identity, new_identity_state, Phase};
use crate::reflector::{fetch_reflector, new_reflector_state};
use crate::k8ssandra::{fetch_k8ssandra, new_k8c_state};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagStatus {
    Running,
    Ok,
    Info,
    Warn,
    Err,
}

impl DiagStatus {
    pub fn label(self) -> &'static str {
        match self {
            DiagStatus::Running => "…",
            DiagStatus::Ok => "✓",
            DiagStatus::Info => "i",
            DiagStatus::Warn => "!",
            DiagStatus::Err => "✗",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticStep {
    pub title: String,
    pub command: String,
    pub status: DiagStatus,
    pub lines: Vec<(LineColor, String)>,
}

#[derive(Default, Debug, Clone)]
pub struct DiagnosticState {
    pub running: bool,
    pub finished: bool,
    pub started_at: Option<Instant>,
    pub elapsed_ms: Option<u128>,
    pub steps: Vec<DiagnosticStep>,
    pub current_step: Option<usize>,
    pub run_id: u64,
}

pub type SharedDiagnostic = Arc<Mutex<DiagnosticState>>;

pub fn new_diagnostic_state() -> SharedDiagnostic {
    Arc::new(Mutex::new(DiagnosticState::default()))
}

// Append a step in the "Running" state and return its index, or None if this run was superseded
// (so the caller bails out early instead of doing more work).
fn push_step(state: &SharedDiagnostic, run_id: u64, title: &str, command: &str) -> Option<usize> {
    let mut s = state.lock().expect("diagnostic poisoned");
    if s.run_id != run_id {
        return None;
    }
    let idx = s.steps.len();
    s.steps.push(DiagnosticStep {
        title: title.to_string(),
        command: command.to_string(),
        status: DiagStatus::Running,
        lines: Vec::new(),
    });
    s.current_step = Some(idx);
    Some(idx)
}

fn finish_step(
    state: &SharedDiagnostic,
    run_id: u64,
    idx: usize,
    status: DiagStatus,
    lines: Vec<(LineColor, String)>,
) {
    let mut s = state.lock().expect("diagnostic poisoned");
    if s.run_id != run_id {
        return;
    }
    if let Some(step) = s.steps.get_mut(idx) {
        step.status = status;
        step.lines = lines;
    }
}

pub async fn run_diagnostic(client: Client, state: SharedDiagnostic) {
    let run_id = {
        let mut s = state.lock().expect("diagnostic poisoned");
        s.run_id = s.run_id.wrapping_add(1).max(1);
        s.running = true;
        s.finished = false;
        s.started_at = Some(Instant::now());
        s.elapsed_ms = None;
        s.steps.clear();
        s.current_step = None;
        s.run_id
    };

    check_api_health(&client, &state, run_id).await;
    check_cluster_version(&client, &state, run_id).await;
    check_nodes(&client, &state, run_id).await;
    check_system_namespaces(&client, &state, run_id).await;
    check_kube_system_pods(&client, &state, run_id).await;
    check_dns(&client, &state, run_id).await;
    check_cni(&client, &state, run_id).await;
    check_validating_webhooks(&client, &state, run_id).await;
    check_mutating_webhooks(&client, &state, run_id).await;
    check_rancher(&client, &state, run_id).await;
    check_problem_pods(&client, &state, run_id).await;
    check_persistent_volumes(&client, &state, run_id).await;
    check_storage(&client, &state, run_id).await;
    check_capacity(&client, &state, run_id).await;
    check_flux(&client, &state, run_id).await;
    check_cert_manager(&client, &state, run_id).await;
    check_kyverno(&client, &state, run_id).await;
    check_velero(&client, &state, run_id).await;
    check_reflector(&client, &state, run_id).await;
    check_argocd(&client, &state, run_id).await;
    check_identity(&client, &state, run_id).await;
    check_k8ssandra(&client, &state, run_id).await;
    check_rbac(&client, &state, run_id).await;
    check_recent_warnings(&client, &state, run_id).await;

    let mut s = state.lock().expect("diagnostic poisoned");
    if s.run_id != run_id {
        return;
    }
    s.running = false;
    s.finished = true;
    s.current_step = None;
    if let Some(t) = s.started_at {
        s.elapsed_ms = Some(t.elapsed().as_millis());
    }
}

// Probe the apiserver health endpoints directly via raw requests (equivalent to `kubectl get --raw`).
async fn check_api_health(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    for path in ["/livez", "/readyz", "/healthz"] {
        let title = format!("API server {}", path);
        let cmd = format!("kubectl get --raw='{}'", path);
        let Some(idx) = push_step(state, run_id, &title, &cmd) else { return; };
        let req = Request::get(path).body(Vec::new()).unwrap();
        let mut lines = Vec::new();
        let (status, body) = match client.request_text(req).await {
            Ok(text) => (DiagStatus::Ok, text),
            Err(e) => (DiagStatus::Err, e.to_string()),
        };
        let snippet: String = body.chars().take(200).collect();
        lines.push((
            match status {
                DiagStatus::Ok => LineColor::Ok,
                _ => LineColor::Err,
            },
            if status == DiagStatus::Ok {
                fill(active().diag_response, &[("body", snippet.trim())])
            } else {
                fill(active().diag_error, &[("e", snippet.trim())])
            },
        ));
        finish_step(state, run_id, idx, status, lines);
    }
}

async fn check_cluster_version(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_version,
        "kubectl get --raw='/version'",
    ) else {
        return;
    };
    let req = Request::get("/version").body(Vec::new()).unwrap();
    let mut lines = Vec::new();
    let status = match client.request_text(req).await {
        Ok(text) => {
            let v: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            let git = v
                .get("gitVersion")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let platform = v
                .get("platform")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let go = v.get("goVersion").and_then(|x| x.as_str()).unwrap_or("?");
            lines.push((LineColor::Ok, format!("kubernetes: {}", git)));
            lines.push((LineColor::Dim, format!("platform: {}, go: {}", platform, go)));
            DiagStatus::Ok
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_nodes(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, "Nodes", "kubectl get nodes") else {
        return;
    };
    let api: Api<Node> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let total = list.items.len();
            let mut not_ready = 0usize;
            let mut pressure = Vec::new();
            let mut unschedulable = 0usize;
            let mut any_issue = false;
            for n in &list.items {
                let name = n.metadata.name.clone().unwrap_or_default();
                let conds = n.status.as_ref().and_then(|s| s.conditions.as_ref());
                let mut ready = false;
                let mut pressure_here: Vec<&str> = Vec::new();
                if let Some(cs) = conds {
                    for c in cs {
                        match c.type_.as_str() {
                            "Ready" => {
                                ready = c.status == "True";
                            }
                            "MemoryPressure" | "DiskPressure" | "PIDPressure"
                            | "NetworkUnavailable"
                                if c.status == "True" =>
                            {
                                pressure_here.push(c.type_.as_str());
                            }
                            _ => {}
                        }
                    }
                }
                if !ready {
                    not_ready += 1;
                    any_issue = true;
                    lines.push((
                        LineColor::Err,
                        format!("{}: NotReady", name),
                    ));
                }
                if !pressure_here.is_empty() {
                    any_issue = true;
                    pressure.push(format!("{}: {}", name, pressure_here.join(",")));
                }
                if n.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false) {
                    unschedulable += 1;
                    any_issue = true;
                    lines.push((
                        LineColor::Warn,
                        fill(active().diag_node_cordoned, &[("name", &name)]),
                    ));
                }
            }
            for p in &pressure {
                lines.push((LineColor::Warn, format!("pressure: {}", p)));
            }
            lines.insert(
                0,
                (
                    if any_issue {
                        LineColor::Warn
                    } else {
                        LineColor::Ok
                    },
                    format!(
                        "{} node(s), notReady={}, unschedulable={}, sous pression={}",
                        total,
                        not_ready,
                        unschedulable,
                        pressure.len()
                    ),
                ),
            );
            if any_issue {
                if not_ready > 0 {
                    DiagStatus::Err
                } else {
                    DiagStatus::Warn
                }
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_system_namespaces(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_system_ns,
        "kubectl get ns",
    ) else {
        return;
    };
    let api: Api<Namespace> = Api::all(client.clone());
    let candidates = [
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "cattle-system",
        "cattle-fleet-system",
        "cattle-fleet-local-system",
        "cattle-impersonation-system",
        "cattle-monitoring-system",
        "cattle-logging-system",
        "kyverno",
        "gatekeeper-system",
        "cert-manager",
        "ingress-nginx",
        "istio-system",
        "linkerd",
        "calico-system",
        "tigera-operator",
        "kube-flannel",
        "cilium",
        "rook-ceph",
        "longhorn-system",
        "openshift-monitoring",
        "monitoring",
    ];
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let names: std::collections::BTreeSet<String> = list
                .items
                .iter()
                .filter_map(|n| n.metadata.name.clone())
                .collect();
            let found: Vec<&&str> = candidates.iter().filter(|c| names.contains(**c)).collect();
            lines.push((
                LineColor::Info,
                fill(active().diag_ns_total, &[("n", &names.len().to_string())]),
            ));
            lines.push((
                LineColor::Plain,
                fill(
                    active().diag_ns_found,
                    &[("list", &found.iter().map(|s| **s).collect::<Vec<_>>().join(", "))],
                ),
            ));
            DiagStatus::Info
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_kube_system_pods(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "Pods kube-system",
        "kubectl -n kube-system get pods",
    ) else {
        return;
    };
    let api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut total = 0usize;
            let mut not_ready = 0usize;
            let mut high_restarts: Vec<(String, i32)> = Vec::new();
            let mut crashloop = 0usize;
            for p in &list.items {
                total += 1;
                let name = p.metadata.name.clone().unwrap_or_default();
                let status = p.status.as_ref();
                let phase = status.and_then(|s| s.phase.clone()).unwrap_or_default();
                let ready = status
                    .and_then(|s| s.container_statuses.as_ref())
                    .map(|cs| cs.iter().all(|c| c.ready))
                    .unwrap_or(false);
                if !ready && phase != "Succeeded" {
                    not_ready += 1;
                    lines.push((LineColor::Warn, format!("{} : phase={} ready=false", name, phase)));
                }
                if let Some(cs) = status.and_then(|s| s.container_statuses.as_ref()) {
                    for c in cs {
                        if c.restart_count >= 3 {
                            high_restarts.push((name.clone(), c.restart_count));
                        }
                        if let Some(w) = &c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                            if w.reason.as_deref() == Some("CrashLoopBackOff") {
                                crashloop += 1;
                            }
                        }
                    }
                }
            }
            high_restarts.sort_by_key(|(_, r)| std::cmp::Reverse(*r));
            high_restarts.truncate(5);
            for (n, r) in &high_restarts {
                lines.push((
                    LineColor::Warn,
                    fill(active().diag_restarts, &[("name", n), ("n", &r.to_string())]),
                ));
            }
            let summary = fill(
                active().diag_pods_summary,
                &[
                    ("total", &total.to_string()),
                    ("notready", &not_ready.to_string()),
                    ("crashloop", &crashloop.to_string()),
                    ("restarts", &high_restarts.len().to_string()),
                ],
            );
            let head = if not_ready > 0 || crashloop > 0 {
                LineColor::Warn
            } else {
                LineColor::Ok
            };
            lines.insert(0, (head, summary));
            if crashloop > 0 || not_ready > 2 {
                DiagStatus::Err
            } else if not_ready > 0 || !high_restarts.is_empty() {
                DiagStatus::Warn
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_dns(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_dns,
        "kubectl -n kube-system get pods -l k8s-app=kube-dns",
    ) else {
        return;
    };
    let api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let lp = ListParams::default().labels("k8s-app=kube-dns");
    let mut lines = Vec::new();
    let status = match api.list(&lp).await {
        Ok(list) => {
            if list.items.is_empty() {
                lines.push((
                    LineColor::Warn,
                    active().diag_no_coredns.into(),
                ));
                DiagStatus::Warn
            } else {
                let mut ready = 0;
                let mut total = 0;
                for p in &list.items {
                    total += 1;
                    let r = p
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                        .map(|cs| cs.iter().all(|c| c.ready))
                        .unwrap_or(false);
                    if r {
                        ready += 1;
                    }
                }
                lines.push((
                    if ready == total {
                        LineColor::Ok
                    } else {
                        LineColor::Warn
                    },
                    fill(active().diag_coredns_ready, &[("ready", &ready.to_string()), ("total", &total.to_string())]),
                ));
                if ready == total {
                    DiagStatus::Ok
                } else {
                    DiagStatus::Warn
                }
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_cni(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "CNI (calico/cilium/flannel)",
        "kubectl get pods -A -l k8s-app in (calico-node,cilium-agent,kube-flannel-ds)",
    ) else {
        return;
    };
    let api: Api<Pod> = Api::all(client.clone());
    let mut lines = Vec::new();
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut found_any = false;
    let queries = [
        ("calico", "k8s-app=calico-node"),
        ("cilium", "k8s-app=cilium"),
        ("flannel", "app=flannel"),
        ("kube-router", "k8s-app=kube-router"),
        ("weave", "name=weave-net"),
    ];
    for (label, sel) in queries {
        let lp = ListParams::default().labels(sel);
        if let Ok(list) = api.list(&lp).await {
            if !list.items.is_empty() {
                found_any = true;
                let mut ready = 0usize;
                let total = list.items.len();
                for p in &list.items {
                    let r = p
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                        .map(|cs| cs.iter().all(|c| c.ready))
                        .unwrap_or(false);
                    if r {
                        ready += 1;
                    }
                }
                counts.insert(label, (ready, total));
            }
        }
    }
    let status = if !found_any {
        lines.push((
            LineColor::Info,
            active().diag_no_cni.into(),
        ));
        DiagStatus::Info
    } else {
        let mut all_ok = true;
        for (k, (ready, total)) in &counts {
            let ok = ready == total;
            if !ok {
                all_ok = false;
            }
            lines.push((
                if ok { LineColor::Ok } else { LineColor::Warn },
                fill(active().diag_cni_ready, &[("name", k), ("ready", &ready.to_string()), ("total", &total.to_string())]),
            ));
        }
        if all_ok {
            DiagStatus::Ok
        } else {
            DiagStatus::Warn
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_validating_webhooks(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "ValidatingWebhookConfigurations",
        "kubectl get validatingwebhookconfigurations",
    ) else {
        return;
    };
    let api: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut total = 0usize;
            let mut fail_close = 0usize;
            for w in &list.items {
                total += 1;
                let name = w.metadata.name.clone().unwrap_or_default();
                if let Some(hooks) = &w.webhooks {
                    let fail = hooks
                        .iter()
                        .any(|h| h.failure_policy.as_deref() == Some("Fail"));
                    if fail {
                        fail_close += 1;
                        let hl = highlight_webhook_owner(&name);
                        lines.push((
                            LineColor::Warn,
                            format!("{} (failurePolicy=Fail){}", name, hl),
                        ));
                    }
                }
            }
            lines.insert(
                0,
                (
                    if fail_close > 0 {
                        LineColor::Warn
                    } else {
                        LineColor::Ok
                    },
                    fill(
                        active().diag_validating_webhooks,
                        &[("total", &total.to_string()), ("closed", &fail_close.to_string())],
                    ),
                ),
            );
            if fail_close > 0 {
                DiagStatus::Warn
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_mutating_webhooks(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "MutatingWebhookConfigurations",
        "kubectl get mutatingwebhookconfigurations",
    ) else {
        return;
    };
    let api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut total = 0usize;
            let mut fail_close = 0usize;
            for w in &list.items {
                total += 1;
                let name = w.metadata.name.clone().unwrap_or_default();
                if let Some(hooks) = &w.webhooks {
                    let fail = hooks
                        .iter()
                        .any(|h| h.failure_policy.as_deref() == Some("Fail"));
                    if fail {
                        fail_close += 1;
                        let hl = highlight_webhook_owner(&name);
                        lines.push((
                            LineColor::Warn,
                            format!("{} (failurePolicy=Fail){}", name, hl),
                        ));
                    }
                }
            }
            lines.insert(
                0,
                (
                    if fail_close > 0 {
                        LineColor::Warn
                    } else {
                        LineColor::Ok
                    },
                    fill(
                        active().diag_mutating_webhooks,
                        &[("total", &total.to_string()), ("closed", &fail_close.to_string())],
                    ),
                ),
            );
            if fail_close > 0 {
                DiagStatus::Warn
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

// Annotate a fail-closed webhook with the product likely behind it, to explain cluster-wide impact.
fn highlight_webhook_owner(name: &str) -> String {
    let n = name.to_lowercase();
    let known = [
        ("kyverno", "policy engine"),
        ("gatekeeper", "OPA"),
        ("cert-manager", "TLS"),
        ("rancher", "rancher webhook"),
        ("istio", "service mesh"),
        ("linkerd", "service mesh"),
        ("vault", "secrets"),
        ("argo", "argo"),
        ("flux", "fluxcd"),
        ("trivy", "image scan"),
    ];
    for (k, label) in known {
        if n.contains(k) {
            return format!(" — {}", label);
        }
    }
    String::new()
}

// Detect how Rancher relates to this cluster (local server, imported via cattle-cluster-agent,
// or fleet-only) and analyze the relevant pod logs to confirm the management tunnel is healthy.
async fn check_rancher(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_rancher,
        "kubectl -n cattle-system get deploy,pods",
    ) else {
        return;
    };
    let mut lines = Vec::new();
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let cattle_present = ns_api.get("cattle-system").await.is_ok();
    let fleet_local_present = ns_api.get("cattle-fleet-local-system").await.is_ok();
    let fleet_present = ns_api.get("cattle-fleet-system").await.is_ok();
    if !cattle_present && !fleet_present && !fleet_local_present {
        lines.push((
            LineColor::Info,
            active().diag_no_cattle.into(),
        ));
        finish_step(state, run_id, idx, DiagStatus::Info, lines);
        return;
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), "cattle-system");
    let local_pods = pods
        .list(&ListParams::default().labels("app=rancher"))
        .await
        .ok();
    let agent_pods = pods
        .list(&ListParams::default().labels("app=cattle-cluster-agent"))
        .await
        .ok();

    let local_total = local_pods.as_ref().map(|l| l.items.len()).unwrap_or(0);
    let agent_total = agent_pods.as_ref().map(|l| l.items.len()).unwrap_or(0);

    let st = active();
    let kind = if local_total > 0 {
        st.diag_rancher_local
    } else if agent_total > 0 {
        st.diag_rancher_imported
    } else if fleet_local_present {
        st.diag_rancher_fleet
    } else {
        st.diag_rancher_neither
    };
    lines.push((LineColor::Info, fill(st.diag_rancher_kind, &[("kind", kind)])));

    let count_ready = |pods: &kube::core::ObjectList<Pod>| -> usize {
        pods.items
            .iter()
            .filter(|p| {
                p.status
                    .as_ref()
                    .and_then(|s| s.container_statuses.as_ref())
                    .map(|cs| !cs.is_empty() && cs.iter().all(|c| c.ready))
                    .unwrap_or(false)
            })
            .count()
    };
    if let Some(list) = &local_pods {
        if !list.items.is_empty() {
            let ready = count_ready(list);
            lines.push((
                if ready == list.items.len() {
                    LineColor::Ok
                } else {
                    LineColor::Warn
                },
                fill(
                    st.diag_rancher_server_ready,
                    &[("ready", &ready.to_string()), ("total", &list.items.len().to_string())],
                ),
            ));
        }
    }
    if let Some(list) = &agent_pods {
        if !list.items.is_empty() {
            let ready = count_ready(list);
            lines.push((
                if ready == list.items.len() {
                    LineColor::Ok
                } else {
                    LineColor::Warn
                },
                fill(
                    st.diag_agent_ready,
                    &[("ready", &ready.to_string()), ("total", &list.items.len().to_string())],
                ),
            ));
        }
    }
    if fleet_present || fleet_local_present {
        let mut bits = Vec::new();
        if fleet_local_present {
            bits.push("cattle-fleet-local-system");
        }
        if fleet_present {
            bits.push("cattle-fleet-system");
        }
        lines.push((LineColor::Plain, format!("fleet: {}", bits.join(", "))));
    }

    let server_url: Option<String> = if local_total > 0 {
        rancher_url_from_setting(client).await
    } else if agent_total > 0 {
        rancher_url_from_agent_deploy(client).await
    } else {
        rancher_url_from_setting(client)
            .await
            .or(rancher_url_from_agent_deploy(client).await)
    };

    if let Some(url) = &server_url {
        let label = if local_total > 0 { "server-url" } else { st.diag_upstream_url };
        lines.push((LineColor::Info, format!("{}: {}", label, url)));
    }

    let status = if agent_total > 0 {
        analyze_agent_logs(client, &mut lines).await
    } else if local_total > 0 {
        analyze_rancher_logs(client, &mut lines).await
    } else {
        lines.push((
            LineColor::Info,
            st.diag_nothing_to_analyse.into(),
        ));
        DiagStatus::Info
    };

    finish_step(state, run_id, idx, status, lines);
}

// Scan the last ~200 lines of cattle-cluster-agent logs and classify failures (DNS/TLS/websocket)
// vs. a healthy tunnel, returning the worst observed severity.
async fn analyze_agent_logs(client: &Client, lines: &mut Vec<(LineColor, String)>) -> DiagStatus {
    let pods: Api<Pod> = Api::namespaced(client.clone(), "cattle-system");
    let list = match pods.list(&ListParams::default().labels("app=cattle-cluster-agent")).await {
        Ok(l) => l.items,
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_list_agent_pods, &[("e", &e.to_string())])));
            return DiagStatus::Err;
        }
    };
    let pod = match list.into_iter().find(|p| {
        p.status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .as_deref()
            == Some("Running")
    }) {
        Some(p) => p,
        None => {
            lines.push((LineColor::Warn, active().diag_no_agent_running.into()));
            return DiagStatus::Warn;
        }
    };
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    lines.push((LineColor::Dim, fill(active().diag_logs_from_pod, &[("name", &pod_name)])));

    let lp = LogParams { tail_lines: Some(200), ..Default::default() };
    let text = match pods.logs(&pod_name, &lp).await {
        Ok(t) => t,
        Err(e) => {
            lines.push((
                LineColor::Err,
                fill(active().diag_logs_failed, &[("name", &pod_name), ("e", &e.to_string())]),
            ));
            return DiagStatus::Err;
        }
    };

    let mut tunnel_ok = false;
    let mut connect_failures: Vec<String> = Vec::new();
    let mut tls_failures: Vec<String> = Vec::new();
    let mut dns_failures: Vec<String> = Vec::new();
    let mut other_errors: Vec<String> = Vec::new();
    let mut last_relevant: Option<String> = None;

    for raw_line in text.lines().rev().take(200) {
        let l = raw_line.trim();
        let lower = l.to_lowercase();
        if lower.contains("connection registered") || lower.contains("session registered")
            || lower.contains("starting agent") || lower.contains("watching metadata")
            || lower.contains("connected to ")
        {
            tunnel_ok = true;
            if last_relevant.is_none() { last_relevant = Some(l.to_string()); }
        }
        if lower.contains("websocket: bad handshake") || lower.contains("error during websocket handshake")
            || lower.contains("websocket close")
        {
            connect_failures.push(l.to_string());
        }
        if lower.contains("x509") || lower.contains("certificate signed by unknown")
            || lower.contains("tls handshake") || lower.contains("certificate has expired")
        {
            tls_failures.push(l.to_string());
        }
        if lower.contains("no such host") || lower.contains("dns lookup") || lower.contains("temporary failure in name resolution") {
            dns_failures.push(l.to_string());
        }
        if (lower.contains("failed to") || lower.contains("error") || lower.contains("dial tcp"))
            && !lower.contains("ignoring") && !lower.contains("retrying")
        {
            other_errors.push(l.to_string());
        }
    }

    let push_some = |lines: &mut Vec<(LineColor, String)>, label: &str, items: &[String], color: LineColor| {
        if items.is_empty() { return; }
        lines.push((color, format!("{} ({})", label, items.len())));
        for it in items.iter().take(3) {
            lines.push((LineColor::Dim, format!("  {}", truncate(it, 200))));
        }
    };

    if tunnel_ok && dns_failures.is_empty() && tls_failures.is_empty() && connect_failures.len() <= 1 {
        lines.push((LineColor::Ok, active().diag_tunnel_ok.into()));
        if let Some(l) = last_relevant {
            lines.push((
                LineColor::Dim,
                fill(active().diag_last_trace, &[("line", &truncate(&l, 200))]),
            ));
        }
        return DiagStatus::Ok;
    }

    let mut worst = DiagStatus::Warn;
    if !dns_failures.is_empty() || !tls_failures.is_empty() {
        worst = DiagStatus::Err;
    }
    if !connect_failures.is_empty() && !tunnel_ok {
        worst = DiagStatus::Err;
    }

    let st = active();
    push_some(lines, st.diag_dns_failures, &dns_failures, LineColor::Err);
    push_some(lines, st.diag_tls_failures, &tls_failures, LineColor::Err);
    push_some(lines, st.diag_ws_failures, &connect_failures, LineColor::Err);
    push_some(lines, st.diag_other_errors, &other_errors, LineColor::Warn);
    if !tunnel_ok && dns_failures.is_empty() && tls_failures.is_empty() && connect_failures.is_empty() && other_errors.is_empty() {
        lines.push((LineColor::Warn, st.diag_no_tunnel_marker.into()));
    }
    worst
}

async fn analyze_rancher_logs(client: &Client, lines: &mut Vec<(LineColor, String)>) -> DiagStatus {
    let pods: Api<Pod> = Api::namespaced(client.clone(), "cattle-system");
    let list = match pods.list(&ListParams::default().labels("app=rancher")).await {
        Ok(l) => l.items,
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_list_rancher_pods, &[("e", &e.to_string())])));
            return DiagStatus::Err;
        }
    };
    let pod = match list.into_iter().find(|p| {
        p.status.as_ref().and_then(|s| s.phase.clone()).as_deref() == Some("Running")
    }) {
        Some(p) => p,
        None => {
            lines.push((LineColor::Warn, active().diag_no_rancher_running.into()));
            return DiagStatus::Warn;
        }
    };
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    lines.push((LineColor::Dim, fill(active().diag_logs_from_pod, &[("name", &pod_name)])));

    let lp = LogParams { tail_lines: Some(150), ..Default::default() };
    let text = match pods.logs(&pod_name, &lp).await {
        Ok(t) => t,
        Err(e) => {
            lines.push((
                LineColor::Err,
                fill(active().diag_logs_failed, &[("name", &pod_name), ("e", &e.to_string())]),
            ));
            return DiagStatus::Err;
        }
    };

    let mut errors: Vec<String> = Vec::new();
    let mut serving_ok = false;
    for l in text.lines().rev().take(150) {
        let lower = l.to_lowercase();
        if lower.contains("rancher startup complete") || lower.contains("starting catalog controller")
            || lower.contains("listening on :443")
        {
            serving_ok = true;
        }
        if lower.contains("error") || lower.contains("panic") {
            errors.push(l.to_string());
        }
    }
    if serving_ok && errors.len() <= 2 {
        lines.push((LineColor::Ok, active().diag_rancher_serving.into()));
        return DiagStatus::Ok;
    }
    if !errors.is_empty() {
        lines.push((
            LineColor::Warn,
            fill(active().diag_rancher_errors, &[("n", &errors.len().to_string())]),
        ));
        for e in errors.iter().take(3) {
            lines.push((LineColor::Dim, format!("  {}", truncate(e, 200))));
        }
    }
    if !serving_ok {
        lines.push((LineColor::Warn, active().diag_no_rancher_start.into()));
    }
    DiagStatus::Warn
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

async fn rancher_url_from_setting(client: &Client) -> Option<String> {
    let gvk = GroupVersionKind::gvk("management.cattle.io", "v3", "Setting");
    let (ar, _) = discovery::pinned_kind(client, &gvk).await.ok()?;
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    let s = api.get("server-url").await.ok()?;
    let v = s.data.get("value").and_then(|x| x.as_str())?.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

async fn rancher_url_from_agent_deploy(client: &Client) -> Option<String> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), "cattle-system");
    let dep = api.get("cattle-cluster-agent").await.ok()?;
    let containers = dep
        .spec?
        .template
        .spec?
        .containers;
    for c in containers {
        if let Some(envs) = c.env {
            for e in envs {
                if e.name == "CATTLE_SERVER" {
                    if let Some(v) = e.value {
                        let v = v.trim().to_string();
                        if !v.is_empty() {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    None
}


async fn check_problem_pods(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_failing_pods,
        "kubectl get pods -A",
    ) else {
        return;
    };
    let api: Api<Pod> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut crashloop: Vec<String> = Vec::new();
            let mut imagepull: Vec<String> = Vec::new();
            let mut pending: Vec<String> = Vec::new();
            let mut oom: Vec<String> = Vec::new();
            let total = list.items.len();
            for p in &list.items {
                let ns = p.metadata.namespace.clone().unwrap_or_default();
                let name = p.metadata.name.clone().unwrap_or_default();
                let st = p.status.as_ref();
                let phase = st.and_then(|s| s.phase.clone()).unwrap_or_default();
                if phase == "Pending" {
                    pending.push(format!("{}/{}", ns, name));
                }
                if let Some(cs) = st.and_then(|s| s.container_statuses.as_ref()) {
                    for c in cs {
                        if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                            match w.reason.as_deref() {
                                Some("CrashLoopBackOff") => crashloop.push(format!("{}/{}", ns, name)),
                                Some("ImagePullBackOff") | Some("ErrImagePull") => {
                                    imagepull.push(format!("{}/{}", ns, name))
                                }
                                _ => {}
                            }
                        }
                        if let Some(t) = c.last_state.as_ref().and_then(|s| s.terminated.as_ref()) {
                            if t.reason.as_deref() == Some("OOMKilled") {
                                oom.push(format!("{}/{}", ns, name));
                            }
                        }
                    }
                }
            }
            crashloop.sort();
            crashloop.dedup();
            imagepull.sort();
            imagepull.dedup();
            pending.sort();
            pending.dedup();
            oom.sort();
            oom.dedup();
            lines.push((
                LineColor::Info,
                fill(active().diag_pods_total, &[("n", &total.to_string())]),
            ));
            push_problem_list(&mut lines, "CrashLoopBackOff", &crashloop, LineColor::Err);
            push_problem_list(&mut lines, "ImagePullBackOff", &imagepull, LineColor::Err);
            push_problem_list(&mut lines, "Pending", &pending, LineColor::Warn);
            push_problem_list(&mut lines, "OOMKilled (last)", &oom, LineColor::Warn);
            if !crashloop.is_empty() || !imagepull.is_empty() {
                DiagStatus::Err
            } else if !pending.is_empty() || !oom.is_empty() {
                DiagStatus::Warn
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

fn push_problem_list(lines: &mut Vec<(LineColor, String)>, label: &str, items: &[String], color: LineColor) {
    if items.is_empty() {
        return;
    }
    lines.push((color, format!("{}: {}", label, items.len())));
    for it in items.iter().take(8) {
        lines.push((LineColor::Dim, format!("  - {}", it)));
    }
    if items.len() > 8 {
        lines.push((
            LineColor::Dim,
            fill(active().diag_more_items, &[("n", &(items.len() - 8).to_string())]),
        ));
    }
}

async fn check_persistent_volumes(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, "Persistent Volumes", "kubectl get pv") else {
        return;
    };
    let api: Api<PersistentVolume> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            let mut failed = Vec::new();
            for v in &list.items {
                let phase = v
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                *counts.entry(phase.clone()).or_insert(0) += 1;
                if phase == "Failed" {
                    failed.push(v.metadata.name.clone().unwrap_or_default());
                }
            }
            let summary = counts
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(" ");
            let head = if !failed.is_empty() {
                LineColor::Err
            } else {
                LineColor::Ok
            };
            lines.push((
                head,
                fill(
                    active().diag_pv_summary,
                    &[("n", &list.items.len().to_string()), ("summary", &summary)],
                ),
            ));
            for f in &failed {
                lines.push((LineColor::Err, format!("Failed: {}", f)));
            }
            if !failed.is_empty() {
                DiagStatus::Err
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_recent_warnings(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_warnings,
        "kubectl get events -A --field-selector type=Warning",
    ) else {
        return;
    };
    let api: Api<K8sEvent> = Api::all(client.clone());
    let mut lines = Vec::new();
    let status = match api
        .list(&ListParams::default().fields("type=Warning"))
        .await
    {
        Ok(list) => {
            let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
            for e in &list.items {
                let reason = e.reason.clone().unwrap_or_else(|| "?".to_string());
                *by_reason.entry(reason).or_insert(0) += 1;
            }
            let total = list.items.len();
            lines.push((
                if total == 0 {
                    LineColor::Ok
                } else {
                    LineColor::Warn
                },
                fill(active().diag_warning_count, &[("n", &total.to_string())]),
            ));
            let mut sorted: Vec<(String, usize)> = by_reason.into_iter().collect();
            sorted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            for (reason, n) in sorted.into_iter().take(8) {
                lines.push((LineColor::Plain, format!("{:>4} × {}", n, reason)));
            }
            if total > 0 {
                DiagStatus::Warn
            } else {
                DiagStatus::Ok
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, fill(active().diag_error, &[("e", &e.to_string())])));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

// The worst of two statuses, so a step's headline reflects its most severe finding.
fn worse(a: DiagStatus, b: DiagStatus) -> DiagStatus {
    fn rank(s: DiagStatus) -> u8 {
        match s {
            DiagStatus::Ok => 0,
            DiagStatus::Running | DiagStatus::Info => 1,
            DiagStatus::Warn => 2,
            DiagStatus::Err => 3,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

// Render a storage-family hint (shared by storage, velero and capacity) and fold its level into the
// running step status, so the modules' own verdicts drive the diagnostic instead of being re-derived.
fn push_storage_hints(
    lines: &mut Vec<(LineColor, String)>,
    hints: &[crate::storage::Hint],
    status: &mut DiagStatus,
) {
    use crate::storage::HintLevel;
    for h in hints {
        let (color, sev) = match h.level {
            HintLevel::Info => (LineColor::Info, DiagStatus::Info),
            HintLevel::Warn => (LineColor::Warn, DiagStatus::Warn),
            HintLevel::Danger => (LineColor::Err, DiagStatus::Err),
        };
        lines.push((color, h.text.clone()));
        *status = worse(*status, sev);
    }
}

fn push_reflector_hints(
    lines: &mut Vec<(LineColor, String)>,
    hints: &[crate::reflector::Hint],
    status: &mut DiagStatus,
) {
    use crate::reflector::HintLevel;
    for h in hints {
        let (color, sev) = match h.level {
            HintLevel::Info => (LineColor::Info, DiagStatus::Info),
            HintLevel::Warn => (LineColor::Warn, DiagStatus::Warn),
            HintLevel::Danger => (LineColor::Err, DiagStatus::Err),
        };
        lines.push((color, h.text.clone()));
        *status = worse(*status, sev);
    }
}

async fn check_storage(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_storage, "kubectl get pvc,pv,sc -A") else {
        return;
    };
    let store = new_storage_state();
    fetch_storage(client.clone(), None, store.clone()).await;
    let s = store.lock().expect("storage poisoned");
    let mut lines = Vec::new();
    let status = if let Some(e) = &s.error {
        lines.push((LineColor::Err, fill(active().diag_error, &[("e", e)])));
        DiagStatus::Err
    } else {
        let mut status = DiagStatus::Ok;
        let pending = s.pvcs.iter().filter(|p| p.phase == "Pending").count();
        lines.push((
            LineColor::Info,
            fill(
                active().diag_storage_summary,
                &[
                    ("pvcs", &s.pvcs.len().to_string()),
                    ("pvs", &s.pvs.len().to_string()),
                    ("classes", &s.classes.len().to_string()),
                ],
            ),
        ));
        status = worse(status, DiagStatus::Info);
        if s.released_bytes > 0 {
            lines.push((
                LineColor::Warn,
                fill(
                    active().diag_storage_released,
                    &[("size", &crate::events::format_memory_bytes(s.released_bytes))],
                ),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        for p in s.pvcs.iter().filter(|p| p.phase == "Pending").take(6) {
            lines.push((LineColor::Warn, format!("PVC Pending: {}/{}", p.namespace, p.name)));
        }
        if pending > 6 {
            lines.push((
                LineColor::Dim,
                fill(active().diag_more_items, &[("n", &(pending - 6).to_string())]),
            ));
        }
        if pending > 0 {
            status = worse(status, DiagStatus::Warn);
        }
        push_storage_hints(&mut lines, &s.cluster_hints, &mut status);
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_capacity(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_capacity, "kubectl get nodes,resourcequota -A") else {
        return;
    };
    let cap = new_capacity_state();
    fetch_capacity(client.clone(), cap.clone()).await;
    let s = cap.lock().expect("capacity poisoned");
    let mut lines = Vec::new();
    let status = if let Some(e) = &s.error {
        lines.push((LineColor::Err, fill(active().diag_error, &[("e", e)])));
        DiagStatus::Err
    } else {
        let mut status = DiagStatus::Info;
        let tight = s.quotas.iter().filter(|q| q.worst_pct() >= 90).count();
        lines.push((
            if tight > 0 { LineColor::Warn } else { LineColor::Info },
            fill(
                active().diag_capacity_summary,
                &[("nodes", &s.nodes.len().to_string()), ("quotas", &tight.to_string())],
            ),
        ));
        for q in s.quotas.iter().filter(|q| q.worst_pct() >= 90).take(6) {
            lines.push((
                if q.worst_pct() >= 100 { LineColor::Err } else { LineColor::Warn },
                format!("{}/{}: {}%", q.namespace, q.name, q.worst_pct()),
            ));
            status = worse(status, if q.worst_pct() >= 100 { DiagStatus::Err } else { DiagStatus::Warn });
        }
        push_storage_hints(&mut lines, &s.cluster_hints, &mut status);
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_flux(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_flux,
        "kubectl get kustomizations,helmreleases,gitrepositories -A",
    ) else {
        return;
    };
    let fx = new_flux_state();
    fetch_flux(client.clone(), fx.clone()).await;
    let s = fx.lock().expect("flux poisoned");
    let mut lines = Vec::new();
    let status = if s.resources.is_empty() {
        lines.push((LineColor::Info, active().diag_flux_absent.into()));
        DiagStatus::Info
    } else {
        let (ready, failed, unknown, suspended, reconciling) = s.counts();
        lines.push((
            if failed > 0 {
                LineColor::Err
            } else if unknown > 0 {
                LineColor::Warn
            } else {
                LineColor::Ok
            },
            fill(
                active().diag_flux_summary,
                &[
                    ("total", &s.resources.len().to_string()),
                    ("failed", &failed.to_string()),
                    ("suspended", &suspended.to_string()),
                    ("reconciling", &reconciling.to_string()),
                    ("ready", &ready.to_string()),
                ],
            ),
        ));
        for r in s.resources.iter().filter(|r| !r.suspended && r.ready == FluxReady::Failed).take(8) {
            lines.push((
                LineColor::Err,
                format!("{} {}/{}: {}", r.kind, r.namespace, r.name, truncate(&r.message, 160)),
            ));
        }
        if failed > 0 {
            DiagStatus::Err
        } else if unknown > 0 {
            DiagStatus::Warn
        } else {
            DiagStatus::Ok
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_cert_manager(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_certs, "kubectl get certificates -A") else {
        return;
    };
    let cs = new_certs_state();
    fetch_certs(client.clone(), cs.clone()).await;
    let s = cs.lock().expect("certs poisoned");
    let mut lines = Vec::new();
    let status = if !s.installed {
        lines.push((LineColor::Info, active().diag_certs_absent.into()));
        DiagStatus::Info
    } else {
        let (total, ready, failed, inflight, expiring) = s.counts();
        lines.push((
            if failed > 0 {
                LineColor::Err
            } else if expiring > 0 {
                LineColor::Warn
            } else {
                LineColor::Ok
            },
            fill(
                active().diag_certs_summary,
                &[
                    ("total", &total.to_string()),
                    ("failed", &failed.to_string()),
                    ("inflight", &inflight.to_string()),
                    ("expiring", &expiring.to_string()),
                    ("ready", &ready.to_string()),
                ],
            ),
        ));
        for r in s
            .resources
            .iter()
            .filter(|r| r.kind == CmKind::Certificate && r.ready == CmReady::Failed)
            .take(8)
        {
            lines.push((
                LineColor::Err,
                format!("{}/{}: {}", r.namespace, r.name, truncate(&r.message, 160)),
            ));
        }
        if failed > 0 {
            DiagStatus::Err
        } else if expiring > 0 {
            DiagStatus::Warn
        } else {
            DiagStatus::Ok
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_kyverno(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_kyverno, "kubectl get clusterpolicies,polr -A") else {
        return;
    };
    let ky = new_kyverno_state();
    fetch_kyverno(client.clone(), ky.clone()).await;
    let s = ky.lock().expect("kyverno poisoned");
    let mut lines = Vec::new();
    let status = if !s.installed {
        lines.push((LineColor::Info, active().diag_kyverno_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Ok;
        let (policies, enforcing, _notready, fail, warn, error) = s.counts();
        lines.push((
            if fail > 0 || error > 0 {
                LineColor::Warn
            } else {
                LineColor::Ok
            },
            fill(
                active().diag_kyverno_summary,
                &[
                    ("policies", &policies.to_string()),
                    ("enforcing", &enforcing.to_string()),
                    ("fail", &fail.to_string()),
                    ("warn", &warn.to_string()),
                    ("error", &error.to_string()),
                ],
            ),
        ));
        status = worse(status, DiagStatus::Info);
        if fail > 0 || error > 0 {
            status = worse(status, DiagStatus::Warn);
        }
        if !s.health.controllers_ok() {
            lines.push((LineColor::Err, active().diag_kyverno_ctrl_down.into()));
            status = worse(status, DiagStatus::Err);
        }
        if s.health.silently_inactive() {
            lines.push((LineColor::Warn, active().diag_kyverno_silent.into()));
            status = worse(status, DiagStatus::Warn);
        }
        if s.backlog.stuck() > 0 {
            lines.push((
                if s.backlog.has_pileup() { LineColor::Err } else { LineColor::Warn },
                fill(
                    active().diag_kyverno_backlog,
                    &[
                        ("stuck", &s.backlog.stuck().to_string()),
                        ("pending", &s.backlog.pending.to_string()),
                        ("failed", &s.backlog.failed.to_string()),
                    ],
                ),
            ));
            status = worse(status, if s.backlog.has_pileup() { DiagStatus::Err } else { DiagStatus::Warn });
            if let Some(age) = &s.backlog.oldest_stuck {
                lines.push((LineColor::Dim, fill(active().diag_kyverno_oldest, &[("age", age)])));
            }
        } else if s.backlog.known {
            lines.push((
                LineColor::Ok,
                fill(active().diag_kyverno_ur_ok, &[("total", &s.backlog.total.to_string())]),
            ));
        }
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_velero(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_velero, "kubectl get backups,schedules -A") else {
        return;
    };
    let vel = new_velero_state();
    fetch_velero(client.clone(), vel.clone()).await;
    let s = vel.lock().expect("velero poisoned");
    let mut lines = Vec::new();
    let status = if !s.installed {
        lines.push((LineColor::Info, active().diag_velero_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Info;
        let problems = s.problems();
        lines.push((
            if problems > 0 { LineColor::Warn } else { LineColor::Ok },
            fill(
                active().diag_velero_summary,
                &[
                    ("schedules", &s.schedules.len().to_string()),
                    ("backups", &s.backups.len().to_string()),
                    ("restores", &s.restores.len().to_string()),
                    ("problems", &problems.to_string()),
                ],
            ),
        ));
        if !s.server.running() {
            lines.push((LineColor::Err, active().diag_velero_server_down.into()));
            status = worse(status, DiagStatus::Err);
        }
        match s.last_success {
            Some(ts) => {
                let now = chrono::Utc::now().timestamp();
                lines.push((
                    LineColor::Ok,
                    fill(active().diag_velero_last_success, &[("age", &age_of(ts, now))]),
                ));
            }
            None => {
                lines.push((LineColor::Warn, active().diag_velero_no_success.into()));
                status = worse(status, DiagStatus::Warn);
            }
        }
        for b in s.backups.iter().filter(|b| b.failed() || b.partially_failed()).take(6) {
            lines.push((LineColor::Err, format!("{}/{}: {}", b.namespace, b.name, b.phase)));
            status = worse(status, DiagStatus::Err);
        }
        if !s.uncovered.is_empty() {
            lines.push((
                LineColor::Warn,
                fill(active().diag_velero_uncovered, &[("n", &s.uncovered.len().to_string())]),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        push_storage_hints(&mut lines, &s.cluster_hints, &mut status);
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

// Cassandra's own question, which no other step asks: is anything restorable. A cluster whose
// schedules all fire on time and whose runs all fail reads as healthy everywhere else.
async fn check_k8ssandra(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_k8ssandra, "kubectl get k8ssandraclusters,medusabackupjobs -A") else {
        return;
    };
    let k8c = new_k8c_state();
    fetch_k8ssandra(client.clone(), k8c.clone()).await;
    let s = k8c.lock().expect("k8ssandra poisoned");
    let mut lines = Vec::new();
    let status = if !s.installed {
        // Absence is never a fault: most clusters do not run k8ssandra.
        lines.push((LineColor::Info, active().diag_k8ssandra_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Info;
        let problems = s.problems();
        lines.push((
            if problems > 0 { LineColor::Warn } else { LineColor::Ok },
            fill(
                active().diag_k8ssandra_summary,
                &[
                    ("clusters", &s.clusters.len().to_string()),
                    ("nodes", &s.nodes.len().to_string()),
                    ("backups", &s.jobs.len().to_string()),
                    ("problems", &problems.to_string()),
                ],
            ),
        ));
        match s.last_restorable {
            Some(ts) => {
                let now = chrono::Utc::now().timestamp();
                lines.push((
                    LineColor::Ok,
                    fill(active().diag_k8ssandra_last_backup, &[("age", &age_of(ts, now))]),
                ));
            }
            // Not a warning: a database with no restore point is the worst state this step can find.
            None if !s.schedules.is_empty() => {
                lines.push((LineColor::Err, active().diag_k8ssandra_no_backup.into()));
                status = worse(status, DiagStatus::Err);
            }
            None => {}
        }
        for d in s.datacenters.iter().filter(|d| d.stopped || !d.ready()).take(6) {
            lines.push((LineColor::Err, format!("{}/{}", d.namespace, d.name)));
            status = worse(status, DiagStatus::Err);
        }
        for n in s.nodes.iter().filter(|n| !n.ready).take(6) {
            lines.push((LineColor::Err, format!("{}/{}", n.namespace, n.name)));
            status = worse(status, DiagStatus::Err);
        }
        // The schedules whose every recent run failed: the finding this whole view exists for.
        for sched in s
            .schedules
            .iter()
            .filter(|x| x.hints.iter().any(|h| h.level >= crate::k8ssandra::HintLevel::Danger))
            .take(6)
        {
            lines.push((LineColor::Err, format!("{}/{}", sched.namespace, sched.name)));
            status = worse(status, DiagStatus::Err);
        }
        push_storage_hints(&mut lines, &s.cluster_hints, &mut status);
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_reflector(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_reflector, "kubectl get deploy -A -l app.kubernetes.io/name=reflector") else {
        return;
    };
    let refl = new_reflector_state();
    fetch_reflector(client.clone(), refl.clone()).await;
    let s = refl.lock().expect("reflector poisoned");
    let mut lines = Vec::new();
    let status = if s.controller_present == Some(false) && s.sources.is_empty() && s.orphans.is_empty() {
        lines.push((LineColor::Info, active().diag_reflector_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Info;
        let (sources, mirrors, problems) = s.summary();
        lines.push((
            if problems > 0 { LineColor::Warn } else { LineColor::Ok },
            fill(
                active().diag_reflector_summary,
                &[
                    ("sources", &sources.to_string()),
                    ("mirrors", &mirrors.to_string()),
                    ("problems", &problems.to_string()),
                ],
            ),
        ));
        push_reflector_hints(&mut lines, &s.cluster_hints, &mut status);
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_argocd(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_argocd, "kubectl get applications.argoproj.io -A") else {
        return;
    };
    let argo = new_argo_state();
    fetch_argocd(client.clone(), argo.clone()).await;
    let s = argo.lock().expect("argocd poisoned");
    let mut lines = Vec::new();
    let status = if !s.server.present {
        lines.push((LineColor::Info, active().diag_argocd_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Info;
        let blind = s.blind();
        let oos = s.out_of_sync();
        let bad = s.unhealthy();
        lines.push((
            if blind > 0 || bad > 0 {
                LineColor::Warn
            } else if oos > 0 {
                LineColor::Info
            } else {
                LineColor::Ok
            },
            fill(
                active().diag_argocd_summary,
                &[
                    ("apps", &s.apps.len().to_string()),
                    ("oos", &oos.to_string()),
                    ("blind", &blind.to_string()),
                    ("bad", &bad.to_string()),
                ],
            ),
        ));
        push_storage_hints(&mut lines, &s.server.hints, &mut status);
        // The Applications nobody can vouch for come first: an OutOfSync row is a known gap, a row
        // whose comparison failed is a row whose green columns were computed before the failure.
        for a in s.apps.iter().filter(|a| a.comparison_broken()).take(8) {
            lines.push((
                LineColor::Warn,
                format!("{}/{}: sync {} · health {}", a.namespace, a.name, a.sync, a.health),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        for a in s
            .apps
            .iter()
            .filter(|a| a.health == "Degraded" || matches!(a.op_phase.as_str(), "Failed" | "Error"))
            .take(8)
        {
            lines.push((
                LineColor::Err,
                format!(
                    "{}/{}: health {} · operation {}",
                    a.namespace, a.name, a.health, a.op_phase
                ),
            ));
            status = worse(status, DiagStatus::Err);
        }
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

// kdt-identity, through the very fetch the view uses: a second set of queries here would be a
// second thing to keep true.
//
// The finding worth the step is the one nothing else surfaces: a group nobody bound. Its members
// authenticate and then get 403 everywhere, and every object involved reconciles perfectly.
async fn check_identity(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        active().diag_step_identity,
        "kubectl get kdtusers,kdtgroups",
    ) else {
        return;
    };
    let ident = new_identity_state();
    fetch_identity(client.clone(), ident.clone()).await;
    let s = ident.lock().expect("identity poisoned");
    let mut lines = Vec::new();
    let status = if !s.installed {
        // Absence is not a problem to report: most clusters have no local accounts at all.
        lines.push((LineColor::Info, active().diag_identity_absent.into()));
        DiagStatus::Info
    } else {
        let mut status = DiagStatus::Info;
        let unbound = s.unbound_groups();
        let locked = s.users.iter().filter(|u| u.phase == Phase::Locked).count();
        lines.push((
            if unbound > 0 { LineColor::Warn } else { LineColor::Ok },
            fill(
                active().diag_identity_summary,
                &[
                    ("users", &s.users.len().to_string()),
                    ("active", &s.active_users().to_string()),
                    ("groups", &s.groups.len().to_string()),
                    ("unbound", &unbound.to_string()),
                ],
            ),
        ));
        if locked > 0 {
            lines.push((
                LineColor::Warn,
                fill(active().diag_identity_locked, &[("n", &locked.to_string())]),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        for g in s.groups.iter().filter(|g| g.bindings.is_empty()).take(8) {
            lines.push((
                LineColor::Warn,
                fill(
                    active().diag_identity_unbound,
                    &[("group", &g.name), ("subject", &g.effective_subject())],
                ),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        for g in s.groups.iter().filter(|g| !g.unknown.is_empty()).take(8) {
            lines.push((
                LineColor::Warn,
                fill(
                    active().diag_identity_unknown,
                    &[("group", &g.name), ("members", &g.unknown.join(", "))],
                ),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        // Sessions still open on a disabled account: since 1.0 the controller closes them itself,
        // so finding them says it is not reconciling — and the person is still renewing access.
        let stuck: Vec<&str> = s
            .users
            .iter()
            .filter(|u| u.disabled && u.sessions.as_ref().is_some_and(|x| x.open > 0))
            .map(|u| u.name.as_str())
            .take(8)
            .collect();
        if !stuck.is_empty() {
            lines.push((
                LineColor::Warn,
                fill(active().diag_identity_stuck_sessions, &[("users", &stuck.join(", "))]),
            ));
            status = worse(status, DiagStatus::Warn);
        }
        // The one access revocation cannot reach. Stated once for the cluster, and only as Info:
        // it is the chart's default and a deliberate trade, not a fault — but it is the fact that
        // decides whether "sessions closed" means the person is actually out.
        if s.delivery.download_open() {
            lines.push((LineColor::Info, active().diag_identity_download.into()));
        }
        status
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_rbac(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(state, run_id, active().diag_step_rbac, "kubectl get clusterrolebindings,rolebindings -A") else {
        return;
    };
    let rb = new_rbac_state();
    fetch_rbac(client.clone(), critical_namespaces(&[]), rb.clone()).await;
    let s = rb.lock().expect("rbac poisoned");
    let mut lines = Vec::new();
    let status = if let Some(e) = &s.error {
        lines.push((LineColor::Err, fill(active().diag_error, &[("e", e)])));
        DiagStatus::Err
    } else {
        let crit = s.bindings.iter().filter(|b| b.severity == Severity::Critical).count();
        let high = s.bindings.iter().filter(|b| b.severity == Severity::High).count();
        lines.push((
            if crit > 0 {
                LineColor::Err
            } else if high > 0 {
                LineColor::Warn
            } else {
                LineColor::Ok
            },
            fill(
                active().diag_rbac_summary,
                &[
                    ("bindings", &s.bindings.len().to_string()),
                    ("roles", &s.roles.len().to_string()),
                    ("crit", &crit.to_string()),
                    ("high", &high.to_string()),
                ],
            ),
        ));
        for b in s
            .bindings
            .iter()
            .filter(|b| b.severity == Severity::Critical)
            .take(8)
        {
            lines.push((
                LineColor::Err,
                format!("{} {}: {}", b.binding_kind, b.binding_name, b.role_ref.label()),
            ));
        }
        if crit > 0 {
            DiagStatus::Err
        } else if high > 0 {
            DiagStatus::Warn
        } else {
            DiagStatus::Ok
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

// Flatten the diagnostic steps into a plain-text block suitable for the AI prompt or clipboard.
pub fn format_diagnostic_for_ai(state: &DiagnosticState) -> String {
    let mut out = String::new();
    out.push_str(active().diag_ai_header);
    if let Some(ms) = state.elapsed_ms {
        out.push_str(&fill(
            active().diag_ai_duration,
            &[("ms", &ms.to_string()), ("n", &state.steps.len().to_string())],
        ));
    }
    for s in &state.steps {
        out.push_str(&format!(
            "\n[{}] {} ({})\n  $ {}\n",
            s.status.label(),
            s.title,
            match s.status {
                DiagStatus::Ok => "ok",
                DiagStatus::Info => "info",
                DiagStatus::Warn => "warn",
                DiagStatus::Err => "err",
                DiagStatus::Running => "running",
            },
            s.command,
        ));
        for (_, l) in &s.lines {
            out.push_str(&format!("  {}\n", l));
        }
    }
    out
}
