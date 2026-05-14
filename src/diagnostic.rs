use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use http::Request;
use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Event as K8sEvent, Namespace, Node, PersistentVolume, Pod};
use kube::api::{DynamicObject, ListParams, LogParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Api, Client};

use crate::events::LineColor;

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
                format!("réponse: {}", snippet.trim())
            } else {
                format!("erreur: {}", snippet.trim())
            },
        ));
        finish_step(state, run_id, idx, status, lines);
    }
}

async fn check_cluster_version(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "Version cluster",
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
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
                            | "NetworkUnavailable" => {
                                if c.status == "True" {
                                    pressure_here.push(c.type_.as_str());
                                }
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
                    lines.push((LineColor::Warn, format!("{}: cordonné (unschedulable)", name)));
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_system_namespaces(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "Namespaces système présents",
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
                format!("namespaces totaux: {}", names.len()),
            ));
            lines.push((
                LineColor::Plain,
                format!(
                    "détectés: {}",
                    found.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
                ),
            ));
            DiagStatus::Info
        }
        Err(e) => {
            lines.push((LineColor::Err, format!("erreur: {}", e)));
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
            high_restarts.sort_by(|a, b| b.1.cmp(&a.1));
            high_restarts.truncate(5);
            for (n, r) in &high_restarts {
                lines.push((LineColor::Warn, format!("{} : restarts={}", n, r)));
            }
            let summary = format!(
                "{} pods, notReady={}, crashloop={}, top-restarts={}",
                total,
                not_ready,
                crashloop,
                high_restarts.len()
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_dns(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "DNS cluster (CoreDNS)",
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
                    "aucun pod label k8s-app=kube-dns trouvé".into(),
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
                    format!("{}/{} pods CoreDNS prêts", ready, total),
                ));
                if ready == total {
                    DiagStatus::Ok
                } else {
                    DiagStatus::Warn
                }
            }
        }
        Err(e) => {
            lines.push((LineColor::Err, format!("erreur: {}", e)));
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
            "aucun CNI commun détecté via labels (peut être managé hors cluster)".into(),
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
                format!("{}: {}/{} pods prêts", k, ready, total),
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
                    format!(
                        "{} webhooks de validation, dont {} en fail-close (impact sur cluster si KO)",
                        total, fail_close
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
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
                    format!(
                        "{} webhooks mutants, dont {} en fail-close",
                        total, fail_close
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

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

async fn check_rancher(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "Rancher (local ou cluster importé)",
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
            "aucun namespace cattle-* — cluster non lié à rancher".into(),
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

    let kind = if local_total > 0 {
        "rancher local (server installé sur ce cluster)"
    } else if agent_total > 0 {
        "cluster importé (piloté par rancher externe)"
    } else if fleet_local_present {
        "cluster local fleet (sans server rancher dans cattle-system)"
    } else {
        "cattle-* présent mais ni server rancher ni cattle-cluster-agent"
    };
    lines.push((LineColor::Info, format!("type détecté: {}", kind)));

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
                format!("rancher server pods: {}/{} prêts", ready, list.items.len()),
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
                format!(
                    "cattle-cluster-agent: {}/{} prêts",
                    ready,
                    list.items.len()
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
        let label = if local_total > 0 { "server-url" } else { "URL upstream rancher (CATTLE_SERVER)" };
        lines.push((LineColor::Info, format!("{}: {}", label, url)));
    }

    let status = if agent_total > 0 {
        analyze_agent_logs(client, &mut lines).await
    } else if local_total > 0 {
        analyze_rancher_logs(client, &mut lines).await
    } else {
        lines.push((
            LineColor::Info,
            "ni server rancher ni cattle-cluster-agent — rien à analyser".into(),
        ));
        DiagStatus::Info
    };

    finish_step(state, run_id, idx, status, lines);
}

async fn analyze_agent_logs(client: &Client, lines: &mut Vec<(LineColor, String)>) -> DiagStatus {
    let pods: Api<Pod> = Api::namespaced(client.clone(), "cattle-system");
    let list = match pods.list(&ListParams::default().labels("app=cattle-cluster-agent")).await {
        Ok(l) => l.items,
        Err(e) => {
            lines.push((LineColor::Err, format!("liste pods agent: {}", e)));
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
            lines.push((LineColor::Warn, "aucun pod cattle-cluster-agent en Running".into()));
            return DiagStatus::Warn;
        }
    };
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    lines.push((LineColor::Dim, format!("logs lus sur pod: {}", pod_name)));

    let lp = LogParams { tail_lines: Some(200), ..Default::default() };
    let text = match pods.logs(&pod_name, &lp).await {
        Ok(t) => t,
        Err(e) => {
            lines.push((LineColor::Err, format!("kubectl logs {} échoue: {}", pod_name, e)));
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
        lines.push((LineColor::Ok, "tunnel cattle-cluster-agent → rancher: établi".into()));
        if let Some(l) = last_relevant {
            lines.push((LineColor::Dim, format!("  dernière trace utile: {}", truncate(&l, 200))));
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

    push_some(lines, "DNS échec", &dns_failures, LineColor::Err);
    push_some(lines, "TLS échec", &tls_failures, LineColor::Err);
    push_some(lines, "websocket échec", &connect_failures, LineColor::Err);
    push_some(lines, "autres erreurs", &other_errors, LineColor::Warn);
    if !tunnel_ok && dns_failures.is_empty() && tls_failures.is_empty() && connect_failures.is_empty() && other_errors.is_empty() {
        lines.push((LineColor::Warn, "aucun marqueur clair de tunnel établi dans les 200 dernières lignes".into()));
    }
    worst
}

async fn analyze_rancher_logs(client: &Client, lines: &mut Vec<(LineColor, String)>) -> DiagStatus {
    let pods: Api<Pod> = Api::namespaced(client.clone(), "cattle-system");
    let list = match pods.list(&ListParams::default().labels("app=rancher")).await {
        Ok(l) => l.items,
        Err(e) => {
            lines.push((LineColor::Err, format!("liste pods rancher: {}", e)));
            return DiagStatus::Err;
        }
    };
    let pod = match list.into_iter().find(|p| {
        p.status.as_ref().and_then(|s| s.phase.clone()).as_deref() == Some("Running")
    }) {
        Some(p) => p,
        None => {
            lines.push((LineColor::Warn, "aucun pod rancher en Running".into()));
            return DiagStatus::Warn;
        }
    };
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    lines.push((LineColor::Dim, format!("logs lus sur pod: {}", pod_name)));

    let lp = LogParams { tail_lines: Some(150), ..Default::default() };
    let text = match pods.logs(&pod_name, &lp).await {
        Ok(t) => t,
        Err(e) => {
            lines.push((LineColor::Err, format!("kubectl logs {} échoue: {}", pod_name, e)));
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
        lines.push((LineColor::Ok, "rancher serveur opérationnel (logs récents)".into()));
        return DiagStatus::Ok;
    }
    if !errors.is_empty() {
        lines.push((LineColor::Warn, format!("erreurs récentes dans les logs rancher ({})", errors.len())));
        for e in errors.iter().take(3) {
            lines.push((LineColor::Dim, format!("  {}", truncate(e, 200))));
        }
    }
    if !serving_ok {
        lines.push((LineColor::Warn, "aucun marqueur de démarrage rancher trouvé dans les logs".into()));
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
        "Pods en erreur (cluster)",
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
                format!("{} pods total cluster", total),
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
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
        lines.push((LineColor::Dim, format!("  ... ({} de plus)", items.len() - 8)));
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
            lines.push((head, format!("{} PV: {}", list.items.len(), summary)));
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

async fn check_recent_warnings(client: &Client, state: &SharedDiagnostic, run_id: u64) {
    let Some(idx) = push_step(
        state,
        run_id,
        "Évènements warning récents",
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
                format!("{} évènements Warning visibles dans la fenêtre serveur", total),
            ));
            let mut sorted: Vec<(String, usize)> = by_reason.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
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
            lines.push((LineColor::Err, format!("erreur: {}", e)));
            DiagStatus::Err
        }
    };
    finish_step(state, run_id, idx, status, lines);
}

pub fn format_diagnostic_for_ai(state: &DiagnosticState) -> String {
    let mut out = String::new();
    out.push_str("Diagnostic cluster automatisé:\n");
    if let Some(ms) = state.elapsed_ms {
        out.push_str(&format!("durée: {} ms, {} étapes\n", ms, state.steps.len()));
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
