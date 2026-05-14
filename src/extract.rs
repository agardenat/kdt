use std::sync::{Arc, Mutex};
use std::time::Instant;

use kube::Client;

use crate::ai::{query_ai_direct, AiConfig, AiLanguage};
use crate::diagnostic::{
    format_diagnostic_for_ai, new_diagnostic_state, run_diagnostic, DiagStatus,
};
use crate::events::{
    fetch_node_usage, fetch_nodes, format_cpu_milli, format_memory_bytes, new_node_list_state,
    new_node_usage_state, NodeUsageState, PodUsageRow,
};
use crate::lang;
use crate::pdf;

#[derive(Default, Debug, Clone)]
pub struct ExtractState {
    pub running: bool,
    pub finished: bool,
    pub message: String,
    pub current: usize,
    pub total: usize,
    pub error: Option<String>,
    pub output_path: Option<String>,
    pub started_at: Option<Instant>,
    pub elapsed_ms: Option<u128>,
    pub run_id: u64,
}

pub type SharedExtract = Arc<Mutex<ExtractState>>;

pub fn new_extract_state() -> SharedExtract {
    Arc::new(Mutex::new(ExtractState::default()))
}

fn update(state: &SharedExtract, run_id: u64, current: usize, total: usize, msg: &str) -> bool {
    let mut s = state.lock().expect("extract poisoned");
    if s.run_id != run_id {
        return false;
    }
    s.current = current;
    s.total = total;
    s.message = msg.to_string();
    true
}

pub async fn run_full_extract(
    client: Client,
    config: AiConfig,
    lang: AiLanguage,
    ctx_label: String,
    ns_label: String,
    state: SharedExtract,
) {
    let st = lang::t(lang);
    let run_id = {
        let mut s = state.lock().expect("extract poisoned");
        s.run_id = s.run_id.wrapping_add(1).max(1);
        s.running = true;
        s.finished = false;
        s.started_at = Some(Instant::now());
        s.error = None;
        s.output_path = None;
        s.message = st.progress_init.to_string();
        s.current = 0;
        s.total = 0;
        s.run_id
    };

    if !update(&state, run_id, 1, 100, st.progress_list_nodes) {
        return;
    }
    let node_list_state = new_node_list_state();
    fetch_nodes(client.clone(), node_list_state.clone()).await;
    let nodes: Vec<String> = {
        let s = node_list_state.lock().expect("node list poisoned");
        s.nodes.iter().map(|n| n.name.clone()).collect()
    };

    let total_steps = 2 + 2 * nodes.len() + 1;
    let mut current = 1;

    current += 1;
    if !update(&state, run_id, current, total_steps, st.progress_diag_collect) {
        return;
    }
    let diag_state = new_diagnostic_state();
    run_diagnostic(client.clone(), diag_state.clone()).await;
    let (diag_steps, diag_summary) = {
        let s = diag_state.lock().expect("diag poisoned");
        (s.steps.clone(), format_diagnostic_for_ai(&s))
    };

    current += 1;
    if !update(&state, run_id, current, total_steps, st.progress_diag_ai) {
        return;
    }
    let diag_prompt = build_prompt_diagnostic(&ctx_label, &ns_label, &diag_summary);
    let (diag_ai_content, diag_ai_error) = match query_ai_direct(&config, lang, &diag_prompt).await
    {
        Ok(c) => (c, None),
        Err(e) => (String::new(), Some(e)),
    };

    let mut node_sections: Vec<pdf::NodeSection> = Vec::new();
    for (i, name) in nodes.iter().enumerate() {
        current += 1;
        let msg = st
            .progress_node_usage_fmt
            .replace("{i}", &(i + 1).to_string())
            .replace("{n}", &nodes.len().to_string())
            .replace("{name}", name);
        if !update(&state, run_id, current, total_steps, &msg) {
            return;
        }
        let nu_state = new_node_usage_state();
        fetch_node_usage(client.clone(), name.clone(), nu_state.clone()).await;
        let snap: NodeUsageState = { nu_state.lock().expect("nu poisoned").clone() };

        current += 1;
        let msg = st
            .progress_node_ai_fmt
            .replace("{i}", &(i + 1).to_string())
            .replace("{n}", &nodes.len().to_string())
            .replace("{name}", name);
        if !update(&state, run_id, current, total_steps, &msg) {
            return;
        }
        let usage_text = format_node_usage_text(&snap);
        let prompt = build_prompt_node(&ctx_label, name, &usage_text);
        let (ai_content, ai_error) = match query_ai_direct(&config, lang, &prompt).await {
            Ok(c) => (c, None),
            Err(e) => (String::new(), Some(e)),
        };

        node_sections.push(node_section_from(
            name,
            &snap,
            &config.model,
            ai_content,
            ai_error,
        ));
    }

    current += 1;
    if !update(&state, run_id, current, total_steps, st.progress_pdf) {
        return;
    }

    let mut diag_ok = 0;
    let mut diag_warn = 0;
    let mut diag_err = 0;
    let mut diag_info = 0;
    let pdf_steps: Vec<pdf::DiagStep> = diag_steps
        .iter()
        .map(|s| {
            match s.status {
                DiagStatus::Ok => diag_ok += 1,
                DiagStatus::Warn => diag_warn += 1,
                DiagStatus::Err => diag_err += 1,
                DiagStatus::Info => diag_info += 1,
                DiagStatus::Running => {}
            }
            pdf::DiagStep {
                status: match s.status {
                    DiagStatus::Ok => "ok",
                    DiagStatus::Warn => "warn",
                    DiagStatus::Err => "err",
                    DiagStatus::Info => "info",
                    DiagStatus::Running => "info",
                },
                title: s.title.clone(),
                command: s.command.clone(),
                lines: s
                    .lines
                    .iter()
                    .map(|(c, t)| pdf::DiagLine {
                        color: line_color_to_pdf(*c),
                        text: t.clone(),
                    })
                    .collect(),
            }
        })
        .collect();
    let diag_doc = pdf::DiagDoc {
        ok: diag_ok,
        warn: diag_warn,
        err: diag_err,
        info: diag_info,
        steps: pdf_steps,
        ai_model: config.model.clone(),
        ai_content: diag_ai_content,
        ai_error: diag_ai_error,
    };

    let report_title = match lang {
        AiLanguage::Fr => "Extraction complète",
        AiLanguage::En => "Full extraction",
    };
    let report = pdf::Report {
        title: report_title.to_string(),
        context: ctx_label.clone(),
        namespace: ns_label.clone(),
        generated_at: format!("{}", k8s_openapi::jiff::Timestamp::now()),
        diagnostic: Some(diag_doc),
        nodes: node_sections,
    };

    let dir = pdf::downloads_dir();
    let safe_ctx: String = ctx_label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let path = dir.join(pdf::timestamped_filename(&format!("kdt-extract-{}", safe_ctx)));

    let result = pdf::export_to_pdf(&path, &report);

    let mut s = state.lock().expect("extract poisoned");
    if s.run_id != run_id {
        return;
    }
    s.running = false;
    s.finished = true;
    if let Some(t) = s.started_at {
        s.elapsed_ms = Some(t.elapsed().as_millis());
    }
    match result {
        Ok(()) => {
            s.output_path = Some(path.display().to_string());
            s.message = st.progress_pdf_done.to_string();
        }
        Err(e) => s.error = Some(e),
    }
}

fn line_color_to_pdf(c: crate::events::LineColor) -> &'static str {
    use crate::events::LineColor::*;
    match c {
        Plain => "plain",
        Ok => "ok",
        Warn => "warn",
        Err => "err",
        Info => "info",
        Dim => "dim",
    }
}

fn build_prompt_diagnostic(ctx: &str, ns: &str, body: &str) -> String {
    format!(
        "Contexte: {ctx} (namespace courant: {ns})\n\nVoici un diagnostic cluster automatisé. Analyse-le et propose un résumé : état général, points d'attention, actions recommandées. Sois structuré (Diagnostic, Cause probable, Actions recommandées).\n\n----- Diagnostic -----\n{body}\n",
        ctx = ctx, ns = ns, body = body,
    )
}

fn build_prompt_node(ctx: &str, node: &str, body: &str) -> String {
    format!(
        "Contexte: {ctx}\nNoeud: {node}\n\nVoici un état d'utilisation des conteneurs sur ce noeud. Identifie les conteneurs problématiques (sur-provisionnés, à risque OOM, sans request/limit), les tendances, et propose des actions. Sois structuré (Diagnostic, Conteneurs prioritaires, Actions recommandées).\n\n----- Usage du noeud -----\n{body}\n",
        ctx = ctx, node = node, body = body,
    )
}

pub fn format_node_usage_text(s: &NodeUsageState) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "Node allocatable: cpu={}, memory={}\n",
        format_cpu_milli(s.alloc_cpu_milli),
        format_memory_bytes(s.alloc_mem_bytes)
    ));
    body.push_str(&format!(
        "metrics-server: {}\n",
        if s.metrics_available { "available" } else { "unavailable (use=null)" }
    ));
    let totals = compute_totals(&s.rows);
    body.push_str(&format!(
        "\nUser containers ({}): cpu req={} lim={} use={}, mem req={} lim={} use={}\n",
        totals.user_n,
        format_cpu_milli(totals.u_cpu_req),
        format_cpu_milli(totals.u_cpu_lim),
        format_cpu_milli(totals.u_cpu_use),
        format_memory_bytes(totals.u_mem_req),
        format_memory_bytes(totals.u_mem_lim),
        format_memory_bytes(totals.u_mem_use),
    ));
    body.push_str(&format!(
        "System containers ({}): cpu req={} use={}, mem req={} use={}\n",
        totals.sys_n,
        format_cpu_milli(totals.s_cpu_req),
        format_cpu_milli(totals.s_cpu_use),
        format_memory_bytes(totals.s_mem_req),
        format_memory_bytes(totals.s_mem_use),
    ));
    body.push_str("\nDétails par container avec problème :\n");
    let mut printed = 0;
    for r in &s.rows {
        if !row_has_issue(r) {
            continue;
        }
        if printed >= 80 {
            body.push_str("(... liste tronquée ...)\n");
            break;
        }
        printed += 1;
        let opt = |v: Option<i64>, fmt: fn(i64) -> String| {
            v.map(fmt).unwrap_or_else(|| "-".to_string())
        };
        let mut tags = Vec::new();
        let cpu_at_limit =
            matches!((r.cpu_use, r.cpu_lim), (Some(u), Some(l)) if l > 0 && u >= l);
        let mem_at_limit =
            matches!((r.mem_use, r.mem_lim), (Some(u), Some(l)) if l > 0 && u >= l);
        if r.cpu_req.is_none() {
            tags.push("noCpuReq");
        }
        if r.mem_req.is_none() {
            tags.push("noMemReq");
        }
        if r.mem_lim.is_none() {
            tags.push("noMemLim");
        }
        if cpu_at_limit {
            tags.push("cpuMax");
        }
        if mem_at_limit {
            tags.push("OOMrisk");
        }
        body.push_str(&format!(
            "{}{}/{} [{}] cpu={}/{}/{} mem={}/{}/{} ready={} rst={} -> {}\n",
            if r.is_system { "[sys] " } else { "" },
            r.namespace,
            r.pod,
            r.container,
            opt(r.cpu_req, format_cpu_milli),
            opt(r.cpu_lim, format_cpu_milli),
            opt(r.cpu_use, format_cpu_milli),
            opt(r.mem_req, format_memory_bytes),
            opt(r.mem_lim, format_memory_bytes),
            opt(r.mem_use, format_memory_bytes),
            if r.ready { "Y" } else { "N" },
            r.restarts,
            tags.join(","),
        ));
    }
    body
}

struct Totals {
    user_n: usize,
    sys_n: usize,
    u_cpu_req: i64,
    u_cpu_lim: i64,
    u_cpu_use: i64,
    u_mem_req: i64,
    u_mem_lim: i64,
    u_mem_use: i64,
    s_cpu_req: i64,
    s_cpu_use: i64,
    s_mem_req: i64,
    s_mem_use: i64,
}

fn compute_totals(rows: &[PodUsageRow]) -> Totals {
    let mut t = Totals {
        user_n: 0,
        sys_n: 0,
        u_cpu_req: 0,
        u_cpu_lim: 0,
        u_cpu_use: 0,
        u_mem_req: 0,
        u_mem_lim: 0,
        u_mem_use: 0,
        s_cpu_req: 0,
        s_cpu_use: 0,
        s_mem_req: 0,
        s_mem_use: 0,
    };
    for r in rows {
        let cr = r.cpu_req.unwrap_or(0);
        let cl = r.cpu_lim.unwrap_or(0);
        let cu = r.cpu_use.unwrap_or(0);
        let mr = r.mem_req.unwrap_or(0);
        let ml = r.mem_lim.unwrap_or(0);
        let mu = r.mem_use.unwrap_or(0);
        if r.is_system {
            t.sys_n += 1;
            t.s_cpu_req += cr;
            t.s_cpu_use += cu;
            t.s_mem_req += mr;
            t.s_mem_use += mu;
        } else {
            t.user_n += 1;
            t.u_cpu_req += cr;
            t.u_cpu_lim += cl;
            t.u_cpu_use += cu;
            t.u_mem_req += mr;
            t.u_mem_lim += ml;
            t.u_mem_use += mu;
        }
    }
    t
}

fn row_has_issue(r: &PodUsageRow) -> bool {
    let cpu_at_limit = matches!((r.cpu_use, r.cpu_lim), (Some(u), Some(l)) if l > 0 && u >= l);
    let mem_at_limit = matches!((r.mem_use, r.mem_lim), (Some(u), Some(l)) if l > 0 && u >= l);
    let cpu_under = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
    let mem_under = matches!((r.mem_req, r.mem_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
    let cpu_over_lim = matches!((r.cpu_lim, r.cpu_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);
    let mem_over_lim = matches!((r.mem_lim, r.mem_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);
    cpu_at_limit
        || mem_at_limit
        || cpu_under
        || mem_under
        || cpu_over_lim
        || mem_over_lim
        || r.cpu_req.is_none()
        || r.mem_req.is_none()
        || r.mem_lim.is_none()
}

pub fn node_section_from(
    name: &str,
    s: &NodeUsageState,
    ai_model: &str,
    ai_content: String,
    ai_error: Option<String>,
) -> pdf::NodeSection {
    let totals = compute_totals(&s.rows);
    let alloc_cpu = s.alloc_cpu_milli;
    let alloc_mem = s.alloc_mem_bytes;

    let mut sorted: Vec<&PodUsageRow> = s.rows.iter().collect();
    sorted.sort_by(|a, b| {
        a.is_system
            .cmp(&b.is_system)
            .then(b.mem_req.unwrap_or(-1).cmp(&a.mem_req.unwrap_or(-1)))
            .then(a.namespace.cmp(&b.namespace))
            .then(a.pod.cmp(&b.pod))
            .then(a.container.cmp(&b.container))
    });

    let rows: Vec<pdf::NodeRowData> = sorted
        .iter()
        .map(|r| {
            let cpu_at_limit =
                matches!((r.cpu_use, r.cpu_lim), (Some(u), Some(l)) if l > 0 && u >= l);
            let mem_at_limit =
                matches!((r.mem_use, r.mem_lim), (Some(u), Some(l)) if l > 0 && u >= l);
            let cpu_req_under_used = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
            let mem_req_under_used = matches!((r.mem_req, r.mem_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
            let cpu_extreme = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 5);
            let mem_extreme = matches!((r.mem_req, r.mem_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 5);
            let cpu_lim_excessive = matches!((r.cpu_lim, r.cpu_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);
            let mem_lim_excessive = matches!((r.mem_lim, r.mem_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);

            let restarts_color: &'static str = if r.restarts >= 5 { "err" } else if r.restarts >= 1 { "warn" } else { "dim" };
            let ready_color: &'static str = if r.ready { "ok" } else { "err" };

            let cpu_req_marker = if cpu_extreme { "↡" } else if cpu_req_under_used { "▼" } else { "" };
            let mem_req_marker = if mem_extreme { "↡" } else if mem_req_under_used { "▼" } else { "" };
            let cpu_lim_marker = if cpu_lim_excessive { "≫" } else { "" };
            let mem_lim_marker = if mem_lim_excessive { "≫" } else { "" };
            let cpu_use_marker = if cpu_at_limit { "▲" } else { "" };
            let mem_use_marker = if mem_at_limit { "▲" } else { "" };

            pdf::NodeRowData {
                system: r.is_system,
                namespace: r.namespace.clone(),
                pod: r.pod.clone(),
                container: r.container.clone(),
                cpu_req: pdf::UsageCell::for_value(r.cpu_req, alloc_cpu, format_cpu_milli, true).with_marker(cpu_req_marker),
                cpu_lim: cell_for_lim(r.cpu_lim, alloc_cpu, format_cpu_milli).with_marker(cpu_lim_marker),
                cpu_use: pdf::UsageCell::for_value(r.cpu_use, alloc_cpu, format_cpu_milli, false).with_marker(cpu_use_marker),
                mem_req: pdf::UsageCell::for_value(r.mem_req, alloc_mem, format_memory_bytes, true).with_marker(mem_req_marker),
                mem_lim: pdf::UsageCell::for_value(r.mem_lim, alloc_mem, format_memory_bytes, true).with_marker(mem_lim_marker),
                mem_use: pdf::UsageCell::for_value(r.mem_use, alloc_mem, format_memory_bytes, false).with_marker(mem_use_marker),
                ready: if r.ready { "Y".to_string() } else { "N".to_string() },
                ready_color,
                restarts: r.restarts,
                restarts_color,
            }
        })
        .collect();

    pdf::NodeSection {
        name: name.to_string(),
        allocatable_cpu: format_cpu_milli(s.alloc_cpu_milli),
        allocatable_mem: format_memory_bytes(s.alloc_mem_bytes),
        metrics_available: s.metrics_available,
        user_count: totals.user_n,
        system_count: totals.sys_n,
        user_cpu_req: format_cpu_milli(totals.u_cpu_req),
        user_cpu_lim: format_cpu_milli(totals.u_cpu_lim),
        user_cpu_use: format_cpu_milli(totals.u_cpu_use),
        user_mem_req: format_memory_bytes(totals.u_mem_req),
        user_mem_lim: format_memory_bytes(totals.u_mem_lim),
        user_mem_use: format_memory_bytes(totals.u_mem_use),
        sys_cpu_req: format_cpu_milli(totals.s_cpu_req),
        sys_cpu_use: format_cpu_milli(totals.s_cpu_use),
        sys_mem_req: format_memory_bytes(totals.s_mem_req),
        sys_mem_use: format_memory_bytes(totals.s_mem_use),
        rows,
        ai_model: ai_model.to_string(),
        ai_content,
        ai_error,
    }
}

fn cell_for_lim(v: Option<i64>, alloc: i64, fmt: fn(i64) -> String) -> pdf::UsageCell {
    match v {
        None => pdf::UsageCell::new("—".to_string(), 0),
        Some(val) => pdf::UsageCell::new(fmt(val), pdf::incidence_level(val, alloc)),
    }
}
