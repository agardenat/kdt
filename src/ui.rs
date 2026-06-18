use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};

const DIM: Color = Color::Rgb(150, 150, 150);
const SYS_DIM: Color = Color::Rgb(95, 95, 95);

use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap};
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;

use crate::ai::{
    default_provider_index, query_ai, resolve_providers, update_sections_count, update_stage,
    AiConfig, AiLanguage, AiProviderResolved, SharedAi,
};
use crate::config::{self, FileConfig};
use crate::diagnostic::{
    format_diagnostic_for_ai, new_diagnostic_state, run_diagnostic, DiagStatus, DiagnosticStep,
    SharedDiagnostic,
};
use crate::clip;
use crate::extract::{new_extract_state, run_full_extract, SharedExtract};
use crate::lang;
use crate::pdf;
use crate::enrich::{fetch_related, gather_extra_context_with_progress, new_related_state, SharedRelated};
use crate::events::{
    fetch_logs, fetch_namespaces, fetch_node_usage, fetch_nodes, fetch_status,
    format_cpu_milli, format_memory_bytes, new_node_list_state, new_node_usage_state,
    new_ns_list_state, spawn_watcher, EventRecord, LineColor, Severity, SharedBuffer, SharedLog,
    SharedNodeList, SharedNodeUsage, SharedNsList, SharedStatus,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter { All, Warnings, Errors }

impl Filter {
    fn label(self) -> &'static str {
        match self { Filter::All => "ALL", Filter::Warnings => "WARN", Filter::Errors => "ERR" }
    }
    fn matches(self, r: &EventRecord) -> bool {
        match self {
            Filter::All => true,
            Filter::Warnings => r.severity == Severity::Warning,
            Filter::Errors => r.severity == Severity::Warning && is_critical_reason(&r.reason),
        }
    }
}

fn is_critical_reason(reason: &str) -> bool {
    matches!(
        reason,
        "BackOff" | "CrashLoopBackOff" | "ImagePullBackOff" | "ErrImagePull"
        | "OOMKilled" | "Evicted" | "FailedScheduling" | "FailedMount"
        | "FailedCreate" | "FailedCreatePodSandBox" | "FailedSync"
        | "FailedKillPod" | "FailedAttachVolume" | "Unhealthy"
        | "NodeNotReady" | "NetworkNotReady" | "Killing"
    ) || reason.starts_with("Failed") || reason.starts_with("Err")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Selection, NsPicker, AiPanel, DetailFull, Nodes, NodesFull, NodeUsage, Diagnostic, Extract }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeUsageSort { MemReq, CpuReq, Alpha }

impl NodeUsageSort {
    fn next(self) -> Self {
        match self {
            NodeUsageSort::MemReq => NodeUsageSort::CpuReq,
            NodeUsageSort::CpuReq => NodeUsageSort::Alpha,
            NodeUsageSort::Alpha => NodeUsageSort::MemReq,
        }
    }
    fn label(self) -> &'static str {
        match self {
            NodeUsageSort::MemReq => "mem-req↓",
            NodeUsageSort::CpuReq => "cpu-req↓",
            NodeUsageSort::Alpha => "alpha",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab { Logs, Status, Related }

impl DetailTab {
    fn next(self) -> Self {
        match self { Self::Logs => Self::Status, Self::Status => Self::Related, Self::Related => Self::Logs }
    }
    fn prev(self) -> Self {
        match self { Self::Logs => Self::Related, Self::Status => Self::Logs, Self::Related => Self::Status }
    }
}

pub struct App {
    pub buffer: SharedBuffer,
    pub filter: Filter,
    pub namespace_label: String,
    pub context_label: String,
    pub should_quit: bool,
    pub mode: Mode,
    pub table_state: TableState,
    pub snapshot: Vec<EventRecord>,
    pub last_pod_key: Option<String>,
    pub last_status_key: Option<String>,
    pub client: kube::Client,
    pub log_state: SharedLog,
    pub status_state: SharedStatus,
    pub detail_tab: DetailTab,
    pub log_scroll: usize,
    pub status_scroll: usize,
    pub related_scroll: usize,
    pub h_scroll: usize,
    pub detail_h_scroll: usize,
    pub ns_pick_state: SharedNsList,
    pub ns_cursor: usize,
    pub watcher_handle: JoinHandle<()>,
    pub buffer_capacity: usize,
    pub ai_state: SharedAi,
    pub ai_scroll: usize,
    pub ai_language: AiLanguage,
    pub related_state: SharedRelated,
    pub last_related_key: Option<String>,
    pub ai_providers: Vec<AiProviderResolved>,
    pub ai_provider_idx: usize,
    pub return_mode: Mode,
    pub node_list_state: SharedNodeList,
    pub node_cursor: usize,
    pub last_node_status_key: Option<String>,
    pub node_usage_state: SharedNodeUsage,
    pub node_usage_scroll: usize,
    pub node_usage_sort: NodeUsageSort,
    pub diagnostic_state: SharedDiagnostic,
    pub diagnostic_scroll: usize,
    pub extract_state: SharedExtract,
    pub node_refresh_handle: Option<JoinHandle<()>>,
    pub clipboard_status: Option<(std::time::Instant, String)>,
    pub pending_node_select: Option<String>,
    pub scroll_frozen: bool,
    pub selected_uid: Option<String>,
}

impl App {
    pub fn new(
        buffer: SharedBuffer,
        namespace_label: String,
        context_label: String,
        client: kube::Client,
        log_state: SharedLog,
        status_state: SharedStatus,
        ai_state: SharedAi,
        watcher_handle: JoinHandle<()>,
        buffer_capacity: usize,
        file_config: FileConfig,
    ) -> Self {
        let initial_lang = config::initial_language(&file_config).unwrap_or(AiLanguage::Fr);
        let ai_providers = resolve_providers(&file_config);
        let ai_provider_idx = default_provider_index(&file_config, &ai_providers);
        Self {
            buffer,
            filter: Filter::All,
            namespace_label,
            context_label,
            should_quit: false,
            mode: Mode::Selection,
            table_state: TableState::default(),
            snapshot: Vec::new(),
            last_pod_key: None,
            last_status_key: None,
            client,
            log_state,
            status_state,
            detail_tab: DetailTab::Logs,
            log_scroll: 0,
            status_scroll: 0,
            related_scroll: 0,
            h_scroll: 0,
            detail_h_scroll: 0,
            ns_pick_state: new_ns_list_state(),
            ns_cursor: 0,
            watcher_handle,
            buffer_capacity,
            ai_state,
            ai_scroll: 0,
            ai_language: initial_lang,
            related_state: new_related_state(),
            last_related_key: None,
            ai_providers,
            ai_provider_idx,
            return_mode: Mode::Selection,
            node_list_state: new_node_list_state(),
            node_cursor: 0,
            last_node_status_key: None,
            node_usage_state: new_node_usage_state(),
            node_usage_scroll: 0,
            node_usage_sort: NodeUsageSort::MemReq,
            diagnostic_state: new_diagnostic_state(),
            diagnostic_scroll: 0,
            extract_state: new_extract_state(),
            node_refresh_handle: None,
            clipboard_status: None,
            pending_node_select: None,
            scroll_frozen: false,
            selected_uid: None,
        }
    }


    fn reset_to_follow(&mut self) {
        self.mode = Mode::Selection;
        self.scroll_frozen = false;
        self.selected_uid = None;
        self.reset_scroll();
    }

    fn refresh_live_snapshot(&mut self) {
        let snap: Vec<EventRecord> = {
            let buf = self.buffer.lock().expect("buffer poisoned");
            buf.iter()
                .filter(|r| self.filter.matches(r))
                .cloned()
                .collect()
        };
        if snap.is_empty() { return; }
        let last = snap.len() - 1;
        let idx = match self.selected_uid.as_ref() {
            Some(uid) => snap.iter().position(|r| &r.uid == uid),
            None => Some(last),
        };
        let idx = match idx {
            Some(i) => i,
            None => {
                self.selected_uid = None;
                last
            }
        };
        self.snapshot = snap;
        self.table_state.select(Some(idx));
        self.maybe_fetch_logs();
        self.maybe_fetch_status();
        self.maybe_fetch_related();
    }

    fn move_selection(&mut self, delta: i32) {
        if self.snapshot.is_empty() { return; }
        let last = self.snapshot.len() - 1;
        let cur = self.table_state.selected().unwrap_or(last) as i32;
        let new = (cur + delta).clamp(0, last as i32) as usize;
        self.table_state.select(Some(new));
        self.selected_uid = if new == last {
            None
        } else {
            self.snapshot.get(new).map(|r| r.uid.clone())
        };
        self.reset_scroll();
        self.maybe_fetch_logs();
        self.maybe_fetch_status();
        self.maybe_fetch_related();
    }

    fn cycle_tab(&mut self) {
        self.detail_tab = self.detail_tab.next();
        if self.detail_tab == DetailTab::Status { self.maybe_fetch_status(); }
    }
    fn cycle_tab_back(&mut self) {
        self.detail_tab = self.detail_tab.prev();
        if self.detail_tab == DetailTab::Status { self.maybe_fetch_status(); }
    }

    fn scroll_detail(&mut self, delta: i32) {
        let target = self.scroll_target();
        let cur = *target as i32;
        *target = cur.saturating_add(delta).max(0) as usize;
    }
    fn scroll_detail_top(&mut self) { *self.scroll_target() = usize::MAX / 2; }
    fn scroll_detail_bottom(&mut self) { *self.scroll_target() = 0; }

    fn scroll_target(&mut self) -> &mut usize {
        match self.detail_tab {
            DetailTab::Logs => &mut self.log_scroll,
            DetailTab::Status => &mut self.status_scroll,
            DetailTab::Related => &mut self.related_scroll,
        }
    }

    fn reset_scroll(&mut self) {
        self.log_scroll = 0;
        self.status_scroll = 0;
        self.related_scroll = 0;
        self.detail_h_scroll = 0;
    }

    fn clear_status_state(&self) {
        let mut s = self.status_state.lock().expect("status state poisoned");
        s.current_key = None;
        s.lines.clear();
        s.error = None;
        s.loading = false;
    }

    fn maybe_fetch_related(&mut self) {
        let Some(idx) = self.table_state.selected() else { return; };
        let Some(rec) = self.snapshot.get(idx).cloned() else { return; };
        let key = format!("{}|{}|{}/{}", rec.api_version, rec.kind, rec.namespace, rec.name);
        if self.last_related_key.as_deref() == Some(&key) { return; }
        self.last_related_key = Some(key.clone());
        {
            let mut s = self.related_state.lock().expect("related state poisoned");
            s.current_key = Some(key.clone());
            s.sections.clear();
            s.error = None;
            s.loading = true;
        }
        let client = self.client.clone();
        let state = self.related_state.clone();
        tokio::spawn(async move {
            fetch_related(client, rec, key, state).await;
        });
    }

    fn maybe_fetch_logs(&mut self) {
        let Some(idx) = self.table_state.selected() else { return; };
        let Some(rec) = self.snapshot.get(idx) else { return; };
        if rec.kind != "Pod" {
            let mut s = self.log_state.lock().expect("log state poisoned");
            s.current_key = None;
            s.lines.clear();
            s.error = Some(format!("logs n/a for kind={}", rec.kind));
            s.loading = false;
            self.last_pod_key = None;
            return;
        }
        let key = format!("{}/{}", rec.namespace, rec.name);
        if self.last_pod_key.as_deref() == Some(&key) { return; }
        self.last_pod_key = Some(key.clone());
        {
            let mut s = self.log_state.lock().expect("log state poisoned");
            s.current_key = Some(key.clone());
            s.lines.clear();
            s.error = None;
            s.loading = true;
        }
        let client = self.client.clone();
        let log_state = self.log_state.clone();
        let namespace = rec.namespace.clone();
        let pod = rec.name.clone();
        tokio::spawn(async move {
            fetch_logs(client, namespace, pod, key, log_state, 500).await;
        });
    }

    fn maybe_fetch_status(&mut self) {
        let Some(idx) = self.table_state.selected() else { return; };
        let Some(rec) = self.snapshot.get(idx) else { return; };
        let key = format!("{}|{}|{}/{}", rec.api_version, rec.kind, rec.namespace, rec.name);
        if self.last_status_key.as_deref() == Some(&key) { return; }
        self.last_status_key = Some(key.clone());
        {
            let mut s = self.status_state.lock().expect("status state poisoned");
            s.current_key = Some(key.clone());
            s.lines.clear();
            s.error = None;
            s.loading = true;
        }
        let client = self.client.clone();
        let status_state = self.status_state.clone();
        let api_version = rec.api_version.clone();
        let kind = rec.kind.clone();
        let namespace = rec.namespace.clone();
        let name = rec.name.clone();
        tokio::spawn(async move {
            fetch_status(client, api_version, kind, namespace, name, key, status_state).await;
        });
    }

    fn enter_ns_picker(&mut self) {
        {
            let mut s = self.ns_pick_state.lock().expect("ns list poisoned");
            s.loading = true;
            s.namespaces.clear();
            s.error = None;
        }
        self.ns_cursor = 0;
        self.mode = Mode::NsPicker;
        let client = self.client.clone();
        let state = self.ns_pick_state.clone();
        tokio::spawn(async move {
            fetch_namespaces(client, state).await;
        });
    }

    fn exit_ns_picker(&mut self) {
        self.mode = Mode::Selection;
    }

    fn current_ai_config(&self) -> Result<AiConfig, String> {
        match self.ai_providers.get(self.ai_provider_idx) {
            Some(p) => AiConfig::from_resolved(p),
            None => Err("aucun fournisseur IA configuré".to_string()),
        }
    }

    fn ai_provider_name(&self) -> &str {
        self.ai_providers
            .get(self.ai_provider_idx)
            .map(|p| p.name.as_str())
            .unwrap_or("-")
    }

    fn cycle_ai_provider(&mut self) {
        let msg = if self.ai_providers.len() > 1 {
            self.ai_provider_idx = (self.ai_provider_idx + 1) % self.ai_providers.len();
            format!("IA: {}", self.ai_provider_name())
        } else {
            format!("IA: {} (seul fournisseur)", self.ai_provider_name())
        };
        self.clipboard_status = Some((std::time::Instant::now(), msg));
    }

    fn enter_ai_panel(&mut self) {
        let source_mode = if self.mode == Mode::AiPanel { self.return_mode } else { self.mode };
        let rec = match source_mode {
            Mode::Nodes | Mode::NodesFull | Mode::NodeUsage => match self.synthetic_node_record() {
                Some(r) => r,
                None => return,
            },
            Mode::Diagnostic => self.synthetic_diagnostic_record(),
            _ => {
                let Some(idx) = self.table_state.selected() else { return; };
                let Some(r) = self.snapshot.get(idx).cloned() else { return; };
                r
            }
        };

        let usage_extra = if matches!(source_mode, Mode::NodeUsage) {
            let s = self.node_usage_state.lock().expect("node usage poisoned");
            if s.rows.is_empty() { None } else { Some(format_node_usage_for_ai(&s)) }
        } else { None };

        let diagnostic_extra = if matches!(source_mode, Mode::Diagnostic) {
            let s = self.diagnostic_state.lock().expect("diagnostic poisoned");
            if s.steps.is_empty() {
                None
            } else {
                Some((
                    "Cluster diagnostic".to_string(),
                    format_diagnostic_for_ai(&s),
                ))
            }
        } else { None };

        if self.mode != Mode::AiPanel {
            self.return_mode = self.mode;
        }

        let config = match self.current_ai_config() {
            Ok(c) => c,
            Err(e) => {
                let key = format!("err-{}", rec.uid);
                let mut s = self.ai_state.lock().expect("ai state poisoned");
                s.current_key = Some(key);
                s.loading = false;
                s.content.clear();
                s.error = Some(e);
                s.prompt_preview.clear();
                drop(s);
                self.mode = Mode::AiPanel;
                self.ai_scroll = 0;
                return;
            }
        };

        let logs_text = capture_logs_text(&self.log_state);
        let status_text = capture_status_text(&self.status_state);
        let related_text = capture_related_text(&self.buffer, &rec);
        let ctx_label = self.context_label.clone();
        let ns_label = self.namespace_label.clone();
        let client = self.client.clone();
        let lang = self.ai_language;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let key = format!("{}-{}-{}", rec.uid, rec.time, nanos);

        let model = config.model.clone();
        {
            let mut s = self.ai_state.lock().expect("ai state poisoned");
            s.current_key = Some(key.clone());
            s.loading = true;
            s.content.clear();
            s.error = None;
            s.prompt_preview.clear();
            s.stage = "Préparation...".to_string();
            s.started_at = Some(std::time::Instant::now());
            s.sections_count = 0;
            s.model = model;
            s.export_status = None;
        }
        self.mode = Mode::AiPanel;
        self.ai_scroll = 0;

        let state = self.ai_state.clone();
        tokio::spawn(async move {
            let progress_state = state.clone();
            let progress_key = key.clone();
            let progress = |stage: &str, count: usize| {
                update_stage(&progress_state, &progress_key, stage);
                update_sections_count(&progress_state, &progress_key, count);
            };
            let mut extra = gather_extra_context_with_progress(&client, &rec, progress).await;
            if let Some(u) = usage_extra { extra.insert(0, u); }
            if let Some(d) = diagnostic_extra { extra.insert(0, d); }
            update_sections_count(&state, &key, extra.len());
            update_stage(&state, &key, "Construction du prompt...");
            let prompt = build_ai_prompt(&rec, &ctx_label, &ns_label, &logs_text, &status_text, &related_text, &extra);
            {
                let mut s = state.lock().expect("ai state poisoned");
                if s.current_key.as_deref() == Some(&key) {
                    s.prompt_preview = prompt.clone();
                }
            }
            query_ai(config, prompt, lang, key, state).await;
        });
    }

    fn exit_ai_panel(&mut self) {
        self.mode = self.return_mode;
    }

    fn enter_detail_full(&mut self) {
        if self.snapshot.is_empty() || self.table_state.selected().is_none() { return; }
        self.mode = Mode::DetailFull;
    }

    fn exit_detail_full(&mut self) {
        self.mode = Mode::Selection;
    }

    fn enter_diagnostic(&mut self) {
        if self.mode != Mode::AiPanel {
            self.return_mode = self.mode;
        }
        self.mode = Mode::Diagnostic;
        self.diagnostic_scroll = 0;
        let client = self.client.clone();
        let state = self.diagnostic_state.clone();
        tokio::spawn(async move { run_diagnostic(client, state).await; });
    }

    fn exit_diagnostic(&mut self) {
        self.mode = Mode::Selection;
    }

    fn refresh_diagnostic(&self) {
        let client = self.client.clone();
        let state = self.diagnostic_state.clone();
        tokio::spawn(async move { run_diagnostic(client, state).await; });
    }

    fn export_diagnostic_pdf(&mut self, with_ai: bool) {
        let (steps, ai_content, ai_error, ai_model) = {
            let d = self.diagnostic_state.lock().expect("diagnostic poisoned");
            let a = self.ai_state.lock().expect("ai state poisoned");
            (d.steps.clone(), a.content.clone(), a.error.clone(), a.model.clone())
        };
        let st = lang::t(self.ai_language);
        if steps.is_empty() {
            self.set_export_status(st.lbl_export_empty_diag);
            return;
        }
        let diag_doc = build_diag_doc(
            &steps,
            if with_ai { &ai_content } else { "" },
            if with_ai { ai_error.as_deref() } else { None },
            if with_ai { &ai_model } else { "" },
        );
        let report = pdf::Report {
            title: st.title_diagnostic.to_string(),
            context: self.context_label.clone(),
            namespace: self.namespace_label.clone(),
            generated_at: format!("{}", k8s_openapi::jiff::Timestamp::now()),
            diagnostic: Some(diag_doc),
            nodes: Vec::new(),
        };
        let path = self.build_pdf_path("diag");
        self.set_export_status(st.lbl_pdf_generating);
        match pdf::export_to_pdf(&path, &report) {
            Ok(()) => self.set_export_status(&format!("{}: {}", st.lbl_pdf_exported, path.display())),
            Err(e) => self.set_export_status(&format!("{}: {}", st.lbl_pdf_error, e)),
        }
    }

    fn export_node_usage_pdf(&mut self, with_ai: bool) {
        let st = lang::t(self.ai_language);
        let (snap, name) = {
            let s = self.node_usage_state.lock().expect("node usage poisoned");
            if s.rows.is_empty() {
                self.set_export_status(st.lbl_export_empty_usage);
                return;
            }
            (s.clone(), s.current_node.clone().unwrap_or_default())
        };
        let (ai_content, ai_error, ai_model) = if with_ai {
            let a = self.ai_state.lock().expect("ai state poisoned");
            (a.content.clone(), a.error.clone(), a.model.clone())
        } else {
            (String::new(), None, String::new())
        };
        let section = crate::extract::node_section_from(
            &name,
            &snap,
            &ai_model,
            ai_content,
            ai_error,
        );
        let report = pdf::Report {
            title: format!("{} {}", st.title_node_usage, name),
            context: self.context_label.clone(),
            namespace: self.namespace_label.clone(),
            generated_at: format!("{}", k8s_openapi::jiff::Timestamp::now()),
            diagnostic: None,
            nodes: vec![section],
        };
        let safe_node: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
            .collect();
        let path = self.build_pdf_path(&format!("node-{}", safe_node));
        self.set_export_status(st.lbl_pdf_generating);
        match pdf::export_to_pdf(&path, &report) {
            Ok(()) => self.set_export_status(&format!("{}: {}", st.lbl_pdf_exported, path.display())),
            Err(e) => self.set_export_status(&format!("{}: {}", st.lbl_pdf_error, e)),
        }
    }

    fn build_pdf_path(&self, kind: &str) -> std::path::PathBuf {
        let dir = pdf::downloads_dir();
        let safe_ctx: String = self
            .context_label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
            .collect();
        dir.join(pdf::timestamped_filename(&format!("kdt-{}-{}", kind, safe_ctx)))
    }

    pub fn clipboard_status_active(&self) -> Option<&str> {
        self.clipboard_status.as_ref().and_then(|(t, msg)| {
            if t.elapsed().as_secs() < 3 { Some(msg.as_str()) } else { None }
        })
    }

    fn copy_current_view(&mut self) {
        let text = match self.mode {
            Mode::AiPanel => {
                let s = self.ai_state.lock().expect("ai state poisoned");
                s.content.clone()
            }
            Mode::Diagnostic => {
                let d = self.diagnostic_state.lock().expect("diag poisoned");
                crate::diagnostic::format_diagnostic_for_ai(&d)
            }
            Mode::NodeUsage => {
                let s = self.node_usage_state.lock().expect("node usage poisoned");
                crate::extract::format_node_usage_text(&s)
            }
            Mode::Extract => {
                let s = self.extract_state.lock().expect("extract poisoned");
                s.output_path.clone().unwrap_or_else(|| s.message.clone())
            }
            _ => String::new(),
        };
        if text.is_empty() {
            self.clipboard_status = Some((std::time::Instant::now(), "rien à copier".to_string()));
            return;
        }
        let n_lines = text.lines().count();
        let n_bytes = text.len();
        match clip::copy_to_clipboard(&text) {
            Ok(()) => {
                self.clipboard_status = Some((
                    std::time::Instant::now(),
                    format!("{} lignes ({} caractères) copiés", n_lines, n_bytes),
                ));
            }
            Err(e) => {
                self.clipboard_status = Some((std::time::Instant::now(), format!("copie KO: {}", e)));
            }
        }
    }

    fn enter_extract(&mut self) {
        let already_running = {
            let s = self.extract_state.lock().expect("extract poisoned");
            s.running
        };
        if !already_running {
            let config = match self.current_ai_config() {
                Ok(c) => c,
                Err(e) => {
                    let mut s = self.extract_state.lock().expect("extract poisoned");
                    s.running = false;
                    s.finished = true;
                    s.error = Some(format!("config IA: {}", e));
                    s.message = "config IA manquante".to_string();
                    self.return_mode = self.mode;
                    self.mode = Mode::Extract;
                    return;
                }
            };
            let client = self.client.clone();
            let lang = self.ai_language;
            let ctx = self.context_label.clone();
            let ns = self.namespace_label.clone();
            let state = self.extract_state.clone();
            tokio::spawn(async move {
                run_full_extract(client, config, lang, ctx, ns, state).await;
            });
        }
        self.return_mode = if self.mode == Mode::Extract { self.return_mode } else { self.mode };
        self.mode = Mode::Extract;
    }

    fn exit_extract(&mut self) {
        let running = self.extract_state.lock().expect("extract poisoned").running;
        if running {
            return;
        }
        self.mode = if matches!(self.return_mode, Mode::Extract) { Mode::Selection } else { self.return_mode };
    }

    fn set_export_status(&self, msg: &str) {
        let mut s = self.ai_state.lock().expect("ai state poisoned");
        s.export_status = Some(msg.to_string());
    }

    fn synthetic_diagnostic_record(&self) -> EventRecord {
        EventRecord {
            uid: format!(
                "diagnostic-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            ),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: Severity::Normal,
            reason: "ClusterDiagnostic".to_string(),
            api_version: "kdt/v1".to_string(),
            kind: "Diagnostic".to_string(),
            namespace: String::new(),
            name: self.context_label.clone(),
            message: "Diagnostic cluster automatisé".to_string(),
            component: "kdt".to_string(),
            host: String::new(),
            count: 1,
        }
    }

    fn enter_nodes_mode(&mut self) {
        self.mode = Mode::Nodes;
        self.node_cursor = 0;
        self.last_node_status_key = None;
        self.detail_tab = DetailTab::Status;
        self.log_scroll = 0;
        self.status_scroll = 0;
        self.detail_h_scroll = 0;
        self.refresh_nodes();
        self.start_node_auto_refresh();
        self.maybe_fetch_node_status();
    }

    fn enter_nodes_mode_for_selected_event(&mut self) {
        let target = {
            let Some(idx) = self.table_state.selected() else { return; };
            let Some(rec) = self.snapshot.get(idx) else { return; };
            rec.node_name()
        };
        let Some(name) = target else { return; };
        self.enter_nodes_mode();
        let pos = {
            let s = self.node_list_state.lock().expect("node list poisoned");
            s.nodes.iter().position(|n| n.name == name)
        };
        if let Some(pos) = pos {
            self.node_cursor = pos;
            self.last_node_status_key = None;
            self.maybe_fetch_node_status();
        } else {
            self.pending_node_select = Some(name);
        }
    }

    fn exit_nodes_mode(&mut self) {
        self.mode = Mode::Selection;
        self.last_node_status_key = None;
        self.last_status_key = None;
        self.stop_node_auto_refresh();
        self.clear_status_state();
    }

    fn start_node_auto_refresh(&mut self) {
        self.stop_node_auto_refresh();
        let client = self.client.clone();
        let state = self.node_list_state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_nodes(client.clone(), state.clone()).await;
            }
        });
        self.node_refresh_handle = Some(handle);
    }

    fn stop_node_auto_refresh(&mut self) {
        if let Some(h) = self.node_refresh_handle.take() {
            h.abort();
        }
    }

    fn enter_nodes_full(&mut self) {
        let len = self.node_list_state.lock().expect("node list poisoned").nodes.len();
        if len == 0 { return; }
        self.mode = Mode::NodesFull;
    }

    fn exit_nodes_full(&mut self) {
        self.mode = Mode::Nodes;
    }

    fn move_node_selection(&mut self, delta: i32) {
        let len = self.node_list_state.lock().expect("node list poisoned").nodes.len();
        if len == 0 { return; }
        let cur = self.node_cursor as i32;
        let max = len as i32 - 1;
        let new = (cur + delta).clamp(0, max) as usize;
        self.node_cursor = new;
        self.status_scroll = 0;
        self.detail_h_scroll = 0;
        self.maybe_fetch_node_status();
    }

    fn refresh_nodes(&self) {
        {
            let mut s = self.node_list_state.lock().expect("node list poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.node_list_state.clone();
        tokio::spawn(async move { fetch_nodes(client, state).await; });
    }

    fn maybe_fetch_node_status(&mut self) {
        let name = {
            let s = self.node_list_state.lock().expect("node list poisoned");
            s.nodes.get(self.node_cursor).map(|n| n.name.clone())
        };
        let Some(name) = name else { return; };
        let key = format!("Node|{}", name);
        if self.last_node_status_key.as_deref() == Some(&key) { return; }
        self.last_node_status_key = Some(key.clone());
        {
            let mut s = self.status_state.lock().expect("status state poisoned");
            s.current_key = Some(key.clone());
            s.lines.clear();
            s.error = None;
            s.loading = true;
        }
        let client = self.client.clone();
        let status_state = self.status_state.clone();
        tokio::spawn(async move {
            crate::events::fetch_status(
                client,
                "v1".to_string(),
                "Node".to_string(),
                String::new(),
                name,
                key,
                status_state,
            ).await;
        });
    }

    fn enter_node_usage(&mut self) {
        let name = {
            let s = self.node_list_state.lock().expect("node list poisoned");
            s.nodes.get(self.node_cursor).map(|n| n.name.clone())
        };
        let Some(name) = name else { return; };
        self.mode = Mode::NodeUsage;
        self.node_usage_scroll = 0;
        let client = self.client.clone();
        let state = self.node_usage_state.clone();
        tokio::spawn(async move { fetch_node_usage(client, name, state).await; });
    }

    fn exit_node_usage(&mut self) {
        self.mode = Mode::Nodes;
    }

    fn refresh_node_usage(&self) {
        let name = {
            let s = self.node_list_state.lock().expect("node list poisoned");
            s.nodes.get(self.node_cursor).map(|n| n.name.clone())
        };
        let Some(name) = name else { return; };
        let client = self.client.clone();
        let state = self.node_usage_state.clone();
        tokio::spawn(async move { fetch_node_usage(client, name, state).await; });
    }

    fn synthetic_node_record(&self) -> Option<EventRecord> {
        let s = self.node_list_state.lock().expect("node list poisoned");
        let n = s.nodes.get(self.node_cursor)?;
        let abnormal = if n.abnormal.is_empty() {
            "aucune condition anormale".to_string()
        } else {
            format!("conditions anormales: {}", n.abnormal.join(", "))
        };
        Some(EventRecord {
            uid: format!("node-{}", n.name),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: if n.abnormal.is_empty() && n.schedulable && n.ready == "True" { Severity::Normal } else { Severity::Warning },
            reason: "NodeStatus".to_string(),
            api_version: "v1".to_string(),
            kind: "Node".to_string(),
            namespace: String::new(),
            name: n.name.clone(),
            message: format!(
                "Node ready={} schedulable={} version={}; {}",
                n.ready, n.schedulable, n.version, abnormal,
            ),
            component: String::new(),
            host: n.name.clone(),
            count: 1,
        })
    }

    fn confirm_ns(&mut self) {
        let ns_opt: Option<String> = {
            let s = self.ns_pick_state.lock().expect("ns list poisoned");
            if self.ns_cursor == 0 {
                None
            } else {
                s.namespaces.get(self.ns_cursor - 1).cloned()
            }
        };
        self.namespace_label = match &ns_opt { Some(n) => n.clone(), None => "all".to_string() };
        self.watcher_handle.abort();
        {
            let mut buf = self.buffer.lock().expect("buffer poisoned");
            buf.clear();
        }
        self.watcher_handle = spawn_watcher(
            self.client.clone(),
            ns_opt,
            self.buffer.clone(),
            self.buffer_capacity,
        );
        self.mode = Mode::Selection;
        self.scroll_frozen = false;
        self.selected_uid = None;
        self.snapshot.clear();
        self.table_state.select(None);
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
    }
}

pub async fn run(mut app: App) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app).await;
    ratatui::restore();
    result
}

async fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut visible_rows: usize = 20;

    loop {
        if app.mode == Mode::Selection && !app.scroll_frozen {
            app.refresh_live_snapshot();
        }
        terminal.draw(|f| visible_rows = draw(f, app))?;
        if app.should_quit { break; }
        tokio::select! {
            _ = ticker.tick() => {}
            maybe = events.next() => match maybe {
                Some(Ok(ev)) => handle_event(app, ev),
                Some(Err(e)) => return Err(e.into()),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => { app.should_quit = true; }
        }
    }
    Ok(())
}

fn handle_event(app: &mut App, ev: Event) {
    let Event::Key(k) = ev else { return };
    if k.kind != KeyEventKind::Press { return; }
    match (k.code, k.modifiers, app.mode) {
        (KeyCode::Char('m'), _, Mode::AiPanel) => {
            app.cycle_ai_provider();
            app.enter_ai_panel();
        }
        (KeyCode::Char('m'), _, Mode::NsPicker) => {}
        (KeyCode::Char('m'), _, _) => app.cycle_ai_provider(),

        (KeyCode::Up, _, Mode::NsPicker) => {
            if app.ns_cursor > 0 { app.ns_cursor -= 1; }
        }
        (KeyCode::Down, _, Mode::NsPicker) => {
            let max = app.ns_pick_state.lock().expect("ns list poisoned").namespaces.len();
            if app.ns_cursor < max { app.ns_cursor += 1; }
        }
        (KeyCode::Enter, _, Mode::NsPicker) => app.confirm_ns(),
        (KeyCode::Esc, _, Mode::NsPicker) => app.exit_ns_picker(),
        (_, _, Mode::NsPicker) => {}

        (KeyCode::Esc, _, Mode::AiPanel) => app.exit_ai_panel(),
        (KeyCode::Char('i'), _, Mode::AiPanel) => app.exit_ai_panel(),
        (KeyCode::Char('q'), _, Mode::AiPanel) => app.exit_ai_panel(),
        (KeyCode::Up, _, Mode::AiPanel) => app.ai_scroll = app.ai_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::AiPanel) => app.ai_scroll = app.ai_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::AiPanel) => app.ai_scroll = app.ai_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::AiPanel) => app.ai_scroll = app.ai_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::AiPanel) => app.ai_scroll = 0,
        (KeyCode::Char('G'), _, Mode::AiPanel) => app.ai_scroll = usize::MAX / 2,
        (KeyCode::Char('l'), _, Mode::AiPanel) => {
            app.ai_language = app.ai_language.toggle();
            app.enter_ai_panel();
        }
        (KeyCode::Char('p' | 'P'), _, Mode::AiPanel) if app.return_mode == Mode::Diagnostic => {
            app.export_diagnostic_pdf(true);
        }
        (KeyCode::Char('p' | 'P'), _, Mode::AiPanel) if app.return_mode == Mode::NodeUsage => {
            app.export_node_usage_pdf(true);
        }
        (KeyCode::Char('c'), _, Mode::AiPanel) => app.copy_current_view(),
        (_, _, Mode::AiPanel) => {}

        (KeyCode::Up, m, Mode::DetailFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::DetailFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::DetailFull) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::DetailFull) => app.scroll_detail(-10),
        (KeyCode::Left, m, Mode::DetailFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::DetailFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, Mode::DetailFull) => app.detail_h_scroll = 0,
        (KeyCode::Tab, _, Mode::DetailFull) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::DetailFull) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::DetailFull) => app.exit_detail_full(),
        (KeyCode::Esc, _, Mode::DetailFull) => app.exit_detail_full(),
        (KeyCode::Char('i'), _, Mode::DetailFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::DetailFull) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Char('g'), _, Mode::DetailFull) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::DetailFull) => app.scroll_detail_bottom(),
        (KeyCode::Char('s'), _, Mode::DetailFull) => app.scroll_frozen = !app.scroll_frozen,

        (KeyCode::Up, m, Mode::Nodes) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::Nodes) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::Up, _, Mode::Nodes) => app.move_node_selection(-1),
        (KeyCode::Down, _, Mode::Nodes) => app.move_node_selection(1),
        (KeyCode::PageUp, _, Mode::Nodes) => app.move_node_selection(-10),
        (KeyCode::PageDown, _, Mode::Nodes) => app.move_node_selection(10),
        (KeyCode::Enter, _, Mode::Nodes) => app.enter_nodes_full(),
        (KeyCode::Esc, _, Mode::Nodes) => app.exit_nodes_mode(),
        (KeyCode::Char('r'), _, Mode::Nodes) => app.refresh_nodes(),
        (KeyCode::Char('i'), _, Mode::Nodes) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Nodes) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Char('N'), _, Mode::Nodes) => app.exit_nodes_mode(),
        (KeyCode::Char('u'), _, Mode::Nodes) => app.enter_node_usage(),

        (KeyCode::Esc, _, Mode::NodeUsage) => app.exit_node_usage(),
        (KeyCode::Char('u'), _, Mode::NodeUsage) => app.exit_node_usage(),
        (KeyCode::Char('q'), _, Mode::NodeUsage) => app.exit_node_usage(),
        (KeyCode::Up, _, Mode::NodeUsage) => app.node_usage_scroll = app.node_usage_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::NodeUsage) => app.node_usage_scroll = app.node_usage_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::NodeUsage) => app.node_usage_scroll = app.node_usage_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::NodeUsage) => app.node_usage_scroll = app.node_usage_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::NodeUsage) => app.node_usage_scroll = 0,
        (KeyCode::Char('G'), _, Mode::NodeUsage) => app.node_usage_scroll = usize::MAX / 2,
        (KeyCode::Char('r'), _, Mode::NodeUsage) => app.refresh_node_usage(),
        (KeyCode::Char('i'), _, Mode::NodeUsage) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::NodeUsage) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Char('s'), _, Mode::NodeUsage) => {
            app.node_usage_sort = app.node_usage_sort.next();
            app.node_usage_scroll = 0;
        }
        (KeyCode::Char('p' | 'P'), _, Mode::NodeUsage) => {
            app.export_node_usage_pdf(false);
        }
        (KeyCode::Char('c'), _, Mode::NodeUsage) => app.copy_current_view(),
        (_, _, Mode::NodeUsage) => {}

        (KeyCode::Up, m, Mode::NodesFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::NodesFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::NodesFull) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::NodesFull) => app.scroll_detail(-10),
        (KeyCode::Left, m, Mode::NodesFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::NodesFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, Mode::NodesFull) => app.detail_h_scroll = 0,
        (KeyCode::Enter, _, Mode::NodesFull) => app.exit_nodes_full(),
        (KeyCode::Esc, _, Mode::NodesFull) => app.exit_nodes_full(),
        (KeyCode::Char('g'), _, Mode::NodesFull) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::NodesFull) => app.scroll_detail_bottom(),
        (KeyCode::Char('i'), _, Mode::NodesFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::NodesFull) => app.ai_language = app.ai_language.toggle(),

        (KeyCode::Left, m, _) if !m.contains(KeyModifiers::SHIFT) => {
            app.h_scroll = app.h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, _) if !m.contains(KeyModifiers::SHIFT) => {
            app.h_scroll = app.h_scroll.saturating_add(5);
        }
        (KeyCode::Left, m, Mode::Selection) if m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::Selection) if m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, _) => app.h_scroll = 0,
        (KeyCode::Char('q'), _, _) => app.should_quit = true,
        (KeyCode::Char('c'), KeyModifiers::CONTROL, _) => app.should_quit = true,

        (KeyCode::Char('D'), _, Mode::Selection) => app.enter_diagnostic(),
        (KeyCode::Char('X'), _, Mode::Selection) => app.enter_extract(),

        (KeyCode::Esc, _, Mode::Diagnostic) => app.exit_diagnostic(),
        (KeyCode::Char('D'), _, Mode::Diagnostic) => app.exit_diagnostic(),
        (KeyCode::Up, _, Mode::Diagnostic) => app.diagnostic_scroll = app.diagnostic_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::Diagnostic) => app.diagnostic_scroll = app.diagnostic_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::Diagnostic) => app.diagnostic_scroll = app.diagnostic_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::Diagnostic) => app.diagnostic_scroll = app.diagnostic_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::Diagnostic) => app.diagnostic_scroll = 0,
        (KeyCode::Char('G'), _, Mode::Diagnostic) => app.diagnostic_scroll = usize::MAX / 2,
        (KeyCode::Char('r'), _, Mode::Diagnostic) => app.refresh_diagnostic(),
        (KeyCode::Char('i'), _, Mode::Diagnostic) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Diagnostic) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Char('p' | 'P'), _, Mode::Diagnostic) => app.export_diagnostic_pdf(false),
        (KeyCode::Char('c'), _, Mode::Diagnostic) => app.copy_current_view(),
        (_, _, Mode::Diagnostic) => {}

        (KeyCode::Esc, _, Mode::Extract) => app.exit_extract(),
        (KeyCode::Char('c'), _, Mode::Extract) => app.copy_current_view(),
        (_, _, Mode::Extract) => {}

        (KeyCode::Char('s'), _, Mode::Selection) => app.scroll_frozen = !app.scroll_frozen,
        (KeyCode::Esc, _, Mode::Selection) => app.reset_to_follow(),
        (KeyCode::Char('n'), _, Mode::Selection) => app.enter_ns_picker(),
        (KeyCode::Char('a' | 'A'), _, Mode::Selection) => app.filter = Filter::All,
        (KeyCode::Char('w' | 'W'), _, Mode::Selection) => app.filter = Filter::Warnings,
        (KeyCode::Char('e' | 'E'), _, Mode::Selection) => app.filter = Filter::Errors,
        (KeyCode::Char('N'), _, Mode::Selection) => app.enter_nodes_mode_for_selected_event(),
        (KeyCode::Char('N'), _, Mode::DetailFull) => app.enter_nodes_mode_for_selected_event(),
        (KeyCode::Char('i'), _, Mode::Selection) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Selection) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Enter, _, Mode::Selection) => app.enter_detail_full(),
        (KeyCode::Up, m, Mode::Selection) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::Selection) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::Up, _, Mode::Selection) => app.move_selection(-1),
        (KeyCode::Down, _, Mode::Selection) => app.move_selection(1),
        (KeyCode::PageUp, _, Mode::Selection) => app.move_selection(-10),
        (KeyCode::PageDown, _, Mode::Selection) => app.move_selection(10),
        (KeyCode::Tab, _, Mode::Selection) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::Selection) => app.cycle_tab_back(),
        (KeyCode::Char('u'), KeyModifiers::CONTROL, Mode::Selection) => app.scroll_detail(10),
        (KeyCode::Char('d'), KeyModifiers::CONTROL, Mode::Selection) => app.scroll_detail(-10),
        (KeyCode::Char('g'), _, Mode::Selection) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::Selection) => app.scroll_detail_bottom(),
        _ => {}
    }
}

fn draw(f: &mut ratatui::Frame, app: &mut App) -> usize {
    let area = f.area();
    let draw_mode = match app.mode {
        Mode::NsPicker => Mode::Selection,
        Mode::AiPanel => match app.return_mode {
            Mode::NodeUsage => Mode::Nodes,
            Mode::Diagnostic => Mode::Selection,
            Mode::Extract => Mode::Selection,
            m => m,
        },
        Mode::NodeUsage => Mode::Nodes,
        Mode::Diagnostic => Mode::Selection,
        Mode::Extract => Mode::Selection,
        m => m,
    };

    let layout = match draw_mode {
        Mode::Selection => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(area.height / 2),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(area),
        Mode::DetailFull => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
            .split(area),
        Mode::Nodes => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(area.height / 2),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(area),
        Mode::NodesFull => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
            .split(area),
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract => unreachable!(),
    };

    let (header_a, detail_a, table_a, footer_a): (Rect, Option<Rect>, Option<Rect>, Rect) = match draw_mode {
        Mode::Selection => (layout[0], Some(layout[1]), Some(layout[2]), layout[3]),
        Mode::DetailFull => (layout[0], Some(layout[1]), None, layout[2]),
        Mode::Nodes => (layout[0], Some(layout[1]), Some(layout[2]), layout[3]),
        Mode::NodesFull => (layout[0], Some(layout[1]), None, layout[2]),
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract => unreachable!(),
    };

    let st = lang::t(app.ai_language);
    let mode_label = match app.mode {
        Mode::Selection => st.mode_selection,
        Mode::NsPicker => st.mode_ns,
        Mode::AiPanel => st.mode_ai,
        Mode::DetailFull => st.mode_detail,
        Mode::Nodes => st.mode_nodes,
        Mode::NodesFull => st.mode_node_detail,
        Mode::NodeUsage => st.mode_node_usage,
        Mode::Diagnostic => st.mode_diagnostic,
        Mode::Extract => st.mode_extract,
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" kdt ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            "  ctx={}  ns={}  filter={}  mode={}{}  lang={}",
            app.context_label,
            app.namespace_label,
            app.filter.label(),
            mode_label,
            if app.mode == Mode::Selection && !app.scroll_frozen { "↻" } else { "" },
            app.ai_language.label(),
        )),
    ]));
    f.render_widget(header, header_a);

    if let Some(da) = detail_a {
        draw_detail(f, app, da);
    }

    let visible_rows = table_a.map(|a| a.height.saturating_sub(3) as usize).unwrap_or(0);
    if let Some(ta) = table_a {
        if draw_mode == Mode::Nodes {
            draw_nodes_table(f, app, ta);
        } else {
            let rows: Vec<Row> = match draw_mode {
                Mode::Selection => app.snapshot.iter().map(|r| row_for(r, app.h_scroll)).collect(),
                Mode::DetailFull | Mode::NsPicker | Mode::AiPanel | Mode::Nodes | Mode::NodesFull | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract => unreachable!(),
            };

            let header_row = Row::new(vec![
                Cell::from("TIME"), Cell::from("SEV"), Cell::from("NS"), Cell::from("KIND"),
                Cell::from("NAME"), Cell::from("REASON"), Cell::from("CNT"), Cell::from("MESSAGE"),
            ])
            .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

            let widths = [
                Constraint::Length(8), Constraint::Length(4), Constraint::Length(20),
                Constraint::Length(14), Constraint::Length(40), Constraint::Length(22),
                Constraint::Length(4), Constraint::Min(20),
            ];

            let table = Table::new(rows, widths)
                .header(header_row)
                .block(Block::default().borders(Borders::ALL).title("events"))
                .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
                .highlight_symbol("> ");

            f.render_stateful_widget(table, ta, &mut app.table_state);
        }
    }

    let kbg = Style::default().fg(Color::Black).bg(Color::White);
    let mut footer_spans = match draw_mode {
        Mode::Selection => vec![
            Span::styled(" q ", kbg), Span::raw(format!(" {}   ", st.k_quit)),
            Span::styled(" a ", kbg), Span::raw(" "),
            filter_label(st.lbl_filter_label_all, app.filter == Filter::All),
            Span::raw("   "),
            Span::styled(" w ", kbg), Span::raw(" "),
            filter_label(st.lbl_filter_label_warn, app.filter == Filter::Warnings),
            Span::raw("   "),
            Span::styled(" e ", kbg), Span::raw(" "),
            filter_label(st.lbl_filter_label_err, app.filter == Filter::Errors),
            Span::raw("   "),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" s ", kbg), Span::raw(format!(" {}   ", if app.scroll_frozen { st.k_unfreeze } else { st.k_freeze })),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" Shift+↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" n ", kbg), Span::raw(format!(" {}   ", st.k_namespace)),
            Span::styled(" N ", kbg), Span::raw(format!(" {}   ", st.k_nodes)),
            Span::styled(" D ", kbg), Span::raw(format!(" {}   ", st.k_diag)),
            Span::styled(" X ", kbg), Span::raw(format!(" {}   ", st.k_extract)),
            Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st.k_ai)),
            Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st.k_lang, app.ai_language.label())),
        ],
        Mode::DetailFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st.k_page)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
            Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st.k_ai)),
            Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st.k_lang, app.ai_language.label())),
        ],
        Mode::Nodes => vec![
            Span::styled(" Esc/N ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" u ", kbg), Span::raw(format!(" {}   ", st.k_node_usage)),
            Span::styled(" Shift+↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
            Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st.k_ai)),
            Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st.k_lang, app.ai_language.label())),
        ],
        Mode::NodesFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st.k_page)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
            Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st.k_ai)),
            Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st.k_lang, app.ai_language.label())),
        ],
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract => unreachable!(),
    };
    footer_spans.push(Span::raw("   "));
    footer_spans.push(Span::styled(" m ", kbg));
    footer_spans.push(Span::raw(format!(" {}:{}", st.k_provider, app.ai_provider_name())));
    if let Some(msg) = app.clipboard_status_active() {
        footer_spans.push(Span::raw("   "));
        footer_spans.push(Span::styled(
            msg.to_string(),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(footer_spans)), footer_a);

    if app.mode == Mode::NsPicker {
        draw_ns_picker_popup(f, app, area);
    }
    if app.mode == Mode::NodeUsage
        || (app.mode == Mode::AiPanel && app.return_mode == Mode::NodeUsage)
    {
        draw_node_usage_popup(f, app, area);
    }
    if app.mode == Mode::Diagnostic
        || (app.mode == Mode::AiPanel && app.return_mode == Mode::Diagnostic)
    {
        draw_diagnostic_popup(f, app, area);
    }
    if app.mode == Mode::Extract {
        draw_extract_popup(f, app, area);
    }
    if app.mode == Mode::AiPanel {
        draw_ai_panel_popup(f, app, area);
    }

    visible_rows
}

fn draw_extract_popup(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let s = app.extract_state.lock().expect("extract poisoned").clone();

    let popup_w = (area.width * 70 / 100).max(50).min(area.width);
    let popup_h: u16 = 11;
    let popup_h = popup_h.min(area.height.saturating_sub(2)).max(7);
    let popup_area = centered_rect(popup_w, popup_h, area);

    f.render_widget(Clear, popup_area);

    let pct = if s.total > 0 { (s.current * 100) / s.total.max(1) } else { 0 };
    let bar_w = popup_area.width.saturating_sub(6) as usize;
    let filled = (bar_w * pct.min(100)) / 100;
    let bar: String = std::iter::repeat('█').take(filled).chain(std::iter::repeat('░').take(bar_w.saturating_sub(filled))).collect();

    let elapsed_ms = s
        .elapsed_ms
        .or_else(|| s.started_at.map(|t| t.elapsed().as_millis()))
        .unwrap_or(0);

    let st = lang::t(app.ai_language);
    let title: String = if s.running {
        format!(" {} ", st.title_extraction_running)
    } else if s.error.is_some() {
        format!(" {} ", st.title_extraction_error)
    } else if s.finished {
        format!(" {} ", st.title_extraction_finished)
    } else {
        format!(" {} ", st.title_extraction)
    };

    let mut lines: Vec<Line> = Vec::new();
    if s.running {
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", st.lbl_step), Style::default().fg(DIM)),
            Span::styled(format!("{}/{}", s.current, s.total), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(format!("{}%", pct), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(format!("({:.1}s)", (elapsed_ms as f64) / 1000.0), Style::default().fg(DIM)),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("  {}  ", bar), Style::default().fg(Color::Cyan))));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("→ ", Style::default().fg(Color::Cyan)),
            Span::styled(s.message.clone(), Style::default().fg(Color::White)),
        ]));
    } else if let Some(e) = &s.error {
        lines.push(Line::from(Span::styled(st.lbl_extraction_failed, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(e.clone(), Style::default().fg(Color::Red))));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("  {}", st.lbl_press_esc_close), Style::default().fg(DIM))));
    } else if s.finished {
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", st.lbl_extraction_done), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(format!("({:.1}s)", (elapsed_ms as f64) / 1000.0), Style::default().fg(DIM)),
        ]));
        lines.push(Line::from(""));
        if let Some(p) = &s.output_path {
            lines.push(Line::from(vec![
                Span::styled(format!("{} : ", st.lbl_pdf_pdf_label), Style::default().fg(DIM)),
                Span::styled(p.clone(), Style::default().fg(Color::Cyan)),
            ]));
            lines.push(Line::from(Span::styled("  c pour copier le chemin", Style::default().fg(DIM))));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("  {}", st.lbl_press_esc_close), Style::default().fg(DIM))));
        if let Some(m) = app.clipboard_status_active() {
            lines.push(Line::from(Span::styled(format!("  ✂ {}", m), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
        }
    } else {
        lines.push(Line::from(Span::styled(st.lbl_preparation, Style::default().fg(Color::Yellow))));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(if s.error.is_some() { Color::Red } else if s.finished { Color::Green } else { Color::Cyan }));
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(p, popup_area);
}

fn draw_node_usage_popup(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (rows, loading, error, metrics_available, alloc_cpu, alloc_mem, current_node) = {
        let s = app.node_usage_state.lock().expect("node usage poisoned");
        (s.rows.clone(), s.loading, s.error.clone(), s.metrics_available, s.alloc_cpu_milli, s.alloc_mem_bytes, s.current_node.clone())
    };

    let popup_area = centered_rect(area.width, area.height, area);
    f.render_widget(Clear, popup_area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(6), Constraint::Length(1)])
        .split(popup_area);
    let header_a = layout[0];
    let body_a = layout[1];
    let totals_a = layout[2];
    let footer_a = layout[3];

    let mut sum_cpu_req = 0_i64; let mut sum_cpu_lim = 0_i64; let mut sum_cpu_use = 0_i64;
    let mut sum_mem_req = 0_i64; let mut sum_mem_lim = 0_i64; let mut sum_mem_use = 0_i64;
    for r in &rows {
        sum_cpu_req += r.cpu_req.unwrap_or(0);
        sum_cpu_lim += r.cpu_lim.unwrap_or(0);
        sum_cpu_use += r.cpu_use.unwrap_or(0);
        sum_mem_req += r.mem_req.unwrap_or(0);
        sum_mem_lim += r.mem_lim.unwrap_or(0);
        sum_mem_use += r.mem_use.unwrap_or(0);
    }

    let visible_body_rows = body_a.height.saturating_sub(3) as usize;
    let max_scroll = rows.len().saturating_sub(visible_body_rows);
    if app.node_usage_scroll > max_scroll { app.node_usage_scroll = max_scroll; }

    let st_hdr = lang::t(app.ai_language);
    let header_lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", st_hdr.title_node_usage), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(current_node.unwrap_or_else(|| "?".to_string()), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw("    "),
            Span::styled(format!("{} containers", rows.len()), Style::default().fg(DIM)),
            Span::raw("    "),
            Span::styled(if metrics_available { st_hdr.lbl_metrics_ok } else { st_hdr.lbl_metrics_unavailable },
                Style::default().fg(if metrics_available { Color::Green } else { Color::Yellow })),
            Span::raw("    "),
            Span::styled(format!("{}: {} (s)", st_hdr.k_sort, app.node_usage_sort.label()), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  CPU ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("req={} lim={} use={}", format_cpu_milli(sum_cpu_req), format_cpu_milli(sum_cpu_lim), format_cpu_milli(sum_cpu_use)),
                Style::default().fg(Color::White)),
            Span::raw("  /  alloc="),
            Span::styled(format_cpu_milli(alloc_cpu), Style::default().fg(Color::Cyan)),
            Span::raw("  ("),
            Span::styled(format!("{}% req", pct_local(sum_cpu_req, alloc_cpu)), Style::default().fg(pct_color(pct_local(sum_cpu_req, alloc_cpu)))),
            Span::raw(", "),
            Span::styled(format!("{}% use", pct_local(sum_cpu_use, alloc_cpu)), Style::default().fg(pct_color(pct_local(sum_cpu_use, alloc_cpu)))),
            Span::raw(")    "),
            Span::styled("MEM ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("req={} lim={} use={}", format_memory_bytes(sum_mem_req), format_memory_bytes(sum_mem_lim), format_memory_bytes(sum_mem_use)),
                Style::default().fg(Color::White)),
            Span::raw("  /  alloc="),
            Span::styled(format_memory_bytes(alloc_mem), Style::default().fg(Color::Cyan)),
            Span::raw("  ("),
            Span::styled(format!("{}% req", pct_local(sum_mem_req, alloc_mem)), Style::default().fg(pct_color(pct_local(sum_mem_req, alloc_mem)))),
            Span::raw(", "),
            Span::styled(format!("{}% use", pct_local(sum_mem_use, alloc_mem)), Style::default().fg(pct_color(pct_local(sum_mem_use, alloc_mem)))),
            Span::raw(")"),
        ]),
        Line::from(""),
    ];
    f.render_widget(
        Paragraph::new(header_lines).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan))),
        header_a,
    );

    let st = lang::t(app.ai_language);
    if loading && rows.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(st.lbl_loading, Style::default().fg(Color::Yellow))))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, body_a);
    } else if let Some(e) = error {
        let p = Paragraph::new(Line::from(Span::styled(e, Style::default().fg(Color::Red))))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red)));
        f.render_widget(p, body_a);
    } else {
        let header_row = Row::new(vec![
            Cell::from(" "), Cell::from("NS"), Cell::from("POD"), Cell::from("CONTAINER"),
            Cell::from("CPU req"), Cell::from("CPU lim"), Cell::from("CPU use"),
            Cell::from("MEM req"), Cell::from("MEM lim"), Cell::from("MEM use"),
            Cell::from("R"), Cell::from("RST"), Cell::from("ISSUES"),
        ])
        .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

        let opt_or_dash = |v: Option<i64>, fmt: fn(i64) -> String| -> String {
            v.map(fmt).unwrap_or_else(|| "—".to_string())
        };

        let mut missing_req = 0usize;
        let mut over_req = 0usize;
        let mut excessive_lim = 0usize;
        let mut at_limit = 0usize;

        let mut sorted_rows: Vec<&crate::events::PodUsageRow> = rows.iter().collect();
        match app.node_usage_sort {
            NodeUsageSort::MemReq => sorted_rows.sort_by(|a, b| {
                a.is_system.cmp(&b.is_system)
                    .then(b.mem_req.unwrap_or(-1).cmp(&a.mem_req.unwrap_or(-1)))
                    .then(a.namespace.cmp(&b.namespace))
                    .then(a.pod.cmp(&b.pod))
                    .then(a.container.cmp(&b.container))
            }),
            NodeUsageSort::CpuReq => sorted_rows.sort_by(|a, b| {
                a.is_system.cmp(&b.is_system)
                    .then(b.cpu_req.unwrap_or(-1).cmp(&a.cpu_req.unwrap_or(-1)))
                    .then(a.namespace.cmp(&b.namespace))
                    .then(a.pod.cmp(&b.pod))
                    .then(a.container.cmp(&b.container))
            }),
            NodeUsageSort::Alpha => sorted_rows.sort_by(|a, b| {
                a.is_system.cmp(&b.is_system)
                    .then(a.namespace.cmp(&b.namespace))
                    .then(a.pod.cmp(&b.pod))
                    .then(a.container.cmp(&b.container))
            }),
        }

        let body_rows: Vec<Row> = sorted_rows.iter().skip(app.node_usage_scroll).map(|&r| {
            let cpu_at_limit = matches!((r.cpu_use, r.cpu_lim), (Some(u), Some(l)) if l > 0 && u >= l);
            let mem_at_limit = matches!((r.mem_use, r.mem_lim), (Some(u), Some(l)) if l > 0 && u >= l);
            if cpu_at_limit || mem_at_limit { at_limit += 1; }

            let cpu_use_color = if let (Some(u), Some(l)) = (r.cpu_use, r.cpu_lim) {
                if l > 0 && u >= l { Color::Red }
                else if l > 0 && u * 100 / l >= 80 { Color::Yellow }
                else { Color::Green }
            } else { Color::Gray };
            let mem_use_color = if let (Some(u), Some(l)) = (r.mem_use, r.mem_lim) {
                if l > 0 && u >= l { Color::Red }
                else if l > 0 && u * 100 / l >= 80 { Color::Yellow }
                else { Color::Green }
            } else { Color::Gray };

            let cpu_req_under_used = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(use_)) if req > 0 && use_ * 100 / req < 30);
            let mem_req_under_used = matches!((r.mem_req, r.mem_use), (Some(req), Some(use_)) if req > 0 && use_ * 100 / req < 30);
            let cpu_extreme = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(use_)) if req > 0 && use_ * 100 / req < 5);
            let mem_extreme = matches!((r.mem_req, r.mem_use), (Some(req), Some(use_)) if req > 0 && use_ * 100 / req < 5);
            if cpu_req_under_used || mem_req_under_used { over_req += 1; }
            if r.cpu_req.is_none() || r.mem_req.is_none() { missing_req += 1; }

            let cpu_lim_excessive = matches!((r.cpu_lim, r.cpu_req), (Some(lim), Some(req)) if req > 0 && lim > req * 4);
            let mem_lim_excessive = matches!((r.mem_lim, r.mem_req), (Some(lim), Some(req)) if req > 0 && lim > req * 4);
            if cpu_lim_excessive || mem_lim_excessive { excessive_lim += 1; }

            let cpu_req_bg = incidence_bg(r.cpu_req, alloc_cpu);
            let cpu_lim_bg = incidence_bg(r.cpu_lim, alloc_cpu);
            let cpu_use_bg = incidence_bg(r.cpu_use, alloc_cpu);
            let mem_req_bg = incidence_bg(r.mem_req, alloc_mem);
            let mem_lim_bg = incidence_bg(r.mem_lim, alloc_mem);
            let mem_use_bg = incidence_bg(r.mem_use, alloc_mem);

            let apply_bg = |bg: Option<Color>, missing: bool| -> Style {
                let mut s = Style::default();
                if missing {
                    s = s.fg(Color::Red).add_modifier(Modifier::BOLD);
                } else if let Some(c) = bg {
                    s = s.bg(c).fg(Color::White).add_modifier(Modifier::BOLD);
                }
                s
            };
            let cpu_req_style = apply_bg(cpu_req_bg, r.cpu_req.is_none());
            let mem_req_style = apply_bg(mem_req_bg, r.mem_req.is_none());
            let cpu_lim_style = if r.cpu_lim.is_none() { Style::default().fg(DIM) } else { apply_bg(cpu_lim_bg, false) };
            let mem_lim_style = apply_bg(mem_lim_bg, r.mem_lim.is_none());

            let mut issues: Vec<&str> = Vec::new();
            if r.cpu_req.is_none() { issues.push("noCpuReq"); }
            if r.mem_req.is_none() { issues.push("noMemReq"); }
            if r.mem_lim.is_none() { issues.push("noMemLim"); }
            if cpu_extreme { issues.push("cpuOver!!"); }
            else if cpu_req_under_used { issues.push("cpuOver"); }
            if mem_extreme { issues.push("memOver!!"); }
            else if mem_req_under_used { issues.push("memOver"); }
            if cpu_lim_excessive { issues.push("cpuLim≫"); }
            if mem_lim_excessive { issues.push("memLim≫"); }
            if cpu_at_limit { issues.push("cpuMax"); }
            if mem_at_limit { issues.push("OOMrisk"); }
            let issues_text = issues.join(",");
            let issues_color = if issues.iter().any(|s| matches!(*s, "OOMrisk" | "cpuMax" | "noMemReq" | "noCpuReq" | "noMemLim")) {
                Color::Red
            } else if !issues.is_empty() {
                Color::Yellow
            } else {
                DIM
            };

            let ready_label = if r.ready { "Y" } else { "N" };
            let ready_color = if r.ready { Color::Green } else { Color::Red };
            let restart_color = if r.restarts >= 5 { Color::Red } else if r.restarts >= 1 { Color::Yellow } else { DIM };

            let _ = (cpu_req_under_used, mem_req_under_used, cpu_extreme, mem_extreme, cpu_lim_excessive, mem_lim_excessive);

            let ns_prefix = if r.is_system { "·" } else { " " };
            let ns_color = if r.is_system { SYS_DIM } else { DIM };
            let pod_color = if r.is_system { SYS_DIM } else { Color::Reset };
            let cont_color = if r.is_system { SYS_DIM } else { Color::Cyan };

            let cpu_use_style = if r.cpu_use.is_none() {
                Style::default().fg(cpu_use_color)
            } else if let Some(bg) = cpu_use_bg {
                Style::default().bg(bg).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(cpu_use_color)
            };
            let mem_use_style = if r.mem_use.is_none() {
                Style::default().fg(mem_use_color)
            } else if let Some(bg) = mem_use_bg {
                Style::default().bg(bg).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(mem_use_color)
            };

            Row::new(vec![
                Cell::from(ns_prefix).style(Style::default().fg(SYS_DIM)),
                Cell::from(r.namespace.clone()).style(Style::default().fg(ns_color)),
                Cell::from(r.pod.clone()).style(Style::default().fg(pod_color)),
                Cell::from(r.container.clone()).style(Style::default().fg(cont_color)),
                Cell::from(opt_or_dash(r.cpu_req, format_cpu_milli)).style(cpu_req_style),
                Cell::from(opt_or_dash(r.cpu_lim, format_cpu_milli)).style(cpu_lim_style),
                Cell::from(opt_or_dash(r.cpu_use, format_cpu_milli)).style(cpu_use_style),
                Cell::from(opt_or_dash(r.mem_req, format_memory_bytes)).style(mem_req_style),
                Cell::from(opt_or_dash(r.mem_lim, format_memory_bytes)).style(mem_lim_style),
                Cell::from(opt_or_dash(r.mem_use, format_memory_bytes)).style(mem_use_style),
                Cell::from(ready_label).style(Style::default().fg(ready_color).add_modifier(Modifier::BOLD)),
                Cell::from(r.restarts.to_string()).style(Style::default().fg(restart_color)),
                Cell::from(issues_text).style(Style::default().fg(issues_color).add_modifier(if issues_color == Color::Red { Modifier::BOLD } else { Modifier::empty() })),
            ])
        }).collect();

        let widths = [
            Constraint::Length(1), Constraint::Length(20), Constraint::Min(20), Constraint::Length(20),
            Constraint::Length(8), Constraint::Length(8), Constraint::Length(8),
            Constraint::Length(9), Constraint::Length(9), Constraint::Length(9),
            Constraint::Length(2), Constraint::Length(4), Constraint::Min(28),
        ];
        let user_count = rows.iter().filter(|r| !r.is_system).count();
        let sys_count = rows.iter().filter(|r| r.is_system).count();
        let title = format!(
            " {} user + {} system (·) · {} req-manquant · {} sur-provisionné · {} lim-excessif · {} à-la-limite ",
            user_count, sys_count, missing_req, over_req, excessive_lim, at_limit,
        );
        let table = Table::new(body_rows, widths)
            .header(header_row)
            .block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(table, body_a);
    }

    let st_f = lang::t(app.ai_language);
    let totals_title = format!(" {} ", st_f.lbl_node_diagnostic);
    f.render_widget(
        Paragraph::new(build_totals_lines(&rows, alloc_cpu, alloc_mem))
            .block(Block::default().borders(Borders::ALL).title(totals_title)),
        totals_a,
    );

    let kbg = Style::default().fg(Color::Black).bg(Color::White);
    let mut spans = vec![
        Span::styled(" Esc/u ", kbg), Span::raw(format!(" {}   ", st_f.k_close)),
        Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st_f.k_scroll)),
        Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st_f.k_page)),
        Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st_f.k_top_bot)),
        Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st_f.k_refresh)),
        Span::styled(" s ", kbg), Span::raw(format!(" {}:{}   ", st_f.k_sort, app.node_usage_sort.label())),
        Span::styled(" p ", kbg), Span::raw(format!(" {}   ", st_f.k_pdf)),
        Span::styled(" c ", kbg), Span::raw(" copier   "),
        Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st_f.k_ai)),
        Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st_f.k_lang, app.ai_language.label())),
    ];
    if let Some(m) = app.clipboard_status_active() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(format!("✂ {}", m), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    }
    let footer = Paragraph::new(Line::from(spans));
    f.render_widget(footer, footer_a);
}

fn build_totals_lines(rows: &[crate::events::PodUsageRow], alloc_cpu: i64, alloc_mem: i64) -> Vec<Line<'static>> {
    use crate::events::{format_cpu_milli, format_memory_bytes};
    let (mut u_cr, mut u_cl, mut u_cu) = (0_i64, 0_i64, 0_i64);
    let (mut u_mr, mut u_ml, mut u_mu) = (0_i64, 0_i64, 0_i64);
    let (mut s_cr, mut s_cl, mut s_cu) = (0_i64, 0_i64, 0_i64);
    let (mut s_mr, mut s_ml, mut s_mu) = (0_i64, 0_i64, 0_i64);
    let (mut un, mut sn) = (0usize, 0usize);
    for r in rows {
        if r.is_system {
            sn += 1;
            s_cr += r.cpu_req.unwrap_or(0); s_cl += r.cpu_lim.unwrap_or(0); s_cu += r.cpu_use.unwrap_or(0);
            s_mr += r.mem_req.unwrap_or(0); s_ml += r.mem_lim.unwrap_or(0); s_mu += r.mem_use.unwrap_or(0);
        } else {
            un += 1;
            u_cr += r.cpu_req.unwrap_or(0); u_cl += r.cpu_lim.unwrap_or(0); u_cu += r.cpu_use.unwrap_or(0);
            u_mr += r.mem_req.unwrap_or(0); u_ml += r.mem_lim.unwrap_or(0); u_mu += r.mem_use.unwrap_or(0);
        }
    }
    let t_cr = u_cr + s_cr; let t_cl = u_cl + s_cl; let t_cu = u_cu + s_cu;
    let t_mr = u_mr + s_mr; let t_ml = u_ml + s_ml; let t_mu = u_mu + s_mu;
    let cpu_waste = (t_cr - t_cu).max(0);
    let mem_waste = (t_mr - t_mu).max(0);
    let waste_cpu_pct = if t_cr > 0 { cpu_waste * 100 / t_cr } else { 0 };
    let waste_mem_pct = if t_mr > 0 { mem_waste * 100 / t_mr } else { 0 };

    let label = |s: &'static str, color: Color| Span::styled(s, Style::default().fg(color).add_modifier(Modifier::BOLD));
    let val   = |s: String, color: Color| Span::styled(s, Style::default().fg(color));
    let dim   = |s: String| Span::styled(s, Style::default().fg(DIM));
    let plain = |s: &'static str| Span::raw(s);

    fn line_for(
        label_text: &'static str,
        label_color: Color,
        n: usize,
        cr: i64, cl: i64, cu: i64,
        mr: i64, ml: i64, mu: i64,
        alloc_cpu: i64, alloc_mem: i64,
    ) -> Line<'static> {
        use crate::events::{format_cpu_milli, format_memory_bytes};
        let pct_cr = if alloc_cpu > 0 { cr * 100 / alloc_cpu } else { 0 };
        let pct_cl = if alloc_cpu > 0 { cl * 100 / alloc_cpu } else { 0 };
        let pct_cu = if alloc_cpu > 0 { cu * 100 / alloc_cpu } else { 0 };
        let pct_mr = if alloc_mem > 0 { mr * 100 / alloc_mem } else { 0 };
        let pct_ml = if alloc_mem > 0 { ml * 100 / alloc_mem } else { 0 };
        let pct_mu = if alloc_mem > 0 { mu * 100 / alloc_mem } else { 0 };
        Line::from(vec![
            Span::styled(format!("{:<6}", label_text), Style::default().fg(label_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("({:>3}) ", n), Style::default().fg(DIM)),
            Span::raw("cpu req="), Span::styled(format!("{:<7}", format_cpu_milli(cr)), Style::default().fg(Color::White)),
            Span::styled(format!("({:>3}%) ", pct_cr), Style::default().fg(pct_color(pct_cr))),
            Span::raw("lim="), Span::styled(format!("{:<7}", format_cpu_milli(cl)), Style::default().fg(Color::White)),
            Span::styled(format!("({:>3}%) ", pct_cl), Style::default().fg(pct_color(pct_cl))),
            Span::raw("use="), Span::styled(format!("{:<7}", format_cpu_milli(cu)), Style::default().fg(Color::Green)),
            Span::styled(format!("({:>3}%)  ", pct_cu), Style::default().fg(DIM)),
            Span::raw("mem req="), Span::styled(format!("{:<8}", format_memory_bytes(mr)), Style::default().fg(Color::White)),
            Span::styled(format!("({:>3}%) ", pct_mr), Style::default().fg(pct_color(pct_mr))),
            Span::raw("lim="), Span::styled(format!("{:<8}", format_memory_bytes(ml)), Style::default().fg(Color::White)),
            Span::styled(format!("({:>3}%) ", pct_ml), Style::default().fg(pct_color(pct_ml))),
            Span::raw("use="), Span::styled(format!("{:<8}", format_memory_bytes(mu)), Style::default().fg(Color::Green)),
            Span::styled(format!("({:>3}%)", pct_mu), Style::default().fg(DIM)),
        ])
    }

    let _ = (label, val, dim, plain);
    vec![
        line_for("USER",  Color::Cyan, un, u_cr, u_cl, u_cu, u_mr, u_ml, u_mu, alloc_cpu, alloc_mem),
        line_for("SYS",   SYS_DIM,    sn, s_cr, s_cl, s_cu, s_mr, s_ml, s_mu, alloc_cpu, alloc_mem),
        line_for("TOTAL", Color::White, un + sn, t_cr, t_cl, t_cu, t_mr, t_ml, t_mu, alloc_cpu, alloc_mem),
        Line::from(vec![
            Span::styled(format!("{:<6}", "WASTE"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("(req-use) ", Style::default().fg(DIM)),
            Span::raw("cpu="), Span::styled(format_cpu_milli(cpu_waste), Style::default().fg(Color::Yellow)),
            Span::styled(format!(" ({}% non utilisé)  ", waste_cpu_pct), Style::default().fg(if waste_cpu_pct > 50 { Color::Yellow } else { DIM })),
            Span::raw("mem="), Span::styled(format_memory_bytes(mem_waste), Style::default().fg(Color::Yellow)),
            Span::styled(format!(" ({}% non utilisé)", waste_mem_pct), Style::default().fg(if waste_mem_pct > 50 { Color::Yellow } else { DIM })),
        ]),
    ]
}

fn pct_local(v: i64, total: i64) -> i64 {
    if total > 0 { v.saturating_mul(100) / total } else { 0 }
}

fn pct_color(p: i64) -> Color {
    if p >= 100 { Color::Red }
    else if p >= 80 { Color::Yellow }
    else if p >= 50 { Color::Cyan }
    else { Color::Green }
}

fn incidence_bg(value: Option<i64>, alloc: i64) -> Option<Color> {
    let v = value?;
    if alloc <= 0 || v <= 0 { return None; }
    let pct = v.saturating_mul(1000) / alloc;
    if pct >= 300 { Some(Color::Rgb(200, 30, 30)) }
    else if pct >= 200 { Some(Color::Rgb(170, 45, 45)) }
    else if pct >= 120 { Some(Color::Rgb(140, 55, 55)) }
    else if pct >= 60 { Some(Color::Rgb(110, 60, 60)) }
    else if pct >= 20 { Some(Color::Rgb(80, 55, 55)) }
    else { None }
}

fn diag_status_color(s: DiagStatus) -> Color {
    match s {
        DiagStatus::Running => Color::Cyan,
        DiagStatus::Ok => Color::Green,
        DiagStatus::Info => Color::Blue,
        DiagStatus::Warn => Color::Yellow,
        DiagStatus::Err => Color::Red,
    }
}

fn line_color_to_style(c: LineColor) -> Style {
    match c {
        LineColor::Plain => Style::default(),
        LineColor::Ok => Style::default().fg(Color::Green),
        LineColor::Warn => Style::default().fg(Color::Yellow),
        LineColor::Err => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        LineColor::Info => Style::default().fg(Color::Cyan),
        LineColor::Dim => Style::default().fg(DIM),
    }
}

fn draw_diagnostic_popup(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (running, finished, started_at, elapsed_ms, steps, current_step) = {
        let s = app.diagnostic_state.lock().expect("diagnostic poisoned");
        (s.running, s.finished, s.started_at, s.elapsed_ms, s.steps.clone(), s.current_step)
    };

    let popup_area = centered_rect(area.width, area.height, area);
    f.render_widget(Clear, popup_area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)])
        .split(popup_area);
    let header_a = layout[0];
    let body_a = layout[1];
    let footer_a = layout[2];

    let mut ok_n = 0usize; let mut warn_n = 0usize; let mut err_n = 0usize; let mut info_n = 0usize;
    for s in &steps {
        match s.status {
            DiagStatus::Ok => ok_n += 1,
            DiagStatus::Warn => warn_n += 1,
            DiagStatus::Err => err_n += 1,
            DiagStatus::Info => info_n += 1,
            _ => {}
        }
    }
    let st = lang::t(app.ai_language);
    let elapsed = elapsed_ms
        .map(|m| format!("{} ms", m))
        .or_else(|| started_at.map(|t| format!("{} ms", t.elapsed().as_millis())))
        .unwrap_or_else(|| "—".to_string());
    let state_label = if running { st.lbl_running } else if finished { st.lbl_finished } else { st.lbl_ready };

    let header_lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", st.title_diagnostic), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(app.context_label.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw("    "),
            Span::styled(state_label, Style::default().fg(if running { Color::Cyan } else if err_n > 0 { Color::Red } else if warn_n > 0 { Color::Yellow } else { Color::Green })),
            Span::raw("    "),
            Span::styled(format!("{} {}", steps.len(), st.lbl_steps), Style::default().fg(DIM)),
            Span::raw("    "),
            Span::styled(format!("ok={} info={} warn={} err={}", ok_n, info_n, warn_n, err_n),
                Style::default().fg(Color::White)),
            Span::raw("    "),
            Span::styled(format!("{}: {}", st.lbl_duration, elapsed), Style::default().fg(DIM)),
        ]),
        Line::from(Span::styled(
            format!("`i` {}", st.ai_send_to_ai_legend),
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    f.render_widget(
        Paragraph::new(header_lines).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan))),
        header_a,
    );

    let mut all_lines: Vec<Line> = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        let status_color = diag_status_color(s.status);
        let is_current = current_step == Some(i);
        let title_style = if is_current {
            Style::default().fg(Color::White).bg(Color::Rgb(40, 40, 70)).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        };
        all_lines.push(Line::from(vec![
            Span::styled(format!(" {} ", s.status.label()), Style::default().fg(Color::Black).bg(status_color).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled(s.title.clone(), title_style),
        ]));
        all_lines.push(Line::from(vec![
            Span::styled("   $ ", Style::default().fg(DIM)),
            Span::styled(s.command.clone(), Style::default().fg(Color::Cyan)),
        ]));
        for (lc, txt) in &s.lines {
            all_lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(txt.clone(), line_color_to_style(*lc)),
            ]));
        }
        all_lines.push(Line::from(""));
    }
    if all_lines.is_empty() {
        all_lines.push(Line::from(Span::styled(
            st.lbl_preparation,
            Style::default().fg(Color::Yellow),
        )));
    }

    let visible_h = body_a.height.saturating_sub(2) as usize;
    let max_scroll = all_lines.len().saturating_sub(visible_h);
    if app.diagnostic_scroll > max_scroll { app.diagnostic_scroll = max_scroll; }

    let p = Paragraph::new(all_lines)
        .scroll((app.diagnostic_scroll as u16, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ({} ok / {} warn / {} err) ", st.lbl_steps, ok_n, warn_n, err_n)),
        );
    f.render_widget(p, body_a);

    let kbg = Style::default().fg(Color::Black).bg(Color::White);
    let mut spans = vec![
        Span::styled(" Esc/q ", kbg), Span::raw(format!(" {}   ", st.k_close)),
        Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
        Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st.k_page)),
        Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_relaunch)),
        Span::styled(" p ", kbg), Span::raw(format!(" {}   ", st.k_pdf)),
        Span::styled(" c ", kbg), Span::raw(" copier   "),
        Span::styled(" i ", kbg), Span::raw(format!(" {}   ", st.k_send_to_ai)),
        Span::styled(" l ", kbg), Span::raw(format!(" {}:{}", st.k_lang, app.ai_language.label())),
    ];
    if let Some(m) = app.clipboard_status_active() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(format!("✂ {}", m), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    }
    let footer = Paragraph::new(Line::from(spans));
    f.render_widget(footer, footer_a);
}

fn draw_ai_panel_popup(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, content, error, stage, started_at, sections_count, model, export_status) = {
        let s = app.ai_state.lock().expect("ai state poisoned");
        (s.loading, s.content.clone(), s.error.clone(), s.stage.clone(), s.started_at, s.sections_count, s.model.clone(), s.export_status.clone())
    };

    let popup_width = (area.width * 80 / 100).max(60).min(area.width);
    let popup_height = (area.height * 80 / 100).max(15).min(area.height);
    let popup_area = centered_rect(popup_width, popup_height, area);

    f.render_widget(Clear, popup_area);

    let st = lang::t(app.ai_language);
    let pdf_capable = matches!(app.return_mode, Mode::Diagnostic | Mode::NodeUsage);
    let extra_keys = if pdf_capable { format!("  p {}", st.k_pdf) } else { String::new() };
    let export_suffix = export_status
        .as_ref()
        .map(|s| format!("  · {}", s))
        .unwrap_or_default();
    let clip_suffix = app
        .clipboard_status_active()
        .map(|m| format!("  · ✂ {}", m))
        .unwrap_or_default();
    let title = format!(
        " {} [{} · {}]  ↑↓ {}  PgUp/PgDn {}  g/G {}  l {}  m {}{}  c copier  Esc {}{}{} ",
        st.title_ai_analysis,
        app.ai_language.label(),
        app.ai_provider_name(),
        st.k_scroll,
        st.k_page,
        st.k_top_bot,
        st.k_lang,
        st.k_provider,
        extra_keys,
        st.k_close,
        export_suffix,
        clip_suffix,
    );

    let (lines, border_color): (Vec<Line<'static>>, Color) = if let Some(e) = error {
        (
            e.lines().map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(Color::Red)))).collect(),
            Color::Red,
        )
    } else if loading && content.is_empty() {
        (loading_lines(&stage, started_at, sections_count, &model, app.ai_language), Color::Yellow)
    } else if content.is_empty() {
        (vec![Line::from("(réponse vide)")], DIM)
    } else {
        (render_markdown_lines(&content, popup_width.saturating_sub(2) as usize), Color::Cyan)
    };

    let inner_h = popup_height.saturating_sub(2) as usize;
    let total = lines.len();
    let max_scroll = total.saturating_sub(inner_h);
    if app.ai_scroll > max_scroll { app.ai_scroll = max_scroll; }

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.ai_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(border_color)));
    f.render_widget(p, popup_area);
}

fn draw_ns_picker_popup(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let (namespaces, loading, error) = {
        let s = app.ns_pick_state.lock().expect("ns list poisoned");
        (s.namespaces.clone(), s.loading, s.error.clone())
    };

    let popup_width = (area.width * 55 / 100).max(40).min(area.width);
    let items_count = namespaces.len() + 1;
    let popup_height = (items_count as u16 + 4).min(area.height.saturating_sub(4)).max(5);
    let popup_area = centered_rect(popup_width, popup_height, area);

    f.render_widget(Clear, popup_area);

    let st = lang::t(app.ai_language);
    let title = format!(" {} ", st.lbl_select_namespace);

    if loading {
        let p = Paragraph::new(st.lbl_loading)
            .block(Block::default().borders(Borders::ALL).title(title.clone()).border_style(Style::default().fg(Color::Cyan)));
        f.render_widget(p, popup_area);
        return;
    }

    if let Some(e) = error {
        let p = Paragraph::new(Span::styled(e, Style::default().fg(Color::Red)))
            .block(Block::default().borders(Borders::ALL).title(title.clone()).border_style(Style::default().fg(Color::Red)));
        f.render_widget(p, popup_area);
        return;
    }

    let mut items: Vec<ListItem> = vec![
        ListItem::new(format!(" {}", st.lbl_all_namespaces)).style(Style::default().fg(Color::Cyan)),
    ];
    for ns in &namespaces {
        items.push(ListItem::new(format!(" {}", ns)));
    }

    let mut list_state = ListState::default();
    list_state.select(Some(app.ns_cursor));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(Color::Cyan)))
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, popup_area, &mut list_state);
}

fn draw_nodes_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (nodes, loading, error) = {
        let s = app.node_list_state.lock().expect("node list poisoned");
        (s.nodes.clone(), s.loading, s.error.clone())
    };

    if let Some(target) = app.pending_node_select.clone() {
        if let Some(pos) = nodes.iter().position(|n| n.name == target) {
            app.node_cursor = pos;
            app.pending_node_select = None;
            app.last_node_status_key = None;
            app.maybe_fetch_node_status();
        } else if !loading && !nodes.is_empty() {
            app.pending_node_select = None;
        }
    }

    let title = if loading {
        format!("nodes ({}, loading...)", nodes.len())
    } else if let Some(e) = &error {
        format!("nodes (erreur: {})", e)
    } else {
        format!("nodes ({})", nodes.len())
    };

    let header_row = Row::new(vec![
        Cell::from("NAME"), Cell::from("READY"), Cell::from("ROLES"),
        Cell::from("VERSION"), Cell::from("AGE"), Cell::from("ALERTS"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = nodes.iter().map(|n| {
        let ready_color = if n.ready == "True" { Color::Green } else { Color::Red };
        let row_style = if !n.schedulable || !n.abnormal.is_empty() {
            Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0))
        } else if n.ready != "True" {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let alerts = {
            let mut a = n.abnormal.clone();
            if !n.schedulable { a.insert(0, "Cordoned".into()); }
            if a.is_empty() { String::new() } else { a.join(",") }
        };
        let alert_color = if alerts.is_empty() { DIM } else { Color::Red };
        Row::new(vec![
            Cell::from(n.name.clone()),
            Cell::from(n.ready.clone()).style(Style::default().fg(ready_color).add_modifier(Modifier::BOLD)),
            Cell::from(n.roles.clone()).style(Style::default().fg(Color::Cyan)),
            Cell::from(n.version.clone()).style(Style::default().fg(DIM)),
            Cell::from(n.age.clone()).style(Style::default().fg(DIM)),
            Cell::from(alerts).style(Style::default().fg(alert_color).add_modifier(Modifier::BOLD)),
        ])
        .style(row_style)
    }).collect();

    let widths = [
        Constraint::Min(30), Constraint::Length(7), Constraint::Length(20),
        Constraint::Length(14), Constraint::Length(8), Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    let mut state = TableState::default();
    state.select(Some(app.node_cursor));
    f.render_stateful_widget(table, area, &mut state);
}

fn loading_lines(
    stage: &str,
    started_at: Option<std::time::Instant>,
    sections_count: usize,
    model: &str,
    lang: AiLanguage,
) -> Vec<Line<'static>> {
    let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let spinner = spinner_chars[(now_ms / 100) as usize % spinner_chars.len()];

    let elapsed_secs = started_at.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
    let elapsed = format!("{:.1}s", elapsed_secs);

    let mut dots = String::new();
    for _ in 0..((now_ms / 400) as usize % 4) { dots.push('.'); }

    let st = lang::t(lang);
    let stage_text = if stage.is_empty() { st.lbl_preparation.to_string() } else { stage.to_string() };
    let (elapsed_label, resources_label, model_label, lang_label, hint) = match lang {
        AiLanguage::Fr => ("⏱ écoulé : ", "◆ ressources collectées : ", "⌨ modèle : ", "    langue : ", "    (les requêtes longues peuvent prendre 30-60s sur de gros prompts)"),
        AiLanguage::En => ("⏱ elapsed: ",  "◆ resources collected: ",   "⌨ model: ",   "    language: ", "    (long requests may take 30-60s for large prompts)"),
    };
    let _ = st;

    vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{} ", spinner), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(stage_text, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(dots, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(elapsed_label, Style::default().fg(DIM)),
            Span::styled(elapsed, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(resources_label, Style::default().fg(DIM)),
            Span::styled(sections_count.to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(model_label, Style::default().fg(DIM)),
            Span::styled(model.to_string(), Style::default().fg(Color::Cyan)),
            Span::styled(lang_label, Style::default().fg(DIM)),
            Span::styled(lang.label().to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            hint,
            Style::default().fg(DIM),
        )),
    ]
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

fn draw_detail(f: &mut ratatui::Frame, app: &mut App, area: ratatui::layout::Rect) {
    let is_node_mode = matches!(app.mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage));
    let title = if is_node_mode {
        let name = {
            let s = app.node_list_state.lock().expect("node list poisoned");
            s.nodes.get(app.node_cursor).map(|n| n.name.clone()).unwrap_or_default()
        };
        Line::from(Span::styled(
            format!(" Node detail: {} ", name),
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(vec![
            tab_span("Logs", app.detail_tab == DetailTab::Logs),
            Span::raw(" │ "),
            tab_span("Status", app.detail_tab == DetailTab::Status),
            Span::raw(" │ "),
            tab_span("Related", app.detail_tab == DetailTab::Related),
        ])
    };

    let lines: Vec<Line<'static>> = if is_node_mode {
        status_lines(app)
    } else {
        match app.detail_tab {
            DetailTab::Logs => log_lines(app),
            DetailTab::Status => status_lines(app),
            DetailTab::Related => related_lines(app),
        }
    };

    let visible = area.height.saturating_sub(2) as usize;
    let total = lines.len();
    let max_scroll = total.saturating_sub(visible);

    let scroll_offset = {
        let target = app.scroll_target();
        if *target > max_scroll { *target = max_scroll; }
        *target
    };

    let scroll = if total > visible {
        (total - visible).saturating_sub(scroll_offset) as u16
    } else {
        0
    };

    let p = Paragraph::new(lines)
        .scroll((scroll, app.detail_h_scroll as u16))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}


fn tab_span(label: &str, active: bool) -> Span<'static> {
    if active {
        Span::styled(
            format!(" {} ", label),
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!(" {} ", label), Style::default().fg(Color::Gray))
    }
}

fn filter_label(label: &str, active: bool) -> Span<'static> {
    let style = if active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    Span::styled(label.to_string(), style)
}

fn log_lines(app: &App) -> Vec<Line<'static>> {
    let s = app.log_state.lock().expect("log state poisoned");
    if let Some(e) = &s.error {
        return vec![Line::from(Span::styled(e.clone(), Style::default().fg(Color::Red)))];
    }
    if s.loading && s.lines.is_empty() {
        return vec![Line::from("(loading...)")];
    }
    s.lines.iter().map(|l| colorize_log_line(l)).collect()
}

fn colorize_log_line(l: &str) -> Line<'static> {
    if l.starts_with("══ ") {
        return Line::from(Span::styled(
            l.to_string(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    }
    if l.starts_with("(aucun log)") || l.starts_with("(échec récupération logs") {
        return Line::from(Span::styled(l.to_string(), Style::default().fg(DIM)));
    }
    let bytes = l.as_bytes();
    if bytes.len() > 5
        && matches!(bytes[0], b'I' | b'W' | b'E' | b'F')
        && bytes[1..5].iter().all(|c| c.is_ascii_digit())
    {
        let style = match bytes[0] {
            b'E' | b'F' => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            b'W' => Style::default().fg(Color::Yellow),
            _ => Style::default().fg(Color::Gray),
        };
        return Line::from(Span::styled(l.to_string(), style));
    }
    let lower = l.to_lowercase();
    let style = if lower.contains("error")
        || lower.contains("err]") || lower.contains("[err ")
        || lower.contains("fatal") || lower.contains("panic")
        || lower.contains("\"error\"") || lower.contains("level=error")
        || lower.contains(" failed") || lower.starts_with("failed")
    {
        Style::default().fg(Color::Red)
    } else if lower.contains("warn") || lower.contains("\"warning\"") || lower.contains("level=warn") {
        Style::default().fg(Color::Yellow)
    } else if lower.contains("debug") || lower.contains("trace") || lower.contains("level=debug") {
        Style::default().fg(DIM)
    } else if lower.contains("info") || lower.contains("level=info") {
        Style::default().fg(Color::Gray)
    } else if l.starts_with("    at ") || l.starts_with("\tat ") || l.starts_with("Caused by") {
        Style::default().fg(DIM)
    } else {
        Style::default()
    };
    Line::from(Span::styled(l.to_string(), style))
}

fn status_lines(app: &App) -> Vec<Line<'static>> {
    let s = app.status_state.lock().expect("status state poisoned");
    if let Some(e) = &s.error {
        return vec![Line::from(Span::styled(e.clone(), Style::default().fg(Color::Red)))];
    }
    if s.loading && s.lines.is_empty() {
        return vec![Line::from("(loading...)")];
    }
    s.lines
        .iter()
        .map(|(c, t)| Line::from(Span::styled(t.clone(), Style::default().fg(line_color(*c)))))
        .collect()
}

fn related_lines(app: &App) -> Vec<Line<'static>> {
    let Some(idx) = app.table_state.selected() else { return Vec::new(); };
    let Some(rec) = app.snapshot.get(idx) else { return Vec::new(); };
    let target_ns = rec.namespace.clone();
    let target_name = rec.name.clone();
    let target_kind = rec.kind.clone();

    let mut lines: Vec<Line<'static>> = Vec::new();

    let event_lines: Vec<Line<'static>> = {
        let buf = app.buffer.lock().expect("buffer poisoned");
        buf.iter()
            .filter(|r| r.namespace == target_ns && r.name == target_name && r.kind == target_kind)
            .map(|r| {
                let msg_style = match r.severity {
                    Severity::Warning if is_critical_reason(&r.reason) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    Severity::Warning => Style::default().fg(Color::Yellow),
                    Severity::Normal => Style::default().fg(Color::Gray),
                };
                let component = if r.component.is_empty() { String::new() } else { format!(" [{}]", r.component) };
                Line::from(vec![
                    Span::styled(format_time(r), Style::default().fg(DIM)),
                    Span::raw("  "),
                    Span::styled(r.reason.clone(), Style::default().fg(Color::Cyan)),
                    Span::styled(component, Style::default().fg(DIM)),
                    Span::raw("  "),
                    Span::styled(r.message.clone(), msg_style),
                    Span::styled(format!("  x{}", r.count), Style::default().fg(DIM)),
                ])
            })
            .collect()
    };

    if !event_lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Événements ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        lines.extend(event_lines);
    }

    let (loading, sections, error) = {
        let s = app.related_state.lock().expect("related state poisoned");
        (s.loading, s.sections.clone(), s.error.clone())
    };

    if loading || !sections.is_empty() || error.is_some() {
        if !lines.is_empty() { lines.push(Line::from("")); }
        lines.push(Line::from(Span::styled(
            "── Ressources contextuelles ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        if let Some(e) = error {
            lines.push(Line::from(Span::styled(e, Style::default().fg(Color::Red))));
        } else if loading && sections.is_empty() {
            lines.push(Line::from(Span::styled("(récupération...)", Style::default().fg(Color::Yellow))));
        } else if sections.is_empty() {
            lines.push(Line::from(Span::styled("(aucune ressource détectée pour ce type d'événement)", Style::default().fg(DIM))));
        } else {
            for (title, body) in sections.iter() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("◆ {}", title),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                for body_line in body.lines() {
                    lines.push(colorize_json_line(body_line));
                }
            }
        }
    }

    lines
}

fn colorize_json_line(line: &str) -> Line<'static> {
    let trimmed = line.trim_start();
    let indent_len = line.len() - trimmed.len();
    let indent = line[..indent_len].to_string();

    if trimmed.is_empty() {
        return Line::from(line.to_string());
    }

    if matches!(trimmed, "{" | "}" | "[" | "]" | "}," | "],") || trimmed == "}, {" {
        return Line::from(Span::styled(line.to_string(), Style::default().fg(DIM)));
    }

    if trimmed.starts_with('"') {
        if let Some(end_q) = trimmed[1..].find('"') {
            let key_full = &trimmed[..end_q + 2];
            let after_key = &trimmed[end_q + 2..];
            if after_key.starts_with(':') {
                let value_part = after_key[1..].trim_start();
                let value_style = if value_part.starts_with('"') {
                    Style::default().fg(Color::Green)
                } else if value_part.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
                    Style::default().fg(Color::Magenta)
                } else if value_part.starts_with("true") || value_part.starts_with("false") {
                    Style::default().fg(Color::Magenta)
                } else if value_part.starts_with("null") {
                    Style::default().fg(DIM)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let sep_offset = end_q + 2;
                let value_offset = sep_offset + 1;
                let separator = ":".to_string();
                let value_with_pad = trimmed[value_offset..].to_string();
                return Line::from(vec![
                    Span::raw(indent),
                    Span::styled(key_full.to_string(), Style::default().fg(Color::Cyan)),
                    Span::styled(separator, Style::default().fg(DIM)),
                    Span::styled(value_with_pad, value_style),
                ]);
            }
        }
    }

    Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Gray)))
}

fn render_markdown_lines(content: &str, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut in_code_block = false;
    let mut table_buf: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();

        if !in_code_block && trimmed.starts_with('|') && trimmed[1..].contains('|') {
            table_buf.push(trimmed.to_string());
            continue;
        }
        if !table_buf.is_empty() {
            render_table_block(&table_buf, width, &mut out);
            table_buf.clear();
        }

        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            out.push(Line::from(Span::styled(line.to_string(), Style::default().fg(DIM))));
            continue;
        }
        if in_code_block {
            out.push(Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Green))));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("### ") {
            out.push(Line::from(Span::styled(format!("### {}", rest), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("## ") {
            out.push(Line::from(Span::styled(format!("## {}", rest), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            out.push(Line::from(Span::styled(format!("# {}", rest), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))));
            continue;
        }
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            let indent = &line[..line.len() - trimmed.len()];
            let rest = &trimmed[2..];
            let mut spans = vec![
                Span::raw(indent.to_string()),
                Span::styled("• ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ];
            spans.extend(render_inline_spans(rest));
            out.push(Line::from(spans));
            continue;
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_digit() && (bytes[1] == b'.' || (bytes[1].is_ascii_digit() && bytes[2] == b'.')) {
            let indent = &line[..line.len() - trimmed.len()];
            let mut spans = vec![Span::raw(indent.to_string())];
            spans.extend(render_inline_spans_with_first_bold(trimmed));
            out.push(Line::from(spans));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("> ") {
            out.push(Line::from(Span::styled(format!("> {}", rest), Style::default().fg(Color::Magenta))));
            continue;
        }

        let indent = &line[..line.len() - trimmed.len()];
        let mut spans = vec![Span::raw(indent.to_string())];
        spans.extend(render_inline_spans(trimmed));
        out.push(Line::from(spans));
    }
    if !table_buf.is_empty() {
        render_table_block(&table_buf, width, &mut out);
    }
    out
}

fn split_table_row(line: &str) -> Vec<String> {
    let s = line.trim();
    let s = s.strip_prefix('|').unwrap_or(s);
    let s = s.strip_suffix('|').unwrap_or(s);
    s.split('|')
        .map(|c| c.trim().split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

fn is_table_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|c| {
            let t = c.trim();
            !t.is_empty() && t.chars().all(|ch| ch == '-' || ch == ':' || ch == ' ')
        })
}

fn wrap_cell(text: &str, w: usize) -> Vec<String> {
    if w == 0 {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split(' ') {
        if word.chars().count() > w {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let mut chunk = String::new();
            for ch in word.chars() {
                if chunk.chars().count() == w {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(ch);
            }
            cur = chunk;
            continue;
        }
        let add = if cur.is_empty() { word.chars().count() } else { cur.chars().count() + 1 + word.chars().count() };
        if add > w {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        } else {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
    }
    if !cur.is_empty() || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

fn render_table_block(buf: &[String], width: usize, out: &mut Vec<Line<'static>>) {
    let rows: Vec<Vec<String>> = buf.iter().map(|l| split_table_row(l)).collect();
    let ncols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    if ncols == 0 {
        return;
    }
    let body: Vec<&Vec<String>> = rows.iter().filter(|r| !is_table_separator(r)).collect();
    if body.is_empty() {
        return;
    }

    let mut natural = vec![0usize; ncols];
    for r in &body {
        for (i, c) in r.iter().enumerate() {
            natural[i] = natural[i].max(c.chars().count());
        }
    }

    let sep = " │ ";
    let overhead = sep.chars().count() * ncols.saturating_sub(1);
    let budget = width.saturating_sub(overhead).max(ncols * 4);
    let total: usize = natural.iter().sum();
    let col_w: Vec<usize> = if total <= budget {
        natural.clone()
    } else {
        let mut w: Vec<usize> = natural
            .iter()
            .map(|&n| ((n * budget) / total.max(1)).max(6))
            .collect();
        let mut over = w.iter().sum::<usize>().saturating_sub(budget);
        while over > 0 {
            if let Some((idx, _)) = w.iter().enumerate().max_by_key(|(_, &v)| v) {
                if w[idx] <= 6 {
                    break;
                }
                w[idx] -= 1;
                over -= 1;
            } else {
                break;
            }
        }
        w
    };

    let header_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    for (ri, row) in body.iter().enumerate() {
        let is_header = ri == 0;
        let wrapped: Vec<Vec<String>> = (0..ncols)
            .map(|i| {
                let cell = row.get(i).map(|s| s.as_str()).unwrap_or("");
                wrap_cell(cell, col_w[i])
            })
            .collect();
        let height = wrapped.iter().map(|c| c.len()).max().unwrap_or(1);
        for h in 0..height {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for i in 0..ncols {
                if i > 0 {
                    spans.push(Span::styled(sep.to_string(), Style::default().fg(DIM)));
                }
                let txt = wrapped[i].get(h).cloned().unwrap_or_default();
                let pad = col_w[i].saturating_sub(txt.chars().count());
                let padded = format!("{}{}", txt, " ".repeat(pad));
                if is_header {
                    spans.push(Span::styled(padded, header_style));
                } else {
                    spans.push(Span::raw(padded));
                }
            }
            out.push(Line::from(spans));
        }
        if is_header {
            let total_w: usize = col_w.iter().sum::<usize>() + overhead;
            out.push(Line::from(Span::styled(
                "─".repeat(total_w.min(width.max(1))),
                Style::default().fg(DIM),
            )));
        }
    }
    out.push(Line::from(""));
}

fn render_inline_spans_with_first_bold(s: &str) -> Vec<Span<'static>> {
    if let Some(idx) = s.find(' ') {
        let (head, tail) = s.split_at(idx);
        let mut spans = vec![Span::styled(head.to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))];
        spans.extend(render_inline_spans(tail));
        spans
    } else {
        vec![Span::styled(s.to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]
    }
}

fn render_inline_spans(line: &str) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let mut in_code = false;
    let mut bold = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '`' {
            flush(&mut spans, &mut buf, in_code, bold);
            in_code = !in_code;
            continue;
        }
        if !in_code && c == '*' && chars.peek() == Some(&'*') {
            chars.next();
            flush(&mut spans, &mut buf, in_code, bold);
            bold = !bold;
            continue;
        }
        buf.push(c);
    }
    flush(&mut spans, &mut buf, in_code, bold);
    if spans.is_empty() {
        spans.push(Span::raw(String::new()));
    }
    spans
}

fn flush(spans: &mut Vec<Span<'static>>, buf: &mut String, in_code: bool, bold: bool) {
    if buf.is_empty() { return; }
    let mut style = Style::default();
    if in_code {
        style = style.fg(Color::Green);
    }
    if bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    spans.push(Span::styled(std::mem::take(buf), style));
}

fn line_color(c: LineColor) -> Color {
    match c {
        LineColor::Plain => Color::White,
        LineColor::Ok => Color::Green,
        LineColor::Warn => Color::Yellow,
        LineColor::Err => Color::Red,
        LineColor::Info => Color::Cyan,
        LineColor::Dim => DIM,
    }
}

fn row_for(r: &EventRecord, h_scroll: usize) -> Row<'static> {
    let time_str = format_time(r);
    let (sev_label, sev_style) = match r.severity {
        Severity::Warning if is_critical_reason(&r.reason) => (
            "ERR",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Severity::Warning => (
            "WARN",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Severity::Normal => ("OK", Style::default().fg(Color::Green)),
    };
    let reason_style = if r.severity == Severity::Warning && is_critical_reason(&r.reason) {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if r.severity == Severity::Warning {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let row_style = match r.severity {
        Severity::Warning if is_critical_reason(&r.reason) => Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0)),
        Severity::Warning => Style::default().fg(Color::White),
        Severity::Normal => Style::default().fg(Color::Gray),
    };

    let message = slice_from(&r.message, h_scroll);

    Row::new(vec![
        Cell::from(time_str).style(Style::default().fg(DIM)),
        Cell::from(sev_label).style(sev_style),
        Cell::from(r.namespace.clone()),
        Cell::from(r.kind.clone()),
        Cell::from(r.name.clone()),
        Cell::from(r.reason.clone()).style(reason_style),
        Cell::from(format!("x{}", r.count)),
        Cell::from(message),
    ])
    .style(row_style)
}

fn slice_from(s: &str, n: usize) -> String {
    if n == 0 { s.to_string() } else { s.chars().skip(n).collect() }
}

fn format_node_usage_for_ai(s: &crate::events::NodeUsageState) -> (String, String) {
    use crate::events::{format_cpu_milli, format_memory_bytes};
    let mut body = String::new();
    body.push_str(&format!("Node allocatable: cpu={}, memory={}\n",
        format_cpu_milli(s.alloc_cpu_milli), format_memory_bytes(s.alloc_mem_bytes)));
    body.push_str(&format!("metrics-server: {}\n",
        if s.metrics_available { "available" } else { "unavailable (use=null)" }));

    let (mut user_cpu_req, mut user_mem_req) = (0_i64, 0_i64);
    let (mut user_cpu_lim, mut user_mem_lim) = (0_i64, 0_i64);
    let (mut user_cpu_use, mut user_mem_use) = (0_i64, 0_i64);
    let (mut sys_cpu_req, mut sys_mem_req) = (0_i64, 0_i64);
    let (mut sys_cpu_use, mut sys_mem_use) = (0_i64, 0_i64);
    let mut user_n = 0; let mut sys_n = 0;
    for r in &s.rows {
        let (cr, lr, ur, mr, ml, mu) = (
            r.cpu_req.unwrap_or(0), r.cpu_lim.unwrap_or(0), r.cpu_use.unwrap_or(0),
            r.mem_req.unwrap_or(0), r.mem_lim.unwrap_or(0), r.mem_use.unwrap_or(0),
        );
        if r.is_system {
            sys_n += 1;
            sys_cpu_req += cr; sys_mem_req += mr; sys_cpu_use += ur; sys_mem_use += mu;
        } else {
            user_n += 1;
            user_cpu_req += cr; user_cpu_lim += lr; user_cpu_use += ur;
            user_mem_req += mr; user_mem_lim += ml; user_mem_use += mu;
        }
    }
    body.push_str(&format!(
        "\nUser containers ({}): cpu req={} lim={} use={}, mem req={} lim={} use={}\n",
        user_n,
        format_cpu_milli(user_cpu_req), format_cpu_milli(user_cpu_lim), format_cpu_milli(user_cpu_use),
        format_memory_bytes(user_mem_req), format_memory_bytes(user_mem_lim), format_memory_bytes(user_mem_use),
    ));
    body.push_str(&format!(
        "System containers ({}, hors influence directe utilisateur): cpu req={} use={}, mem req={} use={}\n",
        sys_n,
        format_cpu_milli(sys_cpu_req), format_cpu_milli(sys_cpu_use),
        format_memory_bytes(sys_mem_req), format_memory_bytes(sys_mem_use),
    ));

    body.push_str("\nDétails par container (USER d'abord, system préfixé `[sys]`, focus sur ceux avec problème) :\n");
    let mut printed = 0;
    for r in &s.rows {
        let cpu_at_limit = matches!((r.cpu_use, r.cpu_lim), (Some(u), Some(l)) if l > 0 && u >= l);
        let mem_at_limit = matches!((r.mem_use, r.mem_lim), (Some(u), Some(l)) if l > 0 && u >= l);
        let cpu_under = matches!((r.cpu_req, r.cpu_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
        let mem_under = matches!((r.mem_req, r.mem_use), (Some(req), Some(u)) if req > 0 && u * 100 / req < 30);
        let cpu_over_lim = matches!((r.cpu_lim, r.cpu_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);
        let mem_over_lim = matches!((r.mem_lim, r.mem_req), (Some(l), Some(rq)) if rq > 0 && l > rq * 4);
        let has_issue = cpu_at_limit || mem_at_limit || cpu_under || mem_under || cpu_over_lim || mem_over_lim
            || r.cpu_req.is_none() || r.mem_req.is_none() || r.mem_lim.is_none();
        if !has_issue { continue; }
        if printed >= 80 { body.push_str("(... liste tronquée ...)\n"); break; }
        printed += 1;
        let mut tags = Vec::new();
        if r.cpu_req.is_none() { tags.push("noCpuReq"); }
        if r.mem_req.is_none() { tags.push("noMemReq"); }
        if r.mem_lim.is_none() { tags.push("noMemLim"); }
        if cpu_under { tags.push("cpuOver"); }
        if mem_under { tags.push("memOver"); }
        if cpu_over_lim { tags.push("cpuLim>>"); }
        if mem_over_lim { tags.push("memLim>>"); }
        if cpu_at_limit { tags.push("cpuMax"); }
        if mem_at_limit { tags.push("OOMrisk"); }
        let opt = |v: Option<i64>, fmt: fn(i64) -> String| v.map(fmt).unwrap_or_else(|| "-".to_string());
        body.push_str(&format!(
            "{}{}/{} [{}] cpu={}/{}/{} mem={}/{}/{} ready={} rst={} -> {}\n",
            if r.is_system { "[sys] " } else { "" },
            r.namespace, r.pod, r.container,
            opt(r.cpu_req, format_cpu_milli), opt(r.cpu_lim, format_cpu_milli), opt(r.cpu_use, format_cpu_milli),
            opt(r.mem_req, format_memory_bytes), opt(r.mem_lim, format_memory_bytes), opt(r.mem_use, format_memory_bytes),
            if r.ready { "Y" } else { "N" }, r.restarts,
            tags.join(","),
        ));
    }
    body.push_str("\nNote: les pods `[sys]` (CSI drivers, defender, addons CNI/cloud, monitoring système) ne sont pas modifiables par l'utilisateur final ; concentrer le diagnostic et les recommandations sur les pods USER.\n");
    ("Node usage (per-container avec issues)".to_string(), body)
}

fn format_time(r: &EventRecord) -> String {
    let s = r.time.to_string();
    if let Some(t) = s.split('T').nth(1) {
        t.split('.').next().unwrap_or(t).trim_end_matches('Z').to_string()
    } else {
        s
    }
}

fn capture_logs_text(state: &SharedLog) -> String {
    let s = state.lock().expect("log state poisoned");
    if let Some(e) = &s.error { return format!("(indisponible: {})", e); }
    if s.loading && s.lines.is_empty() { return "(en cours de chargement)".to_string(); }
    if s.lines.is_empty() { return "(aucun log)".to_string(); }
    let n = s.lines.len();
    let start = n.saturating_sub(200);
    s.lines[start..].join("\n")
}

fn capture_status_text(state: &SharedStatus) -> String {
    let s = state.lock().expect("status state poisoned");
    if let Some(e) = &s.error { return format!("(indisponible: {})", e); }
    if s.loading && s.lines.is_empty() { return "(en cours de chargement)".to_string(); }
    if s.lines.is_empty() { return "(aucun status)".to_string(); }
    s.lines.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>().join("\n")
}

fn capture_related_text(buffer: &SharedBuffer, rec: &EventRecord) -> String {
    let buf = buffer.lock().expect("buffer poisoned");
    let mut related: Vec<String> = buf.iter()
        .filter(|r| r.namespace == rec.namespace && r.name == rec.name && r.kind == rec.kind)
        .map(|r| format!(
            "[{}] {} {} (x{}) — {}",
            r.time,
            match r.severity { Severity::Warning => "WARN", Severity::Normal => "OK" },
            r.reason, r.count, r.message,
        ))
        .collect();
    let max = 50;
    if related.len() > max {
        let drop = related.len() - max;
        related.drain(0..drop);
    }
    if related.is_empty() { "(aucun)".to_string() } else { related.join("\n") }
}

fn build_ai_prompt(
    rec: &EventRecord,
    ctx_label: &str,
    ns_label: &str,
    logs: &str,
    status: &str,
    related: &str,
    extra: &[(String, String)],
) -> String {
    let mut extra_block = String::new();
    if extra.is_empty() {
        extra_block.push_str("(aucun)");
    } else {
        for (i, (title, body)) in extra.iter().enumerate() {
            if i > 0 { extra_block.push_str("\n\n"); }
            extra_block.push_str("### ");
            extra_block.push_str(title);
            extra_block.push_str("\n```json\n");
            extra_block.push_str(body);
            extra_block.push_str("\n```");
        }
    }

    format!(
"# Analyse d'un événement Kubernetes

## Contexte cluster
- Context: {ctx}
- Namespace surveillé: {ns_label}

## Événement principal
- Time: {time}
- Severity: {sev}
- Reason: {reason}
- Kind: {kind}
- ApiVersion: {api}
- Object: {ns}/{name}
- Component: {comp}
- Count: {count}
- Message: {msg}

## Statut de l'objet impliqué
{status}

## Logs récents (objet/pod, jusqu'à 200 dernières lignes)
{logs}

## Événements liés (même objet)
{related}

## Ressources contextuelles attachées
{extra_block}

## Demande
Donne un diagnostic concis : cause racine la plus probable, vérifications à mener, et actions correctives concrètes (commandes kubectl quand pertinent). Si des policies Kyverno ou des règles RBAC sont fournies, exploite-les pour identifier la règle bloquante et proposer le patch minimal.",
        ctx = ctx_label,
        ns_label = ns_label,
        time = rec.time,
        sev = match rec.severity { Severity::Warning => "Warning", Severity::Normal => "Normal" },
        reason = rec.reason,
        kind = rec.kind,
        api = rec.api_version,
        ns = rec.namespace,
        name = rec.name,
        comp = rec.component,
        count = rec.count,
        msg = rec.message,
    )
}

fn build_diag_doc(
    steps: &[DiagnosticStep],
    ai_content: &str,
    ai_error: Option<&str>,
    ai_model: &str,
) -> pdf::DiagDoc {
    let mut ok = 0; let mut warn = 0; let mut err = 0; let mut info = 0;
    for s in steps {
        match s.status {
            DiagStatus::Ok => ok += 1,
            DiagStatus::Warn => warn += 1,
            DiagStatus::Err => err += 1,
            DiagStatus::Info => info += 1,
            DiagStatus::Running => {}
        }
    }
    let pdf_steps: Vec<pdf::DiagStep> = steps
        .iter()
        .map(|s| pdf::DiagStep {
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
        })
        .collect();

    pdf::DiagDoc {
        ok, warn, err, info,
        steps: pdf_steps,
        ai_model: ai_model.to_string(),
        ai_content: ai_content.to_string(),
        ai_error: ai_error.map(|s| s.to_string()),
    }
}

fn line_color_to_pdf(c: LineColor) -> &'static str {
    match c {
        LineColor::Plain => "plain",
        LineColor::Ok => "ok",
        LineColor::Warn => "warn",
        LineColor::Err => "err",
        LineColor::Info => "info",
        LineColor::Dim => "dim",
    }
}
