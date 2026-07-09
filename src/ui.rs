//! ratatui terminal UI: the central `App` state machine, its modes (events, nodes, usage,
//! diagnostic, flux, pods, rbac security, AI panel, command palette…), the key dispatcher, and all
//! rendering.
//!
//! Background work (log/status/AI/node fetches) is spawned onto tokio and writes into shared
//! state; each fetch carries a key/id that is re-checked before committing, so results from a
//! superseded selection are dropped instead of overwriting the current view.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};

const DIM: Color = Color::Rgb(150, 150, 150);
const SYS_DIM: Color = Color::Rgb(95, 95, 95);

use ratatui::text::{Line, Span, Text};
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
use crate::flux::{
    build_flux_tree, controller_for_kind, fetch_flux, fetch_inventory, flux_tree_uid, new_flux_state,
    new_inventory_state, new_reconcile_status, reconcile, set_suspend, FlatTreeNode, FluxReady,
    FluxResource, InventoryItem, ReconcileScope, SharedFlux, SharedInventory, SharedReconcile,
    ALL_CONTROLLERS,
};

// A rendered row of the Flux dependency tree: either a Flux resource node, or one applied object
// from an expanded Kustomization's inventory (shown as a child, with live readiness).
pub enum TreeRow {
    Res(FlatTreeNode),
    Inv { ks_uid: String, depth: usize, item: InventoryItem },
}
use crate::lang;
use crate::pdf;
use crate::pods::{
    fetch_workloads, new_pods_state, run_force_recycle, run_restart, run_scale, PodResource,
    SharedPods, WorkloadResource,
};
use crate::rbac::{
    critical_namespaces, fetch_rbac, new_rbac_state, Finding as RbacFinding, RbacBinding,
    Severity as RbacSeverity, SharedRbac,
};
use crate::vulnerabilities::{
    fetch_vulnerabilities, new_vuln_state, K8sVersionRisk, Sev as VulnSev, SharedVuln, VulnComponent,
};

// A selectable row in the vulnerability view: the k8s control-plane risk (always first when known)
// or one scanned image.
#[derive(Clone)]
enum VulnRow {
    K8s(K8sVersionRisk),
    Image(VulnComponent),
}
use crate::secrets::{
    fetch_secrets, new_secrets_state, Expiry, SecretInfo, SharedSecrets,
};
use crate::configmaps::{
    fetch_configmaps, human_size, new_configmaps_state, ConfigMapInfo, SharedConfigMaps,
};
use crate::svc::{
    endpoint_belongs_to, fetch_network, new_network_state, EndpointRow, IngressClassResource,
    IngressResource, ServiceResource, SharedNetwork,
};

// The two object worlds the Services/Ingress view toggles between (palette `svc` vs `ingress`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetWorld {
    Services,
    Ingress,
}

// One visual row of the network view: a parent (Service / IngressClass) or its children, plus the
// flat Ingress row. Kept index-aligned with the snapshot so the detail panel tracks the selection.
#[derive(Debug, Clone)]
enum NetRow {
    Service(ServiceResource),
    Endpoint(EndpointRow),
    Ingress(IngressResource),
    IngressClass(IngressClassResource),
}
use crate::enrich::{fetch_related, gather_extra_context_with_progress, new_related_state, SharedRelated};

// In-panel reveal of a secret's data values (`b`/`d`). Hidden by default and reset whenever the
// selection changes, so values never linger on screen unintentionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretReveal { Hidden, Base64, Decoded }

// First entry of every data-copy picker: copies the whole object manifest instead of a single key.
const MANIFEST_ENTRY: &str = "manifest (YAML)";

// Modal picker shown on `c` over a secret: pick which data key to copy (decoded) to the clipboard.
struct SecretsCopyMenu {
    title: String,
    keys: Vec<String>,
    cursor: usize,
}

// Same idea for ConfigMaps: pick a key to copy its (plain-text) value.
struct ConfigmapsCopyMenu {
    title: String,
    keys: Vec<String>,
    cursor: usize,
}

// How the secrets table is filtered (`f`): every secret, only TLS, or only TLS within 30 days of
// expiry (or already expired).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretFilter { All, Tls, Expiring }

impl SecretFilter {
    fn label(self) -> &'static str {
        match self { SecretFilter::All => "ALL", SecretFilter::Tls => "TLS", SecretFilter::Expiring => "EXPIRING" }
    }
    fn matches(self, s: &SecretInfo) -> bool {
        match self {
            SecretFilter::All => true,
            SecretFilter::Tls => s.is_tls(),
            SecretFilter::Expiring => s
                .tls
                .as_ref()
                .map(|c| c.expiry != Expiry::Ok)
                .unwrap_or(false),
        }
    }
}
use crate::events::{
    fetch_cluster_info, fetch_flux_logs, fetch_logs, fetch_namespaces, fetch_node_usage,
    fetch_nodes, fetch_status, fetch_workload_logs, format_cpu_milli, format_memory_bytes,
    new_cluster_info_state,
    new_log_state, new_node_list_state, new_node_usage_state, new_ns_list_state, spawn_watcher,
    EventRecord, LineColor, Severity, SharedBuffer, SharedClusterInfo, SharedLog, SharedNodeList,
    SharedNodeUsage, SharedNsList, SharedStatus,
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

// Event reasons treated as "errors" by the Errors filter (crash/oom/scheduling/mount failures…).
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
pub enum Mode { Selection, NsPicker, AiPanel, DetailFull, Nodes, NodesFull, NodeUsage, Diagnostic, Extract, Command, Flux, FluxFull, FluxLogs, Pods, PodsFull, Rbac, RbacFull, Vuln, VulnFull, Secrets, SecretsFull, Configmaps, ConfigmapsFull, Services, ServicesFull }

// One visual line in the merged workloads view: either a workload (parent/group row) or one of its
// pods (child row). The order of `App::pods_rows` is the on-screen order and stays aligned with
// `App::snapshot` (and thus `table_state`), so a selected index maps to the same row in both.
#[derive(Clone)]
pub enum PodRow {
    Workload(WorkloadResource),
    Pod(PodResource),
}

// The operation a menu entry runs once confirmed. Maps directly onto the existing App methods.
#[derive(Clone)]
enum MenuAction {
    Rescale,
    Recycle,
    Restart,
    Reconcile(ReconcileScope),
    ScaleDelta(i32),
    ScaleZero,
    ScaleSet,
}

// One labelled choice in the action menu overlay, with an explanatory line shown under the list.
struct ActionItem {
    label: &'static str,
    desc: &'static str,
    action: MenuAction,
}

// Overlay shown over the Pods/Flux views: pick an action from a list, then (for destructive ones)
// confirm. `confirming` flips the popup into a yes/no prompt; `input` holds the numeric entry buffer
// while typing a target replica count for `ScaleSet`.
struct ActionMenu {
    title: &'static str,
    items: Vec<ActionItem>,
    cursor: usize,
    confirm: bool,
    confirming: bool,
    input: Option<String>,
}

// Command palette entries: (canonical name, aliases). Drives `:` palette resolution/completion.
const COMMANDS: &[(&str, &[&str])] = &[
    ("events", &["ev", "event"]),
    ("namespace", &["ns", "namespaces"]),
    ("nodes", &["no", "node"]),
    ("workloads", &["wl", "workload", "deploy", "deployments", "pods", "po", "pod"]),
    ("flux", &["fl", "ks", "kustomizations", "hr", "helmreleases"]),
    ("flux-logs", &["logs", "fluxlogs", "fl-logs"]),
    ("rbac", &["rb", "roles", "bindings", "security", "sec"]),
    ("vuln", &["vulnerabilities", "vulns", "cve", "cves"]),
    ("secrets", &["secret", "se", "tls", "certs", "certificates"]),
    ("configmaps", &["configmap", "cm", "config", "configs"]),
    ("services", &["svc", "service", "svcs"]),
    ("ingress", &["ing", "ingresses", "ingressclass", "ingressclasses"]),
    ("quit", &["q"]),
];

// Resolve palette input to a command: exact name/alias match, otherwise a unique name prefix.
fn resolve_command(input: &str) -> Option<&'static str> {
    let q = input.trim().to_lowercase();
    if q.is_empty() { return None; }
    for (name, aliases) in COMMANDS {
        if *name == q || aliases.contains(&q.as_str()) {
            return Some(name);
        }
    }
    let matches: Vec<&'static str> = COMMANDS
        .iter()
        .filter(|(name, _)| name.starts_with(&q))
        .map(|(name, _)| *name)
        .collect();
    if matches.len() == 1 { Some(matches[0]) } else { None }
}

fn command_name_suggestions(input: &str) -> Vec<&'static str> {
    let q = input.trim().to_lowercase();
    COMMANDS
        .iter()
        .filter(|(name, aliases)| {
            q.is_empty() || name.starts_with(&q) || aliases.iter().any(|a| a.starts_with(&q))
        })
        .map(|(name, _)| *name)
        .collect()
}

// Commands that take an optional namespace argument (`:ns/pods/events <name>`).
fn command_takes_ns(cmd: &str) -> bool {
    matches!(cmd, "events" | "namespace" | "workloads")
}

// Map a namespace argument to a watcher scope: `all`/`*`/`0`/empty mean "all namespaces".
fn ns_arg_to_opt(arg: &str) -> Option<String> {
    let a = arg.trim();
    if a.is_empty() || a == "all" || a == "*" || a == "0" {
        None
    } else {
        Some(a.to_string())
    }
}

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
        match self {
            Self::Logs => Self::Status,
            Self::Status => Self::Related,
            Self::Related => Self::Logs,
        }
    }
    fn prev(self) -> Self {
        match self {
            Self::Logs => Self::Related,
            Self::Status => Self::Logs,
            Self::Related => Self::Status,
        }
    }
}

// Central UI state. Fields prefixed `last_*_key` cache the identity of the currently displayed
// selection to avoid re-fetching; `*_state`/`*_handle` hold shared async results and task handles.
pub struct App {
    pub buffer: SharedBuffer,
    pub filter: Filter,
    pub namespace_label: String,
    pub context_label: String,
    pub cluster_label: String,
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
    // While true, the Related tab is held at the top (cleared once the user scrolls it).
    pub related_pin_top: bool,
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
    pub command_input: String,
    pub command_cursor: usize,
    pub command_return_mode: Mode,
    pub flux_state: SharedFlux,
    pub reconcile_status: SharedReconcile,
    pub flux_logs_state: SharedLog,
    pub flux_logs_handle: Option<JoinHandle<()>>,
    pub last_inventory_tick: std::time::Instant,
    pub flux_tree: bool,
    pub flux_collapsed: std::collections::HashSet<String>,
    // Flattened tree currently displayed (resource nodes + expanded inventory children).
    pub flux_tree_view: Vec<TreeRow>,
    // Kustomizations whose inventory is expanded in the tree: uid → (api_version, kind, ns, name).
    pub flux_inv_expanded: std::collections::HashMap<String, (String, String, String, String)>,
    // Fetched inventory per expanded Kustomization uid (live status of its applied objects).
    pub flux_inv: std::collections::HashMap<String, SharedInventory>,
    pub last_flux_sel_uid: Option<String>,
    pub flux_refresh_handle: Option<JoinHandle<()>>,
    // Set when entering the Flux view: land on the first Kustomization once the list is first loaded.
    pub flux_select_first_ks: bool,
    // A flux_tree_uid ("kind|ns/name") to select once the Flux list loads (e.g. jumping from an RBAC
    // binding to its managing Kustomization/HelmRelease). Takes precedence over first-Kustomization.
    pub flux_pending_select: Option<String>,
    pub cluster_info: SharedClusterInfo,
    pub pods_state: SharedPods,
    // Flattened display rows (workload then its pods), kept in lockstep with `snapshot`.
    pub pods_rows: Vec<PodRow>,
    // When true, the workloads view shows parent workload rows with their pods nested under them;
    // when false (default) only pods are listed flat. Toggled with `t`.
    pub pods_show_workloads: bool,
    pub pods_saved_replicas: std::collections::HashMap<String, i32>,
    pub pods_refresh_handle: Option<JoinHandle<()>>,
    pub last_pods_sel_uid: Option<String>,
    // Services/Ingress view: shared inventory, the flattened display rows (index-aligned with the
    // snapshot), which world is shown, and whether children are nested (`t` toggle).
    pub network_state: SharedNetwork,
    net_rows: Vec<NetRow>,
    net_world: NetWorld,
    net_group: bool,
    pub net_refresh_handle: Option<JoinHandle<()>>,
    last_net_sel_uid: Option<String>,
    // When the namespace picker was opened from the pods view, return to it (not the events view).
    pub ns_return_pods: bool,
    pub rbac_state: SharedRbac,
    pub rbac_cursor: usize,
    pub rbac_min_sev: RbacSeverity,
    pub rbac_detail_scroll: usize,
    pub rbac_refresh_handle: Option<JoinHandle<()>>,
    pub vuln_state: SharedVuln,
    pub vuln_cursor: usize,
    pub vuln_min_sev: VulnSev,
    pub vuln_detail_scroll: usize,
    pub vuln_refresh_handle: Option<JoinHandle<()>>,
    pub secrets_state: SharedSecrets,
    pub secrets_cursor: usize,
    secrets_filter: SecretFilter,
    secrets_reveal: SecretReveal,
    secrets_copy_menu: Option<SecretsCopyMenu>,
    pub secrets_detail_scroll: usize,
    pub secrets_refresh_handle: Option<JoinHandle<()>>,
    pub configmaps_state: SharedConfigMaps,
    pub configmaps_cursor: usize,
    configmaps_copy_menu: Option<ConfigmapsCopyMenu>,
    pub configmaps_detail_scroll: usize,
    pub configmaps_h_scroll: usize,
    pub configmaps_refresh_handle: Option<JoinHandle<()>>,
    // Built-in critical namespaces merged with the user's config overrides.
    pub critical_ns: Vec<String>,
    // Active action-menu overlay (rescale/recycle/restart or reconcile scopes). `None` when closed.
    action_menu: Option<ActionMenu>,
}

impl App {
    pub fn new(
        buffer: SharedBuffer,
        namespace_label: String,
        context_label: String,
        cluster_label: String,
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
            cluster_label,
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
            related_pin_top: false,
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
            command_input: String::new(),
            command_cursor: 0,
            command_return_mode: Mode::Selection,
            flux_state: new_flux_state(),
            reconcile_status: new_reconcile_status(),
            flux_logs_state: new_log_state(),
            flux_logs_handle: None,
            last_inventory_tick: std::time::Instant::now(),
            flux_tree: true,
            flux_collapsed: std::collections::HashSet::new(),
            flux_tree_view: Vec::new(),
            flux_inv_expanded: std::collections::HashMap::new(),
            flux_inv: std::collections::HashMap::new(),
            last_flux_sel_uid: None,
            flux_refresh_handle: None,
            flux_select_first_ks: false,
            flux_pending_select: None,
            cluster_info: new_cluster_info_state(),
            pods_state: new_pods_state(),
            pods_rows: Vec::new(),
            pods_show_workloads: false,
            network_state: new_network_state(),
            net_rows: Vec::new(),
            net_world: NetWorld::Services,
            net_group: false,
            net_refresh_handle: None,
            last_net_sel_uid: None,
            pods_saved_replicas: std::collections::HashMap::new(),
            pods_refresh_handle: None,
            last_pods_sel_uid: None,
            ns_return_pods: false,
            rbac_state: new_rbac_state(),
            rbac_cursor: 0,
            rbac_min_sev: RbacSeverity::Info,
            rbac_detail_scroll: 0,
            rbac_refresh_handle: None,
            vuln_state: new_vuln_state(),
            vuln_cursor: 0,
            vuln_min_sev: VulnSev::Unknown,
            vuln_detail_scroll: 0,
            vuln_refresh_handle: None,
            secrets_state: new_secrets_state(),
            secrets_cursor: 0,
            secrets_filter: SecretFilter::All,
            secrets_reveal: SecretReveal::Hidden,
            secrets_copy_menu: None,
            secrets_detail_scroll: 0,
            secrets_refresh_handle: None,
            configmaps_state: new_configmaps_state(),
            configmaps_cursor: 0,
            configmaps_copy_menu: None,
            configmaps_detail_scroll: 0,
            configmaps_h_scroll: 0,
            configmaps_refresh_handle: None,
            critical_ns: critical_namespaces(&file_config.critical_namespaces),
            action_menu: None,
        }
    }

    fn spawn_cluster_info_refresh(&self) {
        let client = self.client.clone();
        let state = self.cluster_info.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(20));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                fetch_cluster_info(client.clone(), state.clone()).await;
            }
        });
    }



    fn reset_to_follow(&mut self) {
        self.mode = Mode::Selection;
        self.scroll_frozen = false;
        self.selected_uid = None;
        self.reset_scroll();
    }

    // Rebuild the visible event list from the buffer applying the active filter. When following
    // (no anchored uid) the cursor stays on the newest row; otherwise it tracks the anchored uid.
    fn refresh_live_snapshot(&mut self) {
        let mut snap: Vec<EventRecord> = {
            let buf = self.buffer.lock().expect("buffer poisoned");
            buf.iter()
                .filter(|r| self.filter.matches(r))
                .cloned()
                .collect()
        };
        // The watcher emits (and re-emits on reconnect) in arbitrary order, so sort by timestamp
        // to present events chronologically with the newest at the bottom (where following anchors).
        snap.sort_by_key(|r| r.time);
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
        if self.detail_tab == DetailTab::Related { self.related_pin_top = true; }
    }
    fn cycle_tab_back(&mut self) {
        self.detail_tab = self.detail_tab.prev();
        if self.detail_tab == DetailTab::Status { self.maybe_fetch_status(); }
        if self.detail_tab == DetailTab::Related { self.related_pin_top = true; }
    }

    fn scroll_detail(&mut self, delta: i32) {
        self.related_pin_top = false;
        let target = self.scroll_target();
        let cur = *target as i32;
        *target = cur.saturating_add(delta).max(0) as usize;
    }
    fn scroll_detail_top(&mut self) { self.related_pin_top = false; *self.scroll_target() = usize::MAX / 2; }
    fn scroll_detail_bottom(&mut self) { self.related_pin_top = false; *self.scroll_target() = 0; }

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

    // Kick off a related-context fetch for the selected object, but only if the selection key
    // changed since the last fetch (debounce while scrolling). Same pattern in maybe_fetch_logs/status.
    fn maybe_fetch_related(&mut self) {
        let Some(idx) = self.table_state.selected() else { return; };
        let Some(rec) = self.snapshot.get(idx).cloned() else { return; };
        let key = format!("{}|{}|{}/{}", rec.api_version, rec.kind, rec.namespace, rec.name);
        if self.last_related_key.as_deref() == Some(&key) { return; }
        self.last_related_key = Some(key.clone());
        // Related is read top-down: anchor to the top until the user scrolls (re-pinned each frame so
        // it stays at the top while the content streams in).
        self.related_pin_top = true;
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
        // Flux CRDs are not Pods: show the relevant controller's logs filtered to this object.
        if rec.component == "flux" {
            let key = format!("flux:{}|{}/{}", rec.kind, rec.namespace, rec.name);
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
            let controllers = vec![controller_for_kind(&rec.kind).to_string()];
            let filter = Some((rec.namespace.clone(), rec.name.clone()));
            tokio::spawn(async move {
                fetch_flux_logs(client, controllers, filter, key, log_state, 500).await;
            });
            return;
        }
        // A workload row in the workloads view: a workload has no logs of its own, so aggregate the
        // logs of all its pods (one `▼ pod <name>` section each).
        if matches!(self.mode, Mode::Pods | Mode::PodsFull) {
            if let Some((namespace, pods)) = self.selected_workload_pods() {
                let key = format!("wl-logs:{}|{}/{}", rec.kind, rec.namespace, rec.name);
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
                tokio::spawn(async move {
                    fetch_workload_logs(client, namespace, pods, key, log_state, 500).await;
                });
                return;
            }
        }
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
        self.ns_return_pods = matches!(self.mode, Mode::Pods | Mode::PodsFull);
        self.ns_cursor = 0;
        self.mode = Mode::NsPicker;
        let client = self.client.clone();
        let state = self.ns_pick_state.clone();
        tokio::spawn(async move {
            fetch_namespaces(client, state).await;
        });
    }

    fn exit_ns_picker(&mut self) {
        if self.ns_return_pods {
            self.ns_return_pods = false;
            self.mode = Mode::Pods;
        } else {
            self.mode = Mode::Selection;
        }
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

    // Open the AI panel and launch an analysis for the current context. Captures the relevant
    // local data (logs/status/related, plus node-usage or diagnostic text), builds the prompt in a
    // background task, and sends it to the active provider. This is the point where cluster data
    // leaves the machine for the external AI endpoint.
    fn enter_ai_panel(&mut self) {
        let source_mode = if self.mode == Mode::AiPanel { self.return_mode } else { self.mode };
        let rec = match source_mode {
            Mode::Nodes | Mode::NodesFull | Mode::NodeUsage => match self.synthetic_node_record() {
                Some(r) => r,
                None => return,
            },
            Mode::Diagnostic => self.synthetic_diagnostic_record(),
            Mode::Rbac | Mode::RbacFull => match self.synthetic_rbac_record() {
                Some(r) => r,
                None => return,
            },
            Mode::Vuln | Mode::VulnFull => match self.synthetic_vuln_record() {
                Some(r) => r,
                None => return,
            },
            Mode::Secrets | Mode::SecretsFull => match self.synthetic_secrets_record() {
                Some(r) => r,
                None => return,
            },
            Mode::Configmaps | Mode::ConfigmapsFull => match self.synthetic_configmaps_record() {
                Some(r) => r,
                None => return,
            },
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
            let char_budget = prompt_char_budget(config.context_window);
            let prompt = build_ai_prompt(&rec, &ctx_label, &ns_label, &logs_text, &status_text, &related_text, &extra, char_budget);
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
            if t.elapsed().as_secs() < 6 { Some(msg.as_str()) } else { None }
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
        self.copy_text(text);
    }

    // Copy the text of the detail panel tab (Logs/Status/Related, or the node status) currently
    // shown, mirroring exactly what draw_detail renders for the active mode.
    fn copy_detail_view(&mut self) {
        let text = detail_visible_text(self);
        self.copy_text(text);
    }

    fn copy_text(&mut self, text: String) {
        if text.trim().is_empty() {
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

    // Build a placeholder EventRecord so the diagnostic/node views can reuse the event-oriented
    // AI pipeline (which keys everything off an EventRecord).
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

    fn enter_command(&mut self) {
        if self.mode == Mode::Command { return; }
        self.command_return_mode = self.mode;
        self.command_input.clear();
        self.command_cursor = 0;
        self.mode = Mode::Command;
        // Prefetch namespaces so `:ns/pods/events <name>` can autocomplete.
        let client = self.client.clone();
        let state = self.ns_pick_state.clone();
        tokio::spawn(async move { fetch_namespaces(client, state).await; });
    }

    fn exit_command(&mut self) {
        self.mode = self.command_return_mode;
        self.command_input.clear();
    }

    fn command_push(&mut self, c: char) {
        // A single space separates the command from its namespace argument.
        if c == ' ' {
            if !self.command_input.is_empty() && !self.command_input.ends_with(' ') {
                self.command_input.push(' ');
            }
        } else if c.is_ascii_alphanumeric() || c == '-' || c == '/' || c == '.' {
            self.command_input.push(c.to_ascii_lowercase());
        }
        // Typing narrows the list, so any prior selection is stale.
        self.command_cursor = 0;
    }

    fn command_backspace(&mut self) {
        self.command_input.pop();
        self.command_cursor = 0;
    }

    // Move the palette selection with the up/down arrows, clamped to the suggestion list.
    fn move_command_selection(&mut self, delta: i32) {
        let len = self.command_suggestions().len();
        if len == 0 {
            self.command_cursor = 0;
            return;
        }
        let max = len as i32 - 1;
        self.command_cursor = (self.command_cursor as i32 + delta).clamp(0, max) as usize;
    }

    // Suggestions for the palette: command names before the space, matching namespaces after it.
    fn command_suggestions(&self) -> Vec<String> {
        let input = self.command_input.trim_start();
        match input.split_once(' ') {
            None => command_name_suggestions(input).into_iter().map(String::from).collect(),
            Some((cmd, rest)) => {
                let Some(name) = resolve_command(cmd) else { return Vec::new(); };
                if !command_takes_ns(name) { return Vec::new(); }
                let partial = rest.trim().to_lowercase();
                let s = self.ns_pick_state.lock().expect("ns list poisoned");
                let mut out = Vec::new();
                if "all".starts_with(&partial) { out.push(format!("{} all", name)); }
                for ns in &s.namespaces {
                    if ns.to_lowercase().starts_with(&partial) {
                        out.push(format!("{} {}", name, ns));
                    }
                }
                out
            }
        }
    }

    fn command_autocomplete(&mut self) {
        let suggestions = self.command_suggestions();
        if let Some(sel) = suggestions.get(self.command_cursor).or_else(|| suggestions.first()) {
            self.command_input = sel.clone();
            self.command_cursor = 0;
        }
    }

    fn command_run(&mut self) {
        // Enter runs the highlighted suggestion (or the raw input if nothing matches).
        let suggestions = self.command_suggestions();
        if let Some(sel) = suggestions.get(self.command_cursor) {
            self.command_input = sel.clone();
        }
        let input = self.command_input.trim().to_string();
        let (cmd_part, arg) = match input.split_once(' ') {
            Some((c, rest)) => (c.to_string(), Some(rest.trim().to_string())),
            None => (input.clone(), None),
        };
        let Some(cmd) = resolve_command(&cmd_part) else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("commande inconnue: {}", self.command_input.trim()),
            ));
            self.exit_command();
            return;
        };
        let origin = self.command_return_mode;
        self.command_input.clear();
        // A namespace argument (when the command accepts one) re-scopes the watcher before switching.
        let ns_arg = arg
            .as_ref()
            .filter(|a| !a.is_empty() && command_takes_ns(cmd))
            .map(|a| ns_arg_to_opt(a));
        match cmd {
            "quit" => self.should_quit = true,
            "events" => {
                self.mode = origin;
                self.leave_special_modes();
                if let Some(ns_opt) = ns_arg { self.apply_namespace(ns_opt); }
                self.reset_to_follow();
            }
            "namespace" => {
                self.mode = origin;
                self.leave_special_modes();
                match ns_arg {
                    Some(ns_opt) => {
                        self.apply_namespace(ns_opt);
                        self.mode = Mode::Selection;
                    }
                    None => self.enter_ns_picker(),
                }
            }
            "nodes" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_nodes_mode();
            }
            "workloads" => {
                self.mode = origin;
                self.leave_special_modes();
                if let Some(ns_opt) = ns_arg { self.apply_namespace(ns_opt); }
                self.enter_pods_mode();
            }
            "flux" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_flux_mode();
            }
            "flux-logs" => {
                self.mode = origin;
                if !matches!(self.mode, Mode::Flux | Mode::FluxFull) {
                    self.leave_special_modes();
                    self.enter_flux_mode();
                }
                self.enter_flux_logs();
            }
            "rbac" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_rbac_mode();
            }
            "vuln" => {
                // Always opens: with Trivy Operator it lists scanned images; without it, the view
                // falls back to the Kubernetes version risk alone (server version + official feed).
                self.mode = origin;
                self.leave_special_modes();
                self.enter_vuln_mode();
            }
            "secrets" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_secrets_mode();
            }
            "configmaps" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_configmaps_mode();
            }
            "services" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_network_mode(NetWorld::Services);
            }
            "ingress" => {
                self.mode = origin;
                self.leave_special_modes();
                self.enter_network_mode(NetWorld::Ingress);
            }
            _ => self.exit_command(),
        }
    }

    fn leave_special_modes(&mut self) {
        match self.mode {
            Mode::Nodes | Mode::NodesFull | Mode::NodeUsage => {
                self.stop_node_auto_refresh();
                self.clear_status_state();
            }
            Mode::Flux | Mode::FluxFull => {
                self.stop_flux_auto_refresh();
                self.clear_status_state();
            }
            Mode::Pods | Mode::PodsFull => {
                self.stop_pods_auto_refresh();
                self.clear_status_state();
            }
            Mode::Rbac | Mode::RbacFull => {
                self.stop_rbac_auto_refresh();
            }
            Mode::Vuln | Mode::VulnFull => {
                self.stop_vuln_auto_refresh();
            }
            Mode::Secrets | Mode::SecretsFull => {
                self.stop_secrets_auto_refresh();
            }
            Mode::Configmaps | Mode::ConfigmapsFull => {
                self.stop_configmaps_auto_refresh();
            }
            Mode::Services | Mode::ServicesFull => {
                self.stop_network_auto_refresh();
                self.clear_status_state();
            }
            _ => {}
        }
        self.mode = Mode::Selection;
    }

    fn enter_flux_mode(&mut self) {
        self.mode = Mode::Flux;
        self.detail_tab = DetailTab::Status;
        self.flux_select_first_ks = true;
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_flux_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
        self.refresh_flux();
        self.start_flux_auto_refresh();
        self.refresh_flux_snapshot();
    }

    fn exit_flux_mode(&mut self) {
        self.mode = Mode::Selection;
        self.stop_flux_auto_refresh();
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_flux_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.clear_status_state();
        self.reset_to_follow();
    }

    fn refresh_flux_snapshot(&mut self) {
        // In tree mode the snapshot follows the flattened tree order so selection, detail panes and
        // actions keep working off snapshot indices; otherwise it is the flat resource list. Each
        // expanded Kustomization's inventory objects are interleaved as child rows right after it.
        let recs: Vec<EventRecord> = {
            let s = self.flux_state.lock().expect("flux poisoned");
            if self.flux_tree {
                let flat = build_flux_tree(&s.resources, &self.flux_collapsed);
                let mut view: Vec<TreeRow> = Vec::with_capacity(flat.len());
                let mut recs: Vec<EventRecord> = Vec::with_capacity(flat.len());
                for n in flat {
                    let r = &s.resources[n.idx];
                    recs.push(synthetic_flux_record(r));
                    let uid = flux_tree_uid(r);
                    let depth = n.depth;
                    let expanded = r.kind == "Kustomization" && self.flux_inv_expanded.contains_key(&uid);
                    view.push(TreeRow::Res(n));
                    if expanded {
                        if let Some(inv) = self.flux_inv.get(&uid) {
                            let items = inv.lock().expect("inventory poisoned").items.clone();
                            for it in items {
                                recs.push(synthetic_inventory_record(&uid, &it));
                                view.push(TreeRow::Inv { ks_uid: uid.clone(), depth: depth + 1, item: it });
                            }
                        }
                    }
                }
                self.flux_tree_view = view;
                recs
            } else {
                self.flux_tree_view.clear();
                s.resources.iter().map(synthetic_flux_record).collect()
            }
        };
        let prev_uid = self
            .table_state
            .selected()
            .and_then(|i| self.snapshot.get(i))
            .map(|r| r.uid.clone())
            .or_else(|| self.selected_uid.clone());
        self.snapshot = recs;
        if self.snapshot.is_empty() {
            self.table_state.select(None);
            self.last_flux_sel_uid = None;
            return;
        }
        // Jumping from elsewhere (e.g. RBAC origin) selects a specific resource once it appears.
        let pending = self.flux_pending_select.as_ref().and_then(|uid| {
            let target = format!("flux|{}", uid);
            self.snapshot.iter().position(|r| r.uid == target)
        });
        if pending.is_some() {
            self.flux_pending_select = None;
        }
        // On first load of the Flux view, land on the first Kustomization rather than row 0.
        let first_ks = if self.flux_select_first_ks {
            self.flux_select_first_ks = false;
            self.snapshot.iter().position(|r| r.kind == "Kustomization")
        } else {
            None
        };
        let idx = pending
            .or(first_ks)
            .or_else(|| {
                prev_uid
                    .as_deref()
                    .and_then(|uid| self.snapshot.iter().position(|r| r.uid == uid))
            })
            .unwrap_or(0)
            .min(self.snapshot.len() - 1);
        self.table_state.select(Some(idx));
        self.selected_uid = Some(self.snapshot[idx].uid.clone());
        let cur_uid = self.snapshot[idx].uid.clone();
        if self.last_flux_sel_uid.as_deref() != Some(cur_uid.as_str()) {
            self.last_flux_sel_uid = Some(cur_uid);
            self.maybe_fetch_logs();
            self.maybe_fetch_status();
            self.maybe_fetch_related();
        }
    }

    fn enter_flux_full(&mut self) {
        if self.snapshot.is_empty() { return; }
        if self.detail_tab == DetailTab::Status { self.maybe_fetch_status(); }
        self.mode = Mode::FluxFull;
    }

    fn exit_flux_full(&mut self) {
        self.mode = Mode::Flux;
    }

    // Switches the Flux panel between the flat table and the dependency tree.
    fn toggle_flux_tree(&mut self) {
        self.flux_tree = !self.flux_tree;
        self.refresh_flux_snapshot();
    }

    // Collapses/expands the selected tree node's dependency children (no-op if it has none, or if the
    // selected row is an inventory child).
    fn toggle_flux_node(&mut self) {
        let Some(sel) = self.table_state.selected() else { return; };
        let idx = match self.flux_tree_view.get(sel) {
            Some(TreeRow::Res(node)) if node.has_children => node.idx,
            _ => return,
        };
        let uid = {
            let s = self.flux_state.lock().expect("flux poisoned");
            let Some(r) = s.resources.get(idx) else { return; };
            flux_tree_uid(r)
        };
        if !self.flux_collapsed.remove(&uid) {
            self.flux_collapsed.insert(uid);
        }
        self.refresh_flux_snapshot();
    }

    // The Kustomization that the selected row belongs to: the row itself if it is a Kustomization, or
    // the parent of an inventory child row. Returns (uid, api_version, kind, ns, name).
    fn selected_kustomization(&self) -> Option<(String, String, String, String, String)> {
        let sel = self.table_state.selected()?;
        match self.flux_tree_view.get(sel)? {
            TreeRow::Res(node) => {
                let s = self.flux_state.lock().expect("flux poisoned");
                let r = s.resources.get(node.idx)?;
                if r.kind != "Kustomization" { return None; }
                Some((flux_tree_uid(r), r.api_version.clone(), r.kind.clone(), r.namespace.clone(), r.name.clone()))
            }
            TreeRow::Inv { ks_uid, .. } => {
                let s = self.flux_state.lock().expect("flux poisoned");
                let r = s.resources.iter().find(|r| &flux_tree_uid(r) == ks_uid)?;
                Some((ks_uid.clone(), r.api_version.clone(), r.kind.clone(), r.namespace.clone(), r.name.clone()))
            }
        }
    }

    // `+` on a Kustomization: expand its inventory as child rows and fetch the applied objects' status.
    fn expand_flux_inventory(&mut self) {
        if !self.flux_tree {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "inventaire : disponible en vue arbre (t)".to_string(),
            ));
            return;
        }
        let Some((uid, api_version, kind, ns, name)) = self.selected_kustomization() else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "inventaire : sélectionnez un Kustomization".to_string(),
            ));
            return;
        };
        self.flux_inv_expanded.insert(uid.clone(), (api_version.clone(), kind.clone(), ns.clone(), name.clone()));
        self.fetch_inventory_for(&uid, &api_version, &kind, &ns, &name, false);
        self.refresh_flux_snapshot();
    }

    // `-`: collapse the inventory of the Kustomization the selected row belongs to.
    fn collapse_flux_inventory(&mut self) {
        if let Some((uid, ..)) = self.selected_kustomization() {
            if self.flux_inv_expanded.remove(&uid).is_some() {
                self.refresh_flux_snapshot();
            }
        }
    }

    // Spawn an inventory fetch for one Kustomization into its dedicated shared store (keyed by uid).
    fn fetch_inventory_for(&mut self, uid: &str, api_version: &str, kind: &str, ns: &str, name: &str, force: bool) {
        let state = self.flux_inv.entry(uid.to_string()).or_insert_with(new_inventory_state).clone();
        {
            let mut s = state.lock().expect("inventory poisoned");
            s.current_key = Some(uid.to_string());
            if !force { s.items.clear(); }
            s.error = None;
            s.loading = true;
        }
        let client = self.client.clone();
        let (api_version, kind, ns, name, key) =
            (api_version.to_string(), kind.to_string(), ns.to_string(), name.to_string(), uid.to_string());
        tokio::spawn(async move {
            fetch_inventory(client, api_version, kind, ns, name, key, state).await;
        });
    }

    // Re-fetch every expanded Kustomization's inventory (used by the periodic tick during rollouts).
    fn refresh_expanded_inventories(&mut self) {
        let targets: Vec<(String, String, String, String, String)> = self
            .flux_inv_expanded
            .iter()
            .map(|(uid, (av, kind, ns, name))| (uid.clone(), av.clone(), kind.clone(), ns.clone(), name.clone()))
            .collect();
        for (uid, av, kind, ns, name) in targets {
            self.fetch_inventory_for(&uid, &av, &kind, &ns, &name, true);
        }
    }

    fn refresh_flux(&self) {
        {
            let mut s = self.flux_state.lock().expect("flux poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.flux_state.clone();
        tokio::spawn(async move { fetch_flux(client, state).await; });
    }

    // Requests a Flux reconcile for the chosen scope. RootSync targets the fixed flux-system
    // GitRepository; other scopes apply to the selected resource. The result arrives asynchronously
    // in `reconcile_status` and is drained into a toast.
    fn reconcile_selected(&mut self, scope: ReconcileScope) {
        let target = match scope {
            ReconcileScope::RootSync => Some((
                "source.toolkit.fluxcd.io/v1".to_string(),
                "GitRepository".to_string(),
                "flux-system".to_string(),
                "flux-system".to_string(),
            )),
            _ => self
                .table_state
                .selected()
                .and_then(|i| self.snapshot.get(i))
                .map(|r| {
                    (
                        r.api_version.clone(),
                        r.kind.clone(),
                        r.namespace.clone(),
                        r.name.clone(),
                    )
                }),
        };
        let Some((api_version, kind, ns, name)) = target else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "aucune ressource sélectionnée".to_string(),
            ));
            return;
        };
        self.clipboard_status = Some((
            std::time::Instant::now(),
            format!("⟳ reconcile demandé : {}/{}…", kind, name),
        ));
        let client = self.client.clone();
        let status = self.reconcile_status.clone();
        // Reconciling a Kustomization: expand its inventory in the tree so its objects can be watched
        // live (switch to tree view if needed).
        if kind == "Kustomization" {
            let uid = format!("{}|{}/{}", kind, ns, name);
            self.flux_tree = true;
            self.flux_inv_expanded
                .insert(uid.clone(), (api_version.clone(), kind.clone(), ns.clone(), name.clone()));
            self.fetch_inventory_for(&uid, &api_version, &kind, &ns, &name, false);
            self.refresh_flux_snapshot();
        }
        tokio::spawn(async move {
            reconcile(client, scope, api_version, kind, ns, name, status).await;
        });
    }

    // Folds the latest reconcile/suspend outcome (success/error) into the shared toast.
    fn drain_reconcile_status(&mut self) {
        if let Some(msg) = self.reconcile_status.lock().ok().and_then(|mut s| s.take()) {
            self.clipboard_status = Some(msg);
        }
    }

    // Toggles spec.suspend on the selected resource. The current state comes from the latest flux
    // snapshot; the patch runs async and its result is drained into the toast.
    fn toggle_suspend(&mut self) {
        let Some(rec) = self
            .table_state
            .selected()
            .and_then(|i| self.snapshot.get(i))
            .cloned()
        else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "aucune ressource sélectionnée".to_string(),
            ));
            return;
        };
        let currently_suspended = {
            let s = self.flux_state.lock().expect("flux poisoned");
            s.resources
                .iter()
                .find(|r| r.kind == rec.kind && r.namespace == rec.namespace && r.name == rec.name)
                .map(|r| r.suspended)
                .unwrap_or(false)
        };
        let suspend = !currently_suspended;
        self.clipboard_status = Some((
            std::time::Instant::now(),
            format!(
                "{} {}/{}…",
                if suspend { "⏸ suspend" } else { "▶ resume" },
                rec.kind,
                rec.name
            ),
        ));
        let client = self.client.clone();
        let status = self.reconcile_status.clone();
        let (api_version, kind, ns, name) =
            (rec.api_version.clone(), rec.kind.clone(), rec.namespace.clone(), rec.name.clone());
        tokio::spawn(async move {
            set_suspend(client, api_version, kind, ns, name, suspend, status).await;
        });
    }

    fn start_flux_auto_refresh(&mut self) {
        self.stop_flux_auto_refresh();
        let client = self.client.clone();
        let state = self.flux_state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_flux(client.clone(), state.clone()).await;
            }
        });
        self.flux_refresh_handle = Some(handle);
    }

    fn stop_flux_auto_refresh(&mut self) {
        if let Some(h) = self.flux_refresh_handle.take() {
            h.abort();
        }
    }

    // Opens the aggregated, follow-mode log view of every Flux controller (the `flux logs` view).
    fn enter_flux_logs(&mut self) {
        self.return_mode = self.mode;
        self.mode = Mode::FluxLogs;
        self.reset_scroll();
        {
            let mut s = self.flux_logs_state.lock().expect("log state poisoned");
            s.current_key = Some("flux-logs".to_string());
            s.lines.clear();
            s.error = None;
            s.loading = true;
        }
        self.start_flux_logs_auto_refresh();
    }

    fn exit_flux_logs(&mut self) {
        self.stop_flux_logs_auto_refresh();
        self.mode = if matches!(self.return_mode, Mode::Flux | Mode::FluxFull) {
            self.return_mode
        } else {
            Mode::Flux
        };
    }

    fn start_flux_logs_auto_refresh(&mut self) {
        self.stop_flux_logs_auto_refresh();
        let client = self.client.clone();
        let state = self.flux_logs_state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let controllers = ALL_CONTROLLERS.iter().map(|c| c.to_string()).collect();
                fetch_flux_logs(client.clone(), controllers, None, "flux-logs".to_string(), state.clone(), 200).await;
                ticker.tick().await;
            }
        });
        self.flux_logs_handle = Some(handle);
    }

    fn stop_flux_logs_auto_refresh(&mut self) {
        if let Some(h) = self.flux_logs_handle.take() {
            h.abort();
        }
    }

    fn move_flux_selection(&mut self, delta: i32) {
        if self.snapshot.is_empty() { return; }
        let last = self.snapshot.len() - 1;
        let cur = self.table_state.selected().unwrap_or(0) as i32;
        let new = (cur + delta).clamp(0, last as i32) as usize;
        self.table_state.select(Some(new));
        self.selected_uid = self.snapshot.get(new).map(|r| r.uid.clone());
        self.last_flux_sel_uid = self.selected_uid.clone();
        self.reset_scroll();
        self.maybe_fetch_logs();
        self.maybe_fetch_status();
        self.maybe_fetch_related();
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

    // The namespace scope for pod listing: None means "all namespaces" (the "all" label).
    fn current_ns_opt(&self) -> Option<String> {
        if self.namespace_label == "all" { None } else { Some(self.namespace_label.clone()) }
    }

    fn enter_pods_mode(&mut self) {
        self.mode = Mode::Pods;
        self.pods_rows.clear();
        self.detail_tab = DetailTab::Logs;
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_pods_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
        self.refresh_pods();
        self.start_pods_auto_refresh();
        self.refresh_pods_snapshot();
    }

    fn exit_pods_mode(&mut self) {
        self.mode = Mode::Selection;
        self.stop_pods_auto_refresh();
        self.pods_rows.clear();
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_pods_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.clear_status_state();
        self.reset_to_follow();
    }

    fn enter_pods_full(&mut self) {
        if self.snapshot.is_empty() { return; }
        self.mode = Mode::PodsFull;
    }

    // --- Services / Ingress view --------------------------------------------------------------

    // Open the network view in the given world (Services or Ingress). Both worlds share one fetch and
    // one shared state, so switching world only re-renders; the namespace scope drives the fetch.
    fn enter_network_mode(&mut self, world: NetWorld) {
        self.mode = Mode::Services;
        self.net_world = world;
        self.net_rows.clear();
        // Status is the most useful default tab for Services/Ingress (they have no logs of their own).
        self.detail_tab = DetailTab::Status;
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_net_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
        self.refresh_network();
        self.start_network_auto_refresh();
        self.refresh_net_snapshot();
    }

    fn exit_network_mode(&mut self) {
        self.mode = Mode::Selection;
        self.stop_network_auto_refresh();
        self.net_rows.clear();
        self.snapshot.clear();
        self.table_state.select(None);
        self.selected_uid = None;
        self.last_net_sel_uid = None;
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.clear_status_state();
        self.reset_to_follow();
    }

    fn enter_network_full(&mut self) {
        if self.snapshot.is_empty() { return; }
        self.mode = Mode::ServicesFull;
    }

    fn exit_network_full(&mut self) {
        self.mode = Mode::Services;
    }

    // `t`: toggle nesting of children under their parent (endpoints under a Service, ingresses under
    // their IngressClass). Same meaning as `t` in the workloads view: "show the grouping".
    fn toggle_network_group(&mut self) {
        self.net_group = !self.net_group;
        self.refresh_net_snapshot();
    }

    // `g`: switch between the Services and Ingress worlds (same shared inventory, no reload needed).
    fn cycle_network_world(&mut self) {
        self.net_world = match self.net_world {
            NetWorld::Services => NetWorld::Ingress,
            NetWorld::Ingress => NetWorld::Services,
        };
        self.last_net_sel_uid = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
        self.refresh_net_snapshot();
    }

    // One-shot fetch of the network inventory for the current namespace scope.
    fn refresh_network(&self) {
        {
            let mut s = self.network_state.lock().expect("network poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.network_state.clone();
        let ns = self.current_ns_opt();
        tokio::spawn(async move { fetch_network(client, ns, state).await; });
    }

    fn start_network_auto_refresh(&mut self) {
        self.stop_network_auto_refresh();
        let client = self.client.clone();
        let state = self.network_state.clone();
        let ns = self.current_ns_opt();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_network(client.clone(), ns.clone(), state.clone()).await;
            }
        });
        self.net_refresh_handle = Some(handle);
    }

    fn stop_network_auto_refresh(&mut self) {
        if let Some(h) = self.net_refresh_handle.take() {
            h.abort();
        }
    }

    // Rebuild the flattened display rows and the index-aligned snapshot from the shared state, honoring
    // the active world and the `t` grouping. Selection is preserved by uid across refreshes/toggles so
    // the highlighted row and detail panel stay put. Mirrors `refresh_pods_snapshot`.
    fn refresh_net_snapshot(&mut self) {
        let rows: Vec<NetRow> = {
            let s = self.network_state.lock().expect("network poisoned");
            match (self.net_world, self.net_group) {
                // Services, grouped: each Service followed by its backing endpoints.
                (NetWorld::Services, true) => {
                    let mut rows: Vec<NetRow> =
                        Vec::with_capacity(s.services.len() + s.endpoints.len());
                    for svc in &s.services {
                        rows.push(NetRow::Service(svc.clone()));
                        for ep in s.endpoints.iter().filter(|e| endpoint_belongs_to(e, svc)) {
                            rows.push(NetRow::Endpoint(ep.clone()));
                        }
                    }
                    rows
                }
                // Services, flat: just the Service rows.
                (NetWorld::Services, false) => {
                    s.services.iter().cloned().map(NetRow::Service).collect()
                }
                // Ingress, grouped by class: each IngressClass followed by the ingresses that name it,
                // then ingresses with no class (or an unknown one) trailing as their own group.
                (NetWorld::Ingress, true) => {
                    let mut rows: Vec<NetRow> =
                        Vec::with_capacity(s.ingresses.len() + s.ingress_classes.len());
                    for cls in &s.ingress_classes {
                        rows.push(NetRow::IngressClass(cls.clone()));
                        for ing in s.ingresses.iter().filter(|i| i.class.as_deref() == Some(cls.name.as_str())) {
                            rows.push(NetRow::Ingress(ing.clone()));
                        }
                    }
                    let known: Vec<&str> = s.ingress_classes.iter().map(|c| c.name.as_str()).collect();
                    for ing in s
                        .ingresses
                        .iter()
                        .filter(|i| i.class.as_deref().map(|c| !known.contains(&c)).unwrap_or(true))
                    {
                        rows.push(NetRow::Ingress(ing.clone()));
                    }
                    rows
                }
                // Ingress, flat: just the Ingress rows.
                (NetWorld::Ingress, false) => {
                    s.ingresses.iter().cloned().map(NetRow::Ingress).collect()
                }
            }
        };
        let recs: Vec<EventRecord> = rows.iter().map(synthetic_net_record).collect();
        self.net_rows = rows;
        let prev_uid = self
            .table_state
            .selected()
            .and_then(|i| self.snapshot.get(i))
            .map(|r| r.uid.clone())
            .or_else(|| self.selected_uid.clone());
        self.snapshot = recs;
        if self.snapshot.is_empty() {
            self.table_state.select(None);
            self.last_net_sel_uid = None;
            return;
        }
        let idx = prev_uid
            .as_deref()
            .and_then(|uid| self.snapshot.iter().position(|r| r.uid == uid))
            .unwrap_or(0)
            .min(self.snapshot.len() - 1);
        self.table_state.select(Some(idx));
        self.selected_uid = Some(self.snapshot[idx].uid.clone());
        let cur_uid = self.snapshot[idx].uid.clone();
        if self.last_net_sel_uid.as_deref() != Some(cur_uid.as_str()) {
            self.last_net_sel_uid = Some(cur_uid);
            self.maybe_fetch_status();
            self.maybe_fetch_related();
        }
    }

    fn move_net_selection(&mut self, delta: i32) {
        if self.snapshot.is_empty() { return; }
        let last = self.snapshot.len() - 1;
        let cur = self.table_state.selected().unwrap_or(0) as i32;
        let new = (cur + delta).clamp(0, last as i32) as usize;
        self.table_state.select(Some(new));
        self.selected_uid = self.snapshot.get(new).map(|r| r.uid.clone());
        self.last_net_sel_uid = self.selected_uid.clone();
        self.reset_scroll();
        self.maybe_fetch_logs();
        self.maybe_fetch_status();
        self.maybe_fetch_related();
    }

    // --- RBAC security view -------------------------------------------------------------------

    fn enter_rbac_mode(&mut self) {
        self.mode = Mode::Rbac;
        self.rbac_cursor = 0;
        self.rbac_detail_scroll = 0;
        self.refresh_rbac();
        self.start_rbac_auto_refresh();
    }

    fn exit_rbac_mode(&mut self) {
        self.stop_rbac_auto_refresh();
        self.mode = Mode::Selection;
        self.reset_to_follow();
    }

    fn enter_rbac_full(&mut self) {
        if self.rbac_selected().is_none() { return; }
        self.rbac_detail_scroll = 0;
        self.mode = Mode::RbacFull;
    }

    fn exit_rbac_full(&mut self) {
        self.mode = Mode::Rbac;
    }

    fn refresh_rbac(&self) {
        {
            let mut s = self.rbac_state.lock().expect("rbac poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.rbac_state.clone();
        let crit = self.critical_ns.clone();
        tokio::spawn(async move { fetch_rbac(client, crit, state).await; });
    }

    // RBAC changes slowly; a 30s ticker keeps the view fresh without hammering the API.
    fn start_rbac_auto_refresh(&mut self) {
        self.stop_rbac_auto_refresh();
        let client = self.client.clone();
        let state = self.rbac_state.clone();
        let crit = self.critical_ns.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_rbac(client.clone(), crit.clone(), state.clone()).await;
            }
        });
        self.rbac_refresh_handle = Some(handle);
    }

    fn stop_rbac_auto_refresh(&mut self) {
        if let Some(h) = self.rbac_refresh_handle.take() {
            h.abort();
        }
    }

    // Indices of bindings passing the active severity floor, highest severity first (already sorted).
    fn rbac_visible(&self) -> Vec<RbacBinding> {
        let s = self.rbac_state.lock().expect("rbac poisoned");
        s.bindings
            .iter()
            .filter(|b| b.severity >= self.rbac_min_sev)
            .cloned()
            .collect()
    }

    fn rbac_selected(&self) -> Option<RbacBinding> {
        self.rbac_visible().into_iter().nth(self.rbac_cursor)
    }

    fn move_rbac_selection(&mut self, delta: i32) {
        let len = self.rbac_visible().len();
        if len == 0 { return; }
        let cur = self.rbac_cursor as i32;
        self.rbac_cursor = (cur + delta).clamp(0, len as i32 - 1) as usize;
        self.rbac_detail_scroll = 0;
    }

    // `o` on an RBAC binding: jump to the Flux object that manages it (Kustomization/HelmRelease),
    // landing on it in the Flux tree. No-op for non-Flux provenance.
    fn rbac_open_origin(&mut self) {
        use crate::rbac::Provenance;
        let Some(b) = self.rbac_selected() else { return; };
        let (kind, ns, name) = match &b.provenance {
            Provenance::FluxKustomization { namespace, name } => ("Kustomization", namespace.clone(), name.clone()),
            Provenance::FluxHelmRelease { namespace, name } => ("HelmRelease", namespace.clone(), name.clone()),
            other => {
                self.clipboard_status = Some((
                    std::time::Instant::now(),
                    format!("origine {} : non navigable", other.label()),
                ));
                return;
            }
        };
        self.stop_rbac_auto_refresh();
        self.flux_tree = true;
        self.enter_flux_mode();
        // Override the default first-Kustomization landing with the exact managing object.
        self.flux_select_first_ks = false;
        self.flux_pending_select = Some(format!("{}|{}/{}", kind, ns, name));
    }

    // Cycle the severity floor: all → HIGH+ → CRITICAL → all.
    fn cycle_rbac_filter(&mut self) {
        self.rbac_min_sev = match self.rbac_min_sev {
            RbacSeverity::Info => RbacSeverity::High,
            RbacSeverity::High => RbacSeverity::Critical,
            _ => RbacSeverity::Info,
        };
        self.rbac_cursor = 0;
        self.rbac_detail_scroll = 0;
    }

    // --- Vulnerability view -------------------------------------------------------------------

    fn enter_vuln_mode(&mut self) {
        self.mode = Mode::Vuln;
        self.vuln_cursor = 0;
        self.vuln_detail_scroll = 0;
        self.refresh_vulnerabilities();
        self.start_vuln_auto_refresh();
    }

    fn exit_vuln_mode(&mut self) {
        self.stop_vuln_auto_refresh();
        self.mode = Mode::Selection;
        self.reset_to_follow();
    }

    fn enter_vuln_full(&mut self) {
        if self.vuln_selected().is_none() { return; }
        self.vuln_detail_scroll = 0;
        self.mode = Mode::VulnFull;
    }

    fn exit_vuln_full(&mut self) {
        self.mode = Mode::Vuln;
    }

    // Current server version (read from the cluster banner state) to scope the k8s CVE lookup.
    fn server_version(&self) -> Option<String> {
        self.cluster_info.lock().expect("cluster info poisoned").server_version.clone()
    }

    fn refresh_vulnerabilities(&self) {
        {
            let mut s = self.vuln_state.lock().expect("vuln poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.vuln_state.clone();
        let version = self.server_version();
        tokio::spawn(async move { fetch_vulnerabilities(client, version, state).await; });
    }

    // VulnerabilityReports change slowly (operator rescans on a schedule); a 60s ticker is plenty.
    fn start_vuln_auto_refresh(&mut self) {
        self.stop_vuln_auto_refresh();
        let client = self.client.clone();
        let state = self.vuln_state.clone();
        let version = self.server_version();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_vulnerabilities(client.clone(), version.clone(), state.clone()).await;
            }
        });
        self.vuln_refresh_handle = Some(handle);
    }

    fn stop_vuln_auto_refresh(&mut self) {
        if let Some(h) = self.vuln_refresh_handle.take() {
            h.abort();
        }
    }

    // Selectable rows: the k8s control-plane risk first (when known, always shown), then the scanned
    // images passing the active severity floor (already sorted highest-severity first).
    fn vuln_rows(&self) -> Vec<VulnRow> {
        let s = self.vuln_state.lock().expect("vuln poisoned");
        let mut rows: Vec<VulnRow> = Vec::new();
        if let Some(k8s) = &s.k8s {
            rows.push(VulnRow::K8s(k8s.clone()));
        }
        rows.extend(
            s.components
                .iter()
                .filter(|c| c.max_sev >= self.vuln_min_sev)
                .cloned()
                .map(VulnRow::Image),
        );
        rows
    }

    fn vuln_selected(&self) -> Option<VulnRow> {
        self.vuln_rows().into_iter().nth(self.vuln_cursor)
    }

    fn move_vuln_selection(&mut self, delta: i32) {
        let len = self.vuln_rows().len();
        if len == 0 { return; }
        let cur = self.vuln_cursor as i32;
        self.vuln_cursor = (cur + delta).clamp(0, len as i32 - 1) as usize;
        self.vuln_detail_scroll = 0;
    }

    // Cycle the severity floor: all → HIGH+ → CRITICAL → all.
    fn cycle_vuln_filter(&mut self) {
        self.vuln_min_sev = match self.vuln_min_sev {
            VulnSev::Critical => VulnSev::Unknown,
            VulnSev::High => VulnSev::Critical,
            _ => VulnSev::High,
        };
        self.vuln_cursor = 0;
        self.vuln_detail_scroll = 0;
    }

    // --- Secrets view -------------------------------------------------------------------------

    fn enter_secrets_mode(&mut self) {
        self.mode = Mode::Secrets;
        self.secrets_cursor = 0;
        self.secrets_detail_scroll = 0;
        self.secrets_reveal = SecretReveal::Hidden;
        self.secrets_copy_menu = None;
        self.refresh_secrets();
        self.start_secrets_auto_refresh();
    }

    fn exit_secrets_mode(&mut self) {
        self.stop_secrets_auto_refresh();
        self.mode = Mode::Selection;
        self.reset_to_follow();
    }

    fn enter_secrets_full(&mut self) {
        if self.secret_selected().is_none() { return; }
        self.secrets_detail_scroll = 0;
        self.mode = Mode::SecretsFull;
    }

    fn exit_secrets_full(&mut self) {
        self.mode = Mode::Secrets;
    }

    fn refresh_secrets(&self) {
        {
            let mut s = self.secrets_state.lock().expect("secrets poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.secrets_state.clone();
        tokio::spawn(async move { fetch_secrets(client, state).await; });
    }

    // Secrets change rarely; a 60s ticker keeps the expiry countdown fresh without polling pressure.
    fn start_secrets_auto_refresh(&mut self) {
        self.stop_secrets_auto_refresh();
        let client = self.client.clone();
        let state = self.secrets_state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_secrets(client.clone(), state.clone()).await;
            }
        });
        self.secrets_refresh_handle = Some(handle);
    }

    fn stop_secrets_auto_refresh(&mut self) {
        if let Some(h) = self.secrets_refresh_handle.take() {
            h.abort();
        }
    }

    // The secrets passing the active filter (already sorted urgent-TLS-first by the fetcher).
    fn secret_rows(&self) -> Vec<SecretInfo> {
        let s = self.secrets_state.lock().expect("secrets poisoned");
        s.secrets.iter().filter(|x| self.secrets_filter.matches(x)).cloned().collect()
    }

    fn secret_selected(&self) -> Option<SecretInfo> {
        self.secret_rows().into_iter().nth(self.secrets_cursor)
    }

    fn move_secret_selection(&mut self, delta: i32) {
        let len = self.secret_rows().len();
        if len == 0 { return; }
        let cur = self.secrets_cursor as i32;
        self.secrets_cursor = (cur + delta).clamp(0, len as i32 - 1) as usize;
        self.secrets_detail_scroll = 0;
        // Never carry a revealed value over to a different secret.
        self.secrets_reveal = SecretReveal::Hidden;
    }

    // Cycle the filter: all → TLS only → expiring/expired → all.
    fn cycle_secrets_filter(&mut self) {
        self.secrets_filter = match self.secrets_filter {
            SecretFilter::All => SecretFilter::Tls,
            SecretFilter::Tls => SecretFilter::Expiring,
            SecretFilter::Expiring => SecretFilter::All,
        };
        self.secrets_cursor = 0;
        self.secrets_detail_scroll = 0;
        self.secrets_reveal = SecretReveal::Hidden;
    }

    // Toggle the in-panel reveal of data values: pressing the same key again hides them.
    fn toggle_secret_reveal(&mut self, target: SecretReveal) {
        self.secrets_reveal = if self.secrets_reveal == target { SecretReveal::Hidden } else { target };
        self.secrets_detail_scroll = 0;
    }

    // Open the copy picker on the selected secret (one entry per data key). No-op when empty.
    fn open_secrets_copy_menu(&mut self) {
        let Some(s) = self.secret_selected() else { return; };
        if s.data.is_empty() {
            self.clipboard_status = Some((std::time::Instant::now(), "rien à copier".to_string()));
            return;
        }
        self.secrets_copy_menu = Some(SecretsCopyMenu {
            title: format!("copier — {}/{}", s.namespace, s.name),
            keys: s.data_keys.clone(),
            cursor: 0,
        });
    }

    fn secrets_copy_menu_move(&mut self, delta: i32) {
        if let Some(menu) = self.secrets_copy_menu.as_mut() {
            // Row 0 is the manifest entry, rows 1.. are the data keys.
            let max = menu.keys.len() as i32;
            let cur = menu.cursor as i32;
            menu.cursor = (cur + delta).clamp(0, max) as usize;
        }
    }

    fn secrets_copy_menu_close(&mut self) {
        self.secrets_copy_menu = None;
    }

    // Copy the manifest (row 0) or the decoded value of the picked data key, then close the menu.
    fn secrets_copy_menu_activate(&mut self) {
        let Some(menu) = self.secrets_copy_menu.as_ref() else { return; };
        let cursor = menu.cursor;
        let key = menu.keys.get(cursor.wrapping_sub(1)).cloned();
        self.secrets_copy_menu = None;
        if cursor == 0 {
            let manifest = self.secret_selected().map(|s| s.manifest).unwrap_or_default();
            self.copy_text(manifest);
            return;
        }
        let Some(key) = key else { return; };
        let value = self
            .secret_selected()
            .and_then(|s| s.data.into_iter().find(|(k, _)| *k == key).map(|(_, v)| v));
        match value {
            Some(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_string();
                self.copy_text(text);
            }
            None => {
                self.clipboard_status = Some((std::time::Instant::now(), "clé introuvable".to_string()));
            }
        }
    }

    // --- ConfigMaps view ----------------------------------------------------------------------

    fn enter_configmaps_mode(&mut self) {
        self.mode = Mode::Configmaps;
        self.configmaps_cursor = 0;
        self.configmaps_detail_scroll = 0;
        self.configmaps_h_scroll = 0;
        self.configmaps_copy_menu = None;
        self.refresh_configmaps();
        self.start_configmaps_auto_refresh();
    }

    fn exit_configmaps_mode(&mut self) {
        self.stop_configmaps_auto_refresh();
        self.mode = Mode::Selection;
        self.reset_to_follow();
    }

    fn enter_configmaps_full(&mut self) {
        if self.configmap_selected().is_none() { return; }
        self.configmaps_detail_scroll = 0;
        self.mode = Mode::ConfigmapsFull;
    }

    fn exit_configmaps_full(&mut self) {
        self.mode = Mode::Configmaps;
    }

    fn refresh_configmaps(&self) {
        {
            let mut s = self.configmaps_state.lock().expect("configmaps poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.configmaps_state.clone();
        tokio::spawn(async move { fetch_configmaps(client, state).await; });
    }

    fn start_configmaps_auto_refresh(&mut self) {
        self.stop_configmaps_auto_refresh();
        let client = self.client.clone();
        let state = self.configmaps_state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_configmaps(client.clone(), state.clone()).await;
            }
        });
        self.configmaps_refresh_handle = Some(handle);
    }

    fn stop_configmaps_auto_refresh(&mut self) {
        if let Some(h) = self.configmaps_refresh_handle.take() {
            h.abort();
        }
    }

    fn configmap_rows(&self) -> Vec<ConfigMapInfo> {
        self.configmaps_state.lock().expect("configmaps poisoned").items.clone()
    }

    fn configmap_selected(&self) -> Option<ConfigMapInfo> {
        self.configmap_rows().into_iter().nth(self.configmaps_cursor)
    }

    fn move_configmap_selection(&mut self, delta: i32) {
        let len = self.configmap_rows().len();
        if len == 0 { return; }
        let cur = self.configmaps_cursor as i32;
        self.configmaps_cursor = (cur + delta).clamp(0, len as i32 - 1) as usize;
        self.configmaps_detail_scroll = 0;
        self.configmaps_h_scroll = 0;
    }

    fn open_configmaps_copy_menu(&mut self) {
        let Some(cm) = self.configmap_selected() else { return; };
        let keys = cm.keys();
        if keys.is_empty() {
            self.clipboard_status = Some((std::time::Instant::now(), "rien à copier".to_string()));
            return;
        }
        self.configmaps_copy_menu = Some(ConfigmapsCopyMenu {
            title: format!("copier — {}/{}", cm.namespace, cm.name),
            keys,
            cursor: 0,
        });
    }

    fn configmaps_copy_menu_move(&mut self, delta: i32) {
        if let Some(menu) = self.configmaps_copy_menu.as_mut() {
            // Row 0 is the manifest entry, rows 1.. are the data keys.
            let max = menu.keys.len() as i32;
            let cur = menu.cursor as i32;
            menu.cursor = (cur + delta).clamp(0, max) as usize;
        }
    }

    fn configmaps_copy_menu_close(&mut self) {
        self.configmaps_copy_menu = None;
    }

    // Copy the manifest (row 0) or the picked key's text value. Binary keys report no text value.
    fn configmaps_copy_menu_activate(&mut self) {
        let Some(menu) = self.configmaps_copy_menu.as_ref() else { return; };
        let cursor = menu.cursor;
        let key = menu.keys.get(cursor.wrapping_sub(1)).cloned();
        self.configmaps_copy_menu = None;
        if cursor == 0 {
            let manifest = self.configmap_selected().map(|cm| cm.manifest).unwrap_or_default();
            self.copy_text(manifest);
            return;
        }
        let Some(key) = key else { return; };
        let value = self
            .configmap_selected()
            .and_then(|cm| cm.data.into_iter().find(|(k, _)| *k == key).map(|(_, v)| v));
        match value {
            Some(text) => self.copy_text(text),
            None => {
                self.clipboard_status = Some((
                    std::time::Instant::now(),
                    format!("{key} : binaire, non copiable en texte"),
                ));
            }
        }
    }

    fn exit_pods_full(&mut self) {
        self.mode = Mode::Pods;
    }

    // Kick off a one-shot fetch of workloads + pods for the current namespace scope.
    fn refresh_pods(&self) {
        {
            let mut s = self.pods_state.lock().expect("pods poisoned");
            s.loading = true;
            s.error = None;
        }
        let client = self.client.clone();
        let state = self.pods_state.clone();
        let ns = self.current_ns_opt();
        tokio::spawn(async move { fetch_workloads(client, ns, state).await; });
    }

    // Restarts the 5 s auto-refresh, capturing the current namespace scope. Must be called again
    // whenever the namespace filter changes so the ticker fetches the right set.
    fn start_pods_auto_refresh(&mut self) {
        self.stop_pods_auto_refresh();
        let client = self.client.clone();
        let state = self.pods_state.clone();
        let ns = self.current_ns_opt();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                fetch_workloads(client.clone(), ns.clone(), state.clone()).await;
            }
        });
        self.pods_refresh_handle = Some(handle);
    }

    fn stop_pods_auto_refresh(&mut self) {
        if let Some(h) = self.pods_refresh_handle.take() {
            h.abort();
        }
    }

    // One-shot refresh after a short delay, so a scale/restart action is reflected in the list before
    // the next regular tick (gives quick visual feedback that the action took effect).
    fn schedule_pods_refresh(&self, after_ms: u64) {
        let client = self.client.clone();
        let state = self.pods_state.clone();
        let ns = self.current_ns_opt();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(after_ms)).await;
            fetch_workloads(client, ns, state).await;
        });
    }

    // Rebuild the flattened display rows (and the matching snapshot) from the shared state: each
    // workload row is followed by the pods that resolve to it, then any orphan pods (bare pods or
    // pods of a naked ReplicaSet) close the list. The snapshot carries real api_version/kind/ns/name
    // so the shared detail tabs (Logs/Status/Related) work per pod and per workload, and stays index-
    // aligned with `pods_rows` so a selected table row maps to the same workload/pod in both.
    fn refresh_pods_snapshot(&mut self) {
        let rows: Vec<PodRow> = {
            let s = self.pods_state.lock().expect("pods poisoned");
            // Remember the initial replica count once, so rescale/recycle can restore it.
            for w in &s.workloads {
                if let Some(r) = w.replicas {
                    self.pods_saved_replicas.entry(w.uid.clone()).or_insert(r);
                }
            }
            if self.pods_show_workloads {
                let mut rows: Vec<PodRow> = Vec::with_capacity(s.pods.len() + s.workloads.len());
                for w in &s.workloads {
                    rows.push(PodRow::Workload(w.clone()));
                    for p in s.pods.iter().filter(|p| pod_belongs_to(p, w)) {
                        rows.push(PodRow::Pod(p.clone()));
                    }
                }
                for p in s.pods.iter().filter(|p| !s.workloads.iter().any(|w| pod_belongs_to(p, w))) {
                    rows.push(PodRow::Pod(p.clone()));
                }
                rows
            } else {
                // Pods-only view: flat list of every pod, no parent workload rows.
                s.pods.iter().map(|p| PodRow::Pod(p.clone())).collect()
            }
        };
        let recs: Vec<EventRecord> = rows
            .iter()
            .map(|r| match r {
                PodRow::Workload(w) => synthetic_workload_record(w),
                PodRow::Pod(p) => synthetic_pod_record(p),
            })
            .collect();
        self.pods_rows = rows;
        let prev_uid = self
            .table_state
            .selected()
            .and_then(|i| self.snapshot.get(i))
            .map(|r| r.uid.clone())
            .or_else(|| self.selected_uid.clone());
        self.snapshot = recs;
        if self.snapshot.is_empty() {
            self.table_state.select(None);
            self.last_pods_sel_uid = None;
            return;
        }
        let idx = prev_uid
            .as_deref()
            .and_then(|uid| self.snapshot.iter().position(|r| r.uid == uid))
            .unwrap_or(0)
            .min(self.snapshot.len() - 1);
        self.table_state.select(Some(idx));
        self.selected_uid = Some(self.snapshot[idx].uid.clone());
        let cur_uid = self.snapshot[idx].uid.clone();
        if self.last_pods_sel_uid.as_deref() != Some(cur_uid.as_str()) {
            self.last_pods_sel_uid = Some(cur_uid);
            self.maybe_fetch_logs();
            self.maybe_fetch_status();
            self.maybe_fetch_related();
        }
    }

    // Toggle between the flat pods-only view (default) and the tabular view that nests pods under
    // their originating workload rows.
    fn toggle_pods_workloads(&mut self) {
        self.pods_show_workloads = !self.pods_show_workloads;
        self.refresh_pods_snapshot();
    }

    fn move_pods_selection(&mut self, delta: i32) {
        if self.snapshot.is_empty() { return; }
        let last = self.snapshot.len() - 1;
        let cur = self.table_state.selected().unwrap_or(0) as i32;
        let new = (cur + delta).clamp(0, last as i32) as usize;
        self.table_state.select(Some(new));
        self.selected_uid = self.snapshot.get(new).map(|r| r.uid.clone());
        self.last_pods_sel_uid = self.selected_uid.clone();
        self.reset_scroll();
        self.maybe_fetch_logs();
        self.maybe_fetch_status();
        self.maybe_fetch_related();
    }

    // The workload that scale/restart actions target: the selected row when it is a workload, or the
    // owning workload of the selected pod row (so actions work whether a parent or child is selected).
    fn selected_workload(&self) -> Option<WorkloadResource> {
        let i = self.table_state.selected()?;
        match self.pods_rows.get(i)? {
            PodRow::Workload(w) => Some(w.clone()),
            PodRow::Pod(p) => {
                let o = p.owner.as_ref()?;
                self.pods_rows.iter().find_map(|r| match r {
                    PodRow::Workload(w)
                        if w.kind == o.kind && w.name == o.name && w.namespace == o.namespace =>
                    {
                        Some(w.clone())
                    }
                    _ => None,
                })
            }
        }
    }

    // (namespace, pod names) of the selected workload row, for aggregated log fetching. None when the
    // selected row is a pod (its own logs are fetched directly) or no workload is selected.
    fn selected_workload_pods(&self) -> Option<(String, Vec<String>)> {
        let i = self.table_state.selected()?;
        let PodRow::Workload(w) = self.pods_rows.get(i)? else { return None };
        let s = self.pods_state.lock().expect("pods poisoned");
        let pods: Vec<String> = s
            .pods
            .iter()
            .filter(|p| pod_belongs_to(p, w))
            .map(|p| p.name.clone())
            .collect();
        Some((w.namespace.clone(), pods))
    }

    // Scale the selected workload by a relative delta (clamped at 0).
    fn pods_scale(&mut self, delta: i32) {
        let Some(w) = self.selected_workload() else {
            self.pods_scale_hint();
            return;
        };
        let Some(cur) = w.replicas else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("scale non supporté pour {}", w.kind),
            ));
            return;
        };
        let target = (cur + delta).max(0);
        self.spawn_scale(&w, target);
    }

    // Scale the focused workload to zero (its initial count is already memorised for restore).
    fn pods_scale_zero(&mut self) {
        let Some(w) = self.selected_workload() else {
            self.pods_scale_hint();
            return;
        };
        if w.replicas.is_none() {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("scale non supporté pour {}", w.kind),
            ));
            return;
        }
        self.spawn_scale(&w, 0);
    }

    // Scale the focused workload to an exact replica count (clamped at 0).
    fn pods_scale_set(&mut self, target: i32) {
        let Some(w) = self.selected_workload() else {
            self.pods_scale_hint();
            return;
        };
        if w.replicas.is_none() {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("scale non supporté pour {}", w.kind),
            ));
            return;
        }
        self.spawn_scale(&w, target.max(0));
    }

    // Rescale to the memorised initial count. `force` first scales to 0 then back up, bypassing the
    // rolling update for a hard recycle of all pods.
    fn pods_rescale(&mut self, force: bool) {
        let Some(w) = self.selected_workload() else {
            self.pods_scale_hint();
            return;
        };
        if w.replicas.is_none() {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("scale non supporté pour {}", w.kind),
            ));
            return;
        }
        let target = self
            .pods_saved_replicas
            .get(&w.uid)
            .copied()
            .or(w.replicas)
            .unwrap_or(1);
        let owner = w.as_owner();
        let client = self.client.clone();
        let status = self.reconcile_status.clone();
        if force {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("♻ recyclage {}/{} (0 → {})…", w.kind, w.name, target),
            ));
            tokio::spawn(async move { run_force_recycle(client, owner, target, status).await; });
            // Force-recycle scales to 0 then back up (~2 s); refresh around each step.
            self.schedule_pods_refresh(800);
            self.schedule_pods_refresh(3000);
        } else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("⇅ rescale {}/{} → {}…", w.kind, w.name, target),
            ));
            tokio::spawn(async move { run_scale(client, owner, target, status).await; });
            self.schedule_pods_refresh(1500);
        }
    }

    // Rollout restart of the focused workload (Deployment/StatefulSet/DaemonSet).
    fn pods_restart(&mut self) {
        let Some(w) = self.selected_workload() else {
            self.pods_scale_hint();
            return;
        };
        let owner = w.as_owner();
        self.clipboard_status = Some((
            std::time::Instant::now(),
            format!("↻ restart {}/{}…", w.kind, w.name),
        ));
        let client = self.client.clone();
        let status = self.reconcile_status.clone();
        tokio::spawn(async move { run_restart(client, owner, status).await; });
        self.schedule_pods_refresh(1500);
    }

    fn spawn_scale(&mut self, w: &WorkloadResource, target: i32) {
        let owner = w.as_owner();
        self.clipboard_status = Some((
            std::time::Instant::now(),
            format!("⇅ scale {}/{} → {}…", w.kind, w.name, target),
        ));
        let client = self.client.clone();
        let status = self.reconcile_status.clone();
        tokio::spawn(async move { run_scale(client, owner, target, status).await; });
        self.schedule_pods_refresh(1500);
    }

    fn pods_scale_hint(&mut self) {
        self.clipboard_status = Some((
            std::time::Instant::now(),
            "scale/restart : sélectionnez un workload (ou un de ses pods)".to_string(),
        ));
    }

    // Opens the workload action menu (rescale / recycle / restart). Requires a focused workload,
    // otherwise it falls back to the focus hint.
    fn open_pods_action_menu(&mut self) {
        if self.selected_workload().is_none() {
            self.pods_scale_hint();
            return;
        }
        let st = lang::t(self.ai_language);
        self.action_menu = Some(ActionMenu {
            title: st.menu_pods_title,
            items: vec![
                ActionItem { label: st.k_rescale, desc: st.desc_rescale, action: MenuAction::Rescale },
                ActionItem { label: st.k_force, desc: st.desc_recycle, action: MenuAction::Recycle },
                ActionItem { label: st.k_restart, desc: st.desc_restart, action: MenuAction::Restart },
            ],
            cursor: 0,
            confirm: true,
            confirming: false,
            input: None,
        });
    }

    // Opens the workload scale menu (+1 / -1 / scale 0 / set an exact replica count).
    fn open_pods_scale_menu(&mut self) {
        if self.selected_workload().is_none() {
            self.pods_scale_hint();
            return;
        }
        let st = lang::t(self.ai_language);
        self.action_menu = Some(ActionMenu {
            title: st.menu_scale_title,
            items: vec![
                ActionItem { label: st.k_scale_up, desc: st.desc_scale_up, action: MenuAction::ScaleDelta(1) },
                ActionItem { label: st.k_scale_down, desc: st.desc_scale_down, action: MenuAction::ScaleDelta(-1) },
                ActionItem { label: st.k_scale_zero, desc: st.desc_scale_zero, action: MenuAction::ScaleZero },
                ActionItem { label: st.k_scale_set, desc: st.desc_scale_set, action: MenuAction::ScaleSet },
            ],
            cursor: 0,
            confirm: false,
            confirming: false,
            input: None,
        });
    }

    // Opens the Flux reconcile menu (resource / +source / root sync).
    fn open_flux_action_menu(&mut self) {
        let st = lang::t(self.ai_language);
        self.action_menu = Some(ActionMenu {
            title: st.menu_flux_title,
            items: vec![
                ActionItem { label: st.k_reconcile, desc: st.desc_reconcile, action: MenuAction::Reconcile(ReconcileScope::Resource) },
                ActionItem { label: st.k_reconcile_src, desc: st.desc_reconcile_src, action: MenuAction::Reconcile(ReconcileScope::WithSource) },
                ActionItem { label: st.k_sync_root, desc: st.desc_sync_root, action: MenuAction::Reconcile(ReconcileScope::RootSync) },
            ],
            cursor: 0,
            confirm: true,
            confirming: false,
            input: None,
        });
    }

    fn action_menu_move(&mut self, delta: i32) {
        if let Some(menu) = self.action_menu.as_mut() {
            if menu.confirming || menu.input.is_some() || menu.items.is_empty() { return; }
            let len = menu.items.len() as i32;
            let cur = menu.cursor as i32;
            menu.cursor = (cur + delta).rem_euclid(len) as usize;
        }
    }

    // Enter: arms the confirmation (for destructive menus), opens the numeric entry (`ScaleSet`),
    // or runs the highlighted action and closes.
    fn action_menu_activate(&mut self) {
        let action = match self.action_menu.as_mut() {
            None => return,
            // Confirm numeric entry: parse the typed replica count and apply it.
            Some(menu) if menu.input.is_some() => {
                let target = menu.input.as_ref().and_then(|s| s.parse::<i32>().ok());
                let Some(target) = target else { return; };
                self.action_menu = None;
                self.pods_scale_set(target);
                return;
            }
            Some(menu)
                if matches!(
                    menu.items.get(menu.cursor).map(|it| &it.action),
                    Some(MenuAction::ScaleSet)
                ) =>
            {
                menu.input = Some(String::new());
                return;
            }
            Some(menu) if menu.confirm && !menu.confirming => {
                menu.confirming = true;
                return;
            }
            Some(menu) => menu.items.get(menu.cursor).map(|it| it.action.clone()),
        };
        self.action_menu = None;
        match action {
            Some(MenuAction::Rescale) => self.pods_rescale(false),
            Some(MenuAction::Recycle) => self.pods_rescale(true),
            Some(MenuAction::Restart) => self.pods_restart(),
            Some(MenuAction::Reconcile(scope)) => self.reconcile_selected(scope),
            Some(MenuAction::ScaleDelta(d)) => self.pods_scale(d),
            Some(MenuAction::ScaleZero) => self.pods_scale_zero(),
            Some(MenuAction::ScaleSet) | None => {}
        }
    }

    // Esc: cancels numeric entry, backs out of confirmation, or closes the menu entirely.
    fn action_menu_back(&mut self) {
        match self.action_menu.as_mut() {
            Some(menu) if menu.input.is_some() => menu.input = None,
            Some(menu) if menu.confirming => menu.confirming = false,
            _ => self.action_menu = None,
        }
    }

    // Digit/backspace handling while the numeric replica entry is open. No-op otherwise.
    fn action_menu_input(&mut self, c: char) {
        if let Some(menu) = self.action_menu.as_mut() {
            if let Some(buf) = menu.input.as_mut() {
                if c.is_ascii_digit() && buf.len() < 5 {
                    buf.push(c);
                }
            }
        }
    }

    fn action_menu_backspace(&mut self) {
        if let Some(menu) = self.action_menu.as_mut() {
            if let Some(buf) = menu.input.as_mut() {
                buf.pop();
            }
        }
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

    // Build an event-shaped record describing the selected binding so the AI panel can explain why
    // it is risky (findings + resolved rules), reusing the existing prompt plumbing.
    fn synthetic_rbac_record(&self) -> Option<EventRecord> {
        let b = self.rbac_selected()?;
        let subjects = b.subjects.iter().map(|s| s.label()).collect::<Vec<_>>().join(", ");
        let findings = b
            .findings
            .iter()
            .map(|f| format!("[{}] {}: {}", f.sev.label(), f.tag, f.detail))
            .collect::<Vec<_>>()
            .join("\n");
        let rules = b
            .rules
            .iter()
            .map(|r| format!(
                "  apiGroups={:?} resources={:?} verbs={:?}",
                r.api_groups, r.resources, r.verbs
            ))
            .collect::<Vec<_>>()
            .join("\n");
        let source = b.source.clone().unwrap_or_default();
        let message = format!(
            "{} {} → {}\nscope={}\nsubjects={}\nseverity={}\norigin={}\nsource={}\nfindings:\n{}\nrules:\n{}",
            b.binding_kind,
            b.binding_name,
            b.role_ref.label(),
            b.scope.label(),
            subjects,
            b.severity.label(),
            b.provenance.label(),
            source,
            findings,
            rules,
        );
        Some(EventRecord {
            uid: format!("rbac|{}|{}", b.binding_kind, b.binding_name),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: Severity::Warning,
            reason: format!("RBAC/{}", b.severity.label()),
            api_version: "rbac.authorization.k8s.io/v1".to_string(),
            kind: b.binding_kind.clone(),
            namespace: match &b.scope {
                crate::rbac::Scope::Namespace(ns) => ns.clone(),
                crate::rbac::Scope::ClusterWide => String::new(),
            },
            name: b.binding_name.clone(),
            message,
            component: String::new(),
            host: String::new(),
            count: 1,
        })
    }

    // Event-shaped record for the AI panel: the selected image's CVEs (or the k8s version risk), so
    // the model can summarise impact and the upgrade path.
    fn synthetic_vuln_record(&self) -> Option<EventRecord> {
        match self.vuln_selected()? {
            VulnRow::Image(c) => {
                let cve_lines = c
                    .cves
                    .iter()
                    .take(40)
                    .map(|v| {
                        let fix = if v.fixed.is_empty() {
                            "pas de fix".to_string()
                        } else {
                            format!("{} → {}", v.installed, v.fixed)
                        };
                        format!("[{} {:.1}] {} {} ({})", v.severity.label(), v.score, v.id, v.package, fix)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let message = format!(
                    "image={}:{}\nworkload={}\ncrit={} high={} med={} low={} fixables={}\nCVEs:\n{}",
                    c.image, c.version, c.workload, c.critical, c.high, c.medium, c.low, c.fixable, cve_lines,
                );
                Some(EventRecord {
                    uid: format!("vuln|{}|{}", c.namespace, c.image),
                    time: k8s_openapi::jiff::Timestamp::now(),
                    severity: Severity::Warning,
                    reason: format!("VULN/{}", c.max_sev.label()),
                    api_version: "aquasecurity.github.io/v1alpha1".to_string(),
                    kind: "VulnerabilityReport".to_string(),
                    namespace: c.namespace.clone(),
                    name: c.image.clone(),
                    message,
                    component: String::new(),
                    host: String::new(),
                    count: 1,
                })
            }
            VulnRow::K8s(k) => {
                let cve_lines = k
                    .cves
                    .iter()
                    .take(40)
                    .map(|v| format!("[{} {:.1}] {} {}", v.severity.label(), v.score, v.id, v.title))
                    .collect::<Vec<_>>()
                    .join("\n");
                let target = k.latest_patch.clone().unwrap_or_else(|| "?".to_string());
                let message = format!(
                    "Kubernetes control-plane\nversion serveur={}\ncible (dernier patch mineure)={}\nretard de patch={}\nEOL={}\nCVEs récentes (feed officiel, non filtrées par version):\n{}",
                    k.server_version, target, k.behind, k.eol, cve_lines,
                );
                Some(EventRecord {
                    uid: format!("vuln|k8s|{}", k.server_version),
                    time: k8s_openapi::jiff::Timestamp::now(),
                    severity: Severity::Warning,
                    reason: "VULN/k8s".to_string(),
                    api_version: String::new(),
                    kind: "KubernetesVersion".to_string(),
                    namespace: String::new(),
                    name: k.server_version.clone(),
                    message,
                    component: String::new(),
                    host: String::new(),
                    count: 1,
                })
            }
        }
    }

    // Event-shaped record for the AI panel: the selected secret's type/consumers and, for a TLS
    // secret, the decoded certificate (subject/issuer/SAN/expiry) so the model can flag expiry risk
    // and chain/issuer problems.
    fn synthetic_secrets_record(&self) -> Option<EventRecord> {
        let s = self.secret_selected()?;
        let mut msg = format!(
            "secret={}/{}\ntype={}\nclés={}\norigine={}",
            s.namespace,
            s.name,
            s.type_,
            if s.data_keys.is_empty() { "—".to_string() } else { s.data_keys.join(", ") },
            s.provenance.label(),
        );
        if !s.ingress_refs.is_empty() {
            msg.push_str(&format!("\ningress consommateurs={}", s.ingress_refs.join(", ")));
        }
        if let Some(cm) = &s.cert_manager {
            msg.push_str(&format!("\ncert-manager Certificate={cm}"));
        }
        if let Some(c) = &s.tls {
            msg.push_str(&format!(
                "\n--- certificat TLS ---\nsubject CN={}\nissuer CN={}\nauto-signé={}\nCA={}\nSAN={}\nvalidité={} → {} ({} jours restants)\nclé={}\nserial={}",
                c.subject_cn,
                c.issuer_cn,
                c.self_signed,
                c.is_ca,
                if c.sans.is_empty() { "—".to_string() } else { c.sans.join(", ") },
                c.not_before,
                c.not_after,
                c.days_remaining,
                c.key_algo,
                c.serial,
            ));
            if let Some(ca) = &c.ca_bundle {
                msg.push_str(&format!(
                    "\nCA bundle: CN={} expire {} ({} jours)",
                    ca.subject_cn, ca.not_after, ca.days_remaining,
                ));
            }
        } else if let Some(e) = &s.tls_error {
            msg.push_str(&format!("\ncertificat TLS illisible: {e}"));
        }
        let reason = match s.tls.as_ref().map(|c| c.expiry) {
            Some(Expiry::Expired) => "SECRET/TLS-EXPIRED",
            Some(Expiry::Critical) | Some(Expiry::Warn) => "SECRET/TLS-EXPIRING",
            Some(Expiry::Ok) => "SECRET/TLS",
            None => "SECRET",
        };
        Some(EventRecord {
            uid: format!("secret|{}|{}", s.namespace, s.name),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: if matches!(s.tls.as_ref().map(|c| c.expiry), Some(Expiry::Expired) | Some(Expiry::Critical)) {
                Severity::Warning
            } else {
                Severity::Normal
            },
            reason: reason.to_string(),
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            namespace: s.namespace.clone(),
            name: s.name.clone(),
            message: msg,
            component: String::new(),
            host: String::new(),
            count: 1,
        })
    }

    // Event-shaped record for the AI panel: the selected ConfigMap's keys and (truncated) values so
    // the model can explain what the configuration does or spot misconfigurations.
    fn synthetic_configmaps_record(&self) -> Option<EventRecord> {
        let cm = self.configmap_selected()?;
        let mut msg = format!(
            "configmap={}/{}\norigine={}\nclés texte={} · clés binaires={}",
            cm.namespace,
            cm.name,
            cm.provenance.label(),
            cm.data.len(),
            cm.binary_keys.len(),
        );
        for (k, v) in &cm.data {
            let val: String = v.chars().take(2000).collect();
            msg.push_str(&format!("\n--- {k} ---\n{val}"));
        }
        if !cm.binary_keys.is_empty() {
            msg.push_str(&format!("\nbinaires: {}", cm.binary_keys.join(", ")));
        }
        Some(EventRecord {
            uid: format!("configmap|{}|{}", cm.namespace, cm.name),
            time: k8s_openapi::jiff::Timestamp::now(),
            severity: Severity::Normal,
            reason: "ConfigMap".to_string(),
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: cm.namespace.clone(),
            name: cm.name.clone(),
            message: msg,
            component: String::new(),
            host: String::new(),
            count: 1,
        })
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

    // Apply the namespace picked in the selector: restart the event watcher scoped to it
    // (cursor 0 means "all namespaces"), clearing the buffer and current selection.
    // Scope the event watcher to `ns_opt` (None = all namespaces), clearing the buffer, snapshot and
    // current selection. Shared by the picker, the `:ns/pods/events <name>` palette args and the `0`
    // shortcut.
    fn apply_namespace(&mut self, ns_opt: Option<String>) {
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
        self.scroll_frozen = false;
        self.selected_uid = None;
        self.snapshot.clear();
        self.table_state.select(None);
        self.last_pod_key = None;
        self.last_status_key = None;
        self.last_related_key = None;
        self.reset_scroll();
    }

    // Scope the filter to the namespace of the currently selected row (event or pod) without
    // opening the picker — `:ns` stays available for arbitrary selection.
    fn filter_ns_to_selected(&mut self) {
        let ns = self
            .table_state
            .selected()
            .and_then(|i| self.snapshot.get(i))
            .map(|r| r.namespace.clone())
            .filter(|n| !n.is_empty());
        let Some(ns) = ns else {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "aucun namespace sur l'élément sélectionné".to_string(),
            ));
            return;
        };
        if self.namespace_label == ns {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                format!("déjà filtré sur {}", ns),
            ));
            return;
        }
        let was_pods = matches!(self.mode, Mode::Pods | Mode::PodsFull);
        let was_net = matches!(self.mode, Mode::Services | Mode::ServicesFull);
        let net_world = self.net_world;
        self.apply_namespace(Some(ns));
        if was_pods {
            self.enter_pods_mode();
        } else if was_net {
            self.enter_network_mode(net_world);
        } else {
            self.mode = Mode::Selection;
        }
    }

    // Drop the active namespace filter (`0`), refreshing whichever ns-scoped view is open.
    fn clear_namespace_filter(&mut self) {
        if self.namespace_label == "all" {
            self.clipboard_status = Some((
                std::time::Instant::now(),
                "déjà sur tous les namespaces".to_string(),
            ));
            return;
        }
        let was_pods = matches!(self.mode, Mode::Pods | Mode::PodsFull);
        let was_net = matches!(self.mode, Mode::Services | Mode::ServicesFull);
        let net_world = self.net_world;
        self.apply_namespace(None);
        if was_pods {
            self.enter_pods_mode();
        } else if was_net {
            self.enter_network_mode(net_world);
        } else {
            self.mode = Mode::Selection;
        }
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
        self.apply_namespace(ns_opt);
        if self.ns_return_pods {
            // Re-enter the pods view scoped to the freshly selected namespace.
            self.ns_return_pods = false;
            self.enter_pods_mode();
        } else {
            self.mode = Mode::Selection;
        }
    }
}

pub async fn run(mut app: App) -> Result<()> {
    let mut terminal = ratatui::init();
    app.spawn_cluster_info_refresh();
    let result = run_loop(&mut terminal, &mut app).await;
    ratatui::restore();
    result
}

// Main loop: refresh live snapshots, draw, then await the next input/tick/Ctrl-C. The 250ms ticker
// drives periodic redraws so async results and live event flow appear without keypresses.
async fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut visible_rows: usize = 20;

    loop {
        if app.mode == Mode::Selection && !app.scroll_frozen {
            app.refresh_live_snapshot();
        }
        if matches!(app.mode, Mode::Flux | Mode::FluxFull) {
            app.refresh_flux_snapshot();
            app.drain_reconcile_status();
            if !app.flux_inv_expanded.is_empty()
                && app.last_inventory_tick.elapsed() >= Duration::from_secs(5)
            {
                app.last_inventory_tick = std::time::Instant::now();
                app.refresh_expanded_inventories();
            }
        }
        if matches!(app.mode, Mode::Pods | Mode::PodsFull) {
            app.refresh_pods_snapshot();
            app.drain_reconcile_status();
        }
        if matches!(app.mode, Mode::Services | Mode::ServicesFull) {
            app.refresh_net_snapshot();
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

// Central key dispatcher: matches on (key, modifiers, current mode). Mode-specific arms come first;
// the trailing arms handle keys shared across modes (horizontal scroll, quit…).
fn handle_event(app: &mut App, ev: Event) {
    let Event::Key(k) = ev else { return };
    if k.kind != KeyEventKind::Press { return; }
    // The action menu overlay grabs all input while open (Ctrl-C still quits).
    if app.action_menu.is_some() {
        match (k.code, k.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
            (KeyCode::Enter, _) => app.action_menu_activate(),
            (KeyCode::Esc, _) => app.action_menu_back(),
            (KeyCode::Backspace, _) => app.action_menu_backspace(),
            (KeyCode::Char(c), _) if c.is_ascii_digit() => app.action_menu_input(c),
            (KeyCode::Up | KeyCode::Char('k'), _) => app.action_menu_move(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => app.action_menu_move(1),
            _ => {}
        }
        return;
    }
    // The secrets copy picker grabs all input while open (Ctrl-C still quits).
    if app.secrets_copy_menu.is_some() {
        match (k.code, k.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
            (KeyCode::Enter, _) => app.secrets_copy_menu_activate(),
            (KeyCode::Esc, _) => app.secrets_copy_menu_close(),
            (KeyCode::Up | KeyCode::Char('k'), _) => app.secrets_copy_menu_move(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => app.secrets_copy_menu_move(1),
            _ => {}
        }
        return;
    }
    // The configmaps copy picker grabs all input while open (Ctrl-C still quits).
    if app.configmaps_copy_menu.is_some() {
        match (k.code, k.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
            (KeyCode::Enter, _) => app.configmaps_copy_menu_activate(),
            (KeyCode::Esc, _) => app.configmaps_copy_menu_close(),
            (KeyCode::Up | KeyCode::Char('k'), _) => app.configmaps_copy_menu_move(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => app.configmaps_copy_menu_move(1),
            _ => {}
        }
        return;
    }
    match (k.code, k.modifiers, app.mode) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL, _) => app.should_quit = true,

        (KeyCode::Esc, _, Mode::Command) => app.exit_command(),
        (KeyCode::Enter, _, Mode::Command) => app.command_run(),
        (KeyCode::Up, _, Mode::Command) => app.move_command_selection(-1),
        (KeyCode::Down, _, Mode::Command) => app.move_command_selection(1),
        (KeyCode::Tab, _, Mode::Command) => app.command_autocomplete(),
        (KeyCode::Backspace, _, Mode::Command) => app.command_backspace(),
        (KeyCode::Char(c), m, Mode::Command) if !m.contains(KeyModifiers::CONTROL) => app.command_push(c),
        (_, _, Mode::Command) => {}

        (KeyCode::Char(':'), _, Mode::Selection | Mode::Nodes | Mode::NodesFull | Mode::Flux | Mode::FluxFull | Mode::Pods | Mode::PodsFull | Mode::Rbac | Mode::RbacFull | Mode::Vuln | Mode::VulnFull | Mode::Secrets | Mode::SecretsFull | Mode::Configmaps | Mode::ConfigmapsFull | Mode::Services | Mode::ServicesFull) => {
            app.enter_command();
        }

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

        // Copy the active detail zone (Logs/Status/Related, or node status) wherever that panel is
        // shown — same affordance as the AI/diagnostic views, just on the split detail panel.
        (KeyCode::Char('c'), _, Mode::Selection | Mode::DetailFull | Mode::Nodes | Mode::NodesFull | Mode::Pods | Mode::PodsFull | Mode::Flux | Mode::FluxFull) => app.copy_detail_view(),

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
        (KeyCode::Left, m, Mode::Nodes) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5),
        (KeyCode::Right, m, Mode::Nodes) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_add(5),
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

        (KeyCode::Up, m, Mode::Flux) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::Flux) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::Left, m, Mode::Flux) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5),
        (KeyCode::Right, m, Mode::Flux) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_add(5),
        (KeyCode::Up, _, Mode::Flux) => app.move_flux_selection(-1),
        (KeyCode::Down, _, Mode::Flux) => app.move_flux_selection(1),
        (KeyCode::PageUp, _, Mode::Flux) => app.move_flux_selection(-10),
        (KeyCode::PageDown, _, Mode::Flux) => app.move_flux_selection(10),
        (KeyCode::Tab, _, Mode::Flux) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::Flux) => app.cycle_tab_back(),
        (KeyCode::Char(' '), _, Mode::Flux) if app.flux_tree => app.toggle_flux_node(),
        (KeyCode::Enter, _, Mode::Flux) => app.enter_flux_full(),
        (KeyCode::Char('+'), _, Mode::Flux) => app.expand_flux_inventory(),
        (KeyCode::Char('-'), _, Mode::Flux) => app.collapse_flux_inventory(),
        (KeyCode::Esc, _, Mode::Flux) => app.exit_flux_mode(),
        (KeyCode::F(5), _, Mode::Flux) => app.refresh_flux(),
        (KeyCode::Char('r'), _, Mode::Flux) => app.open_flux_action_menu(),
        (KeyCode::Char('z'), _, Mode::Flux) => app.toggle_suspend(),
        (KeyCode::Char('t'), _, Mode::Flux) => app.toggle_flux_tree(),
        (KeyCode::Char('L'), _, Mode::Flux) => app.enter_flux_logs(),
        (KeyCode::Char('i'), _, Mode::Flux) => app.enter_ai_panel(),
        (KeyCode::Char('g'), _, Mode::Flux) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::Flux) => app.scroll_detail_bottom(),
        (KeyCode::Char('l'), _, Mode::Flux) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Flux) => {}

        (KeyCode::Up, m, Mode::FluxFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::FluxFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::FluxFull) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::FluxFull) => app.scroll_detail(-10),
        (KeyCode::Left, m, Mode::FluxFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::FluxFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, Mode::FluxFull) => app.detail_h_scroll = 0,
        (KeyCode::Tab, _, Mode::FluxFull) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::FluxFull) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::FluxFull) => app.exit_flux_full(),
        (KeyCode::Esc, _, Mode::FluxFull) => app.exit_flux_full(),
        (KeyCode::Char('g'), _, Mode::FluxFull) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::FluxFull) => app.scroll_detail_bottom(),
        (KeyCode::Char('r'), _, Mode::FluxFull) => app.open_flux_action_menu(),
        (KeyCode::Char('z'), _, Mode::FluxFull) => app.toggle_suspend(),
        (KeyCode::Char('L'), _, Mode::FluxFull) => app.enter_flux_logs(),
        (KeyCode::Char('i'), _, Mode::FluxFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::FluxFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::FluxFull) => {}

        (KeyCode::Up, _, Mode::FluxLogs) => app.scroll_detail(1),
        (KeyCode::Down, _, Mode::FluxLogs) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::FluxLogs) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::FluxLogs) => app.scroll_detail(-10),
        (KeyCode::Char('g'), _, Mode::FluxLogs) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::FluxLogs) => app.scroll_detail_bottom(),
        (KeyCode::Esc, _, Mode::FluxLogs) => app.exit_flux_logs(),
        (KeyCode::Char('L'), _, Mode::FluxLogs) => app.exit_flux_logs(),
        (_, _, Mode::FluxLogs) => {}

        (KeyCode::Up, m, Mode::Pods) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::Pods) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::Left, m, Mode::Pods) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5),
        (KeyCode::Right, m, Mode::Pods) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_add(5),
        (KeyCode::Up, _, Mode::Pods) => app.move_pods_selection(-1),
        (KeyCode::Down, _, Mode::Pods) => app.move_pods_selection(1),
        (KeyCode::PageUp, _, Mode::Pods) => app.move_pods_selection(-10),
        (KeyCode::PageDown, _, Mode::Pods) => app.move_pods_selection(10),
        (KeyCode::Tab, _, Mode::Pods) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::Pods) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::Pods) => app.enter_pods_full(),
        (KeyCode::Esc, _, Mode::Pods) => app.exit_pods_mode(),
        (KeyCode::Char('n'), _, Mode::Pods) => app.filter_ns_to_selected(),
        (KeyCode::Char('0'), _, Mode::Pods) => app.clear_namespace_filter(),
        (KeyCode::Char('s'), _, Mode::Pods) => app.open_pods_scale_menu(),
        (KeyCode::Char('r'), _, Mode::Pods) => app.open_pods_action_menu(),
        (KeyCode::Char('i'), _, Mode::Pods) => app.enter_ai_panel(),
        (KeyCode::Char('g'), _, Mode::Pods) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::Pods) => app.scroll_detail_bottom(),
        (KeyCode::Char('l'), _, Mode::Pods) => app.ai_language = app.ai_language.toggle(),
        (KeyCode::Char('t'), _, Mode::Pods) => app.toggle_pods_workloads(),
        (_, _, Mode::Pods) => {}

        (KeyCode::Up, m, Mode::PodsFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::PodsFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::PodsFull) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::PodsFull) => app.scroll_detail(-10),
        (KeyCode::Left, m, Mode::PodsFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::PodsFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, Mode::PodsFull) => app.detail_h_scroll = 0,
        (KeyCode::Tab, _, Mode::PodsFull) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::PodsFull) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::PodsFull) => app.exit_pods_full(),
        (KeyCode::Esc, _, Mode::PodsFull) => app.exit_pods_full(),
        (KeyCode::Char('g'), _, Mode::PodsFull) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::PodsFull) => app.scroll_detail_bottom(),
        (KeyCode::Char('i'), _, Mode::PodsFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::PodsFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::PodsFull) => {}

        (KeyCode::Up, m, Mode::Rbac) if m.contains(KeyModifiers::SHIFT) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_sub(1),
        (KeyCode::Down, m, Mode::Rbac) if m.contains(KeyModifiers::SHIFT) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_add(1),
        (KeyCode::Up, _, Mode::Rbac) => app.move_rbac_selection(-1),
        (KeyCode::Down, _, Mode::Rbac) => app.move_rbac_selection(1),
        (KeyCode::PageUp, _, Mode::Rbac) => app.move_rbac_selection(-10),
        (KeyCode::PageDown, _, Mode::Rbac) => app.move_rbac_selection(10),
        (KeyCode::Enter, _, Mode::Rbac) => app.enter_rbac_full(),
        (KeyCode::Char('o'), _, Mode::Rbac) => app.rbac_open_origin(),
        (KeyCode::Char('f'), _, Mode::Rbac) => app.cycle_rbac_filter(),
        (KeyCode::F(5), _, Mode::Rbac) => app.refresh_rbac(),
        (KeyCode::Esc, _, Mode::Rbac) => app.exit_rbac_mode(),
        (KeyCode::Char('i'), _, Mode::Rbac) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Rbac) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Rbac) => {}

        (KeyCode::Up, _, Mode::RbacFull) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::RbacFull) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::RbacFull) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::RbacFull) => app.rbac_detail_scroll = app.rbac_detail_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::RbacFull) => app.rbac_detail_scroll = 0,
        (KeyCode::Enter, _, Mode::RbacFull) => app.exit_rbac_full(),
        (KeyCode::Esc, _, Mode::RbacFull) => app.exit_rbac_full(),
        (KeyCode::Char('i'), _, Mode::RbacFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::RbacFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::RbacFull) => {}

        (KeyCode::Up, m, Mode::Vuln) if m.contains(KeyModifiers::SHIFT) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_sub(1),
        (KeyCode::Down, m, Mode::Vuln) if m.contains(KeyModifiers::SHIFT) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_add(1),
        (KeyCode::Up, _, Mode::Vuln) => app.move_vuln_selection(-1),
        (KeyCode::Down, _, Mode::Vuln) => app.move_vuln_selection(1),
        (KeyCode::PageUp, _, Mode::Vuln) => app.move_vuln_selection(-10),
        (KeyCode::PageDown, _, Mode::Vuln) => app.move_vuln_selection(10),
        (KeyCode::Enter, _, Mode::Vuln) => app.enter_vuln_full(),
        (KeyCode::Char('f'), _, Mode::Vuln) => app.cycle_vuln_filter(),
        (KeyCode::F(5), _, Mode::Vuln) => app.refresh_vulnerabilities(),
        (KeyCode::Esc, _, Mode::Vuln) => app.exit_vuln_mode(),
        (KeyCode::Char('i'), _, Mode::Vuln) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Vuln) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Vuln) => {}

        (KeyCode::Up, _, Mode::VulnFull) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::VulnFull) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::VulnFull) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::VulnFull) => app.vuln_detail_scroll = app.vuln_detail_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::VulnFull) => app.vuln_detail_scroll = 0,
        (KeyCode::Enter, _, Mode::VulnFull) => app.exit_vuln_full(),
        (KeyCode::Esc, _, Mode::VulnFull) => app.exit_vuln_full(),
        (KeyCode::Char('i'), _, Mode::VulnFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::VulnFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::VulnFull) => {}

        (KeyCode::Up, m, Mode::Secrets) if m.contains(KeyModifiers::SHIFT) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_sub(1),
        (KeyCode::Down, m, Mode::Secrets) if m.contains(KeyModifiers::SHIFT) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_add(1),
        (KeyCode::Up, _, Mode::Secrets) => app.move_secret_selection(-1),
        (KeyCode::Down, _, Mode::Secrets) => app.move_secret_selection(1),
        (KeyCode::PageUp, _, Mode::Secrets) => app.move_secret_selection(-10),
        (KeyCode::PageDown, _, Mode::Secrets) => app.move_secret_selection(10),
        (KeyCode::Enter, _, Mode::Secrets) => app.enter_secrets_full(),
        (KeyCode::Char('f'), _, Mode::Secrets) => app.cycle_secrets_filter(),
        (KeyCode::Char('b'), _, Mode::Secrets) => app.toggle_secret_reveal(SecretReveal::Base64),
        (KeyCode::Char('d'), _, Mode::Secrets) => app.toggle_secret_reveal(SecretReveal::Decoded),
        (KeyCode::Char('c'), _, Mode::Secrets) => app.open_secrets_copy_menu(),
        (KeyCode::F(5), _, Mode::Secrets) => app.refresh_secrets(),
        (KeyCode::Esc, _, Mode::Secrets) => app.exit_secrets_mode(),
        (KeyCode::Char('i'), _, Mode::Secrets) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Secrets) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Secrets) => {}

        (KeyCode::Up, _, Mode::SecretsFull) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::SecretsFull) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::SecretsFull) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::SecretsFull) => app.secrets_detail_scroll = app.secrets_detail_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::SecretsFull) => app.secrets_detail_scroll = 0,
        (KeyCode::Char('b'), _, Mode::SecretsFull) => app.toggle_secret_reveal(SecretReveal::Base64),
        (KeyCode::Char('d'), _, Mode::SecretsFull) => app.toggle_secret_reveal(SecretReveal::Decoded),
        (KeyCode::Char('c'), _, Mode::SecretsFull) => app.open_secrets_copy_menu(),
        (KeyCode::Enter, _, Mode::SecretsFull) => app.exit_secrets_full(),
        (KeyCode::Esc, _, Mode::SecretsFull) => app.exit_secrets_full(),
        (KeyCode::Char('i'), _, Mode::SecretsFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::SecretsFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::SecretsFull) => {}

        (KeyCode::Up, m, Mode::Configmaps) if m.contains(KeyModifiers::SHIFT) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_sub(1),
        (KeyCode::Down, m, Mode::Configmaps) if m.contains(KeyModifiers::SHIFT) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_add(1),
        (KeyCode::Up, _, Mode::Configmaps) => app.move_configmap_selection(-1),
        (KeyCode::Down, _, Mode::Configmaps) => app.move_configmap_selection(1),
        (KeyCode::PageUp, _, Mode::Configmaps) => app.move_configmap_selection(-10),
        (KeyCode::PageDown, _, Mode::Configmaps) => app.move_configmap_selection(10),
        (KeyCode::Left, _, Mode::Configmaps) => app.configmaps_h_scroll = app.configmaps_h_scroll.saturating_sub(5),
        (KeyCode::Right, _, Mode::Configmaps) => app.configmaps_h_scroll = app.configmaps_h_scroll.saturating_add(5),
        (KeyCode::Enter, _, Mode::Configmaps) => app.enter_configmaps_full(),
        (KeyCode::Char('c'), _, Mode::Configmaps) => app.open_configmaps_copy_menu(),
        (KeyCode::F(5), _, Mode::Configmaps) => app.refresh_configmaps(),
        (KeyCode::Esc, _, Mode::Configmaps) => app.exit_configmaps_mode(),
        (KeyCode::Char('i'), _, Mode::Configmaps) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Configmaps) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Configmaps) => {}

        (KeyCode::Up, _, Mode::ConfigmapsFull) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_sub(1),
        (KeyCode::Down, _, Mode::ConfigmapsFull) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_add(1),
        (KeyCode::PageUp, _, Mode::ConfigmapsFull) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_sub(10),
        (KeyCode::PageDown, _, Mode::ConfigmapsFull) => app.configmaps_detail_scroll = app.configmaps_detail_scroll.saturating_add(10),
        (KeyCode::Char('g'), _, Mode::ConfigmapsFull) => app.configmaps_detail_scroll = 0,
        (KeyCode::Left, _, Mode::ConfigmapsFull) => app.configmaps_h_scroll = app.configmaps_h_scroll.saturating_sub(5),
        (KeyCode::Right, _, Mode::ConfigmapsFull) => app.configmaps_h_scroll = app.configmaps_h_scroll.saturating_add(5),
        (KeyCode::Char('c'), _, Mode::ConfigmapsFull) => app.open_configmaps_copy_menu(),
        (KeyCode::Enter, _, Mode::ConfigmapsFull) => app.exit_configmaps_full(),
        (KeyCode::Esc, _, Mode::ConfigmapsFull) => app.exit_configmaps_full(),
        (KeyCode::Char('i'), _, Mode::ConfigmapsFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::ConfigmapsFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::ConfigmapsFull) => {}

        (KeyCode::Up, m, Mode::Services) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::Services) if m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::Left, m, Mode::Services) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5),
        (KeyCode::Right, m, Mode::Services) if m.contains(KeyModifiers::SHIFT) => app.detail_h_scroll = app.detail_h_scroll.saturating_add(5),
        (KeyCode::Up, _, Mode::Services) => app.move_net_selection(-1),
        (KeyCode::Down, _, Mode::Services) => app.move_net_selection(1),
        (KeyCode::PageUp, _, Mode::Services) => app.move_net_selection(-10),
        (KeyCode::PageDown, _, Mode::Services) => app.move_net_selection(10),
        (KeyCode::Tab, _, Mode::Services) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::Services) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::Services) => app.enter_network_full(),
        (KeyCode::Esc, _, Mode::Services) => app.exit_network_mode(),
        (KeyCode::Char('n'), _, Mode::Services) => app.filter_ns_to_selected(),
        (KeyCode::Char('0'), _, Mode::Services) => app.clear_namespace_filter(),
        (KeyCode::Char('t'), _, Mode::Services) => app.toggle_network_group(),
        (KeyCode::Char('g'), _, Mode::Services) => app.cycle_network_world(),
        (KeyCode::F(5), _, Mode::Services) => app.refresh_network(),
        (KeyCode::Char('i'), _, Mode::Services) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::Services) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::Services) => {}

        (KeyCode::Up, m, Mode::ServicesFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(1),
        (KeyCode::Down, m, Mode::ServicesFull) if !m.contains(KeyModifiers::SHIFT) => app.scroll_detail(-1),
        (KeyCode::PageUp, _, Mode::ServicesFull) => app.scroll_detail(10),
        (KeyCode::PageDown, _, Mode::ServicesFull) => app.scroll_detail(-10),
        (KeyCode::Left, m, Mode::ServicesFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_sub(5);
        }
        (KeyCode::Right, m, Mode::ServicesFull) if !m.contains(KeyModifiers::SHIFT) => {
            app.detail_h_scroll = app.detail_h_scroll.saturating_add(5);
        }
        (KeyCode::Home, _, Mode::ServicesFull) => app.detail_h_scroll = 0,
        (KeyCode::Tab, _, Mode::ServicesFull) => app.cycle_tab(),
        (KeyCode::BackTab, _, Mode::ServicesFull) => app.cycle_tab_back(),
        (KeyCode::Enter, _, Mode::ServicesFull) => app.exit_network_full(),
        (KeyCode::Esc, _, Mode::ServicesFull) => app.exit_network_full(),
        (KeyCode::Char('g'), _, Mode::ServicesFull) => app.scroll_detail_top(),
        (KeyCode::Char('G'), _, Mode::ServicesFull) => app.scroll_detail_bottom(),
        (KeyCode::Char('i'), _, Mode::ServicesFull) => app.enter_ai_panel(),
        (KeyCode::Char('l'), _, Mode::ServicesFull) => app.ai_language = app.ai_language.toggle(),
        (_, _, Mode::ServicesFull) => {}

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
        (KeyCode::Char('n'), _, Mode::Selection) => app.filter_ns_to_selected(),
        (KeyCode::Char('0'), _, Mode::Selection) => app.clear_namespace_filter(),
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

// Render the current frame and return the number of visible table rows (used for page scrolling).
// Overlay modes (AI panel, pickers, command palette) reuse a base mode's layout then draw on top.
fn draw(f: &mut ratatui::Frame, app: &mut App) -> usize {
    let area = f.area();
    if app.mode == Mode::FluxLogs {
        return draw_flux_logs(f, app);
    }
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
        Mode::Command => match app.command_return_mode {
            Mode::Nodes | Mode::NodesFull | Mode::Flux | Mode::FluxFull | Mode::Pods | Mode::PodsFull | Mode::Rbac | Mode::RbacFull | Mode::Vuln | Mode::VulnFull | Mode::Secrets | Mode::SecretsFull | Mode::Configmaps | Mode::ConfigmapsFull | Mode::Services | Mode::ServicesFull => app.command_return_mode,
            _ => Mode::Selection,
        },
        m => m,
    };

    let layout = match draw_mode {
        Mode::Selection => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(area.height / 2),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area),
        Mode::DetailFull => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(3), Constraint::Length(3)])
            .split(area),
        Mode::Nodes => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(area.height / 2),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area),
        Mode::NodesFull | Mode::FluxFull | Mode::PodsFull | Mode::RbacFull | Mode::VulnFull | Mode::SecretsFull | Mode::ConfigmapsFull | Mode::ServicesFull => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(3), Constraint::Length(3)])
            .split(area),
        Mode::Flux | Mode::Pods | Mode::Rbac | Mode::Vuln | Mode::Secrets | Mode::Configmaps | Mode::Services => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(area.height / 2),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area),
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract | Mode::Command | Mode::FluxLogs => unreachable!(),
    };

    let (header_a, detail_a, table_a, footer_a): (Rect, Option<Rect>, Option<Rect>, Rect) = match draw_mode {
        Mode::Selection => (layout[0], Some(layout[1]), Some(layout[2]), layout[3]),
        Mode::DetailFull => (layout[0], Some(layout[1]), None, layout[2]),
        Mode::Nodes => (layout[0], Some(layout[1]), Some(layout[2]), layout[3]),
        Mode::NodesFull | Mode::FluxFull | Mode::PodsFull | Mode::RbacFull | Mode::VulnFull | Mode::SecretsFull | Mode::ConfigmapsFull | Mode::ServicesFull => (layout[0], Some(layout[1]), None, layout[2]),
        Mode::Flux | Mode::Pods | Mode::Rbac | Mode::Vuln | Mode::Secrets | Mode::Configmaps | Mode::Services => (layout[0], Some(layout[1]), Some(layout[2]), layout[3]),
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract | Mode::Command | Mode::FluxLogs => unreachable!(),
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
        Mode::Command => st.mode_command,
        Mode::Flux | Mode::FluxFull => st.mode_flux,
        Mode::FluxLogs => st.mode_flux,
        Mode::Pods | Mode::PodsFull => st.mode_pods,
        Mode::Rbac | Mode::RbacFull => st.mode_rbac,
        Mode::Vuln | Mode::VulnFull => st.mode_vuln,
        Mode::Secrets | Mode::SecretsFull => st.mode_secrets,
        Mode::Configmaps | Mode::ConfigmapsFull => st.mode_configmaps,
        Mode::Services | Mode::ServicesFull => st.mode_services,
    };
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!(" kdt v{} ", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  ctx={}  ns={}  filter={}  mode={}{}  lang={}",
                app.context_label,
                app.namespace_label,
                app.filter.label(),
                mode_label,
                if app.mode == Mode::Selection && !app.scroll_frozen { "↻" } else { "" },
                app.ai_language.label(),
            )),
        ]),
        cluster_banner_line(app),
    ]);
    f.render_widget(header, header_a);

    if let Some(da) = detail_a {
        draw_detail(f, app, da);
    }

    let visible_rows = table_a.map(|a| a.height.saturating_sub(3) as usize).unwrap_or(0);
    if let Some(ta) = table_a {
        if draw_mode == Mode::Nodes {
            draw_nodes_table(f, app, ta);
        } else if draw_mode == Mode::Pods {
            draw_pods_tree(f, app, ta);
        } else if draw_mode == Mode::Flux {
            if app.flux_tree {
                draw_flux_tree(f, app, ta);
            } else {
                draw_flux_table(f, app, ta);
            }
        } else if draw_mode == Mode::Rbac {
            draw_rbac_table(f, app, ta);
        } else if draw_mode == Mode::Vuln {
            draw_vuln_table(f, app, ta);
        } else if draw_mode == Mode::Secrets {
            draw_secrets_table(f, app, ta);
        } else if draw_mode == Mode::Configmaps {
            draw_configmaps_table(f, app, ta);
        } else if draw_mode == Mode::Services {
            draw_net_tree(f, app, ta);
        } else {
            let rows: Vec<Row> = match draw_mode {
                Mode::Selection => app.snapshot.iter().map(|r| row_for(r, app.h_scroll)).collect(),
                Mode::DetailFull | Mode::NsPicker | Mode::AiPanel | Mode::Nodes | Mode::NodesFull | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract | Mode::Command | Mode::Flux | Mode::FluxFull | Mode::FluxLogs | Mode::Pods | Mode::PodsFull | Mode::Rbac | Mode::RbacFull | Mode::Vuln | Mode::VulnFull | Mode::Secrets | Mode::SecretsFull | Mode::Configmaps | Mode::ConfigmapsFull | Mode::Services | Mode::ServicesFull => unreachable!(),
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
    let footer_spans = match draw_mode {
        Mode::Selection => vec![
            Span::styled(" q ", kbg), Span::raw(format!(" {}   ", st.k_quit)),
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
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
            Span::styled(" D ", kbg), Span::raw(format!(" {}   ", st.k_diag)),
            Span::styled(" X ", kbg), Span::raw(format!(" {}   ", st.k_extract)),
        ],
        Mode::DetailFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st.k_page)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Nodes => vec![
            Span::styled(" Esc/N ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" u ", kbg), Span::raw(format!(" {}   ", st.k_node_usage)),
            Span::styled(" Shift+↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::NodesFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" PgUp/PgDn ", kbg), Span::raw(format!(" {}   ", st.k_page)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Flux => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            footer_sep(),
            Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_reconcile)),
            Span::styled(" z ", kbg), Span::raw(format!(" {}   ", st.k_suspend)),
            Span::styled(" t ", kbg), Span::raw(format!(" {}   ", st.k_tree)),
            Span::styled(" Space ", kbg), Span::raw(format!(" {}   ", st.k_fold)),
            Span::styled(" +/- ", kbg), Span::raw(format!(" {}   ", st.k_inventory)),
            Span::styled(" L ", kbg), Span::raw(format!(" {}   ", st.k_flux_logs)),
            Span::styled(" F5 ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::FluxFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
            footer_sep(),
            Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_reconcile)),
            Span::styled(" z ", kbg), Span::raw(format!(" {}   ", st.k_suspend)),
            Span::styled(" L ", kbg), Span::raw(format!(" {}   ", st.k_flux_logs)),
        ],
        Mode::Pods => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" n ", kbg), Span::raw(format!(" {}   ", st.k_ns_here)),
            Span::styled(" t ", kbg), Span::raw(format!(" {}   ", if app.pods_show_workloads { "pods" } else { st.k_toggle_wl })),
            footer_sep(),
            Span::styled(" s ", kbg), Span::raw(format!(" {}   ", st.k_scale)),
            Span::styled(" r ", kbg), Span::raw(format!(" {}   ", st.k_actions)),
        ],
        Mode::PodsFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Rbac => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            Span::styled(" o ", kbg), Span::raw(format!(" {}   ", st.k_origin)),
            footer_sep(),
            Span::styled(" f ", kbg), Span::raw(format!(" {}:{}   ", st.k_rbac_filter, app.rbac_min_sev.label())),
            Span::styled(" F5 ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::RbacFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" g ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Vuln => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            footer_sep(),
            Span::styled(" f ", kbg), Span::raw(format!(" {}:{}   ", st.k_rbac_filter, app.vuln_min_sev.label())),
            Span::styled(" F5 ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::VulnFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" g ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Secrets => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            footer_sep(),
            Span::styled(" f ", kbg), Span::raw(format!(" {}:{}   ", st.k_rbac_filter, app.secrets_filter.label())),
            Span::styled(" b ", kbg), Span::raw(format!(" {}   ", st.k_reveal_b64)),
            Span::styled(" d ", kbg), Span::raw(format!(" {}   ", st.k_reveal_plain)),
            Span::styled(" F5 ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::SecretsFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" g ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
            footer_sep(),
            Span::styled(" b ", kbg), Span::raw(format!(" {}   ", st.k_reveal_b64)),
            Span::styled(" d ", kbg), Span::raw(format!(" {}   ", st.k_reveal_plain)),
        ],
        Mode::Configmaps => vec![
            Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
            Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
            footer_sep(),
            Span::styled(" F5 ", kbg), Span::raw(format!(" {}   ", st.k_refresh)),
        ],
        Mode::ConfigmapsFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" ←→ ", kbg), Span::raw(format!(" {}   ", st.k_h_scroll)),
            Span::styled(" g ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::Services => {
            // `t` shows the opposite of the current grouping; `g` names the other world to switch to.
            let toggle_label = if app.net_group {
                st.k_net_flat
            } else if app.net_world == NetWorld::Services {
                "endpoints"
            } else {
                st.k_net_byclass
            };
            let world_label = if app.net_world == NetWorld::Services { "ingress" } else { "services" };
            vec![
                Span::styled(" : ", kbg), Span::raw(format!(" {}   ", st.k_command)),
                Span::styled(" Esc ", kbg), Span::raw(format!(" {}   ", st.k_back)),
                Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_nav)),
                Span::styled(" Enter ", kbg), Span::raw(format!(" {}   ", st.k_zoom)),
                Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
                Span::styled(" n ", kbg), Span::raw(format!(" {}   ", st.k_ns_here)),
                footer_sep(),
                Span::styled(" t ", kbg), Span::raw(format!(" {}   ", toggle_label)),
                Span::styled(" g ", kbg), Span::raw(format!(" {}   ", world_label)),
            ]
        }
        Mode::ServicesFull => vec![
            Span::styled(" Esc/Enter ", kbg), Span::raw(format!(" {}   ", st.k_split)),
            Span::styled(" ↑↓ ", kbg), Span::raw(format!(" {}   ", st.k_scroll)),
            Span::styled(" Tab ", kbg), Span::raw(format!(" {}   ", st.k_view)),
            Span::styled(" g/G ", kbg), Span::raw(format!(" {}   ", st.k_top_bot)),
        ],
        Mode::NsPicker | Mode::AiPanel | Mode::NodeUsage | Mode::Diagnostic | Mode::Extract | Mode::Command | Mode::FluxLogs => unreachable!(),
    };
    // Second line: the tool bar available in every view, always grouped at the same place.
    let has_copy = !matches!(
        draw_mode,
        Mode::Rbac | Mode::RbacFull | Mode::Vuln | Mode::VulnFull
    );
    let mut global_spans = Vec::new();
    if has_copy {
        global_spans.push(Span::styled(" c ", kbg));
        global_spans.push(Span::raw(format!(" {}   ", st.k_copy)));
    }
    global_spans.push(Span::styled(" i ", kbg));
    global_spans.push(Span::raw(format!(" {}   ", st.k_ai)));
    global_spans.push(Span::styled(" l ", kbg));
    global_spans.push(Span::raw(format!(" {}:{}   ", st.k_lang, app.ai_language.label())));
    global_spans.push(Span::styled(" m ", kbg));
    global_spans.push(Span::raw(format!(" {}:{}", st.k_provider, app.ai_provider_name())));

    // Spread every shortcut evenly over two rows: merge context + tool cells, sort by width and
    // deal them alternately. Both rows end up with the same count, the longest cells land last
    // (rightmost), and each column stacks two cells of similar width so it stays homogeneous.
    let mut cells = footer_cells(footer_spans);
    cells.extend(footer_cells(global_spans));
    cells.sort_by_key(|c| cell_width(c));
    let mut top: Vec<Vec<Span<'static>>> = Vec::new();
    let mut bottom: Vec<Vec<Span<'static>>> = Vec::new();
    for (idx, cell) in cells.into_iter().enumerate() {
        if idx % 2 == 0 {
            top.push(cell);
        } else {
            bottom.push(cell);
        }
    }
    let cols = top.len().max(bottom.len());
    let mut widths = vec![0usize; cols];
    for (j, c) in top.iter().enumerate() {
        widths[j] = widths[j].max(cell_width(c));
    }
    for (j, c) in bottom.iter().enumerate() {
        widths[j] = widths[j].max(cell_width(c));
    }
    let top_line = render_footer_row(&top, &widths);
    let mut bottom_line = render_footer_row(&bottom, &widths);
    if let Some(msg) = app.clipboard_status_active() {
        bottom_line.push(Span::styled(
            msg.to_string(),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(
        Paragraph::new(vec![
            Line::from(top_line),
            Line::default(),
            Line::from(bottom_line),
        ]),
        footer_a,
    );

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
    if app.mode == Mode::Command {
        draw_command_popup(f, app, area);
    }
    if app.action_menu.is_some() {
        draw_action_menu_popup(f, app, area);
    }
    if app.secrets_copy_menu.is_some() {
        draw_secrets_copy_menu_popup(f, app, area);
    }
    if app.configmaps_copy_menu.is_some() {
        draw_configmaps_copy_menu_popup(f, app, area);
    }

    visible_rows
}

// Copy picker over a ConfigMap: a highlighted list of its keys; Enter copies the (text) value.
fn draw_configmaps_copy_menu_popup(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let Some(menu) = app.configmaps_copy_menu.as_ref() else { return; };

    let popup_w = (area.width * 50 / 100).max(40).min(area.width);
    let popup_h = (menu.keys.len() as u16 + 6).min(area.height.saturating_sub(2)).max(7);
    let popup_area = centered_rect(popup_w, popup_h, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", menu.title))
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let items: Vec<ListItem> = copy_menu_items(&menu.keys);
    let mut list_state = ListState::default();
    list_state.select(Some(menu.cursor));
    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↑↓ choisir · Enter copier · Esc annuler",
            Style::default().fg(DIM),
        ))),
        chunks[1],
    );
}

// Copy picker over a secret: a highlighted list of its data keys; Enter copies the decoded value.
fn draw_secrets_copy_menu_popup(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let Some(menu) = app.secrets_copy_menu.as_ref() else { return; };

    let popup_w = (area.width * 50 / 100).max(40).min(area.width);
    let popup_h = (menu.keys.len() as u16 + 6).min(area.height.saturating_sub(2)).max(7);
    let popup_area = centered_rect(popup_w, popup_h, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", menu.title))
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let items: Vec<ListItem> = copy_menu_items(&menu.keys);
    let mut list_state = ListState::default();
    list_state.select(Some(menu.cursor));
    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↑↓ choisir · Enter copier (déchiffré) · Esc annuler",
            Style::default().fg(DIM),
        ))),
        chunks[1],
    );
}

// Picker item list shared by the secrets/configmaps copy popups: the manifest entry then the keys.
fn copy_menu_items(keys: &[String]) -> Vec<ListItem<'static>> {
    let mut items = vec![ListItem::new(Line::from(Span::styled(
        format!(" {MANIFEST_ENTRY}"),
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )))];
    items.extend(keys.iter().map(|k| ListItem::new(format!(" {k}"))));
    items
}

// Renders the action menu overlay: a highlighted list of choices with the selected entry's
// description, then a confirmation prompt once an entry is armed.
fn draw_action_menu_popup(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let Some(menu) = app.action_menu.as_ref() else { return; };
    let st = lang::t(app.ai_language);

    let popup_w = (area.width * 60 / 100).max(48).min(area.width);
    let popup_h = (menu.items.len() as u16 + 6).min(area.height.saturating_sub(2)).max(8);
    let popup_area = centered_rect(popup_w, popup_h, area);
    f.render_widget(Clear, popup_area);

    let border = if menu.confirming || menu.input.is_some() { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", menu.title))
        .border_style(Style::default().fg(border));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(inner);

    let items: Vec<ListItem> = menu
        .items
        .iter()
        .map(|it| ListItem::new(format!(" {}", it.label)))
        .collect();
    let mut list_state = ListState::default();
    list_state.select(Some(menu.cursor));
    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let desc = menu.items.get(menu.cursor).map(|it| it.desc).unwrap_or("");
    let footer = if let Some(buf) = menu.input.as_ref() {
        Line::from(Span::styled(
            st.menu_input_prompt.replace("{n}", buf),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else if menu.confirming {
        Line::from(Span::styled(
            st.menu_confirm_prompt,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(st.menu_hint, Style::default().fg(DIM)))
    };
    let p = Paragraph::new(vec![
        Line::from(Span::styled(desc, Style::default().fg(Color::Gray))),
        Line::from(""),
        footer,
    ])
    .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, chunks[1]);
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

fn cluster_banner_line(app: &App) -> Line<'static> {
    let info = app.cluster_info.lock().expect("cluster info poisoned").clone();
    let label = Style::default().fg(SYS_DIM);
    let val = Style::default().fg(Color::Gray);

    if !info.loaded {
        return Line::from(Span::styled("   cluster: chargement des infos…", label));
    }

    let version = info.server_version.clone().unwrap_or_else(|| "?".to_string());
    let mut spans: Vec<Span<'static>> = vec![
        Span::styled("   cluster ", label),
        Span::styled(app.cluster_label.clone(), Style::default().fg(Color::Cyan)),
        Span::styled("   k8s ", label),
        Span::styled(version, val),
        Span::styled("   nodes ", label),
        Span::styled(
            format!("{}/{} ready", info.nodes_ready, info.node_count),
            Style::default().fg(if info.nodes_ready == info.node_count { Color::Green } else { Color::Yellow }),
        ),
    ];

    if info.metrics_available {
        let cpu_pct = pct_local(info.cpu_use_milli, info.cpu_alloc_milli);
        let mem_pct = pct_local(info.mem_use_bytes, info.mem_alloc_bytes);
        spans.push(Span::styled("   CPU ", label));
        spans.push(Span::styled(
            format!("{}/{}", format_cpu_milli(info.cpu_use_milli), format_cpu_milli(info.cpu_alloc_milli)),
            val,
        ));
        spans.push(Span::styled(format!(" ({}%)", cpu_pct), Style::default().fg(pct_color(cpu_pct))));
        spans.push(Span::styled("   MEM ", label));
        spans.push(Span::styled(
            format!("{}/{}", format_memory_bytes(info.mem_use_bytes), format_memory_bytes(info.mem_alloc_bytes)),
            val,
        ));
        spans.push(Span::styled(format!(" ({}%)", mem_pct), Style::default().fg(pct_color(mem_pct))));
    } else {
        spans.push(Span::styled("   CPU alloc ", label));
        spans.push(Span::styled(format_cpu_milli(info.cpu_alloc_milli), val));
        spans.push(Span::styled("   MEM alloc ", label));
        spans.push(Span::styled(format_memory_bytes(info.mem_alloc_bytes), val));
        spans.push(Span::styled("   (metrics-server indispo)", label));
    }

    Line::from(spans)
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

// Adapt a FluxResource into an EventRecord so the Flux view reuses the shared table/detail/AI flow.
fn synthetic_flux_record(r: &FluxResource) -> EventRecord {
    let (severity, reason) = match (r.suspended, r.ready) {
        (true, _) => (Severity::Normal, "Suspended".to_string()),
        (false, FluxReady::Ready) => (Severity::Normal, "Ready".to_string()),
        (false, FluxReady::Reconciling) => (Severity::Normal, "Reconciling".to_string()),
        (false, FluxReady::Failed) => (Severity::Warning, "ReconciliationFailed".to_string()),
        (false, FluxReady::Unknown) => (Severity::Warning, "Unknown".to_string()),
        (false, FluxReady::NotApplicable) => (Severity::Normal, "N/A".to_string()),
    };
    let message = if r.message.is_empty() {
        format!("{} {}/{}", r.kind, r.namespace, r.name)
    } else {
        r.message.clone()
    };
    EventRecord {
        uid: format!("flux|{}|{}/{}", r.kind, r.namespace, r.name),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity,
        reason,
        api_version: r.api_version.clone(),
        kind: r.kind.clone(),
        namespace: r.namespace.clone(),
        name: r.name.clone(),
        message,
        component: "flux".to_string(),
        host: String::new(),
        count: 1,
    }
}

// Snapshot record for one applied inventory object, so selecting it in the tree drives the shared
// Logs/Status/Related detail panes against that real object.
fn synthetic_inventory_record(ks_uid: &str, it: &InventoryItem) -> EventRecord {
    let (severity, reason) = match (it.reconciling, it.ready) {
        (true, _) => (Severity::Normal, "Reconciling".to_string()),
        (_, Some(true)) => (Severity::Normal, "Ready".to_string()),
        (_, Some(false)) => (Severity::Warning, "NotReady".to_string()),
        (_, None) => (Severity::Normal, "Applied".to_string()),
    };
    let message = if it.msg.is_empty() {
        format!("{} {}/{}", it.kind, it.namespace, it.name)
    } else {
        it.msg.clone()
    };
    EventRecord {
        uid: format!("inv|{}|{}|{}/{}", ks_uid, it.kind, it.namespace, it.name),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity,
        reason,
        api_version: it.api_version.clone(),
        kind: it.kind.clone(),
        namespace: it.namespace.clone(),
        name: it.name.clone(),
        message,
        component: "flux".to_string(),
        host: String::new(),
        count: 1,
    }
}

// Colour for a pod STATUS string: green when settled, red for crash/error states, yellow otherwise.
// Row style from the status colour: red rows get a dark-red background, finished (faded) rows are
// dimmed whole-row, everything else is default.
fn pod_row_style(status_color: Color) -> Style {
    if status_color == Color::Red {
        Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0))
    } else if status_color == DIM {
        Style::default().fg(DIM)
    } else {
        Style::default()
    }
}

fn pod_status_color(status: &str) -> Color {
    match status {
        "Running" => Color::Green,
        // Finished successfully: faded, like k9s — healthy but no longer active.
        "Succeeded" | "Completed" => DIM,
        "Pending" | "ContainerCreating" | "PodInitializing" | "Terminating" => Color::Yellow,
        _ => Color::Red,
    }
}

// Adapt a PodResource into an EventRecord so the Pods view reuses the shared table/detail/AI flow.
// kind="Pod"/apiVersion="v1" make the Logs/Status/Related tabs work for the selected pod.
fn synthetic_pod_record(p: &PodResource) -> EventRecord {
    let severity = match pod_status_color(&p.status) {
        Color::Green | DIM => Severity::Normal,
        _ => Severity::Warning,
    };
    let owner = p
        .owner
        .as_ref()
        .map(|o| format!("  ◂ {}/{}", o.kind, o.name))
        .unwrap_or_default();
    EventRecord {
        uid: p.uid.clone(),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity,
        reason: p.status.clone(),
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        namespace: p.namespace.clone(),
        name: p.name.clone(),
        message: format!("ready={} restarts={} node={}{}", p.ready, p.restarts, p.node, owner),
        component: String::new(),
        host: p.node.clone(),
        count: 1,
    }
}

// Adapt a WorkloadResource (the focused object) into an EventRecord. Status/Related tabs work via the
// real kind/apiVersion; Logs shows "n/a" for non-Pod kinds, which is the existing behaviour.
fn synthetic_workload_record(w: &WorkloadResource) -> EventRecord {
    let replicas = w
        .replicas
        .map(|r| format!("{}/{}", w.ready_replicas, r))
        .unwrap_or_else(|| format!("{} ready", w.ready_replicas));
    EventRecord {
        uid: format!("workload|{}", w.uid),
        time: k8s_openapi::jiff::Timestamp::now(),
        severity: Severity::Normal,
        reason: "Workload".to_string(),
        api_version: w.api_version.clone(),
        kind: w.kind.clone(),
        namespace: w.namespace.clone(),
        name: w.name.clone(),
        message: format!("{} {}/{}  replicas={}  age={}", w.kind, w.namespace, w.name, replicas, w.age),
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

// Adapt a network row into an EventRecord so the shared Status/Related tabs work via the real
// apiVersion/kind/namespace/name. Endpoint rows expose themselves as their backing Pod, so selecting
// one yields that pod's status/related/logs just like in the pods view.
fn synthetic_net_record(row: &NetRow) -> EventRecord {
    let now = k8s_openapi::jiff::Timestamp::now();
    match row {
        NetRow::Service(s) => EventRecord {
            uid: format!("net|{}", s.uid),
            time: now,
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
        },
        NetRow::Endpoint(e) => EventRecord {
            uid: format!("net|{}", e.uid),
            time: now,
            severity: if e.ready { Severity::Normal } else { Severity::Warning },
            reason: if e.ready { "Ready".to_string() } else { "NotReady".to_string() },
            api_version: "v1".to_string(),
            kind: if e.target_kind == "Pod" { "Pod".to_string() } else { e.target_kind.clone() },
            namespace: e.service_namespace.clone(),
            name: e.target_name.clone(),
            message: format!("address={} node={} ready={}", e.address, e.node, e.ready),
            component: String::new(),
            host: e.node.clone(),
            count: 1,
        },
        NetRow::Ingress(i) => EventRecord {
            uid: format!("net|{}", i.uid),
            time: now,
            severity: Severity::Normal,
            reason: "Ingress".to_string(),
            api_version: "networking.k8s.io/v1".to_string(),
            kind: "Ingress".to_string(),
            namespace: i.namespace.clone(),
            name: i.name.clone(),
            message: format!(
                "class={} hosts={} tls={} {}",
                i.class.clone().unwrap_or_else(|| "—".to_string()),
                i.hosts,
                i.tls,
                i.rules
            ),
            component: String::new(),
            host: i.address.clone(),
            count: 1,
        },
        NetRow::IngressClass(c) => EventRecord {
            uid: format!("net|{}", c.uid),
            time: now,
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
        },
    }
}

// A usage value (CPU millicores / memory bytes) formatted, or a dim "—" when metrics are unavailable.
fn usage_cell(v: Option<i64>, fmt: fn(i64) -> String) -> Cell<'static> {
    match v {
        Some(v) => Cell::from(fmt(v)).style(Style::default().fg(Color::Cyan)),
        None => Cell::from("—").style(Style::default().fg(DIM)),
    }
}

// Usage as a percentage of a request/limit, coloured by pressure (green→yellow→orange→red).
fn pct_cell(usage: Option<i64>, base: Option<i64>) -> Cell<'static> {
    match (usage, base) {
        (Some(u), Some(b)) if b > 0 => {
            let pct = (u * 100) / b;
            let color = if pct >= 100 {
                Color::Red
            } else if pct >= 90 {
                Color::Rgb(255, 140, 0)
            } else if pct >= 70 {
                Color::Yellow
            } else {
                Color::Green
            };
            Cell::from(format!("{pct}%")).style(Style::default().fg(color))
        }
        _ => Cell::from("—").style(Style::default().fg(DIM)),
    }
}

// Column width fitted to the longest value (and the header), clamped to [min, max].
fn col_width<'a>(values: impl Iterator<Item = &'a str>, header: &str, min: u16, max: u16) -> u16 {
    let longest = values.map(|v| v.chars().count()).max().unwrap_or(0).max(header.len());
    (longest as u16).clamp(min, max)
}

// Does pod `p` resolve up to workload `w` (so it nests under it in the merged view)?
fn pod_belongs_to(p: &PodResource, w: &WorkloadResource) -> bool {
    p.owner
        .as_ref()
        .map(|o| o.kind == w.kind && o.name == w.name && o.namespace == w.namespace)
        .unwrap_or(false)
}

// Merged workloads/pods view: each workload is a parent row, its pods nest under it (depth 1), and
// orphan pods (bare pods or pods of a naked ReplicaSet) trail at the end keeping their namespace.
// Rendered straight from `app.pods_rows`, which is index-aligned with the snapshot/`table_state`, so
// the highlighted row matches the detail panel and the scale/restart target.
fn draw_pods_tree(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, n_pods, n_workloads) = {
        let s = app.pods_state.lock().expect("pods poisoned");
        (s.loading, s.error.clone(), s.pods.len(), s.workloads.len())
    };
    let src = &app.pods_rows;

    let view_label = if app.pods_show_workloads { "workloads" } else { "pods" };
    let title = if let Some(e) = &error {
        format!("{} (erreur: {})", view_label, e)
    } else if loading && src.is_empty() {
        format!("{} (chargement...)", view_label)
    } else if app.pods_show_workloads {
        format!(
            "workloads ({} workloads · {} pods) · ns={} · [t] pods",
            n_workloads, n_pods, app.namespace_label
        )
    } else {
        format!(
            "pods ({} pods) · ns={} · [t] workloads",
            n_pods, app.namespace_label
        )
    };

    // A pod row nests under the workload row it immediately follows when its owner matches; otherwise
    // it is an orphan. `parent[i]` is the index of the owning workload row (None for orphans), used
    // both to aggregate child CPU/MEM onto the workload row and to decide indentation/namespace.
    let mut parent: Vec<Option<usize>> = vec![None; src.len()];
    let mut cur: Option<(&str, &str, &str, usize)> = None;
    for (i, row) in src.iter().enumerate() {
        match row {
            PodRow::Workload(w) => cur = Some((&w.kind, &w.name, &w.namespace, i)),
            PodRow::Pod(p) => {
                if let (Some(o), Some((k, n, ns, idx))) = (p.owner.as_ref(), cur) {
                    if o.kind == k && o.name == n && o.namespace == ns {
                        parent[i] = Some(idx);
                    }
                }
            }
        }
    }
    let mut agg: Vec<(i64, i64, bool, bool)> = vec![(0, 0, false, false); src.len()];
    for (i, row) in src.iter().enumerate() {
        if let (PodRow::Pod(p), Some(idx)) = (row, parent[i]) {
            if let Some(c) = p.cpu_milli {
                agg[idx].0 += c;
                agg[idx].2 = true;
            }
            if let Some(m) = p.mem_bytes {
                agg[idx].1 += m;
                agg[idx].3 = true;
            }
        }
    }

    let header_row = Row::new(vec![
        Cell::from("NAMESPACE"), Cell::from("NAME"), Cell::from("READY"),
        Cell::from("STATUS"), Cell::from("RST"), Cell::from("CPU"), Cell::from("MEM"),
        Cell::from("%CPU/R"), Cell::from("%CPU/L"), Cell::from("%MEM/R"), Cell::from("%MEM/L"),
        Cell::from("IP"), Cell::from("NODE"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    // In the flat pods-only view there are no parent workload rows, so pod names are not indented.
    let pod_indent = if app.pods_show_workloads { "    " } else { "" };
    let blank = || Cell::from("");
    let rows: Vec<Row> = src
        .iter()
        .enumerate()
        .map(|(i, row)| match row {
            PodRow::Workload(w) => {
                let ready = w
                    .replicas
                    .map(|r| format!("{}/{}", w.ready_replicas, r))
                    .unwrap_or_else(|| w.ready_replicas.to_string());
                let (status, status_color) = match w.replicas {
                    Some(r) if w.ready_replicas >= r => ("Ready", Color::Green),
                    Some(_) => ("Scaling", Color::Yellow),
                    None => (w.kind.as_str(), Color::Cyan),
                };
                let (cpu, mem, has_cpu, has_mem) = agg[i];
                Row::new(vec![
                    Cell::from(w.namespace.clone()).style(Style::default().fg(DIM)),
                    Cell::from(format!("▾ {} {}", w.kind, w.name))
                        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Cell::from(ready).style(Style::default().add_modifier(Modifier::BOLD)),
                    Cell::from(status).style(Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                    blank(),
                    usage_cell(has_cpu.then_some(cpu), format_cpu_milli),
                    usage_cell(has_mem.then_some(mem), format_memory_bytes),
                    blank(), blank(), blank(), blank(),
                    blank(),
                    blank(),
                    Cell::from(w.age.clone()).style(Style::default().fg(DIM)),
                ])
            }
            PodRow::Pod(p) => {
                let status_color = pod_status_color(&p.status);
                let restart_color = if p.restarts > 0 { Color::Yellow } else { DIM };
                let orphan = parent[i].is_none();
                let ns_cell = if orphan {
                    Cell::from(p.namespace.clone()).style(Style::default().fg(DIM))
                } else {
                    blank()
                };
                Row::new(vec![
                    ns_cell,
                    Cell::from(format!("{}{}", pod_indent, p.name)),
                    Cell::from(p.ready.clone()),
                    Cell::from(p.status.clone()).style(Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                    Cell::from(p.restarts.to_string()).style(Style::default().fg(restart_color)),
                    usage_cell(p.cpu_milli, format_cpu_milli),
                    usage_cell(p.mem_bytes, format_memory_bytes),
                    pct_cell(p.cpu_milli, p.cpu_req),
                    pct_cell(p.cpu_milli, p.cpu_lim),
                    pct_cell(p.mem_bytes, p.mem_req),
                    pct_cell(p.mem_bytes, p.mem_lim),
                    Cell::from(p.ip.clone()).style(Style::default().fg(DIM)),
                    Cell::from(p.node.clone()).style(Style::default().fg(DIM)),
                    Cell::from(p.age.clone()).style(Style::default().fg(DIM)),
                ])
                .style(pod_row_style(status_color))
            }
        })
        .collect();

    let ns_values = src.iter().map(|r| match r {
        PodRow::Workload(w) => w.namespace.as_str(),
        PodRow::Pod(p) => p.namespace.as_str(),
    });
    let names: Vec<String> = src
        .iter()
        .map(|r| match r {
            PodRow::Workload(w) => format!("▾ {} {}", w.kind, w.name),
            PodRow::Pod(p) => format!("{}{}", pod_indent, p.name),
        })
        .collect();
    let ns_w = col_width(ns_values, "NAMESPACE", 9, 24);
    let name_w = col_width(names.iter().map(|s| s.as_str()), "NAME", 14, 56);
    let widths = [
        Constraint::Length(ns_w), Constraint::Length(name_w), Constraint::Length(7),
        Constraint::Length(12), Constraint::Length(4), Constraint::Length(7), Constraint::Length(9),
        Constraint::Length(7), Constraint::Length(7), Constraint::Length(7), Constraint::Length(7),
        Constraint::Length(15), Constraint::Length(20), Constraint::Length(5),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

// Services/Ingress view: dispatches to the per-world table. Rendered straight from `app.net_rows`,
// which is index-aligned with the snapshot/`table_state`, so the highlighted row drives the detail.
fn draw_net_tree(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    match app.net_world {
        NetWorld::Services => draw_services_table(f, app, area),
        NetWorld::Ingress => draw_ingress_table(f, app, area),
    }
}

// Services table: each Service row, with its backing endpoints nested under it when `t` grouping is on.
fn draw_services_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, n_svc, n_ep) = {
        let s = app.network_state.lock().expect("network poisoned");
        (s.loading, s.error.clone(), s.services.len(), s.endpoints.len())
    };
    let src = &app.net_rows;

    let title = if let Some(e) = &error {
        format!("services (erreur: {})", e)
    } else if loading && src.is_empty() {
        "services (chargement...)".to_string()
    } else if app.net_group {
        format!(
            "services ({} svc · {} endpoints) · ns={} · [t] plat · [g] ingress",
            n_svc, n_ep, app.namespace_label
        )
    } else {
        format!(
            "services ({} svc) · ns={} · [t] endpoints · [g] ingress",
            n_svc, app.namespace_label
        )
    };

    let header_row = Row::new(vec![
        Cell::from("NAMESPACE"), Cell::from("NAME"), Cell::from("TYPE"), Cell::from("CLUSTER-IP"),
        Cell::from("EXTERNAL-IP"), Cell::from("PORTS"), Cell::from("ENDPOINTS"), Cell::from("NODE"),
        Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let ep_indent = if app.net_group { "    " } else { "" };
    let blank = || Cell::from("");
    let rows: Vec<Row> = src
        .iter()
        .map(|row| match row {
            NetRow::Service(s) => {
                let endpoints = format!("{}/{}", s.endpoints_ready, s.endpoints_total);
                let ep_color = if s.endpoints_total == 0 {
                    Color::Red
                } else if s.endpoints_ready < s.endpoints_total {
                    Color::Yellow
                } else {
                    Color::Green
                };
                let prefix = if app.net_group { "▾ " } else { "" };
                Row::new(vec![
                    Cell::from(s.namespace.clone()).style(Style::default().fg(DIM)),
                    Cell::from(format!("{}{}", prefix, s.name))
                        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Cell::from(s.type_.clone()),
                    Cell::from(s.cluster_ip.clone()),
                    Cell::from(s.external_ip.clone()).style(Style::default().fg(DIM)),
                    Cell::from(s.ports.clone()).style(Style::default().fg(DIM)),
                    Cell::from(endpoints).style(Style::default().fg(ep_color).add_modifier(Modifier::BOLD)),
                    blank(),
                    Cell::from(s.age.clone()).style(Style::default().fg(DIM)),
                ])
            }
            NetRow::Endpoint(e) => {
                let (ready_txt, ready_color) = if e.ready {
                    ("✓ ready", Color::Green)
                } else {
                    ("✗ notready", Color::Red)
                };
                Row::new(vec![
                    blank(),
                    Cell::from(format!("{}{}", ep_indent, e.target_name)),
                    Cell::from(e.target_kind.clone()).style(Style::default().fg(DIM)),
                    Cell::from(e.address.clone()),
                    blank(),
                    blank(),
                    Cell::from(ready_txt).style(Style::default().fg(ready_color)),
                    Cell::from(e.node.clone()).style(Style::default().fg(DIM)),
                    blank(),
                ])
            }
            _ => Row::new(vec![blank()]),
        })
        .collect();

    let ns_values = src.iter().map(|r| match r {
        NetRow::Service(s) => s.namespace.as_str(),
        NetRow::Endpoint(e) => e.service_namespace.as_str(),
        _ => "",
    });
    let names: Vec<String> = src
        .iter()
        .map(|r| match r {
            NetRow::Service(s) => s.name.clone(),
            NetRow::Endpoint(e) => format!("{}{}", ep_indent, e.target_name),
            _ => String::new(),
        })
        .collect();
    let ns_w = col_width(ns_values, "NAMESPACE", 9, 24);
    let name_w = col_width(names.iter().map(|s| s.as_str()), "NAME", 14, 48);
    let widths = [
        Constraint::Length(ns_w), Constraint::Length(name_w), Constraint::Length(12),
        Constraint::Length(16), Constraint::Length(18), Constraint::Length(20),
        Constraint::Length(11), Constraint::Length(20), Constraint::Length(5),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

// Ingress table: each Ingress row, grouped under its IngressClass (with the serving controller) when
// `t` grouping is on.
fn draw_ingress_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, n_ing, n_cls) = {
        let s = app.network_state.lock().expect("network poisoned");
        (s.loading, s.error.clone(), s.ingresses.len(), s.ingress_classes.len())
    };
    let src = &app.net_rows;

    let title = if let Some(e) = &error {
        format!("ingress (erreur: {})", e)
    } else if loading && src.is_empty() {
        "ingress (chargement...)".to_string()
    } else if app.net_group {
        format!(
            "ingress ({} ingress · {} classes) · ns={} · [t] plat · [g] services",
            n_ing, n_cls, app.namespace_label
        )
    } else {
        format!(
            "ingress ({} ingress) · ns={} · [t] par class · [g] services",
            n_ing, app.namespace_label
        )
    };

    let header_row = Row::new(vec![
        Cell::from("NAMESPACE"), Cell::from("NAME"), Cell::from("CLASS/CTRL"), Cell::from("HOSTS"),
        Cell::from("ROUTES"), Cell::from("TLS"), Cell::from("ADDRESS"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let ing_indent = if app.net_group { "    " } else { "" };
    let blank = || Cell::from("");
    let rows: Vec<Row> = src
        .iter()
        .map(|row| match row {
            NetRow::IngressClass(c) => {
                let name = if c.is_default {
                    format!("▾ {} (default)", c.name)
                } else {
                    format!("▾ {}", c.name)
                };
                Row::new(vec![
                    blank(),
                    Cell::from(name).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Cell::from(c.controller.clone()).style(Style::default().fg(DIM)),
                    blank(), blank(), blank(), blank(),
                    Cell::from(c.age.clone()).style(Style::default().fg(DIM)),
                ])
            }
            NetRow::Ingress(i) => {
                let (tls_txt, tls_color) = if i.tls { ("TLS", Color::Green) } else { ("—", DIM) };
                // When grouped under their class, ingresses don't repeat the class column.
                let class_cell = if app.net_group {
                    blank()
                } else {
                    Cell::from(i.class.clone().unwrap_or_else(|| "—".to_string()))
                        .style(Style::default().fg(DIM))
                };
                Row::new(vec![
                    Cell::from(i.namespace.clone()).style(Style::default().fg(DIM)),
                    Cell::from(format!("{}{}", ing_indent, i.name)),
                    class_cell,
                    Cell::from(i.hosts.clone()),
                    Cell::from(i.rules.clone()).style(Style::default().fg(DIM)),
                    Cell::from(tls_txt).style(Style::default().fg(tls_color)),
                    Cell::from(i.address.clone()).style(Style::default().fg(DIM)),
                    Cell::from(i.age.clone()).style(Style::default().fg(DIM)),
                ])
            }
            _ => Row::new(vec![blank()]),
        })
        .collect();

    let names: Vec<String> = src
        .iter()
        .map(|r| match r {
            NetRow::IngressClass(c) => format!("▾ {}", c.name),
            NetRow::Ingress(i) => format!("{}{}", ing_indent, i.name),
            _ => String::new(),
        })
        .collect();
    let name_w = col_width(names.iter().map(|s| s.as_str()), "NAME", 14, 40);
    let widths = [
        Constraint::Length(14), Constraint::Length(name_w), Constraint::Length(20),
        Constraint::Length(24), Constraint::Min(20), Constraint::Length(4),
        Constraint::Length(18), Constraint::Length(5),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

// Colour for a severity tier, shared by the RBAC table rows and the detail findings.
fn rbac_sev_color(s: RbacSeverity) -> Color {
    match s {
        RbacSeverity::Critical => Color::Red,
        RbacSeverity::High => Color::Rgb(255, 140, 0),
        RbacSeverity::Medium => Color::Yellow,
        RbacSeverity::Low => Color::Cyan,
        RbacSeverity::Info => DIM,
    }
}

fn rbac_sev_icon(s: RbacSeverity) -> &'static str {
    match s {
        RbacSeverity::Critical => "●",
        RbacSeverity::High => "●",
        RbacSeverity::Medium => "●",
        RbacSeverity::Low => "○",
        RbacSeverity::Info => "·",
    }
}

// Binding-centric security table: one row per binding, sorted by severity, dangerous grants on top.
fn draw_rbac_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, total, counts) = {
        let s = app.rbac_state.lock().expect("rbac poisoned");
        let mut c = [0usize; 5];
        for b in &s.bindings {
            c[b.severity as usize] += 1;
        }
        (s.loading, s.error.clone(), s.bindings.len(), c)
    };
    let visible = app.rbac_visible();
    if !visible.is_empty() {
        app.rbac_cursor = app.rbac_cursor.min(visible.len() - 1);
    }

    let title = if let Some(e) = &error {
        format!("rbac (erreur: {})", e)
    } else if loading && total == 0 {
        "rbac (chargement...)".to_string()
    } else {
        format!(
            "rbac ({} bindings · crit{} high{} med{} low{}) · min={}",
            total,
            counts[RbacSeverity::Critical as usize],
            counts[RbacSeverity::High as usize],
            counts[RbacSeverity::Medium as usize],
            counts[RbacSeverity::Low as usize],
            app.rbac_min_sev.label(),
        )
    };

    let header_row = Row::new(vec![
        Cell::from("SEV"), Cell::from("SCOPE"), Cell::from("SUBJECT"),
        Cell::from("ROLE"), Cell::from("SOURCE"), Cell::from("RISK"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = visible.iter().map(|b| {
        let color = rbac_sev_color(b.severity);
        let subject = match b.subjects.split_first() {
            Some((first, rest)) if rest.is_empty() => first.label(),
            Some((first, rest)) => format!("{} (+{})", first.label(), rest.len()),
            None => "—".to_string(),
        };
        let row_style = if b.severity == RbacSeverity::Critical {
            Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0))
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(format!("{} {}", rbac_sev_icon(b.severity), b.severity.label()))
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Cell::from(b.scope.label()).style(Style::default().fg(scope_color(b))),
            Cell::from(subject),
            Cell::from(b.role_ref.label()).style(Style::default().fg(Color::Cyan)),
            Cell::from(b.provenance.label()).style(Style::default().fg(provenance_color(&b.provenance))),
            Cell::from(b.risk_tags()).style(Style::default().fg(color)),
            Cell::from(b.age.clone()).style(Style::default().fg(DIM)),
        ])
        .style(row_style)
    }).collect();

    let widths = [
        Constraint::Length(9), Constraint::Length(18), Constraint::Length(26),
        Constraint::Length(24), Constraint::Length(22), Constraint::Min(20), Constraint::Length(6),
    ];

    let mut ts = TableState::default();
    if !visible.is_empty() {
        ts.select(Some(app.rbac_cursor));
    }
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut ts);
}

// A namespaced binding in a critical namespace is highlighted even though its scope is "just" a ns.
fn scope_color(b: &RbacBinding) -> Color {
    if matches!(b.scope, crate::rbac::Scope::ClusterWide) {
        Color::Magenta
    } else if b.findings.iter().any(|fd| fd.tag == "critical-ns") {
        Color::Rgb(255, 140, 0)
    } else {
        DIM
    }
}

// GitOps-managed origins read green (auditable); manual/unmanaged grants read red.
fn provenance_color(p: &crate::rbac::Provenance) -> Color {
    use crate::rbac::Provenance::*;
    match p {
        FluxKustomization { .. } | FluxHelmRelease { .. } => Color::Green,
        Helm { .. } | Argo { .. } => Color::Cyan,
        Owner { .. } => DIM,
        Kubectl | Unmanaged => Color::Red,
    }
}

// Detail panel (split top / full screen): selected binding's findings, then its resolved rules.
fn draw_rbac_detail(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(b) = app.rbac_selected() else {
        let p = Paragraph::new(Line::from(Span::styled(
            " sélectionnez un binding ", Style::default().fg(DIM),
        )))
        .block(Block::default().borders(Borders::ALL).title(" rbac "));
        f.render_widget(p, area);
        return;
    };

    let title = Line::from(Span::styled(
        format!(" {} {} ", b.binding_kind, b.binding_name),
        Style::default().fg(Color::Black).bg(rbac_sev_color(b.severity)).add_modifier(Modifier::BOLD),
    ));

    let mut lines: Vec<Line<'static>> = Vec::new();
    let label = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), Style::default().fg(DIM)),
            Span::raw(v),
        ])
    };
    lines.push(label("severity", b.severity.label().to_string()));
    lines.push(label("scope", b.scope.label()));
    lines.push(label("role", b.role_ref.label()));
    if b.via_clusterrole {
        lines.push(label("via", format!("ClusterRole rabattu sur {}", b.scope.label())));
    }
    if b.aggregated {
        lines.push(label("aggregated", "règles composées par agrégation".to_string()));
    }
    lines.push(Line::from(vec![
        Span::styled(format!("{:<10}", "origin"), Style::default().fg(DIM)),
        Span::styled(b.provenance.label(), Style::default().fg(provenance_color(&b.provenance))),
    ]));
    if let Some(src) = &b.source {
        lines.push(label("source", src.clone()));
    }
    for (i, s) in b.subjects.iter().enumerate() {
        lines.push(label(if i == 0 { "subjects" } else { "" }, s.label()));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("FINDINGS", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
    if b.findings.is_empty() {
        lines.push(Line::from(Span::styled("  read-only / sans risque détecté", Style::default().fg(DIM))));
    }
    for fd in &b.findings {
        lines.push(rbac_finding_line(fd));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("RULES", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
    if b.rules.is_empty() {
        lines.push(Line::from(Span::styled("  (aucune règle résolue)", Style::default().fg(DIM))));
    }
    for r in &b.rules {
        let mut spans = vec![
            Span::styled("  verbs ", Style::default().fg(DIM)),
            Span::styled(join_or_star(&r.verbs), Style::default().fg(Color::Yellow)),
            Span::styled("  res ", Style::default().fg(DIM)),
            Span::raw(join_or_star(&r.resources)),
            Span::styled("  grp ", Style::default().fg(DIM)),
            Span::styled(join_or_star(&r.api_groups), Style::default().fg(DIM)),
        ];
        if !r.resource_names.is_empty() {
            spans.push(Span::styled("  names ", Style::default().fg(DIM)));
            spans.push(Span::styled(r.resource_names.join(","), Style::default().fg(Color::Green)));
        }
        lines.push(Line::from(spans));
    }

    let visible = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    if app.rbac_detail_scroll > max_scroll {
        app.rbac_detail_scroll = max_scroll;
    }
    let p = Paragraph::new(lines)
        .scroll((app.rbac_detail_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn rbac_finding_line(fd: &RbacFinding) -> Line<'static> {
    let color = rbac_sev_color(fd.sev);
    Line::from(vec![
        Span::styled(format!("  {} ", rbac_sev_icon(fd.sev)), Style::default().fg(color)),
        Span::styled(format!("{:<8}", fd.sev.label()), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<18}", fd.tag), Style::default().fg(color)),
        Span::raw(fd.detail.clone()),
    ])
}

fn join_or_star(v: &[String]) -> String {
    if v.is_empty() { "—".to_string() } else { v.join(",") }
}

fn vuln_sev_color(s: VulnSev) -> Color {
    match s {
        VulnSev::Critical => Color::Red,
        VulnSev::High => Color::Rgb(255, 140, 0),
        VulnSev::Medium => Color::Yellow,
        VulnSev::Low => Color::Cyan,
        VulnSev::Unknown => DIM,
    }
}

// Image vulnerability table: the k8s control-plane risk first (when known), then one row per scanned
// image, sorted by max severity. Severity floor filters the image rows (`f`).
fn draw_vuln_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, available, total, counts) = {
        let s = app.vuln_state.lock().expect("vuln poisoned");
        (s.loading, s.error.clone(), s.available, s.components.len(), s.counts())
    };
    let rows_data = app.vuln_rows();
    if !rows_data.is_empty() {
        app.vuln_cursor = app.vuln_cursor.min(rows_data.len() - 1);
    }

    let title = if !available {
        // Trivy Operator absent: light fallback showing only the Kubernetes version risk.
        "vuln · k8s seul (Trivy Operator absent → pas de scan d'images)".to_string()
    } else if let Some(e) = &error {
        format!("vuln (erreur: {})", e)
    } else if loading && total == 0 {
        "vuln (chargement...)".to_string()
    } else {
        let (c, h, m, l) = counts;
        format!(
            "vuln ({} images · crit{} high{} med{} low{}) · min={}",
            total, c, h, m, l, app.vuln_min_sev.label(),
        )
    };

    let header_row = Row::new(vec![
        Cell::from("SEV"), Cell::from("NAMESPACE"), Cell::from("COMPONENT"),
        Cell::from("VERSION"), Cell::from("CRIT"), Cell::from("HIGH"), Cell::from("MED"),
        Cell::from("LOW"), Cell::from("→ TARGET"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let count_cell = |n: usize, color: Color| {
        if n == 0 {
            Cell::from("·").style(Style::default().fg(DIM))
        } else {
            Cell::from(n.to_string()).style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        }
    };

    let rows: Vec<Row> = rows_data.iter().map(|row| match row {
        VulnRow::K8s(k) => {
            let crit = k.cves.iter().filter(|c| c.severity == VulnSev::Critical).count();
            let high = k.cves.iter().filter(|c| c.severity == VulnSev::High).count();
            let med = k.cves.iter().filter(|c| c.severity == VulnSev::Medium).count();
            let low = k.cves.iter().filter(|c| c.severity == VulnSev::Low).count();
            let target = match (&k.latest_patch, k.behind) {
                (Some(v), true) => format!("→ {}", v),
                (Some(v), false) => format!("✓ {}", v),
                (None, _) => "?".to_string(),
            };
            let comp = if k.eol {
                "kubernetes (EOL)".to_string()
            } else {
                "kubernetes".to_string()
            };
            let target_color = if k.eol || k.behind { Color::Red } else { Color::Green };
            Row::new(vec![
                Cell::from("k8s").style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                Cell::from("control-plane").style(Style::default().fg(DIM)),
                Cell::from(comp).style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                Cell::from(k.server_version.clone()),
                count_cell(crit, Color::Red),
                count_cell(high, Color::Rgb(255, 140, 0)),
                count_cell(med, Color::Yellow),
                count_cell(low, Color::Cyan),
                Cell::from(target).style(Style::default().fg(target_color).add_modifier(Modifier::BOLD)),
                Cell::from("—").style(Style::default().fg(DIM)),
            ])
            .style(Style::default().bg(Color::Rgb(20, 20, 40)))
        }
        VulnRow::Image(c) => {
            let color = vuln_sev_color(c.max_sev);
            let target = if c.fixable > 0 {
                format!("{} fixables", c.fixable)
            } else {
                "—".to_string()
            };
            Row::new(vec![
                Cell::from(c.max_sev.label()).style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Cell::from(c.namespace.clone()).style(Style::default().fg(DIM)),
                Cell::from(short_image(&c.image)).style(Style::default().add_modifier(Modifier::BOLD)),
                Cell::from(c.version.clone()).style(Style::default().fg(DIM)),
                count_cell(c.critical, Color::Red),
                count_cell(c.high, Color::Rgb(255, 140, 0)),
                count_cell(c.medium, Color::Yellow),
                count_cell(c.low, Color::Cyan),
                Cell::from(target).style(Style::default().fg(if c.fixable > 0 { Color::Green } else { DIM })),
                Cell::from(c.age.clone()).style(Style::default().fg(DIM)),
            ])
        }
    }).collect();

    let widths = [
        Constraint::Length(8), Constraint::Length(16), Constraint::Min(24),
        Constraint::Length(16), Constraint::Length(5), Constraint::Length(5),
        Constraint::Length(5), Constraint::Length(5), Constraint::Length(14), Constraint::Length(6),
    ];

    let mut ts = TableState::default();
    if !rows_data.is_empty() {
        ts.select(Some(app.vuln_cursor));
    }
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut ts);
}

// Keep the trailing image path + tag-relevant part readable when the registry prefix is long.
fn short_image(image: &str) -> String {
    let trimmed = image
        .strip_prefix("index.docker.io/library/")
        .or_else(|| image.strip_prefix("index.docker.io/"))
        .or_else(|| image.strip_prefix("docker.io/library/"))
        .or_else(|| image.strip_prefix("docker.io/"))
        .unwrap_or(image);
    trimmed.to_string()
}

// Detail panel (split top / full screen): the selected component's CVEs, or the k8s version risk.
fn draw_vuln_detail(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(row) = app.vuln_selected() else {
        let p = Paragraph::new(Line::from(Span::styled(
            " sélectionnez un composant ", Style::default().fg(DIM),
        )))
        .block(Block::default().borders(Borders::ALL).title(" vuln "));
        f.render_widget(p, area);
        return;
    };

    let (title, lines) = match &row {
        VulnRow::K8s(k) => vuln_k8s_lines(k),
        VulnRow::Image(c) => vuln_image_lines(c),
    };

    let visible = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    if app.vuln_detail_scroll > max_scroll {
        app.vuln_detail_scroll = max_scroll;
    }
    let p = Paragraph::new(lines)
        .scroll((app.vuln_detail_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn vuln_image_lines(c: &VulnComponent) -> (Line<'static>, Vec<Line<'static>>) {
    let title = Line::from(Span::styled(
        format!(" {} : {} ", short_image(&c.image), c.version),
        Style::default().fg(Color::Black).bg(vuln_sev_color(c.max_sev)).add_modifier(Modifier::BOLD),
    ));
    let label = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), Style::default().fg(DIM)),
            Span::raw(v),
        ])
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(label("workload", c.workload.clone()));
    lines.push(label("image", c.image.clone()));
    lines.push(label(
        "counts",
        format!("crit {} · high {} · med {} · low {} · total {}", c.critical, c.high, c.medium, c.low, c.total()),
    ));
    lines.push(label("fixables", format!("{} CVE corrigibles par mise à jour", c.fixable)));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "CVEs", Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));
    if c.cves.is_empty() {
        lines.push(Line::from(Span::styled("  (aucune)", Style::default().fg(DIM))));
    }
    for v in &c.cves {
        lines.push(vuln_cve_line(v, true));
    }
    (title, lines)
}

fn vuln_k8s_lines(k: &K8sVersionRisk) -> (Line<'static>, Vec<Line<'static>>) {
    let title = Line::from(Span::styled(
        format!(" Kubernetes {} ", k.server_version),
        Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD),
    ));
    let label = |key: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{key:<14}"), Style::default().fg(DIM)),
            Span::raw(v),
        ])
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(label("version", k.server_version.clone()));
    match (&k.latest_patch, k.behind) {
        (Some(v), true) => lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", "cible patch"), Style::default().fg(DIM)),
            Span::styled(format!("→ monter vers {}", v), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ])),
        (Some(v), false) => lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", "cible patch"), Style::default().fg(DIM)),
            Span::styled(format!("✓ à jour ({})", v), Style::default().fg(Color::Green)),
        ])),
        (None, _) => lines.push(label("cible patch", "non résolue".to_string())),
    }
    if k.eol {
        lines.push(Line::from(Span::styled(
            "  ⚠ version hors fenêtre de support (EOL)",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    if let Some(note) = &k.note {
        lines.push(label("note", note.clone()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "CVEs récentes (feed officiel k8s, non filtrées par version)",
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));
    if k.cves.is_empty() {
        lines.push(Line::from(Span::styled("  (aucune / indisponible)", Style::default().fg(DIM))));
    }
    for v in &k.cves {
        lines.push(vuln_cve_line(v, false));
    }
    (title, lines)
}

fn vuln_cve_line(v: &crate::vulnerabilities::Cve, image: bool) -> Line<'static> {
    let color = vuln_sev_color(v.severity);
    let mut spans = vec![
        Span::styled(format!("  {:<5}", v.severity.label()), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:>5.1}  ", v.score), Style::default().fg(color)),
        Span::styled(format!("{:<18}", v.id), Style::default().add_modifier(Modifier::BOLD)),
    ];
    if image {
        let fix = if v.fixed.is_empty() {
            Span::styled("pas de fix".to_string(), Style::default().fg(DIM))
        } else {
            Span::styled(format!("{} → {}", v.installed, v.fixed), Style::default().fg(Color::Green))
        };
        spans.push(Span::styled(format!("{:<22}", v.package), Style::default().fg(Color::Cyan)));
        spans.push(fix);
    } else if !v.title.is_empty() {
        spans.push(Span::raw(v.title.clone()));
    }
    if !v.url.is_empty() {
        spans.push(Span::styled(format!("  {}", v.url), Style::default().fg(DIM)));
    }
    Line::from(spans)
}

// --- Secrets view rendering -------------------------------------------------------------------

// Expiry colour for the table/detail: expired & <15d are red, <30d orange, otherwise green.
fn expiry_color(e: Expiry) -> Color {
    match e {
        Expiry::Expired | Expiry::Critical => Color::Red,
        Expiry::Warn => Color::Rgb(255, 140, 0),
        Expiry::Ok => Color::Green,
    }
}

// Human-readable "EXPIRY" cell: the date plus the signed days remaining (or "expiré").
fn expiry_text(c: &crate::secrets::TlsCert) -> String {
    if c.days_remaining < 0 {
        format!("{} (expiré)", c.not_after)
    } else {
        format!("{} ({}j)", c.not_after, c.days_remaining)
    }
}

// Drop the well-known `kubernetes.io/`/`bootstrap.kubernetes.io/` prefixes so the TYPE column reads
// "tls", "service-account-token", "dockerconfigjson"… instead of the full noisy type string.
fn secret_type_short(t: &str) -> String {
    t.strip_prefix("kubernetes.io/")
        .or_else(|| t.strip_prefix("bootstrap.kubernetes.io/"))
        .unwrap_or(t)
        .to_string()
}

// Secrets table: every secret in scope (filtered by `f`), TLS certs about to expire pinned on top with
// a coloured EXPIRY cell. Non-TLS rows leave EXPIRY blank.
fn draw_secrets_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, cm_present, summary) = {
        let s = app.secrets_state.lock().expect("secrets poisoned");
        (s.loading, s.error.clone(), s.cert_manager_present, s.summary())
    };
    let rows_data = app.secret_rows();
    if !rows_data.is_empty() {
        app.secrets_cursor = app.secrets_cursor.min(rows_data.len() - 1);
    }

    let (total, tls, expired, expiring) = summary;
    let title = if let Some(e) = &error {
        format!("secrets (erreur: {})", e)
    } else if loading && total == 0 {
        "secrets (chargement...)".to_string()
    } else {
        let cm = if cm_present { " · cert-manager ✓" } else { "" };
        format!(
            "secrets ({} · tls{} expirés{} <30j{}){} · filtre={}",
            total, tls, expired, expiring, cm, app.secrets_filter.label(),
        )
    };

    let header_row = Row::new(vec![
        Cell::from("NAMESPACE"), Cell::from("NAME"), Cell::from("TYPE"),
        Cell::from("DATA"), Cell::from("ISSUER"), Cell::from("EXPIRY"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = rows_data.iter().map(|s| {
        let expiry_cell = match (&s.tls, &s.tls_error) {
            (Some(c), _) => Cell::from(expiry_text(c))
                .style(Style::default().fg(expiry_color(c.expiry)).add_modifier(Modifier::BOLD)),
            (None, Some(_)) => Cell::from("cert illisible").style(Style::default().fg(Color::Red)),
            (None, None) => Cell::from("—").style(Style::default().fg(DIM)),
        };
        // Issuer CN for TLS rows; self-signed certs are flagged since their issuer == subject.
        let issuer_cell = match &s.tls {
            Some(c) if c.self_signed => Cell::from(format!("{} (self)", c.issuer_cn))
                .style(Style::default().fg(Color::Yellow)),
            Some(c) => Cell::from(c.issuer_cn.clone()).style(Style::default().fg(DIM)),
            None => Cell::from("—").style(Style::default().fg(DIM)),
        };
        Row::new(vec![
            Cell::from(s.namespace.clone()).style(Style::default().fg(DIM)),
            Cell::from(s.name.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from(secret_type_short(&s.type_)).style(Style::default().fg(if s.is_tls() { Color::Cyan } else { DIM })),
            Cell::from(s.data_keys.len().to_string()).style(Style::default().fg(DIM)),
            issuer_cell,
            expiry_cell,
            Cell::from(s.age.clone()).style(Style::default().fg(DIM)),
        ])
    }).collect();

    let name_w = col_width(rows_data.iter().map(|s| s.name.as_str()), "NAME", 12, 60);
    let widths = [
        Constraint::Length(22), Constraint::Length(name_w), Constraint::Length(20),
        Constraint::Length(5), Constraint::Length(28), Constraint::Length(22), Constraint::Length(6),
    ];

    let mut ts = TableState::default();
    if !rows_data.is_empty() {
        ts.select(Some(app.secrets_cursor));
    }
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut ts);
}

// Detail panel (split top / full screen): the selected secret's decoded certificate plus its
// consumers (Ingress / cert-manager), or the plain key list for a non-TLS secret.
fn draw_secrets_detail(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(s) = app.secret_selected() else {
        let p = Paragraph::new(Line::from(Span::styled(
            " sélectionnez un secret ", Style::default().fg(DIM),
        )))
        .block(Block::default().borders(Borders::ALL).title(" secrets "));
        f.render_widget(p, area);
        return;
    };

    let (title, lines) = secret_detail_lines(&s, app.secrets_reveal);

    let visible = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    if app.secrets_detail_scroll > max_scroll {
        app.secrets_detail_scroll = max_scroll;
    }
    let p = Paragraph::new(lines)
        .scroll((app.secrets_detail_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn secret_detail_lines(s: &SecretInfo, reveal: SecretReveal) -> (Line<'static>, Vec<Line<'static>>) {
    let (title_bg, title_txt) = match (&s.tls, s.is_tls()) {
        (Some(c), _) => (expiry_color(c.expiry), format!(" {}/{} : TLS ", s.namespace, s.name)),
        (None, true) => (Color::Red, format!(" {}/{} : TLS illisible ", s.namespace, s.name)),
        (None, false) => (Color::Cyan, format!(" {}/{} ", s.namespace, s.name)),
    };
    let title = Line::from(Span::styled(
        title_txt,
        Style::default().fg(Color::Black).bg(title_bg).add_modifier(Modifier::BOLD),
    ));

    let label = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<14}"), Style::default().fg(DIM)),
            Span::raw(v),
        ])
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(label("type", s.type_.clone()));
    lines.push(label("origine", s.provenance.label()));
    lines.push(label(
        "clés",
        if s.data_keys.is_empty() { "—".to_string() } else { s.data_keys.join(", ") },
    ));
    lines.push(label("âge", s.age.clone()));

    if let Some(c) = &s.tls {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Certificat", Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )));
        lines.push(label("subject CN", c.subject_cn.clone()));
        let issuer = if c.self_signed {
            format!("{} (auto-signé)", c.issuer_cn)
        } else {
            c.issuer_cn.clone()
        };
        lines.push(label("issuer (CA)", issuer));
        if c.is_ca {
            lines.push(label("contrainte", "certificat de CA (CA:TRUE)".to_string()));
        }
        lines.push(label("clé", c.key_algo.clone()));
        lines.push(label("serial", c.serial.clone()));
        lines.push(label("émis le", c.not_before.clone()));
        let exp = if c.days_remaining < 0 {
            format!("{} — EXPIRÉ depuis {} j", c.not_after, -c.days_remaining)
        } else {
            format!("{} — {} jours restants", c.not_after, c.days_remaining)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", "expire le"), Style::default().fg(DIM)),
            Span::styled(exp, Style::default().fg(expiry_color(c.expiry)).add_modifier(Modifier::BOLD)),
        ]));
        if let Some(ca) = &c.ca_bundle {
            lines.push(label(
                "ca.crt",
                format!("{} · expire {} ({} j)", ca.subject_cn, ca.not_after, ca.days_remaining),
            ));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "SAN (Subject Alternative Names)",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )));
        if c.sans.is_empty() {
            lines.push(Line::from(Span::styled("  (aucun)", Style::default().fg(DIM))));
        }
        for san in &c.sans {
            lines.push(Line::from(Span::raw(format!("  {san}"))));
        }
    } else if let Some(e) = &s.tls_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("certificat illisible : {e}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }

    // Consumers / issuer — the "Related" section folded into the detail panel.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Consommateurs / émetteur",
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));
    if let Some(cm) = &s.cert_manager {
        lines.push(label("cert-manager", format!("Certificate {cm}")));
    }
    if s.ingress_refs.is_empty() {
        lines.push(Line::from(Span::styled("  aucun Ingress référençant ce secret", Style::default().fg(DIM))));
    } else {
        for ing in &s.ingress_refs {
            lines.push(Line::from(vec![
                Span::styled("  ingress ", Style::default().fg(DIM)),
                Span::raw(ing.clone()),
            ]));
        }
    }

    // Revealed data values (`b` base64 / `d` decoded). Hidden by default; never shown unless toggled.
    if reveal != SecretReveal::Hidden {
        lines.push(Line::from(""));
        let (heading, color) = match reveal {
            SecretReveal::Base64 => ("Contenu (base64)", Color::Magenta),
            SecretReveal::Decoded => ("Contenu (déchiffré)", Color::Red),
            SecretReveal::Hidden => unreachable!(),
        };
        lines.push(Line::from(Span::styled(
            heading, Style::default().fg(color).add_modifier(Modifier::BOLD),
        )));
        for (k, v) in &s.data {
            lines.push(Line::from(Span::styled(
                format!("{k}:"), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            match reveal {
                SecretReveal::Base64 => {
                    use base64::Engine;
                    let enc = base64::engine::general_purpose::STANDARD.encode(v);
                    lines.push(Line::from(Span::raw(enc)));
                }
                SecretReveal::Decoded => {
                    for line in String::from_utf8_lossy(v).split('\n') {
                        lines.push(Line::from(Span::raw(format!("  {line}"))));
                    }
                }
                SecretReveal::Hidden => unreachable!(),
            }
        }
    }

    (title, lines)
}

// --- ConfigMaps view rendering ----------------------------------------------------------------

fn draw_configmaps_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (loading, error, total) = {
        let s = app.configmaps_state.lock().expect("configmaps poisoned");
        (s.loading, s.error.clone(), s.items.len())
    };
    let rows_data = app.configmap_rows();
    if !rows_data.is_empty() {
        app.configmaps_cursor = app.configmaps_cursor.min(rows_data.len() - 1);
    }

    let title = if let Some(e) = &error {
        format!("configmaps (erreur: {})", e)
    } else if loading && total == 0 {
        "configmaps (chargement...)".to_string()
    } else {
        format!("configmaps ({})", total)
    };

    let header_row = Row::new(vec![
        Cell::from("NAMESPACE"), Cell::from("NAME"), Cell::from("KEYS"),
        Cell::from("SIZE"), Cell::from("ORIGIN"), Cell::from("AGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = rows_data.iter().map(|cm| {
        let n_keys = cm.data.len() + cm.binary_keys.len();
        Row::new(vec![
            Cell::from(cm.namespace.clone()).style(Style::default().fg(DIM)),
            Cell::from(cm.name.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from(n_keys.to_string()).style(Style::default().fg(DIM)),
            Cell::from(human_size(cm.total_bytes)).style(Style::default().fg(DIM)),
            Cell::from(cm.provenance.label()).style(Style::default().fg(DIM)),
            Cell::from(cm.age.clone()).style(Style::default().fg(DIM)),
        ])
    }).collect();

    let name_w = col_width(rows_data.iter().map(|cm| cm.name.as_str()), "NAME", 12, 60);
    let origin_w = col_width(rows_data.iter().map(|cm| cm.provenance.label()).collect::<Vec<_>>().iter().map(|s| s.as_str()), "ORIGIN", 8, 36);
    let widths = [
        Constraint::Length(22), Constraint::Length(name_w), Constraint::Length(5),
        Constraint::Length(8), Constraint::Length(origin_w), Constraint::Length(6),
    ];

    let mut ts = TableState::default();
    if !rows_data.is_empty() {
        ts.select(Some(app.configmaps_cursor));
    }
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut ts);
}

// Detail panel (split top / full screen): the selected ConfigMap's metadata then every key's value
// inline (ConfigMap data is plain text, shown directly), binary keys listed by name only.
fn draw_configmaps_detail(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(cm) = app.configmap_selected() else {
        let p = Paragraph::new(Line::from(Span::styled(
            " sélectionnez une configmap ", Style::default().fg(DIM),
        )))
        .block(Block::default().borders(Borders::ALL).title(" configmaps "));
        f.render_widget(p, area);
        return;
    };

    let (title, lines) = configmap_detail_lines(&cm);

    let visible = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    if app.configmaps_detail_scroll > max_scroll {
        app.configmaps_detail_scroll = max_scroll;
    }
    let p = Paragraph::new(lines)
        .scroll((app.configmaps_detail_scroll as u16, app.configmaps_h_scroll as u16))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn configmap_detail_lines(cm: &ConfigMapInfo) -> (Line<'static>, Vec<Line<'static>>) {
    let title = Line::from(Span::styled(
        format!(" {}/{} ", cm.namespace, cm.name),
        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
    ));

    let label = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), Style::default().fg(DIM)),
            Span::raw(v),
        ])
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(label("origine", cm.provenance.label()));
    lines.push(label("clés", format!("{} texte · {} binaire", cm.data.len(), cm.binary_keys.len())));
    lines.push(label("taille", human_size(cm.total_bytes)));
    lines.push(label("âge", cm.age.clone()));

    for (k, v) in &cm.data {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("{k}:"), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        for line in v.split('\n') {
            lines.push(Line::from(Span::raw(format!("  {line}"))));
        }
    }

    if !cm.binary_keys.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Clés binaires (binaryData)",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )));
        for k in &cm.binary_keys {
            lines.push(Line::from(Span::raw(format!("  {k}"))));
        }
    }

    (title, lines)
}

fn draw_flux_table(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (resources, loading, error, counts) = {
        let s = app.flux_state.lock().expect("flux poisoned");
        (s.resources.clone(), s.loading, s.error.clone(), s.counts())
    };

    let (ready, failed, unknown, suspended, reconciling) = counts;
    let title = if let Some(e) = &error {
        format!("flux (erreur: {})", e)
    } else if loading && resources.is_empty() {
        "flux (chargement...)".to_string()
    } else {
        format!(
            "flux ({} · ✓{} ✗{} ⟳{} ?{} ⏸{})",
            resources.len(), ready, failed, reconciling, unknown, suspended
        )
    };

    let header_row = Row::new(vec![
        Cell::from("KIND"), Cell::from("NAMESPACE"), Cell::from("NAME"),
        Cell::from("READY"), Cell::from("REVISION"), Cell::from("AGE"), Cell::from("MESSAGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let kind_w = col_width(resources.iter().map(|r| r.kind.as_str()), "KIND", 8, 20);
    let ns_w = col_width(resources.iter().map(|r| r.namespace.as_str()), "NAMESPACE", 9, 24);
    let name_w = col_width(resources.iter().map(|r| r.name.as_str()), "NAME", 12, 50);
    let selected = app.table_state.selected();
    let msg_w = flux_msg_width(area.width, kind_w + ns_w + name_w + 10 + 20 + 6, 7);

    let rows: Vec<Row> = resources.iter().enumerate().map(|(i, r)| {
        let (ready_txt, ready_color) = if r.suspended {
            ("Suspended", Color::Yellow)
        } else {
            match r.ready {
                FluxReady::Ready => ("Ready", Color::Green),
                FluxReady::Reconciling => ("Reconciling", Color::Cyan),
                FluxReady::Failed => ("Failed", Color::Red),
                FluxReady::Unknown => ("Unknown", Color::Yellow),
                FluxReady::NotApplicable => ("N/A", DIM),
            }
        };
        let row_style = match (r.suspended, r.ready) {
            (false, FluxReady::Failed) => Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0)),
            (false, FluxReady::Unknown) => Style::default().fg(Color::Yellow),
            (false, FluxReady::Reconciling) => Style::default().fg(Color::Cyan),
            (true, _) => Style::default().fg(DIM),
            (false, FluxReady::Ready) => Style::default(),
            (false, FluxReady::NotApplicable) => Style::default(),
        };
        let msg_color = if r.ready == FluxReady::Failed && !r.suspended { Color::Red } else { DIM };
        // The focused row expands its message over multiple lines so the full reason is readable.
        let (msg_cell, height) = if selected == Some(i) && !r.message.is_empty() {
            flux_message_cell_wrapped(r, msg_color, msg_w)
        } else {
            (flux_message_cell(r, msg_color), 1)
        };
        Row::new(vec![
            Cell::from(r.kind.clone()).style(Style::default().fg(Color::Cyan)),
            Cell::from(r.namespace.clone()),
            Cell::from(r.name.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from(ready_txt).style(Style::default().fg(ready_color).add_modifier(Modifier::BOLD)),
            Cell::from(r.revision.clone()).style(Style::default().fg(DIM)),
            Cell::from(r.age.clone()).style(Style::default().fg(DIM)),
            msg_cell,
        ])
        .height(height)
        .style(row_style)
    }).collect();

    let widths = [
        Constraint::Length(kind_w), Constraint::Length(ns_w), Constraint::Length(name_w),
        Constraint::Length(10), Constraint::Length(20), Constraint::Length(6), Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

// Renders the Flux dependency tree (source → workload → dependent workloads) with indentation and
// collapse markers, reusing the same status colouring as the flat table.
fn draw_flux_tree(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let (resources, error) = {
        let s = app.flux_state.lock().expect("flux poisoned");
        (s.resources.clone(), s.error.clone())
    };

    let title = if let Some(e) = &error {
        format!("flux arbre (erreur: {})", e)
    } else {
        format!("flux arbre ({} nœuds)", app.flux_tree_view.len())
    };

    let header_row = Row::new(vec![
        Cell::from("RESSOURCE"), Cell::from("READY"), Cell::from("REVISION"),
        Cell::from("AGE"), Cell::from("MESSAGE"),
    ])
    .style(Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    // First pass: build every (indented) label so the RESSOURCE column can be sized before the rows
    // are constructed — the MESSAGE width (needed to wrap the focused row) depends on that column.
    let labels: Vec<String> = app
        .flux_tree_view
        .iter()
        .map(|row| match row {
            TreeRow::Res(n) => {
                let Some(r) = resources.get(n.idx) else { return String::new(); };
                let marker = if n.has_children {
                    if n.collapsed { "▸" } else { "▾" }
                } else {
                    " "
                };
                let mut label = format!("{}{} {} {}", "  ".repeat(n.depth), marker, r.kind, r.name);
                // Show that a Kustomization can reveal (or hide) its applied objects with +/-.
                if r.kind == "Kustomization" {
                    let expanded = app.flux_inv_expanded.contains_key(&flux_tree_uid(r));
                    label.push_str(if expanded { "  ⊟" } else { "  ⊞" });
                }
                label
            }
            TreeRow::Inv { depth, item, .. } => {
                let nsname = if item.namespace.is_empty() {
                    item.name.clone()
                } else {
                    format!("{}/{}", item.namespace, item.name)
                };
                format!("{}{} {} {}", "  ".repeat(*depth), inventory_glyph(item).0, item.kind, nsname)
            }
        })
        .collect();
    let name_w = labels
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .max("RESSOURCE".chars().count());
    let name_col = (name_w as u16).clamp(24, 80);
    let selected = app.table_state.selected();
    let msg_w = flux_msg_width(area.width, name_col + 10 + 18 + 6, 5);

    let mut emit_idx = 0usize;
    let rows: Vec<Row> = app
        .flux_tree_view
        .iter()
        .enumerate()
        .filter_map(|(vi, row)| {
            let this_idx = emit_idx;
            let label = labels[vi].clone();
            let built = match row {
                TreeRow::Res(n) => {
                    let r = resources.get(n.idx)?;
                    let (ready_txt, ready_color) = if r.suspended {
                        ("Suspended", Color::Yellow)
                    } else {
                        match r.ready {
                            FluxReady::Ready => ("Ready", Color::Green),
                            FluxReady::Reconciling => ("Reconciling", Color::Cyan),
                            FluxReady::Failed => ("Failed", Color::Red),
                            FluxReady::Unknown => ("Unknown", Color::Yellow),
                            FluxReady::NotApplicable => ("N/A", DIM),
                        }
                    };
                    let row_style = match (r.suspended, r.ready) {
                        (false, FluxReady::Failed) => Style::default().fg(Color::White).bg(Color::Rgb(40, 0, 0)),
                        (false, FluxReady::Unknown) => Style::default().fg(Color::Yellow),
                        (false, FluxReady::Reconciling) => Style::default().fg(Color::Cyan),
                        (true, _) => Style::default().fg(DIM),
                        (false, FluxReady::Ready) => Style::default(),
                        (false, FluxReady::NotApplicable) => Style::default(),
                    };
                    let msg_color = if r.ready == FluxReady::Failed && !r.suspended { Color::Red } else { DIM };
                    // The focused row expands its message so the full reason is readable inline.
                    let (msg_cell, height) = if selected == Some(this_idx) && !r.message.is_empty() {
                        flux_message_cell_wrapped(r, msg_color, msg_w)
                    } else {
                        (flux_message_cell(r, msg_color), 1)
                    };
                    Row::new(vec![
                        Cell::from(label),
                        Cell::from(ready_txt).style(Style::default().fg(ready_color).add_modifier(Modifier::BOLD)),
                        Cell::from(r.revision.clone()).style(Style::default().fg(DIM)),
                        Cell::from(r.age.clone()).style(Style::default().fg(DIM)),
                        msg_cell,
                    ])
                    .height(height)
                    .style(row_style)
                }
                TreeRow::Inv { item, .. } => {
                    let (_, color) = inventory_glyph(item);
                    let ready_txt = if item.reconciling {
                        "Reconciling"
                    } else {
                        match item.ready {
                            Some(true) => "Ready",
                            Some(false) => "NotReady",
                            None => "—",
                        }
                    };
                    Row::new(vec![
                        Cell::from(label).style(Style::default().fg(color)),
                        Cell::from(ready_txt).style(Style::default().fg(color)),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(item.msg.clone()).style(Style::default().fg(DIM)),
                    ])
                }
            };
            emit_idx += 1;
            Some(built)
        })
        .collect();

    let widths = [
        Constraint::Length(name_col), Constraint::Length(10), Constraint::Length(18),
        Constraint::Length(6), Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

// Message cell for a Flux row, prefixed with a warning badge when a Kustomization prunes (deletes)
// objects removed from git (spec.prune = true).
fn flux_message_cell(r: &FluxResource, msg_color: Color) -> Cell<'static> {
    if r.prune == Some(true) {
        Cell::from(Line::from(vec![
            Span::styled("⚠ prune ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(r.message.clone(), Style::default().fg(msg_color)),
        ]))
    } else {
        Cell::from(r.message.clone()).style(Style::default().fg(msg_color))
    }
}

// Word-wrap to `width` columns, hard-breaking tokens longer than the width (Flux failure messages
// carry long unbreakable tokens like fully-qualified CRD names).
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let mut word = word;
        // Hard-break a token that cannot fit on its own line.
        while word.chars().count() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let cut = word.char_indices().nth(width).map(|(i, _)| i).unwrap_or(word.len());
            lines.push(word[..cut].to_string());
            word = &word[cut..];
        }
        let extra = if cur.is_empty() { 0 } else { 1 };
        if cur.chars().count() + extra + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        } else {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

// Multi-line message cell for the focused row, so a failure reason is fully readable inline instead
// of being truncated at the column edge. Returns the cell and the row height it needs.
fn flux_message_cell_wrapped(r: &FluxResource, msg_color: Color, width: usize) -> (Cell<'static>, u16) {
    let prune_prefix = r.prune == Some(true);
    let prefix = if prune_prefix { "⚠ prune " } else { "" };
    let body = format!("{}{}", prefix, r.message);
    let wrapped = wrap_words(&body, width);
    let height = wrapped.len().clamp(1, 8) as u16;
    let lines: Vec<Line<'static>> = wrapped
        .into_iter()
        .take(8)
        .map(|l| Line::from(Span::styled(l, Style::default().fg(msg_color))))
        .collect();
    (Cell::from(Text::from(lines)), height)
}

// Width available for the flux MESSAGE column: inner width minus the fixed columns and the
// inter-column spacing (ratatui's default column_spacing is 1).
fn flux_msg_width(area_width: u16, fixed: u16, ncols: u16) -> usize {
    let inner = area_width.saturating_sub(2);
    inner.saturating_sub(fixed).saturating_sub(ncols.saturating_sub(1)).max(20) as usize
}

fn draw_command_popup(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let suggestions = app.command_suggestions();

    let popup_w = 56.min(area.width.saturating_sub(2)).max(20);
    let popup_h = 4 + suggestions.len().min(6) as u16;
    let popup_area = centered_rect(popup_w, popup_h, area);
    f.render_widget(Clear, popup_area);

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(":", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(app.command_input.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("▏", Style::default().fg(Color::Cyan)),
    ]));
    lines.push(Line::from(""));
    if suggestions.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (aucune commande)",
            Style::default().fg(Color::Red),
        )));
    } else {
        // Scroll the 6-row window so the highlighted suggestion stays visible.
        const WINDOW: usize = 6;
        let cursor = app.command_cursor.min(suggestions.len().saturating_sub(1));
        let offset = cursor.saturating_sub(WINDOW - 1);
        for (i, name) in suggestions.iter().enumerate().skip(offset).take(WINDOW) {
            let style = if i == cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(Span::styled(format!("  {} ", name), style)));
        }
    }

    let st = lang::t(app.ai_language);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} · Tab={} Enter={} Esc ", st.mode_command, "autocomplete", st.k_confirm));
    f.render_widget(Paragraph::new(lines).block(block), popup_area);
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

// Flatten a styled line back to its plain text (used to copy what the detail panel shows).
fn line_plain(line: &Line) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

// Plain text of the detail panel tab currently displayed, matching draw_detail's tab/node logic
// (RBAC has its own panel and is not handled here — copy is not wired for those modes).
fn detail_visible_text(app: &App) -> String {
    let is_node_mode = matches!(app.mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Nodes | Mode::NodesFull));
    let lines = if is_node_mode {
        status_lines(app)
    } else {
        match app.detail_tab {
            DetailTab::Logs => log_lines(app),
            DetailTab::Status => status_lines(app),
            DetailTab::Related => related_lines(app),
        }
    };
    lines.iter().map(line_plain).collect::<Vec<_>>().join("\n")
}

fn draw_detail(f: &mut ratatui::Frame, app: &mut App, area: ratatui::layout::Rect) {
    let is_rbac_mode = matches!(app.mode, Mode::Rbac | Mode::RbacFull)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Rbac | Mode::RbacFull))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Rbac | Mode::RbacFull));
    if is_rbac_mode {
        draw_rbac_detail(f, app, area);
        return;
    }
    let is_vuln_mode = matches!(app.mode, Mode::Vuln | Mode::VulnFull)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Vuln | Mode::VulnFull))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Vuln | Mode::VulnFull));
    if is_vuln_mode {
        draw_vuln_detail(f, app, area);
        return;
    }
    let is_secrets_mode = matches!(app.mode, Mode::Secrets | Mode::SecretsFull)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Secrets | Mode::SecretsFull))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Secrets | Mode::SecretsFull));
    if is_secrets_mode {
        draw_secrets_detail(f, app, area);
        return;
    }
    let is_configmaps_mode = matches!(app.mode, Mode::Configmaps | Mode::ConfigmapsFull)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Configmaps | Mode::ConfigmapsFull))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Configmaps | Mode::ConfigmapsFull));
    if is_configmaps_mode {
        draw_configmaps_detail(f, app, area);
        return;
    }
    let is_node_mode = matches!(app.mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage)
        || (app.mode == Mode::AiPanel && matches!(app.return_mode, Mode::Nodes | Mode::NodesFull | Mode::NodeUsage))
        || (app.mode == Mode::Command && matches!(app.command_return_mode, Mode::Nodes | Mode::NodesFull));
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

    // The Related tab is held at the top while pinned (re-evaluated each frame so it stays at the top
    // as the content streams in), until the user scrolls.
    let scroll_offset = if !is_node_mode && app.detail_tab == DetailTab::Related && app.related_pin_top {
        app.related_scroll = max_scroll;
        max_scroll
    } else {
        let target = app.scroll_target();
        if *target > max_scroll { *target = max_scroll; }
        *target
    };

    let scroll = if total > visible {
        (total - visible).saturating_sub(scroll_offset) as u16
    } else {
        0
    };

    // Wrap the Status tab (and node status) so long condition messages — typically a Flux
    // reconciliation error — are fully visible instead of being cut at the right edge. Logs and
    // Related keep horizontal scrolling. Status content is short enough that the bottom-anchored
    // scroll math stays accurate after wrapping.
    let wrap_status = is_node_mode || app.detail_tab == DetailTab::Status;
    let block = Block::default().borders(Borders::ALL).title(title);
    let p = if wrap_status {
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(block)
    } else {
        Paragraph::new(lines)
            .scroll((scroll, app.detail_h_scroll as u16))
            .block(block)
    };
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

// Dim vertical divider used to visually separate footer shortcut groups (nav · contextual · global).
fn footer_sep() -> Span<'static> {
    Span::styled("│  ", Style::default().fg(DIM))
}

// Blank columns between grid cells so neighbouring key boxes never touch.
const FOOTER_COL_GAP: usize = 2;

// Split a flat run of footer spans into one cell per shortcut. A new cell starts at every key box
// (white background); labels attach to the current cell; group separators are dropped since the
// column grid provides the visual spacing instead.
fn footer_cells(spans: Vec<Span<'static>>) -> Vec<Vec<Span<'static>>> {
    let mut cells: Vec<Vec<Span<'static>>> = Vec::new();
    for span in spans {
        if span.content.starts_with('│') {
            continue;
        }
        let is_key = span.style.bg == Some(Color::White);
        if is_key || cells.is_empty() {
            cells.push(vec![span]);
        } else {
            cells.last_mut().expect("cell present").push(span);
        }
    }
    cells
}

// Visible width of a cell, ignoring the trailing padding baked into labels.
fn cell_width(cell: &[Span<'static>]) -> usize {
    let text: String = cell.iter().map(|s| s.content.as_ref()).collect();
    text.trim_end().chars().count()
}

// Emit a row's cells, each padded to its column width plus a fixed gap. Trailing whitespace baked
// into labels is stripped first so the padding lands exactly on the column boundary.
fn render_footer_row(cells: &[Vec<Span<'static>>], widths: &[usize]) -> Vec<Span<'static>> {
    let mut out: Vec<Span<'static>> = Vec::new();
    for (j, cell) in cells.iter().enumerate() {
        let last = cell
            .iter()
            .rposition(|s| !s.content.trim_end().is_empty());
        if let Some(last) = last {
            for (idx, span) in cell.iter().enumerate() {
                if idx > last {
                    break;
                }
                if idx == last {
                    out.push(Span::styled(span.content.trim_end().to_string(), span.style));
                } else {
                    out.push(span.clone());
                }
            }
        }
        let pad = widths[j].saturating_sub(cell_width(cell)) + FOOTER_COL_GAP;
        out.push(Span::raw(" ".repeat(pad)));
    }
    out
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

// Status glyph + colour for an applied inventory object (shared by the tree rows).
fn inventory_glyph(it: &InventoryItem) -> (&'static str, Color) {
    if it.reconciling {
        ("⟳", Color::Cyan)
    } else {
        match it.ready {
            Some(true) => ("✓", Color::Green),
            Some(false) => ("✗", Color::Red),
            None => ("·", DIM),
        }
    }
}

fn flux_logs_lines(app: &App) -> Vec<Line<'static>> {
    let s = app.flux_logs_state.lock().expect("log state poisoned");
    if let Some(e) = &s.error {
        return vec![Line::from(Span::styled(e.clone(), Style::default().fg(Color::Red)))];
    }
    if s.loading && s.lines.is_empty() {
        return vec![Line::from("(loading...)")];
    }
    s.lines.iter().map(|l| colorize_log_line(l)).collect()
}

// Full-screen aggregated view of every Flux controller log (the `flux logs` view).
fn draw_flux_logs(f: &mut ratatui::Frame, app: &mut App) -> usize {
    let area = f.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!(" kdt v{} ", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  ctx={}  flux logs (tous controllers, suivi 3 s)", app.context_label)),
        ]),
        cluster_banner_line(app),
    ]);
    f.render_widget(header, layout[0]);

    let lines = flux_logs_lines(app);
    let visible = layout[1].height.saturating_sub(2) as usize;
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
        .scroll((scroll, 0))
        .block(Block::default().borders(Borders::ALL).title("flux logs"));
    f.render_widget(p, layout[1]);

    let footer = Paragraph::new(Line::from(Span::styled(
        " ↑↓ / PgUp / PgDn défil · g/G haut/bas · Esc retour ".to_string(),
        Style::default().fg(DIM),
    )));
    f.render_widget(footer, layout[2]);

    visible
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
                    format!("> {}", title),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                let display = pretty_json_for_display(body);
                for body_line in display.lines() {
                    lines.push(colorize_json_line(body_line));
                }
            }
        }
    }

    lines
}

// Re-expand a compact JSON section body to indented multi-line form for display. The stored body is
// compact (token-minimal for the AI); a trailing truncation marker or a cut object falls back to raw.
fn pretty_json_for_display(body: &str) -> String {
    let (json, suffix) = match body.split_once("\n... ") {
        Some((j, s)) => (j, Some(s)),
        None => (body, None),
    };
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => match serde_json::to_string_pretty(&v) {
            Ok(mut p) => {
                if let Some(s) = suffix {
                    p.push_str("\n... ");
                    p.push_str(s);
                }
                p
            }
            Err(_) => body.to_string(),
        },
        Err(_) => body.to_string(),
    }
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

// Horizontal scroll helper: return `s` with the first `n` characters dropped.
fn slice_from(s: &str, n: usize) -> String {
    if n == 0 { s.to_string() } else { s.chars().skip(n).collect() }
}

// Format a node's usage as a (title, body) prompt section: totals plus per-container detail,
// limited to containers with an issue and capped at 80 rows.
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

// Snapshot the last 200 log lines for inclusion in the AI prompt (or a placeholder if unavailable).
// Char budgets for the high-volume free-text prompt sections. Logs and status are kept by their
// tail (most recent/most diagnostic content) once over budget.
const MAX_LOGS_CHARS: usize = 12_000;
const MAX_STATUS_CHARS: usize = 6_000;
const MAX_RELATED_LINES: usize = 50;

// Collapse runs of identical consecutive lines into "<line>  (xN)" so repeated log/status spam does
// not eat the token budget verbatim.
fn collapse_repeats<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut run: Option<(&'a str, usize)> = None;
    let flush = |out: &mut Vec<String>, line: &str, n: usize| {
        out.push(if n > 1 { format!("{line}  (x{n})") } else { line.to_string() });
    };
    for line in lines {
        match run {
            Some((prev, n)) if prev == line => run = Some((prev, n + 1)),
            Some((prev, n)) => { flush(&mut out, prev, n); run = Some((line, 1)); }
            None => run = Some((line, 1)),
        }
    }
    if let Some((prev, n)) = run { flush(&mut out, prev, n); }
    out
}

// Keep the last `max` chars of `s` (recent content is the most diagnostic for logs/status),
// aligned to a char boundary and prefixed with an elision marker when truncated.
fn cap_chars_tail(s: String, max: usize) -> String {
    if s.len() <= max { return s; }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) { start += 1; }
    format!("... (tronqué)\n{}", &s[start..])
}

fn capture_logs_text(state: &SharedLog) -> String {
    let s = state.lock().expect("log state poisoned");
    if let Some(e) = &s.error { return format!("(indisponible: {})", e); }
    if s.loading && s.lines.is_empty() { return "(en cours de chargement)".to_string(); }
    if s.lines.is_empty() { return "(aucun log)".to_string(); }
    let n = s.lines.len();
    let start = n.saturating_sub(200);
    let collapsed = collapse_repeats(s.lines[start..].iter().map(|l| l.as_str()));
    cap_chars_tail(collapsed.join("\n"), MAX_LOGS_CHARS)
}

fn capture_status_text(state: &SharedStatus) -> String {
    let s = state.lock().expect("status state poisoned");
    if let Some(e) = &s.error { return format!("(indisponible: {})", e); }
    if s.loading && s.lines.is_empty() { return "(en cours de chargement)".to_string(); }
    if s.lines.is_empty() { return "(aucun status)".to_string(); }
    let collapsed = collapse_repeats(s.lines.iter().map(|(_, t)| t.as_str()));
    cap_chars_tail(collapsed.join("\n"), MAX_STATUS_CHARS)
}

// Aggregate buffered events for the same object into the prompt's "related events" section.
// Duplicates (same severity/reason/message) collapse into one line, summing their occurrence
// counts and keeping the most recent timestamp, then the 50 most recent lines are kept.
fn capture_related_text(buffer: &SharedBuffer, rec: &EventRecord) -> String {
    let buf = buffer.lock().expect("buffer poisoned");
    use k8s_openapi::jiff::Timestamp;
    let mut order: Vec<(Severity, String, String)> = Vec::new();
    let mut agg: std::collections::HashMap<(Severity, String, String), (Timestamp, i64)> =
        std::collections::HashMap::new();
    for r in buf.iter().filter(|r| r.namespace == rec.namespace && r.name == rec.name && r.kind == rec.kind) {
        let key = (r.severity, r.reason.clone(), r.message.clone());
        match agg.get_mut(&key) {
            Some((time, count)) => {
                *count += r.count.max(1) as i64;
                if r.time > *time { *time = r.time; }
            }
            None => {
                order.push(key.clone());
                agg.insert(key, (r.time, r.count.max(1) as i64));
            }
        }
    }
    let mut related: Vec<(Timestamp, String)> = order
        .into_iter()
        .map(|key| {
            let (time, count) = agg[&key];
            let (sev, reason, message) = key;
            let line = format!(
                "[{}] {} {} (x{}) — {}",
                time,
                match sev { Severity::Warning => "WARN", Severity::Normal => "OK" },
                reason, count, message,
            );
            (time, line)
        })
        .collect();
    related.sort_by_key(|(t, _)| *t);
    if related.len() > MAX_RELATED_LINES {
        let drop = related.len() - MAX_RELATED_LINES;
        related.drain(0..drop);
    }
    if related.is_empty() {
        "(aucun)".to_string()
    } else {
        related.into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n")
    }
}

// Assemble the full prompt sent to the model: event metadata, object status, recent logs, related
// events, and enrichment sections. This is the complete payload transmitted to the AI endpoint.
// Rough char/token ratio for dense Kubernetes JSON, and tokens held back for the system prompt,
// the model's answer, and a safety margin. Used to derive a char budget from the context window.
const CHARS_PER_TOKEN_EST: usize = 3;
const COMPLETION_RESERVE_TOKENS: usize = 4096;

// Convert a provider context window (tokens) into a char budget for the whole user prompt.
fn prompt_char_budget(context_window: Option<usize>) -> Option<usize> {
    context_window
        .map(|toks| toks.saturating_sub(COMPLETION_RESERVE_TOKENS).saturating_mul(CHARS_PER_TOKEN_EST))
}

// Assemble the enrichment sections within `budget` chars, dropping the lowest-priority ones (later
// in the list) when the budget is exhausted and noting how many were omitted. At least the first
// (highest-priority) section is always included even if it alone exceeds the budget.
fn build_extra_block(extra: &[(String, String)], budget: Option<usize>) -> String {
    if extra.is_empty() { return "(aucun)".to_string(); }
    let mut out = String::new();
    let mut omitted = 0;
    for (i, (title, body)) in extra.iter().enumerate() {
        let sep = if out.is_empty() { "" } else { "\n\n" };
        let section = format!("{sep}### {title}\n```json\n{body}\n```");
        if let Some(b) = budget {
            if !out.is_empty() && out.len() + section.len() > b {
                omitted = extra.len() - i;
                break;
            }
        }
        out.push_str(&section);
    }
    if omitted > 0 {
        out.push_str(&format!(
            "\n\n... ({omitted} section(s) contextuelle(s) omise(s) — budget de contexte atteint)"
        ));
    }
    out
}

fn build_ai_prompt(
    rec: &EventRecord,
    ctx_label: &str,
    ns_label: &str,
    logs: &str,
    status: &str,
    related: &str,
    extra: &[(String, String)],
    char_budget: Option<usize>,
) -> String {
    // Two-pass: render the skeleton with a placeholder for the enrichment block, measure the fixed
    // part, then fill the block with whatever fits in the remaining budget.
    const PLACEHOLDER: &str = "\u{0}";
    let skeleton = build_ai_prompt_inner(rec, ctx_label, ns_label, logs, status, related, PLACEHOLDER);
    let fixed_len = skeleton.len() - PLACEHOLDER.len();
    let extra_budget = char_budget.map(|b| b.saturating_sub(fixed_len));
    let extra_block = build_extra_block(extra, extra_budget);
    skeleton.replace(PLACEHOLDER, &extra_block)
}

fn build_ai_prompt_inner(
    rec: &EventRecord,
    ctx_label: &str,
    ns_label: &str,
    logs: &str,
    status: &str,
    related: &str,
    extra_block: &str,
) -> String {
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
