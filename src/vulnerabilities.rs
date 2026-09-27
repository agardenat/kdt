//! Vulnerability view: lists the cluster's scanned images (their CVEs and CVSS scores, read from
//! Trivy Operator's `VulnerabilityReport` CRDs) plus the risk on the Kubernetes version itself
//! (CVEs from the official k8s feed + the latest patch of the running minor as upgrade target).
//!
//! The whole view is gated on Trivy Operator being installed: without the CRD there is no per-image
//! CVE data, so `:vuln` refuses to open (see `probe_trivy`). Reads follow the same Shared-state +
//! dynamic-discovery pattern as `flux.rs`/`rbac.rs`. The k8s part needs outbound network and degrades
//! gracefully (the image list still shows) when egress is blocked.

use std::sync::{Arc, Mutex};

use kube::api::{Api, DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::Value;

use crate::events::{format_age, EventRecord, LineColor, Severity};
use crate::lang::{fill, Strings};

const TRIVY_GROUP: &str = "aquasecurity.github.io";
const TRIVY_VERSIONS: &[&str] = &["v1alpha1"];
const TRIVY_KIND: &str = "VulnerabilityReport";
const TRIVY_CLUSTER_KIND: &str = "ClusterVulnerabilityReport";

// Official, auto-refreshing Kubernetes CVE feed (JSON Feed) and the patch-version endpoints.
const K8S_CVE_FEED: &str =
    "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json";
const K8S_STABLE: &str = "https://dl.k8s.io/release/stable.txt";
// Most recent feed CVEs surfaced (the feed is not filtered by version, so we cap to the newest).
const K8S_CVE_MAX: usize = 60;

// `Serialize` en minuscules : kdt-web peint la colonne SEV avec la même échelle, nommée pareil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Sev {
    pub fn label(self) -> &'static str {
        match self {
            Sev::Unknown => "UNKNOWN",
            Sev::Low => "LOW",
            Sev::Medium => "MED",
            Sev::High => "HIGH",
            Sev::Critical => "CRIT",
        }
    }

    /// Le liseré d'une ligne : seules CRITICAL et HIGH sont un écart. Une image aux seules CVE
    /// moyennes ou basses est la norme d'un cluster, et la peindre ferait rougir toute la table.
    pub fn tone(self) -> LineColor {
        match self {
            Sev::Critical => LineColor::Err,
            Sev::High => LineColor::Warn,
            _ => LineColor::Ok,
        }
    }

    fn parse(s: &str) -> Sev {
        match s.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Sev::Critical,
            "HIGH" => Sev::High,
            "MEDIUM" => Sev::Medium,
            "LOW" => Sev::Low,
            _ => Sev::Unknown,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Cve {
    pub id: String,
    pub severity: Sev,
    pub score: f64,
    // For an image CVE: the affected package + the installed/fixed versions. For a k8s CVE these are
    // empty and `title` carries the feed summary.
    pub package: String,
    pub installed: String,
    pub fixed: String,
    pub title: String,
    pub url: String,
}

impl Cve {
    fn sort_key(&self) -> (std::cmp::Reverse<u8>, std::cmp::Reverse<i64>) {
        (
            std::cmp::Reverse(self.severity as u8),
            std::cmp::Reverse((self.score * 100.0) as i64),
        )
    }
}

// One scanned image (a VulnerabilityReport), aggregated to its counts and CVE list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnComponent {
    // Le rapport Trivy d'où vient la ligne : kdt-web relit ce seul objet pour le détail d'une image
    // au lieu de faire voyager toutes les CVE de toutes les images à chaque passe.
    pub report_kind: String,
    pub report: String,
    pub namespace: String,
    pub workload: String,
    pub image: String,
    pub version: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub max_sev: Sev,
    pub max_score: f64,
    // Number of CVEs that have a known fixed version (i.e. an upgrade actually fixes them).
    pub fixable: usize,
    pub cves: Vec<Cve>,
    pub age: String,
}

impl VulnComponent {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unknown
    }

    /// La colonne `→ TARGET` d'une image : combien de CVE une mise à jour corrige.
    pub fn target_label(&self, st: &Strings) -> String {
        if self.fixable > 0 {
            fill(st.vuln_fixables_cell, &[("n", &self.fixable.to_string())])
        } else {
            "—".to_string()
        }
    }

    fn sort_key(&self) -> (std::cmp::Reverse<u8>, std::cmp::Reverse<i64>, String, String) {
        (
            std::cmp::Reverse(self.max_sev as u8),
            std::cmp::Reverse((self.max_score * 100.0) as i64),
            self.namespace.clone(),
            self.image.clone(),
        )
    }
}

// Risk on the Kubernetes control-plane version itself.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct K8sVersionRisk {
    pub server_version: String,
    // Latest patch of the running minor (the recommended upgrade target), when resolvable.
    pub latest_patch: Option<String>,
    // True when the server runs an older patch than `latest_patch`.
    pub behind: bool,
    // True when the running minor is no longer in the supported window (latest 3 minors).
    pub eol: bool,
    pub cves: Vec<Cve>,
    // Human note when the network part could not be fetched.
    pub note: Option<String>,
}

impl K8sVersionRisk {
    /// `(crit, high, med, low)` parmi les CVE du feed.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            sev_count(&self.cves, Sev::Critical),
            sev_count(&self.cves, Sev::High),
            sev_count(&self.cves, Sev::Medium),
            sev_count(&self.cves, Sev::Low),
        )
    }

    /// La colonne COMPONENT : une version hors fenêtre de support le dit dans le nom même.
    pub fn component_label(&self) -> &'static str {
        if self.eol { "kubernetes (EOL)" } else { "kubernetes" }
    }

    /// La colonne `→ TARGET` : `→` quand il y a un patch à monter, `✓` quand on est dessus.
    pub fn target_label(&self) -> String {
        match (&self.latest_patch, self.behind) {
            (Some(v), true) => format!("→ {v}"),
            (Some(v), false) => format!("✓ {v}"),
            (None, _) => "?".to_string(),
        }
    }

    /// La cible de patch rédigée, telle que le panneau de détail la dit.
    pub fn target_text(&self, st: &Strings) -> String {
        match (&self.latest_patch, self.behind) {
            (Some(v), true) => fill(st.vuln_upgrade_to, &[("version", v)]),
            (Some(v), false) => fill(st.vuln_up_to_date, &[("version", v)]),
            (None, _) => st.vuln_target_unresolved.to_string(),
        }
    }

    /// Rouge dès qu'il y a un retard de patch ou une version hors support ; vert sinon. Une cible
    /// non résolue n'est pas un « à jour » : sans réseau, on ne sait pas.
    pub fn target_tone(&self) -> LineColor {
        if self.eol || self.behind {
            LineColor::Err
        } else if self.latest_patch.is_some() {
            LineColor::Ok
        } else {
            LineColor::Dim
        }
    }

    /// Le liseré de la ligne : l'écart est le retard ou la sortie de support, pas le fait d'avoir
    /// des CVE — le feed n'est pas filtré par version, il en a toujours.
    pub fn tone(&self) -> LineColor {
        if self.eol || self.behind { LineColor::Err } else { LineColor::Ok }
    }
}

#[derive(Debug, Clone, Default)]
pub struct VulnState {
    pub components: Vec<VulnComponent>,
    pub k8s: Option<K8sVersionRisk>,
    pub error: Option<String>,
    pub loading: bool,
    // Whether Trivy Operator's CRD was found on the last fetch.
    pub available: bool,
}

impl VulnState {
    // (critical, high, medium, low) summed across all components.
    // Totals for the title. `ns` restricts them to one namespace, so the header cannot claim the
    // cluster's CVE count over a list scoped to a single namespace.
    pub fn counts(&self, ns: Option<&str>) -> (usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0);
        for comp in self.components.iter().filter(|x| ns.is_none_or(|n| x.namespace == n)) {
            c.0 += comp.critical;
            c.1 += comp.high;
            c.2 += comp.medium;
            c.3 += comp.low;
        }
        c
    }

    // How many scanned images the scope holds — the `total` the title shows.
    pub fn scanned(&self, ns: Option<&str>) -> usize {
        self.components.iter().filter(|x| ns.is_none_or(|n| x.namespace == n)).count()
    }
}

pub type SharedVuln = Arc<Mutex<VulnState>>;

pub fn new_vuln_state() -> SharedVuln {
    Arc::new(Mutex::new(VulnState::default()))
}

pub async fn fetch_vulnerabilities(client: Client, server_version: Option<String>, state: SharedVuln) {
    {
        let mut s = state.lock().expect("vuln poisoned");
        s.loading = true;
        s.error = None;
    }

    let fresh = vulnerabilities_inventory(&client, server_version, crate::lang::active()).await;

    // Une lecture refusée garde la liste précédente (le TUI la laisse à l'écran avec l'erreur au
    // titre) ; Trivy absent la vide, il n'y a plus rien à montrer.
    let replace = fresh.error.is_none() || !fresh.available;
    let mut s = state.lock().expect("vuln poisoned");
    s.loading = false;
    s.k8s = fresh.k8s;
    s.available = fresh.available;
    s.error = fresh.error;
    if replace {
        s.components = fresh.components;
    }
}

/// Les images scannées et le risque de la version Kubernetes, rendus au lieu d'être déposés.
///
/// Même lecture que `fetch_vulnerabilities`, qui n'est plus que la pose dans le `Mutex` : kdt-web
/// répond à une requête et veut la valeur. La table de chaînes est un paramètre parce qu'un serveur
/// répond à plusieurs personnes qui ne lisent pas forcément la même langue.
pub async fn vulnerabilities_inventory(
    client: &Client,
    server_version: Option<String>,
    st: &'static Strings,
) -> VulnState {
    let k8s = match server_version {
        Some(v) if !v.is_empty() => Some(k8s_version_risk(&v, st).await),
        _ => None,
    };
    let mut out = VulnState { k8s, ..Default::default() };
    match fetch_trivy_reports(client).await {
        Ok(components) => {
            out.available = true;
            out.components = components;
        }
        Err(TrivyError::NotInstalled) => {
            out.available = false;
            out.error = Some(st.vuln_no_trivy.into());
        }
        Err(TrivyError::Api(e)) => {
            out.available = true;
            out.error = Some(e);
        }
    }
    out
}

/// Une ligne de la vue : le risque du control plane (toujours en tête quand il est connu) ou une
/// image scannée.
#[derive(Debug, Clone)]
pub enum VulnRow {
    K8s(K8sVersionRisk),
    Image(VulnComponent),
}

/// Les lignes de la vue, dans l'ordre du TUI : Kubernetes d'abord, puis les images de la portée qui
/// passent le plancher de sévérité (déjà triées de la plus grave à la moins grave).
///
/// La portée cache les images des autres namespaces ; la ligne Kubernetes parle du cluster lui-même
/// et reste quelle que soit la portée. La recherche, elle, reste à l'appelant.
pub fn vuln_rows(state: &VulnState, ns: Option<&str>, min: Sev) -> Vec<VulnRow> {
    let mut rows: Vec<VulnRow> = Vec::new();
    if let Some(k8s) = &state.k8s {
        rows.push(VulnRow::K8s(k8s.clone()));
    }
    rows.extend(
        state
            .components
            .iter()
            .filter(|c| ns.is_none_or(|n| c.namespace == n))
            .filter(|c| c.max_sev >= min)
            .cloned()
            .map(VulnRow::Image),
    );
    rows
}

impl VulnRow {
    /// L'enregistrement que le panneau IA reçoit : les CVE de l'image (ou le risque de la version),
    /// pour que le modèle en résume l'impact et le chemin de mise à jour.
    pub fn record(&self, st: &Strings) -> EventRecord {
        match self {
            VulnRow::Image(c) => {
                let cve_lines = c
                    .cves
                    .iter()
                    .take(40)
                    .map(|v| {
                        let fix = if v.fixed.is_empty() {
                            st.vuln_no_fix.to_string()
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
                EventRecord {
                    uid: format!("vuln|{}|{}", c.namespace, c.image),
                    time: k8s_openapi::jiff::Timestamp::now(),
                    severity: severity_of(c.max_sev.tone()),
                    reason: format!("VULN/{}", c.max_sev.label()),
                    api_version: format!("{TRIVY_GROUP}/{}", TRIVY_VERSIONS[0]),
                    kind: TRIVY_KIND.to_string(),
                    namespace: c.namespace.clone(),
                    name: c.image.clone(),
                    message,
                    component: String::new(),
                    host: String::new(),
                    count: 1,
                }
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
                let message = fill(
                    st.rec_k8s_cve,
                    &[
                        ("version", &k.server_version),
                        ("target", &target),
                        ("behind", &k.behind.to_string()),
                        ("eol", &k.eol.to_string()),
                        ("cves", &cve_lines),
                    ],
                );
                EventRecord {
                    uid: format!("vuln|k8s|{}", k.server_version),
                    time: k8s_openapi::jiff::Timestamp::now(),
                    severity: severity_of(k.tone()),
                    reason: "VULN/k8s".to_string(),
                    api_version: String::new(),
                    kind: "KubernetesVersion".to_string(),
                    namespace: String::new(),
                    name: k.server_version.clone(),
                    message,
                    component: String::new(),
                    host: String::new(),
                    count: 1,
                }
            }
        }
    }
}

/// Un enregistrement n'est un avertissement que si la ligne est un écart : une image aux seules CVE
/// basses est la norme, et le panneau ne doit pas la dire `WARN`.
fn severity_of(tone: LineColor) -> Severity {
    if tone == LineColor::Ok { Severity::Normal } else { Severity::Warning }
}

/// Garde lisible la fin du chemin d'image quand le préfixe du registre est long.
pub fn short_image(image: &str) -> String {
    let trimmed = image
        .strip_prefix("index.docker.io/library/")
        .or_else(|| image.strip_prefix("index.docker.io/"))
        .or_else(|| image.strip_prefix("docker.io/library/"))
        .or_else(|| image.strip_prefix("docker.io/"))
        .unwrap_or(image);
    trimmed.to_string()
}

enum TrivyError {
    NotInstalled,
    Api(String),
}

async fn fetch_trivy_reports(client: &Client) -> Result<Vec<VulnComponent>, TrivyError> {
    let mut resolved = None;
    for v in TRIVY_VERSIONS {
        let gvk = GroupVersionKind::gvk(TRIVY_GROUP, v, TRIVY_KIND);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            resolved = Some(ar);
            break;
        }
    }
    let Some(ar) = resolved else {
        return Err(TrivyError::NotInstalled);
    };

    let mut components: Vec<VulnComponent> = Vec::new();

    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    match api.list(&ListParams::default()).await {
        Ok(list) => {
            for obj in &list.items {
                if let Some(c) = parse_report(obj, TRIVY_KIND) {
                    components.push(c);
                }
            }
        }
        Err(e) => return Err(TrivyError::Api(e.to_string())),
    }

    // Cluster-scoped reports (e.g. node-component images) when the CRD exists.
    for v in TRIVY_VERSIONS {
        let gvk = GroupVersionKind::gvk(TRIVY_GROUP, v, TRIVY_CLUSTER_KIND);
        if let Ok((car, _caps)) = discovery::pinned_kind(client, &gvk).await {
            let capi: Api<DynamicObject> = Api::all_with(client.clone(), &car);
            if let Ok(list) = capi.list(&ListParams::default()).await {
                for obj in &list.items {
                    if let Some(c) = parse_report(obj, TRIVY_CLUSTER_KIND) {
                        components.push(c);
                    }
                }
            }
            break;
        }
    }

    components.sort_by_key(|a| a.sort_key());
    Ok(components)
}

/// Un seul rapport, relu par son nom : le détail d'une image, CVE comprises.
///
/// `kind` est celui que la ligne a porté (`VulnerabilityReport` ou `ClusterVulnerabilityReport`) ;
/// un autre est refusé plutôt que de laisser l'appelant viser un kind arbitraire.
pub async fn vuln_report(
    client: &Client,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<VulnComponent, String> {
    if kind != TRIVY_KIND && kind != TRIVY_CLUSTER_KIND {
        return Err(format!("kind inattendu : {kind}"));
    }
    let mut resolved = None;
    for v in TRIVY_VERSIONS {
        let gvk = GroupVersionKind::gvk(TRIVY_GROUP, v, kind);
        if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
            resolved = Some(ar);
            break;
        }
    }
    let ar = resolved.ok_or_else(|| format!("{kind} introuvable"))?;
    let api: Api<DynamicObject> = if kind == TRIVY_CLUSTER_KIND || namespace.is_empty() {
        Api::all_with(client.clone(), &ar)
    } else {
        Api::namespaced_with(client.clone(), namespace, &ar)
    };
    let obj = api.get(name).await.map_err(|e| e.to_string())?;
    parse_report(&obj, kind).ok_or_else(|| format!("{kind} {name} : pas de rapport"))
}

fn parse_report(obj: &DynamicObject, kind: &str) -> Option<VulnComponent> {
    let labels = obj.metadata.labels.clone().unwrap_or_default();
    let report = obj.data.get("report")?;

    let artifact = report.get("artifact");
    let repository = artifact
        .and_then(|a| a.get("repository"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let registry = report
        .get("registry")
        .and_then(|r| r.get("server"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tag = artifact
        .and_then(|a| a.get("tag"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let image = if registry.is_empty() {
        repository.to_string()
    } else {
        format!("{registry}/{repository}")
    };

    // Workload + container come from the labels Trivy stamps on every report.
    let res_kind = labels
        .get("trivy-operator.aquasecurity.github.io/resource.kind")
        .cloned()
        .unwrap_or_default();
    let res_name = labels
        .get("trivy-operator.aquasecurity.github.io/resource.name")
        .cloned()
        .unwrap_or_default();
    let container = labels
        .get("trivy-operator.aquasecurity.github.io/container.name")
        .cloned()
        .unwrap_or_default();
    let workload = match (res_kind.is_empty(), res_name.is_empty()) {
        (false, false) if !container.is_empty() => format!("{res_kind}/{res_name}:{container}"),
        (false, false) => format!("{res_kind}/{res_name}"),
        _ => obj.metadata.name.clone().unwrap_or_default(),
    };

    let mut cves: Vec<Cve> = Vec::new();
    if let Some(arr) = report.get("vulnerabilities").and_then(|v| v.as_array()) {
        for v in arr {
            cves.push(parse_image_cve(v));
        }
    }
    cves.sort_by_key(|a| a.sort_key());

    let mut comp = VulnComponent {
        report_kind: kind.to_string(),
        report: obj.metadata.name.clone().unwrap_or_default(),
        namespace: obj.metadata.namespace.clone().unwrap_or_default(),
        workload,
        image,
        version: tag.to_string(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        max_sev: Sev::Unknown,
        max_score: 0.0,
        fixable: 0,
        cves,
        age: obj
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| format_age(&t.0))
            .unwrap_or_default(),
    };

    // Prefer the report's own summary counts when present; otherwise derive from the CVE list.
    let summary = report.get("summary");
    let count = |key: &str| {
        summary
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
    };
    comp.critical = count("criticalCount").unwrap_or_else(|| sev_count(&comp.cves, Sev::Critical));
    comp.high = count("highCount").unwrap_or_else(|| sev_count(&comp.cves, Sev::High));
    comp.medium = count("mediumCount").unwrap_or_else(|| sev_count(&comp.cves, Sev::Medium));
    comp.low = count("lowCount").unwrap_or_else(|| sev_count(&comp.cves, Sev::Low));
    comp.unknown = count("unknownCount").unwrap_or_else(|| sev_count(&comp.cves, Sev::Unknown));

    comp.max_sev = comp.cves.iter().map(|c| c.severity).max().unwrap_or(Sev::Unknown);
    comp.max_score = comp.cves.iter().map(|c| c.score).fold(0.0_f64, f64::max);
    comp.fixable = comp.cves.iter().filter(|c| !c.fixed.is_empty()).count();

    Some(comp)
}

fn sev_count(cves: &[Cve], sev: Sev) -> usize {
    cves.iter().filter(|c| c.severity == sev).count()
}

fn parse_image_cve(v: &Value) -> Cve {
    let str_at = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Cve {
        id: str_at("vulnerabilityID"),
        severity: Sev::parse(&str_at("severity")),
        score: v.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0),
        package: str_at("resource"),
        installed: str_at("installedVersion"),
        fixed: str_at("fixedVersion"),
        title: str_at("title"),
        url: str_at("primaryLink"),
    }
}

// --- Kubernetes version risk ------------------------------------------------------------------

/// Le risque de la version Kubernetes : cible de patch, fenêtre de support, CVE du feed officiel.
///
/// Public parce que la réponse ne dépend que de la version et de sources publiques : kdt-web la
/// garde en cache pour tout le monde, là où l'inventaire Trivy, lui, se relit sous chaque identité.
pub async fn k8s_version_risk(server_version: &str, st: &'static Strings) -> K8sVersionRisk {
    let mut risk = K8sVersionRisk {
        server_version: server_version.to_string(),
        ..Default::default()
    };

    let Some((minor, patch)) = parse_minor_patch(server_version) else {
        risk.note = Some(st.vuln_bad_server_version.into());
        return risk;
    };

    // Upgrade target: latest patch of the running minor.
    match http_text(&format!("https://dl.k8s.io/release/stable-1.{minor}.txt")).await {
        Some(latest) => {
            let latest = latest.trim().to_string();
            if let Some((_, lp)) = parse_minor_patch(&latest) {
                risk.behind = patch < lp;
            }
            risk.latest_patch = Some(latest);
        }
        None => risk.note = Some(st.vuln_network_down.into()),
    }

    // Support window: EOL when more than the latest 3 minors behind current stable.
    if let Some(stable) = http_text(K8S_STABLE).await {
        if let Some((stable_minor, _)) = parse_minor_patch(stable.trim()) {
            risk.eol = stable_minor > minor + 2;
        }
    }

    match http_json(K8S_CVE_FEED).await {
        Some(feed) => risk.cves = parse_k8s_feed(&feed),
        None => {
            let n = st.vuln_feed_down.to_string();
            risk.note = Some(match risk.note.take() {
                Some(prev) => format!("{prev} · {n}"),
                None => n,
            });
        }
    }

    risk
}

// Extracts (minor, patch) from a git version like "v1.29.4", "v1.29.4+abc", "v1.29.4-gke.1".
fn parse_minor_patch(v: &str) -> Option<(u32, u32)> {
    let v = v.trim().trim_start_matches('v');
    let mut it = v.split('.');
    let _major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next()?.parse().ok()?;
    let patch_raw = it.next()?;
    let patch_digits: String = patch_raw.chars().take_while(|c| c.is_ascii_digit()).collect();
    let patch: u32 = patch_digits.parse().ok()?;
    Some((minor, patch))
}

fn parse_k8s_feed(feed: &Value) -> Vec<Cve> {
    let Some(items) = feed.get("items").and_then(|i| i.as_array()) else {
        return Vec::new();
    };
    let mut cves: Vec<(String, Cve)> = Vec::new();
    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if !id.starts_with("CVE") {
            continue;
        }
        let content = item.get("content_text").and_then(|v| v.as_str()).unwrap_or("");
        let (severity, score) = parse_cvss(content);
        let url = item
            .get("external_url")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| item.get("url").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let date = item
            .get("date_published")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        cves.push((
            date,
            Cve {
                id: id.to_string(),
                severity,
                score,
                package: String::new(),
                installed: String::new(),
                fixed: String::new(),
                title: item
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                url,
            },
        ));
    }
    // Newest first; the feed is not version-scoped so we only surface the most recent ones.
    cves.sort_by(|a, b| b.0.cmp(&a.0));
    cves.into_iter().take(K8S_CVE_MAX).map(|(_, c)| c).collect()
}

// The feed encodes the rating as e.g. "… — **Medium (6.5)**" at the top of content_text.
fn parse_cvss(content: &str) -> (Sev, f64) {
    let head = &content[..content.len().min(400)];
    for (kw, sev) in [
        ("Critical (", Sev::Critical),
        ("High (", Sev::High),
        ("Medium (", Sev::Medium),
        ("Low (", Sev::Low),
    ] {
        if let Some(p) = head.find(kw) {
            let rest = &head[p + kw.len()..];
            if let Some(end) = rest.find(')') {
                if let Ok(score) = rest[..end].trim().parse::<f64>() {
                    return (sev, score);
                }
            }
        }
    }
    (Sev::Unknown, 0.0)
}

// Bounded end to end: these fetches run in a background task whose only failure mode the UI knows
// is "no answer", so a feed that hangs must resolve to None rather than pin the task forever.
fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()
}

async fn http_text(url: &str) -> Option<String> {
    let resp = http_client()?.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

async fn http_json(url: &str) -> Option<Value> {
    let resp = http_client()?.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minor_patch_variants() {
        assert_eq!(parse_minor_patch("v1.29.4"), Some((29, 4)));
        assert_eq!(parse_minor_patch("v1.29.15+k3s1"), Some((29, 15)));
        assert_eq!(parse_minor_patch("1.30.0-gke.100"), Some((30, 0)));
        assert_eq!(parse_minor_patch("garbage"), None);
    }

    #[test]
    fn cvss_rating_parsed() {
        let c = "**CVSS Rating:**  \n[CVSS:3.1/...](https://x) — **Medium (6.5)**\n\nA vuln...";
        assert_eq!(parse_cvss(c), (Sev::Medium, 6.5));
    }

    #[test]
    fn cvss_missing_is_unknown() {
        assert_eq!(parse_cvss("no rating here"), (Sev::Unknown, 0.0));
    }

    fn report(name: &str, ns: &str, vulns: serde_json::Value) -> DynamicObject {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "VulnerabilityReport",
            "metadata": {
                "name": name,
                "namespace": ns,
                "labels": {
                    "trivy-operator.aquasecurity.github.io/resource.kind": "ReplicaSet",
                    "trivy-operator.aquasecurity.github.io/resource.name": "api-7d9f",
                    "trivy-operator.aquasecurity.github.io/container.name": "api",
                },
            },
            "report": {
                "artifact": { "repository": "library/nginx", "tag": "1.25.3" },
                "registry": { "server": "index.docker.io" },
                "vulnerabilities": vulns,
            },
        }))
        .unwrap()
    }

    #[test]
    fn report_parsed_with_its_name_and_counts_derived() {
        let obj = report(
            "replicaset-api-7d9f-api",
            "shop",
            serde_json::json!([
                { "vulnerabilityID": "CVE-2024-1", "severity": "HIGH", "score": 7.5,
                  "resource": "openssl", "installedVersion": "3.0.1", "fixedVersion": "3.0.13" },
                { "vulnerabilityID": "CVE-2024-2", "severity": "CRITICAL", "score": 9.8,
                  "resource": "zlib", "installedVersion": "1.2", "fixedVersion": "" },
                { "vulnerabilityID": "CVE-2024-3", "severity": "LOW", "resource": "bash" },
            ]),
        );
        let c = parse_report(&obj, TRIVY_KIND).unwrap();
        assert_eq!(c.report, "replicaset-api-7d9f-api");
        assert_eq!(c.report_kind, TRIVY_KIND);
        assert_eq!(c.workload, "ReplicaSet/api-7d9f:api");
        assert_eq!(c.image, "index.docker.io/library/nginx");
        assert_eq!(short_image(&c.image), "nginx");
        assert_eq!((c.critical, c.high, c.medium, c.low), (1, 1, 0, 1));
        assert_eq!(c.max_sev, Sev::Critical);
        assert_eq!(c.fixable, 1);
        // Trié du plus grave au moins grave.
        assert_eq!(c.cves[0].id, "CVE-2024-2");
        assert_eq!(c.max_sev.tone(), LineColor::Err);
    }

    #[test]
    fn rows_keep_k8s_first_whatever_the_scope_and_floor() {
        let a = parse_report(
            &report("a", "shop", serde_json::json!([{ "vulnerabilityID": "C1", "severity": "MEDIUM" }])),
            TRIVY_KIND,
        )
        .unwrap();
        let b = parse_report(
            &report("b", "infra", serde_json::json!([{ "vulnerabilityID": "C2", "severity": "CRITICAL" }])),
            TRIVY_KIND,
        )
        .unwrap();
        let state = VulnState {
            components: vec![b, a],
            k8s: Some(K8sVersionRisk { server_version: "v1.30.1".into(), ..Default::default() }),
            available: true,
            ..Default::default()
        };
        let rows = vuln_rows(&state, Some("shop"), Sev::Unknown);
        assert!(matches!(&rows[0], VulnRow::K8s(_)));
        assert!(matches!(&rows[1], VulnRow::Image(c) if c.namespace == "shop"));
        assert_eq!(rows.len(), 2);
        let rows = vuln_rows(&state, None, Sev::High);
        assert_eq!(rows.len(), 2);
        assert!(matches!(&rows[1], VulnRow::Image(c) if c.namespace == "infra"));
    }

    #[test]
    fn k8s_target_says_unknown_without_network() {
        let k = K8sVersionRisk { server_version: "v1.30.1".into(), ..Default::default() };
        assert_eq!(k.target_label(), "?");
        assert_eq!(k.target_tone(), LineColor::Dim);
        assert_eq!(k.tone(), LineColor::Ok);
        let behind = K8sVersionRisk { latest_patch: Some("v1.30.9".into()), behind: true, ..k };
        assert_eq!(behind.target_label(), "→ v1.30.9");
        assert_eq!(behind.tone(), LineColor::Err);
        assert_eq!(behind.target_text(&crate::lang::EN), "→ upgrade to v1.30.9");
    }
}
