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

use crate::events::format_age;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sev {
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

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct VulnComponent {
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
#[derive(Debug, Clone, Default)]
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
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0);
        for comp in &self.components {
            c.0 += comp.critical;
            c.1 += comp.high;
            c.2 += comp.medium;
            c.3 += comp.low;
        }
        c
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

    let trivy = fetch_trivy_reports(&client).await;
    let k8s = match server_version {
        Some(v) if !v.is_empty() => Some(fetch_k8s_cve(&v).await),
        _ => None,
    };

    let mut s = state.lock().expect("vuln poisoned");
    s.loading = false;
    s.k8s = k8s;
    match trivy {
        Ok(components) => {
            s.available = true;
            s.components = components;
            s.error = None;
        }
        Err(TrivyError::NotInstalled) => {
            s.available = false;
            s.components.clear();
            s.error = Some("Trivy Operator non installé (VulnerabilityReport introuvable)".into());
        }
        Err(TrivyError::Api(e)) => {
            s.available = true;
            s.error = Some(e);
        }
    }
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
                if let Some(c) = parse_report(obj) {
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
                    if let Some(c) = parse_report(obj) {
                        components.push(c);
                    }
                }
            }
            break;
        }
    }

    components.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Ok(components)
}

fn parse_report(obj: &DynamicObject) -> Option<VulnComponent> {
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
    cves.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut comp = VulnComponent {
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

async fn fetch_k8s_cve(server_version: &str) -> K8sVersionRisk {
    let mut risk = K8sVersionRisk {
        server_version: server_version.to_string(),
        ..Default::default()
    };

    let Some((minor, patch)) = parse_minor_patch(server_version) else {
        risk.note = Some("version serveur non interprétable".into());
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
        None => risk.note = Some("réseau indisponible (cible de patch non résolue)".into()),
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
            let n = "feed CVE k8s indisponible (réseau)".to_string();
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

async fn http_text(url: &str) -> Option<String> {
    let resp = reqwest::get(url).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

async fn http_json(url: &str) -> Option<Value> {
    let resp = reqwest::get(url).await.ok()?;
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
}
