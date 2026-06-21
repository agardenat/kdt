//! Gathers extra context related to a Kubernetes event (RBAC, policies, storage, GitOps tools…)
//! to enrich the AI prompt. Each `*_context` helper is best-effort: failures are swallowed so a
//! missing CRD or RBAC denial never breaks enrichment.
//!
//! Security note: the JSON returned here is forwarded to the external AI endpoint. `strip_noise`
//! only removes bookkeeping fields (managedFields, uid…), not application data.

use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim, ServiceAccount};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding, Subject};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{DynamicObject, ListParams};
use kube::core::GroupVersionKind;
use kube::discovery::{self, Scope};
use kube::{Api, Client};

use crate::events::EventRecord;

const MAX_SECTION_CHARS: usize = 8000;
const MAX_BINDINGS: usize = 5;

// Recursively drop high-volume / non-informative metadata so the JSON stays compact in the prompt.
fn strip_noise(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            map.remove("managedFields");
            map.remove("resourceVersion");
            map.remove("uid");
            map.remove("generation");
            map.remove("selfLink");
            map.remove("creationTimestamp");
            if let Some(serde_json::Value::Object(ann)) = map.get_mut("annotations") {
                ann.remove("kubectl.kubernetes.io/last-applied-configuration");
            }
            if map
                .get("annotations")
                .map(|a| a.as_object().map(|o| o.is_empty()).unwrap_or(false))
                .unwrap_or(false)
            {
                map.remove("annotations");
            }
            for child in map.values_mut() {
                strip_noise(child);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr.iter_mut() {
                strip_noise(child);
            }
        }
        _ => {}
    }
}

fn clean_json<T: serde::Serialize>(v: &T) -> Result<String, serde_json::Error> {
    let mut val = serde_json::to_value(v)?;
    strip_noise(&mut val);
    // Compact on purpose: this body is fed verbatim to the AI prompt, so we minimise tokens (no
    // whitespace). The Related view re-expands it for display only (see `pretty_json_for_display`).
    serde_json::to_string(&val)
}

pub async fn gather_extra_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    gather_extra_context_with_progress(client, rec, |_, _| {}).await
}

// Run every context probe in sequence, reporting progress via the callback, and cap each section
// to MAX_SECTION_CHARS. Returns a list of (title, body) sections appended to the AI prompt.
pub async fn gather_extra_context_with_progress<F>(
    client: &Client,
    rec: &EventRecord,
    progress: F,
) -> Vec<(String, String)>
where
    F: Fn(&str, usize),
{
    let mut sections = Vec::new();

    progress("Recherche de policies Kyverno...", sections.len());
    sections.extend(kyverno_context(client, rec).await);

    progress("Analyse des liaisons RBAC (RoleBindings, ClusterRoleBindings)...", sections.len());
    sections.extend(rbac_context(client, rec).await);

    progress("Recherche d'objets cert-manager (Certificate, Issuer)...", sections.len());
    sections.extend(cert_manager_context(client, rec).await);

    progress("Recherche d'objets Velero (Backup, BackupStorageLocation)...", sections.len());
    sections.extend(velero_context(client, rec).await);

    progress("Recherche de l'Ingress et de l'IngressClass...", sections.len());
    sections.extend(ingress_context(client, rec).await);

    progress("Recherche d'objets Rancher (cattle.io)...", sections.len());
    sections.extend(rancher_context(client, rec).await);

    progress("Recherche d'objets Datadog (DatadogAgent)...", sections.len());
    sections.extend(datadog_context(client, rec).await);

    progress("Recherche du stockage (PVC, PV, StorageClass)...", sections.len());
    sections.extend(storage_context(client, rec).await);

    progress("Recherche d'objets Argo CD (Application, AppProject)...", sections.len());
    sections.extend(argocd_context(client, rec).await);

    progress("Recherche d'objets Flux CD (Kustomization, HelmRelease, sources)...", sections.len());
    sections.extend(fluxcd_context(client, rec).await);

    progress("Application des hints outils...", sections.len());
    sections.extend(tool_hints(rec));

    for s in sections.iter_mut() {
        if s.1.len() > MAX_SECTION_CHARS {
            s.1.truncate(MAX_SECTION_CHARS);
            s.1.push_str("\n... (tronqué)");
        }
    }
    sections
}

#[derive(Default, Debug, Clone)]
pub struct RelatedState {
    pub current_key: Option<String>,
    pub sections: Vec<(String, String)>,
    pub loading: bool,
    pub error: Option<String>,
}

pub type SharedRelated = Arc<Mutex<RelatedState>>;

pub fn new_related_state() -> SharedRelated {
    Arc::new(Mutex::new(RelatedState::default()))
}

pub async fn fetch_related(client: Client, rec: EventRecord, key: String, state: SharedRelated) {
    let sections = gather_extra_context(&client, &rec).await;
    let mut s = state.lock().expect("related state poisoned");
    if s.current_key.as_deref() != Some(&key) { return; }
    s.loading = false;
    s.sections = sections;
    s.error = None;
}

async fn kyverno_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let is_policy_kind = rec.kind == "ClusterPolicy" || rec.kind == "Policy";

    if is_policy_kind && !rec.name.is_empty() {
        if let Some(json) = fetch_dynamic_pretty(client, &rec.api_version, &rec.kind, &rec.namespace, &rec.name).await {
            let title = if rec.namespace.is_empty() {
                format!("[kyverno] {} {}", rec.kind, rec.name)
            } else {
                format!("[kyverno] {} {}/{}", rec.kind, rec.namespace, rec.name)
            };
            out.push((title, json));
        }
        return out;
    }

    if rec.component.contains("kyverno") || rec.message.to_lowercase().contains("kyverno") {
        for pname in extract_kyverno_policy_names(&rec.message) {
            if let Some(json) = fetch_dynamic_pretty(client, "kyverno.io/v1", "ClusterPolicy", "", &pname).await {
                out.push((format!("[kyverno] ClusterPolicy {}", pname), json));
                continue;
            }
            if !rec.namespace.is_empty() {
                if let Some(json) = fetch_dynamic_pretty(client, "kyverno.io/v1", "Policy", &rec.namespace, &pname).await {
                    out.push((format!("[kyverno] Policy {}/{}", rec.namespace, pname), json));
                }
            }
        }
    }
    out
}

// Scan an event message for "policy <name>" mentions to locate the offending Kyverno policy.
fn extract_kyverno_policy_names(msg: &str) -> Vec<String> {
    let mut names = Vec::new();
    let lower = msg.to_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find("policy ") {
        let start = search_from + rel + "policy ".len();
        let rest = &msg[start..];
        let end = rest.find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':' | '"' | '\'' | '/'))
            .unwrap_or(rest.len());
        let name = rest[..end].trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
        if !name.is_empty() && !names.iter().any(|n: &String| n == name) {
            names.push(name.to_string());
        }
        search_from = start + end;
    }
    names
}

// On a "forbidden"/RBAC-flavoured message, resolve the ServiceAccount named in it and pull the
// RoleBindings/ClusterRoleBindings (and their roles) that grant it permissions.
async fn rbac_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lower = rec.message.to_lowercase();
    let looks_rbac = lower.contains("forbidden")
        || lower.contains("rbac")
        || lower.contains("system:serviceaccount")
        || (lower.contains("cannot ") && lower.contains("user "));
    if !looks_rbac { return out; }
    let Some((sa_ns, sa_name)) = extract_sa(&rec.message) else { return out; };

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), &sa_ns);
    if let Ok(sa) = sa_api.get(&sa_name).await {
        if let Ok(json) = clean_json(&sa) {
            out.push((format!("[rbac] ServiceAccount {}/{}", sa_ns, sa_name), json));
        }
    } else {
        out.push((
            format!("[rbac] ServiceAccount {}/{}", sa_ns, sa_name),
            "(introuvable)".to_string(),
        ));
    }

    let rb_api: Api<RoleBinding> = Api::namespaced(client.clone(), &sa_ns);
    if let Ok(rbs) = rb_api.list(&ListParams::default()).await {
        let mut count = 0;
        for rb in rbs.items {
            if !subjects_contain_sa(rb.subjects.as_deref(), &sa_ns, &sa_name) { continue; }
            if count >= MAX_BINDINGS { break; }
            count += 1;
            let rb_name = rb.metadata.name.clone().unwrap_or_default();
            let role_ref = rb.role_ref.clone();
            if let Ok(json) = clean_json(&rb) {
                out.push((format!("[rbac] RoleBinding {}/{}", sa_ns, rb_name), json));
            }
            match role_ref.kind.as_str() {
                "Role" => {
                    let api: Api<Role> = Api::namespaced(client.clone(), &sa_ns);
                    if let Ok(r) = api.get(&role_ref.name).await {
                        if let Ok(json) = clean_json(&r) {
                            out.push((format!("[rbac] Role {}/{}", sa_ns, role_ref.name), json));
                        }
                    }
                }
                "ClusterRole" => {
                    let api: Api<ClusterRole> = Api::all(client.clone());
                    if let Ok(r) = api.get(&role_ref.name).await {
                        if let Ok(json) = clean_json(&r) {
                            out.push((format!("[rbac] ClusterRole {}", role_ref.name), json));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    if let Ok(crbs) = crb_api.list(&ListParams::default()).await {
        let mut count = 0;
        for crb in crbs.items {
            if !subjects_contain_sa(crb.subjects.as_deref(), &sa_ns, &sa_name) { continue; }
            if count >= MAX_BINDINGS { break; }
            count += 1;
            let crb_name = crb.metadata.name.clone().unwrap_or_default();
            let role_ref = crb.role_ref.clone();
            if let Ok(json) = clean_json(&crb) {
                out.push((format!("[rbac] ClusterRoleBinding {}", crb_name), json));
            }
            if role_ref.kind == "ClusterRole" {
                let api: Api<ClusterRole> = Api::all(client.clone());
                if let Ok(r) = api.get(&role_ref.name).await {
                    if let Ok(json) = clean_json(&r) {
                        out.push((format!("[rbac] ClusterRole {}", role_ref.name), json));
                    }
                }
            }
        }
    }

    out
}

async fn cert_manager_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let cm_kinds = ["Certificate", "CertificateRequest", "Order", "Challenge", "Issuer", "ClusterIssuer"];
    let is_cm = cm_kinds.contains(&rec.kind.as_str())
        || rec.api_version.contains("cert-manager.io")
        || rec.api_version.contains("acme.cert-manager.io")
        || rec.component.contains("cert-manager");
    if !is_cm { return Vec::new(); }

    let mut out = Vec::new();
    let api_ver = if rec.api_version.is_empty() { "cert-manager.io/v1".to_string() } else { rec.api_version.clone() };

    let obj = fetch_dynamic_obj(client, &api_ver, &rec.kind, &rec.namespace, &rec.name).await;
    if let Some(o) = &obj {
        if let Ok(json) = clean_json(o) {
            let title = if rec.namespace.is_empty() {
                format!("[cert-manager] {} {}", rec.kind, rec.name)
            } else {
                format!("[cert-manager] {} {}/{}", rec.kind, rec.namespace, rec.name)
            };
            out.push((title, json));
        }
    }

    if let Some(o) = obj {
        if rec.kind == "Certificate" || rec.kind == "CertificateRequest" {
            if let Some((issuer_kind, issuer_name)) = extract_issuer_ref(&o.data) {
                let issuer_ns = if issuer_kind == "ClusterIssuer" { "" } else { rec.namespace.as_str() };
                if let Some(json) = fetch_dynamic_pretty(client, "cert-manager.io/v1", &issuer_kind, issuer_ns, &issuer_name).await {
                    let title = if issuer_kind == "ClusterIssuer" {
                        format!("[cert-manager] ClusterIssuer {}", issuer_name)
                    } else {
                        format!("[cert-manager] Issuer {}/{}", issuer_ns, issuer_name)
                    };
                    out.push((title, json));
                }
            }
        }
        if rec.kind == "Challenge" {
            if let Some(order) = o.metadata.owner_references.as_ref()
                .and_then(|rs| rs.iter().find(|r| r.kind == "Order"))
            {
                if let Some(json) = fetch_dynamic_pretty(client, "acme.cert-manager.io/v1", "Order", &rec.namespace, &order.name).await {
                    out.push((format!("[cert-manager] Order {}/{}", rec.namespace, order.name), json));
                }
            }
        }
    }
    out
}

fn extract_issuer_ref(data: &serde_json::Value) -> Option<(String, String)> {
    let r = data.get("spec")?.get("issuerRef")?;
    let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("Issuer").to_string();
    let name = r.get("name").and_then(|v| v.as_str())?.to_string();
    Some((kind, name))
}

async fn velero_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let velero_kinds = ["Backup", "Restore", "Schedule", "BackupStorageLocation", "VolumeSnapshotLocation", "PodVolumeBackup", "PodVolumeRestore"];
    let is_velero = (velero_kinds.contains(&rec.kind.as_str()) && rec.api_version.contains("velero.io"))
        || rec.component.contains("velero")
        || rec.namespace == "velero";
    if !is_velero { return Vec::new(); }

    let mut out = Vec::new();
    let api_ver = if rec.api_version.is_empty() || !rec.api_version.contains("velero.io") {
        "velero.io/v1".to_string()
    } else {
        rec.api_version.clone()
    };

    let obj = fetch_dynamic_obj(client, &api_ver, &rec.kind, &rec.namespace, &rec.name).await;
    if let Some(o) = &obj {
        if let Ok(json) = clean_json(o) {
            out.push((format!("[velero] {} {}/{}", rec.kind, rec.namespace, rec.name), json));
        }
    }

    if let Some(o) = obj {
        if rec.kind == "Backup" || rec.kind == "Restore" {
            if let Some(loc) = o.data.get("spec").and_then(|s| s.get("storageLocation")).and_then(|v| v.as_str()) {
                if let Some(json) = fetch_dynamic_pretty(client, &api_ver, "BackupStorageLocation", &rec.namespace, loc).await {
                    out.push((format!("[velero] BackupStorageLocation {}/{}", rec.namespace, loc), json));
                }
            }
        }
    }
    out
}

async fn ingress_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    if rec.kind != "Ingress" { return Vec::new(); }
    let mut out = Vec::new();

    let tag = if rec.component == "nginx-ingress-controller" || rec.component.contains("ingress-nginx") {
        "ingress-nginx"
    } else if rec.component.contains("nginx-ingress") || rec.component == "f5-ingress" {
        "nginx-ingress F5"
    } else if rec.component.contains("traefik") {
        "traefik"
    } else {
        "ingress"
    };

    let api: Api<Ingress> = Api::namespaced(client.clone(), &rec.namespace);
    let ing = match api.get(&rec.name).await {
        Ok(i) => i,
        Err(_) => return out,
    };
    if let Ok(json) = clean_json(&ing) {
        out.push((format!("[{}] Ingress {}/{}", tag, rec.namespace, rec.name), json));
    }
    if let Some(class_name) = ing.spec.as_ref().and_then(|s| s.ingress_class_name.clone()) {
        let cls_api: Api<IngressClass> = Api::all(client.clone());
        if let Ok(cls) = cls_api.get(&class_name).await {
            if let Ok(json) = clean_json(&cls) {
                out.push((format!("[{}] IngressClass {}", tag, class_name), json));
            }
        }
    }
    out
}

async fn rancher_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let is_rancher = rec.api_version.contains("cattle.io")
        || rec.api_version.contains("management.cattle.io")
        || rec.api_version.contains("provisioning.cattle.io")
        || rec.api_version.contains("fleet.cattle.io")
        || rec.namespace == "cattle-system"
        || rec.namespace == "cattle-fleet-system"
        || rec.namespace == "cattle-fleet-local-system"
        || rec.namespace == "cattle-impersonation-system"
        || rec.component.contains("rancher")
        || rec.component.contains("fleet");
    if !is_rancher { return Vec::new(); }

    let mut out = Vec::new();
    if !rec.kind.is_empty() && !rec.name.is_empty() && !rec.api_version.is_empty() {
        if let Some(json) = fetch_dynamic_pretty(client, &rec.api_version, &rec.kind, &rec.namespace, &rec.name).await {
            let title = if rec.namespace.is_empty() {
                format!("[rancher] {} {}", rec.kind, rec.name)
            } else {
                format!("[rancher] {} {}/{}", rec.kind, rec.namespace, rec.name)
            };
            out.push((title, json));
        }
    }
    out
}

async fn datadog_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let dd_kinds = ["DatadogAgent", "DatadogMonitor", "DatadogMetric", "DatadogSLO", "DatadogDashboard"];
    if !dd_kinds.contains(&rec.kind.as_str()) { return Vec::new(); }
    let api_ver = if rec.api_version.is_empty() {
        match rec.kind.as_str() {
            "DatadogAgent" => "datadoghq.com/v2alpha1".to_string(),
            _ => "datadoghq.com/v1alpha1".to_string(),
        }
    } else {
        rec.api_version.clone()
    };
    let mut out = Vec::new();
    if let Some(json) = fetch_dynamic_pretty(client, &api_ver, &rec.kind, &rec.namespace, &rec.name).await {
        out.push((format!("[datadog] {} {}/{}", rec.kind, rec.namespace, rec.name), json));
    }
    out
}

async fn storage_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if rec.kind == "PersistentVolumeClaim" {
        let api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &rec.namespace);
        let Ok(pvc) = api.get(&rec.name).await else { return out; };
        if let Ok(json) = clean_json(&pvc) {
            out.push((format!("[storage] PersistentVolumeClaim {}/{}", rec.namespace, rec.name), json));
        }
        let sc_name = pvc.spec.as_ref().and_then(|s| s.storage_class_name.clone());
        let volume_name = pvc.spec.as_ref().and_then(|s| s.volume_name.clone());
        if let Some(sc) = sc_name {
            let sc_api: Api<StorageClass> = Api::all(client.clone());
            if let Ok(scobj) = sc_api.get(&sc).await {
                if let Ok(json) = clean_json(&scobj) {
                    out.push((format!("[storage] StorageClass {}", sc), json));
                }
            }
        }
        if let Some(volume_name) = volume_name {
            let pv_api: Api<PersistentVolume> = Api::all(client.clone());
            if let Ok(pv) = pv_api.get(&volume_name).await {
                if let Ok(json) = clean_json(&pv) {
                    out.push((format!("[storage] PersistentVolume {}", volume_name), json));
                }
            }
        }
        return out;
    }
    if rec.kind == "PersistentVolume" {
        let api: Api<PersistentVolume> = Api::all(client.clone());
        let Ok(pv) = api.get(&rec.name).await else { return out; };
        if let Ok(json) = clean_json(&pv) {
            out.push((format!("[storage] PersistentVolume {}", rec.name), json));
        }
        if let Some(sc) = pv.spec.as_ref().and_then(|s| s.storage_class_name.clone()) {
            let sc_api: Api<StorageClass> = Api::all(client.clone());
            if let Ok(scobj) = sc_api.get(&sc).await {
                if let Ok(json) = clean_json(&scobj) {
                    out.push((format!("[storage] StorageClass {}", sc), json));
                }
            }
        }
        if let Some(claim_ref) = pv.spec.as_ref().and_then(|s| s.claim_ref.as_ref()) {
            if let (Some(ns), Some(name)) = (&claim_ref.namespace, &claim_ref.name) {
                let pvc_api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), ns);
                if let Ok(pvc) = pvc_api.get(name).await {
                    if let Ok(json) = clean_json(&pvc) {
                        out.push((format!("[storage] PersistentVolumeClaim {}/{}", ns, name), json));
                    }
                }
            }
        }
    }
    out
}

async fn argocd_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let argo_kinds = ["Application", "AppProject", "ApplicationSet"];
    let is_argo = rec.api_version.contains("argoproj.io")
        || rec.namespace == "argocd"
        || rec.namespace == "argo-cd"
        || rec.component.contains("argocd")
        || (argo_kinds.contains(&rec.kind.as_str()) && rec.api_version.contains("argoproj"));
    if !is_argo { return Vec::new(); }

    let mut out = Vec::new();
    let api_ver = if rec.api_version.is_empty() || !rec.api_version.contains("argoproj.io") {
        "argoproj.io/v1alpha1".to_string()
    } else {
        rec.api_version.clone()
    };

    let obj = fetch_dynamic_obj(client, &api_ver, &rec.kind, &rec.namespace, &rec.name).await;
    if let Some(o) = &obj {
        if let Ok(json) = clean_json(o) {
            out.push((format!("[argocd] {} {}/{}", rec.kind, rec.namespace, rec.name), json));
        }
    }

    if let Some(o) = obj {
        if rec.kind == "Application" {
            if let Some(project) = o.data.get("spec").and_then(|s| s.get("project")).and_then(|p| p.as_str()) {
                if !project.is_empty() && project != "default" {
                    if let Some(json) = fetch_dynamic_pretty(client, &api_ver, "AppProject", &rec.namespace, project).await {
                        out.push((format!("[argocd] AppProject {}/{}", rec.namespace, project), json));
                    }
                }
            }
        }
    }
    out
}

async fn fluxcd_context(client: &Client, rec: &EventRecord) -> Vec<(String, String)> {
    let flux_kinds = [
        "Kustomization", "HelmRelease",
        "GitRepository", "HelmRepository", "OCIRepository", "Bucket", "HelmChart",
        "Receiver", "Alert", "Provider",
        "ImageRepository", "ImagePolicy", "ImageUpdateAutomation",
    ];
    let is_flux = rec.api_version.contains("toolkit.fluxcd.io")
        || rec.namespace == "flux-system"
        || rec.component.contains("flux")
        || (flux_kinds.contains(&rec.kind.as_str()) && rec.api_version.contains("fluxcd"));
    if !is_flux { return Vec::new(); }

    let mut out = Vec::new();
    let obj = fetch_dynamic_obj(client, &rec.api_version, &rec.kind, &rec.namespace, &rec.name).await;
    if let Some(o) = &obj {
        if let Ok(json) = clean_json(o) {
            out.push((format!("[fluxcd] {} {}/{}", rec.kind, rec.namespace, rec.name), json));
        }
    }

    if let Some(o) = obj {
        let source_ref = match rec.kind.as_str() {
            "Kustomization" => o.data.get("spec").and_then(|s| s.get("sourceRef")).cloned(),
            "HelmRelease" => o.data.get("spec")
                .and_then(|s| s.get("chart"))
                .and_then(|c| c.get("spec"))
                .and_then(|cs| cs.get("sourceRef"))
                .cloned()
                .or_else(|| o.data.get("spec").and_then(|s| s.get("chartRef")).cloned()),
            _ => None,
        };
        if let Some(sref) = source_ref {
            if let (Some(kind), Some(name)) = (
                sref.get("kind").and_then(|v| v.as_str()),
                sref.get("name").and_then(|v| v.as_str()),
            ) {
                let ns = sref.get("namespace").and_then(|v| v.as_str()).unwrap_or(&rec.namespace);
                let api_ver = "source.toolkit.fluxcd.io/v1";
                if let Some(json) = fetch_dynamic_pretty(client, api_ver, kind, ns, name).await {
                    out.push((format!("[fluxcd] {} {}/{}", kind, ns, name), json));
                }
            }
        }
    }
    out
}

// Static troubleshooting hints injected when an event matches a known tool (fluent-bit, datadog…),
// giving the model curated background it might otherwise lack.
fn tool_hints(rec: &EventRecord) -> Vec<(String, String)> {
    let mut hints = Vec::new();
    let comp = rec.component.to_lowercase();
    let ns = rec.namespace.to_lowercase();
    let msg = rec.message.to_lowercase();
    let probe = |needle: &str| comp.contains(needle) || ns.contains(needle) || msg.contains(needle);

    if probe("fluent-bit") || probe("fluentbit") {
        hints.push((
            "[hint] fluent-bit".to_string(),
            "Pistes typiques: parser/multiline mal défini, output buffer plein (mem_buf_limit), TLS/CA invalide, écriture vers backend (Loki/ES/Datadog/CloudWatch), filter Kubernetes (échec API), index template (ES). Vérifier: ConfigMap fluent-bit.conf et CR ClusterFilter/ClusterOutput/ClusterParser, RBAC du SA fluent-bit (events,pods,namespaces RO cluster-wide).".to_string(),
        ));
    }
    if probe("datadog") {
        hints.push((
            "[hint] datadog".to_string(),
            "Pistes: API key invalide (DD_API_KEY), kubelet auth (TLS, bearer token), conflit port dogstatsd/statsd, autodiscovery (annotations ad.datadoghq.com/<container>.{check_names,init_configs,instances}), accès kube-state-metrics, Cluster Agent injoignable, leader election. Vérifier le DatadogAgent CR (operator) ou le DaemonSet datadog-agent et son ServiceAccount.".to_string(),
        ));
    }
    if probe("reflector") {
        hints.push((
            "[hint] reflector (emberstack)".to_string(),
            "Annotations source: reflector.v1.k8s.emberstack.com/{reflection-allowed=true, reflection-allowed-namespaces=<csv|regex>, reflection-auto-enabled=true, reflection-auto-namespaces=<csv|regex>}. Annotations destinations (auto-créées): reflects=true, reflects-from=<ns>/<name>. Vérifier le ClusterRole du reflector (lecture Secrets/ConfigMaps cluster-wide) et que la source porte les annotations adéquates.".to_string(),
        ));
    }
    if probe("airflow") {
        hints.push((
            "[hint] airflow".to_string(),
            "Pour KubernetesExecutor / KubernetesPodOperator: vérifier les labels du pod (dag_id, task_id, run_id, try_number) et la config airflow.cfg (kubernetes_executor.*). Erreurs typiques: image worker introuvable, pull secret manquant, ressources insuffisantes (request CPU/mem > capacité), volumes manquants (logs PVC airflow-logs, dags PVC), webserver/scheduler injoignable, RBAC du SA airflow-worker (create/get/watch pods + pods/log dans le ns d'exécution), secrets backend (DB metadata) injoignable.".to_string(),
        ));
    }

    hints
}

fn subjects_contain_sa(subjects: Option<&[Subject]>, sa_ns: &str, sa_name: &str) -> bool {
    subjects.map(|ss| ss.iter().any(|s| {
        s.kind == "ServiceAccount" && s.name == sa_name && s.namespace.as_deref() == Some(sa_ns)
    })).unwrap_or(false)
}

// Parse "system:serviceaccount:<ns>:<name>" out of an error message.
fn extract_sa(msg: &str) -> Option<(String, String)> {
    let needle = "system:serviceaccount:";
    let start = msg.find(needle)? + needle.len();
    let rest = &msg[start..];
    let end = rest.find(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != ':' && c != '.')
        .unwrap_or(rest.len());
    let id = &rest[..end];
    let mut parts = id.splitn(2, ':');
    let ns = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    if ns.is_empty() || name.is_empty() { return None; }
    Some((ns, name))
}

// Fetch any object by GVK via API discovery, choosing the cluster- or namespace-scoped API
// based on the resource's scope. Returns None on any discovery/get failure.
async fn fetch_dynamic_obj(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Option<DynamicObject> {
    if kind.is_empty() || name.is_empty() { return None; }
    let gvk = if let Some((g, v)) = api_version.split_once('/') {
        GroupVersionKind::gvk(g, v, kind)
    } else {
        GroupVersionKind::gvk("", api_version, kind)
    };
    let (ar, caps) = discovery::pinned_kind(client, &gvk).await.ok()?;
    let api: Api<DynamicObject> = if caps.scope == Scope::Cluster {
        Api::all_with(client.clone(), &ar)
    } else {
        Api::namespaced_with(client.clone(), namespace, &ar)
    };
    api.get(name).await.ok()
}

async fn fetch_dynamic_pretty(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Option<String> {
    let obj = fetch_dynamic_obj(client, api_version, kind, namespace, name).await?;
    clean_json(&obj).ok()
}
