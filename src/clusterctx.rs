//! Le cadre du cluster, tel que le prompt IA le porte.
//!
//! Un événement seul ne dit pas où il se produit. La même `CrashLoopBackOff` ne se corrige pas de
//! la même façon sur un k3s mono-nœud et sur un AKS, et un `kubectl patch` sur un Deployment que
//! Flux réconcilie est annulé dans les minutes qui suivent : la réponse juste est dans le dépôt
//! Git. Sans ce cadre, le modèle recommande ce qu'il recommanderait à un cluster imaginaire.
//!
//! # Deux questions
//!
//! - **Le cluster** : version, distribution, nodes, add-ons servis, classes d'ingress et de
//!   stockage. Les mêmes pour tout événement du cluster.
//! - **L'objet** : sa chaîne de propriétaires (Pod → ReplicaSet → Deployment…) et ce qui le gère
//!   — Flux, Argo CD, Helm — lu sur ses labels et annotations.
//!
//! # Rien n'est supposé
//!
//! Chaque ligne est un fait lu : un groupe d'API servi, un label posé, un préfixe de `providerID`.
//! Une lecture refusée fait disparaître sa ligne plutôt que de la remplir d'un défaut — sauf les
//! nodes, dont le refus est lui-même un fait sur les droits de la personne. Un groupe servi dit
//! que les CRD sont là, pas que le controller tourne : le titre le dit au modèle.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::networking::v1::IngressClass;
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::ListParams;
use kube::{Api, Client};

use crate::events::EventRecord;

/// Nodes lus pour résumer le parc : au-delà, le total vient de `remainingItemCount`, et les
/// valeurs distinctes d'un échantillon de cette taille disent déjà si le parc est homogène.
const NODE_SAMPLE: u32 = 100;
/// Valeurs distinctes montrées par attribut de node avant de replier en `+N`.
const MAX_DISTINCT: usize = 3;
/// Propriétaires remontés au plus : Pod → ReplicaSet → Deployment → ressource d'opérateur.
const MAX_OWNER_HOPS: usize = 4;

/// Les add-ons reconnus à leurs groupes d'API. Le libellé est ce que le modèle lit ; les groupes
/// sont ce qui se vérifie. `argoproj.io` n'y est pas : il sert Argo CD, Rollouts et Workflows, et
/// seuls ses kinds les distinguent (voir [`argo_products`]).
const ADDONS: &[(&str, &[&str])] = &[
    (
        "Flux",
        &[
            "source.toolkit.fluxcd.io",
            "kustomize.toolkit.fluxcd.io",
            "helm.toolkit.fluxcd.io",
            "notification.toolkit.fluxcd.io",
            "image.toolkit.fluxcd.io",
        ],
    ),
    ("Rancher", &["management.cattle.io"]),
    ("Fleet", &["fleet.cattle.io"]),
    ("Kyverno", &["kyverno.io"]),
    ("Gatekeeper", &["templates.gatekeeper.sh"]),
    ("cert-manager", &["cert-manager.io"]),
    ("Velero", &["velero.io"]),
    ("Istio", &["networking.istio.io"]),
    ("Linkerd", &["linkerd.io", "policy.linkerd.io"]),
    ("Cilium", &["cilium.io"]),
    ("Calico", &["crd.projectcalico.org", "projectcalico.org"]),
    ("Gateway API", &["gateway.networking.k8s.io"]),
    ("Traefik", &["traefik.io", "traefik.containo.us"]),
    ("Prometheus Operator", &["monitoring.coreos.com"]),
    ("KEDA", &["keda.sh"]),
    ("Karpenter", &["karpenter.sh"]),
    ("VPA", &["autoscaling.k8s.io"]),
    ("External Secrets", &["external-secrets.io"]),
    ("Sealed Secrets", &["bitnami.com"]),
    ("Longhorn", &["longhorn.io"]),
    ("Rook Ceph", &["ceph.rook.io"]),
    ("CloudNativePG", &["postgresql.cnpg.io"]),
    ("Strimzi", &["kafka.strimzi.io"]),
    ("K8ssandra", &["k8ssandra.io"]),
    ("Elastic ECK", &["elasticsearch.k8s.elastic.co"]),
    ("Datadog Operator", &["datadoghq.com"]),
    ("Crossplane", &["pkg.crossplane.io"]),
    ("Knative", &["serving.knative.dev"]),
    ("Tekton", &["tekton.dev"]),
    ("KubeVirt", &["kubevirt.io"]),
    ("kdt-identity", &["identity.kdt.sh"]),
    ("metrics API", &["metrics.k8s.io"]),
    ("volume snapshots", &["snapshot.storage.k8s.io"]),
];

/// Le bloc `## Cluster` du prompt, ou `None` si rien n'a pu être lu.
///
/// `rec` absent : le cadre du cluster seul, pour les analyses qui ne portent pas sur un objet
/// (diagnostic, usage d'un node).
pub async fn prompt_block(client: &Client, rec: Option<&EventRecord>) -> Option<String> {
    let (profile, owner) = tokio::join!(cluster_lines(client), async {
        match rec {
            Some(rec) => ownership_lines(client, rec).await,
            None => Vec::new(),
        }
    });
    let lines: Vec<String> = profile.into_iter().chain(owner).collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

async fn cluster_lines(client: &Client) -> Vec<String> {
    let nodes_api: Api<Node> = Api::all(client.clone());
    let ic_api: Api<IngressClass> = Api::all(client.clone());
    let sc_api: Api<StorageClass> = Api::all(client.clone());
    let node_lp = ListParams::default().limit(NODE_SAMPLE);
    let all = ListParams::default();
    let (version, groups, nodes, ics, scs) = tokio::join!(
        client.apiserver_version(),
        client.list_api_groups(),
        nodes_api.list(&node_lp),
        ic_api.list(&all),
        sc_api.list(&all),
    );

    let served: BTreeMap<String, String> = groups
        .map(|g| {
            g.groups
                .into_iter()
                .map(|g| {
                    let preferred = g
                        .preferred_version
                        .map(|p| p.group_version)
                        .unwrap_or_else(|| g.name.clone());
                    (g.name, preferred)
                })
                .collect()
        })
        .unwrap_or_default();

    let argo = match served.get("argoproj.io") {
        Some(gv) => match client.list_api_group_resources(gv).await {
            Ok(list) => argo_products(list.resources.iter().map(|r| r.kind.as_str())),
            Err(_) => vec!["Argo (argoproj.io)"],
        },
        None => Vec::new(),
    };

    let mut out = Vec::new();
    let (git_version, platform) = match version {
        Ok(v) => (Some(v.git_version), Some(v.platform)),
        Err(_) => (None, None),
    };

    let (node_facts, node_line) = match nodes {
        Ok(list) => {
            let total = list.items.len()
                + list.metadata.remaining_item_count.unwrap_or(0).max(0) as usize;
            let facts = NodeFacts::from_nodes(&list.items, total);
            let line = facts.line();
            (Some(facts), line)
        }
        Err(e) => (None, format!("nodes : illisibles ({})", crate::edit::api_error_text(e))),
    };

    let dists = distributions(
        git_version.as_deref(),
        served.keys().map(String::as_str),
        node_facts.as_ref(),
    );
    if let Some(v) = &git_version {
        let mut line = format!("kubernetes {v}");
        if let Some(p) = platform.as_deref().filter(|p| !p.is_empty()) {
            line.push_str(&format!(" ({p})"));
        }
        if !dists.is_empty() {
            line.push_str(&format!(" · distribution {}", dists.join(", ")));
        }
        out.push(line);
    } else if !dists.is_empty() {
        out.push(format!("distribution {}", dists.join(", ")));
    }
    out.push(node_line);

    let addons = addon_lines(&served, &argo);
    if !addons.is_empty() {
        out.push("add-ons (groupes d'API servis, controller non vérifié) :".to_string());
        out.extend(addons.into_iter().map(|l| format!("- {l}")));
    }

    if let Ok(list) = ics {
        let items: Vec<String> = list
            .items
            .iter()
            .map(|ic| {
                let ctrl = ic.spec.as_ref().and_then(|s| s.controller.clone()).unwrap_or_default();
                class_entry(
                    ic.metadata.name.as_deref().unwrap_or("?"),
                    &ctrl,
                    is_default(&ic.metadata.annotations, "ingressclass.kubernetes.io/is-default-class"),
                )
            })
            .collect();
        if !items.is_empty() {
            out.push(format!("ingressClass : {}", items.join(" · ")));
        }
    }
    if let Ok(list) = scs {
        let items: Vec<String> = list
            .items
            .iter()
            .map(|sc| {
                class_entry(
                    sc.metadata.name.as_deref().unwrap_or("?"),
                    &sc.provisioner,
                    is_default(&sc.metadata.annotations, "storageclass.kubernetes.io/is-default-class"),
                )
            })
            .collect();
        if !items.is_empty() {
            out.push(format!("storageClass : {}", items.join(" · ")));
        }
    }
    out
}

fn is_default(annotations: &Option<BTreeMap<String, String>>, key: &str) -> bool {
    annotations.as_ref().and_then(|a| a.get(key)).is_some_and(|v| v == "true")
}

fn class_entry(name: &str, backend: &str, default: bool) -> String {
    match (backend.is_empty(), default) {
        (true, false) => name.to_string(),
        (true, true) => format!("{name} (défaut)"),
        (false, false) => format!("{name} ({backend})"),
        (false, true) => format!("{name} ({backend}, défaut)"),
    }
}

/// Ce que `argoproj.io` sert réellement, d'après ses kinds.
fn argo_products<'a>(kinds: impl IntoIterator<Item = &'a str>) -> Vec<&'static str> {
    let kinds: BTreeSet<&str> = kinds.into_iter().collect();
    let mut out = Vec::new();
    if kinds.contains("Application") {
        out.push("Argo CD");
    }
    if kinds.contains("Rollout") {
        out.push("Argo Rollouts");
    }
    if kinds.contains("Workflow") {
        out.push("Argo Workflows");
    }
    if kinds.contains("EventSource") || kinds.contains("Sensor") {
        out.push("Argo Events");
    }
    out
}

/// Une ligne par add-on présent, avec la version préférée de chacun de ses groupes : c'est
/// l'`apiVersion` qu'un manifest recommandé doit porter sur ce cluster.
fn addon_lines(served: &BTreeMap<String, String>, argo: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = ADDONS
        .iter()
        .filter_map(|(label, groups)| {
            let versions: Vec<&str> = groups
                .iter()
                .filter_map(|g| served.get(*g).map(String::as_str))
                .collect();
            (!versions.is_empty()).then(|| format!("{label} : {}", versions.join(", ")))
        })
        .collect();
    if let Some(gv) = served.get("argoproj.io") {
        for product in argo {
            out.push(format!("{product} : {gv}"));
        }
    }
    out
}

/// Ce que les nodes lus disent du parc.
#[derive(Debug, Default)]
struct NodeFacts {
    total: usize,
    read: usize,
    control_plane: usize,
    kubelet: Vec<String>,
    runtime: Vec<String>,
    os: Vec<String>,
    arch: Vec<String>,
    provider: Vec<String>,
    label_keys: BTreeSet<String>,
}

impl NodeFacts {
    fn from_nodes(nodes: &[Node], total: usize) -> Self {
        let mut kubelet = BTreeSet::new();
        let mut runtime = BTreeSet::new();
        let mut os = BTreeSet::new();
        let mut arch = BTreeSet::new();
        let mut provider = BTreeSet::new();
        let mut label_keys = BTreeSet::new();
        let mut control_plane = 0;
        for n in nodes {
            if let Some(labels) = &n.metadata.labels {
                if labels.contains_key("node-role.kubernetes.io/control-plane")
                    || labels.contains_key("node-role.kubernetes.io/master")
                {
                    control_plane += 1;
                }
                label_keys.extend(labels.keys().cloned());
            }
            if let Some(pid) = n.spec.as_ref().and_then(|s| s.provider_id.as_deref()) {
                if let Some((scheme, _)) = pid.split_once("://") {
                    provider.insert(scheme.to_string());
                }
            }
            if let Some(info) = n.status.as_ref().and_then(|s| s.node_info.as_ref()) {
                kubelet.insert(info.kubelet_version.clone());
                runtime.insert(info.container_runtime_version.clone());
                os.insert(info.os_image.clone());
                arch.insert(info.architecture.clone());
            }
        }
        let v = |s: BTreeSet<String>| s.into_iter().filter(|x| !x.is_empty()).collect();
        Self {
            total,
            read: nodes.len(),
            control_plane,
            kubelet: v(kubelet),
            runtime: v(runtime),
            os: v(os),
            arch: v(arch),
            provider: v(provider),
            label_keys,
        }
    }

    fn line(&self) -> String {
        let mut parts = vec![if self.read < self.total {
            format!("nodes {} ({} lus)", self.total, self.read)
        } else {
            format!("nodes {}", self.total)
        }];
        if self.control_plane > 0 {
            parts.push(format!("control-plane {}", self.control_plane));
        }
        for (key, values) in [
            ("kubelet", &self.kubelet),
            ("runtime", &self.runtime),
            ("os", &self.os),
            ("arch", &self.arch),
            ("providerID", &self.provider),
        ] {
            if !values.is_empty() {
                parts.push(format!("{key} {}", distinct(values)));
            }
        }
        parts.join(" · ")
    }
}

fn distinct(values: &[String]) -> String {
    let shown: Vec<&str> = values.iter().take(MAX_DISTINCT).map(String::as_str).collect();
    let rest = values.len().saturating_sub(MAX_DISTINCT);
    if rest > 0 {
        format!("{} +{rest}", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// La distribution, reconnue à des marques qui ne trompent pas : suffixe du `gitVersion`, groupe
/// d'API propre, label posé par le fournisseur sur ses nodes, image d'OS.
fn distributions<'a>(
    git_version: Option<&str>,
    served: impl IntoIterator<Item = &'a str>,
    nodes: Option<&NodeFacts>,
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut push = |d: &'static str| {
        if !out.contains(&d) {
            out.push(d);
        }
    };
    if let Some(v) = git_version {
        if v.contains("+k3s") {
            push("k3s");
        }
        if v.contains("+rke2") {
            push("RKE2");
        }
        if v.contains("+k0s") {
            push("k0s");
        }
        if v.contains("-eks-") {
            push("EKS");
        }
        if v.contains("-gke.") {
            push("GKE");
        }
    }
    if served.into_iter().any(|g| g == "config.openshift.io") {
        push("OpenShift");
    }
    if let Some(n) = nodes {
        let has = |k: &str| n.label_keys.contains(k);
        if has("kubernetes.azure.com/cluster") {
            push("AKS");
        }
        if has("eks.amazonaws.com/nodegroup") || has("eks.amazonaws.com/compute-type") {
            push("EKS");
        }
        if has("cloud.google.com/gke-nodepool") {
            push("GKE");
        }
        if has("minikube.k8s.io/name") {
            push("minikube");
        }
        if n.os.iter().any(|o| o.starts_with("Talos")) {
            push("Talos");
        }
        if n.provider.iter().any(|p| p == "kind") {
            push("kind");
        }
    }
    out
}

/// La chaîne de propriétaires de l'objet et ce qui gère sa racine. Vide si l'objet n'a pas pu être
/// lu, et sans ligne « géré par » si la racine ne l'a pas été : ne rien dire vaut mieux que dire
/// « non géré » d'un objet qu'on n'a pas vu.
async fn ownership_lines(client: &Client, rec: &EventRecord) -> Vec<String> {
    if rec.kind.is_empty() || rec.name.is_empty() {
        return Vec::new();
    }
    let mut chain: Vec<String> = Vec::new();
    let mut markers: Vec<String> = Vec::new();
    let mut root_read = false;
    let (mut api_version, mut kind, mut name) =
        (rec.api_version.clone(), rec.kind.clone(), rec.name.clone());
    for _ in 0..MAX_OWNER_HOPS {
        let Some(obj) =
            crate::enrich::fetch_dynamic_obj(client, &api_version, &kind, &rec.namespace, &name).await
        else {
            break;
        };
        chain.push(object_ref(&kind, obj.metadata.namespace.as_deref(), &name));
        // Un objet qui a un controller est géré par lui : ses labels sont souvent la copie d'un
        // template (un Pod hérite du `managed-by: Helm` de son chart), pas la marque de qui l'a
        // appliqué. Seule la racine de la chaîne dit qui gère.
        let owner = obj
            .metadata
            .owner_references
            .as_ref()
            .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)));
        match owner {
            Some(o) => (api_version, kind, name) = (o.api_version.clone(), o.kind.clone(), o.name.clone()),
            None => {
                markers = ownership_markers(
                    obj.metadata.labels.as_ref().unwrap_or(&BTreeMap::new()),
                    obj.metadata.annotations.as_ref().unwrap_or(&BTreeMap::new()),
                );
                root_read = true;
                break;
            }
        }
    }
    if chain.is_empty() {
        return Vec::new();
    }
    let mut out = vec![format!("objet : {}", chain.join(" → "))];
    // Racine non lue (droits, profondeur) : on ne sait pas qui gère, et on ne le dit pas.
    if root_read {
        out.push(format!(
            "géré par : {}",
            if markers.is_empty() {
                "aucun marqueur Flux, Argo CD ni Helm".to_string()
            } else {
                markers.join(" · ")
            }
        ));
    }
    out
}

fn object_ref(kind: &str, namespace: Option<&str>, name: &str) -> String {
    match namespace.filter(|ns| !ns.is_empty()) {
        Some(ns) => format!("{kind} {ns}/{name}"),
        None => format!("{kind} {name}"),
    }
}

/// Les marques qu'un gestionnaire laisse sur ce qu'il applique.
fn ownership_markers(
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let ns_name = |ns_key: &str, name: &str| match labels.get(ns_key) {
        Some(ns) => format!("{ns}/{name}"),
        None => name.to_string(),
    };
    if let Some(name) = labels.get("kustomize.toolkit.fluxcd.io/name") {
        out.push(format!(
            "Flux Kustomization {}",
            ns_name("kustomize.toolkit.fluxcd.io/namespace", name)
        ));
    }
    if let Some(name) = labels.get("helm.toolkit.fluxcd.io/name") {
        out.push(format!(
            "Flux HelmRelease {}",
            ns_name("helm.toolkit.fluxcd.io/namespace", name)
        ));
    }
    if annotations
        .get("kustomize.toolkit.fluxcd.io/reconcile")
        .is_some_and(|v| v == "disabled")
    {
        out.push("réconciliation Flux désactivée sur l'objet".to_string());
    }
    let argo_app = annotations
        .get("argocd.argoproj.io/tracking-id")
        .and_then(|t| t.split(':').next())
        .or_else(|| labels.get("argocd.argoproj.io/instance").map(String::as_str))
        .filter(|a| !a.is_empty());
    if let Some(app) = argo_app {
        out.push(format!("Argo CD Application {app}"));
    }
    match labels.get("app.kubernetes.io/managed-by").map(String::as_str) {
        Some("Helm") => {
            let release = annotations.get("meta.helm.sh/release-name");
            let rns = annotations.get("meta.helm.sh/release-namespace");
            out.push(match (rns, release) {
                (Some(ns), Some(r)) => format!("Helm release {ns}/{r}"),
                (None, Some(r)) => format!("Helm release {r}"),
                _ => "Helm".to_string(),
            });
        }
        Some(other) if !other.is_empty() => {
            out.push(format!("app.kubernetes.io/managed-by={other}"));
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_flux_helmrelease_is_named_with_its_helm_release() {
        let labels = map(&[
            ("helm.toolkit.fluxcd.io/name", "podinfo"),
            ("helm.toolkit.fluxcd.io/namespace", "apps"),
            ("app.kubernetes.io/managed-by", "Helm"),
        ]);
        let ann = map(&[
            ("meta.helm.sh/release-name", "podinfo"),
            ("meta.helm.sh/release-namespace", "apps"),
        ]);
        assert_eq!(
            ownership_markers(&labels, &ann),
            vec!["Flux HelmRelease apps/podinfo", "Helm release apps/podinfo"]
        );
    }

    #[test]
    fn argo_tracking_id_names_the_application() {
        let ann = map(&[("argocd.argoproj.io/tracking-id", "guestbook:apps/Deployment:default/web")]);
        assert_eq!(ownership_markers(&BTreeMap::new(), &ann), vec!["Argo CD Application guestbook"]);
    }

    #[test]
    fn a_disabled_flux_reconciliation_is_reported() {
        let labels = map(&[
            ("kustomize.toolkit.fluxcd.io/name", "infra"),
            ("kustomize.toolkit.fluxcd.io/namespace", "flux-system"),
        ]);
        let ann = map(&[("kustomize.toolkit.fluxcd.io/reconcile", "disabled")]);
        assert_eq!(
            ownership_markers(&labels, &ann),
            vec![
                "Flux Kustomization flux-system/infra",
                "réconciliation Flux désactivée sur l'objet"
            ]
        );
    }

    #[test]
    fn an_unmanaged_object_has_no_marker() {
        let labels = map(&[("app", "web")]);
        assert!(ownership_markers(&labels, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn distributions_come_from_version_groups_and_node_labels() {
        assert_eq!(distributions(Some("v1.35.4+k3s1"), [], None), vec!["k3s"]);
        assert_eq!(distributions(Some("v1.30.2-eks-1552ad0"), [], None), vec!["EKS"]);
        let facts = NodeFacts {
            label_keys: ["kubernetes.azure.com/cluster".to_string()].into(),
            ..NodeFacts::default()
        };
        assert_eq!(distributions(Some("v1.31.1"), [], Some(&facts)), vec!["AKS"]);
        assert_eq!(
            distributions(Some("v1.31.1"), ["config.openshift.io"], None),
            vec!["OpenShift"]
        );
        assert!(distributions(Some("v1.31.1"), ["apps"], None).is_empty());
    }

    #[test]
    fn addons_carry_their_preferred_versions() {
        let served = map(&[
            ("kustomize.toolkit.fluxcd.io", "kustomize.toolkit.fluxcd.io/v1"),
            ("helm.toolkit.fluxcd.io", "helm.toolkit.fluxcd.io/v2"),
            ("argoproj.io", "argoproj.io/v1alpha1"),
            ("apps", "apps/v1"),
        ]);
        assert_eq!(
            addon_lines(&served, &["Argo CD"]),
            vec![
                "Flux : kustomize.toolkit.fluxcd.io/v1, helm.toolkit.fluxcd.io/v2",
                "Argo CD : argoproj.io/v1alpha1",
            ]
        );
    }

    #[test]
    fn argoproj_is_split_by_kind() {
        assert_eq!(argo_products(["Application", "AppProject"]), vec!["Argo CD"]);
        assert_eq!(argo_products(["Rollout", "AnalysisRun"]), vec!["Argo Rollouts"]);
    }

    #[test]
    fn node_line_folds_heterogeneous_values() {
        let facts = NodeFacts {
            total: 250,
            read: 100,
            control_plane: 0,
            kubelet: vec!["v1.30.1".into(), "v1.30.2".into(), "v1.30.3".into(), "v1.30.4".into()],
            arch: vec!["amd64".into()],
            ..NodeFacts::default()
        };
        assert_eq!(
            facts.line(),
            "nodes 250 (100 lus) · kubelet v1.30.1, v1.30.2, v1.30.3 +1 · arch amd64"
        );
    }
}
