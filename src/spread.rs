//! Où les replicas d'un workload ont atterri, et ce que leur concentration coûte.
//!
//! Un Deployment à trois replicas qui les a tous posés sur le même node ne dit rien : ses trois
//! pods sont `Ready`, son rollout est terminé, sa vue Workloads est verte. La perte de ce node
//! emporte pourtant le service entier. C'est la seule question posée ici — combien de replicas
//! partagent un node, et le workload avait-il demandé qu'ils s'écartent.
//!
//! # Ce qui compte comme anormal
//!
//! Pas « deux pods sur un node » : six replicas sur trois nodes en mettent deux partout et c'est
//! exactement ce qu'on veut. L'écart se mesure à la répartition qu'un scheduler équilibré aurait
//! produite — `ceil(replicas / nodes éligibles)` — et seul ce qui la dépasse est signalé.
//!
//! # Les nodes éligibles
//!
//! Un workload qui ne peut aller que sur deux nodes n'a pas à s'excuser de n'être que sur deux
//! nodes. Les nodes retenus sont donc ceux qui sont `Ready`, ordonnançables, qui satisfont le
//! `nodeSelector` du template, et dont les taints `NoSchedule`/`NoExecute` sont tolérées. Sans ce
//! filtre, tout workload paraîtrait mal réparti parce qu'il évite les control-planes.
//!
//! # Ce qui n'est pas jugé
//!
//! Les `nodeAffinity` en expressions et les contraintes de topologie autres que le hostname ne
//! sont pas évaluées : un node est alors compté comme éligible. Un faux « mal réparti » se corrige
//! en lisant le manifeste ; un faux « bien réparti » se paierait le jour de la panne.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{Node, Pod, PodSpec, Taint, Toleration};
use kube::api::{Api, ListParams};
use kube::Client;

use crate::lang::{active, fill};
use crate::storage::{Hint, HintLevel};

/// La clé de topologie qu'un `topologySpreadConstraints` ou une `podAntiAffinity` doit porter pour
/// écarter des replicas node par node. Une contrainte par zone n'empêche rien à l'échelle du node.
const HOSTNAME_KEY: &str = "kubernetes.io/hostname";

/// Ce que le workload a demandé pour écarter ses replicas. Aucun de ces champs ne juge : ils
/// disent ce que le manifeste porte, et c'est le rapprochement avec le placement observé qui
/// devient un constat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Guard {
    /// `requiredDuringSchedulingIgnoredDuringExecution` sur le hostname : le scheduler refusera
    /// de poser deux replicas sur le même node.
    pub required_anti_affinity: bool,
    /// La même en `preferred` : le scheduler essaie, puis passe outre plutôt que de laisser un pod
    /// `Pending`. C'est la forme qui produit les concentrations silencieuses.
    pub preferred_anti_affinity: bool,
    /// `topologySpreadConstraints` sur le hostname, quel que soit son `whenUnsatisfiable`.
    pub topology_spread: bool,
    /// `DoNotSchedule` sur cette contrainte : elle est dure, comme une anti-affinité requise.
    pub topology_hard: bool,
}

impl Guard {
    /// Vrai quand rien dans le template ne demande que les replicas s'écartent par node.
    pub fn absent(&self) -> bool {
        !self.required_anti_affinity && !self.preferred_anti_affinity && !self.topology_spread
    }

    /// Vrai quand une règle dure interdit deux replicas sur un node. Deux replicas malgré elle est
    /// un fait à rapporter, pas une conclusion à tirer : le scheduler ne l'aurait pas permis, donc
    /// quelque chose d'autre a placé ces pods.
    pub fn hard(&self) -> bool {
        self.required_anti_affinity || self.topology_hard
    }
}

/// Un workload multi-replica et la répartition de ses pods vivants sur les nodes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Placement {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// Pods vivants comptés, pas `spec.replicas` : c'est ce qui tourne qui décide de ce qu'on perd.
    pub running: usize,
    /// Replicas demandés, pour distinguer un workload à moitié déployé d'un workload concentré.
    pub desired: i32,
    /// Nodes distincts qui portent ces pods.
    pub nodes: usize,
    /// Nodes sur lesquels ce workload pouvait aller, ce filtre-là étant ce qui rend le constat
    /// honnête. `None` quand la liste des nodes n'a pas pu être lue.
    pub eligible: Option<usize>,
    /// Le node qui en porte le plus, et combien.
    pub worst_node: String,
    pub worst_count: usize,
    /// Pods sans node : en attente de placement, ou impossibles à placer.
    pub pending: usize,
    pub guard: Guard,
    pub hints: Vec<Hint>,
}

impl Placement {
    /// La répartition la plus concentrée qu'un scheduler équilibré aurait produite.
    ///
    /// `None` quand les nodes éligibles n'ont pas pu être établis : il n'y a alors pas d'attendu
    /// auquel comparer, et rien n'est affirmé.
    pub fn balanced_max(&self) -> Option<usize> {
        let eligible = self.eligible?.min(self.running).max(1);
        Some(self.running.div_ceil(eligible))
    }

    /// Vrai quand un node porte plus de replicas que la répartition équilibrée n'en mettrait.
    pub fn concentrated(&self) -> bool {
        match self.balanced_max() {
            Some(max) => self.worst_count > max,
            None => false,
        }
    }

    /// Vrai quand tout le workload tient sur un node alors qu'il pouvait s'étaler : la perte de ce
    /// node est la perte du service.
    pub fn single_point(&self) -> bool {
        self.running > 1
            && self.nodes == 1
            && self.eligible.map(|n| n > 1).unwrap_or(false)
    }

    pub fn level(&self) -> HintLevel {
        self.hints.iter().map(|h| h.level).max().unwrap_or(HintLevel::Info)
    }
}

/// Ce qu'une passe a établi. `nodes_readable` faux veut dire que rien n'est comparé à rien : les
/// placements sont rendus tels quels, sans constat de concentration.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Spread {
    pub placements: Vec<Placement>,
    pub nodes_readable: bool,
    pub schedulable_nodes: usize,
    /// Workloads multi-replica examinés, concentrations signalées comprises.
    pub examined: usize,
}

impl Spread {
    /// Les placements à montrer, les plus graves d'abord, puis les plus concentrés.
    pub fn findings(&self) -> Vec<&Placement> {
        let mut out: Vec<&Placement> = self
            .placements
            .iter()
            .filter(|p| !p.hints.is_empty())
            .collect();
        out.sort_by(|a, b| {
            b.level()
                .cmp(&a.level())
                .then(b.worst_count.cmp(&a.worst_count))
                .then(a.namespace.cmp(&b.namespace))
                .then(a.name.cmp(&b.name))
        });
        out
    }

    pub fn single_points(&self) -> usize {
        self.placements.iter().filter(|p| p.single_point()).count()
    }

    pub fn concentrations(&self) -> usize {
        self.placements.iter().filter(|p| p.concentrated()).count()
    }
}

/// Lit les Deployments, StatefulSets, ReplicaSets, pods et nodes du cluster, et rapproche les
/// pods de leur workload par `ownerReferences`.
///
/// Les ReplicaSets servent de pont Pod → Deployment : c'est la même résolution que la vue Pods,
/// faite ici en une liste plutôt qu'un appel par pod.
pub async fn analyse(client: &Client) -> Result<Spread, String> {
    let deploys: Api<Deployment> = Api::all(client.clone());
    let stses: Api<StatefulSet> = Api::all(client.clone());
    let rses: Api<ReplicaSet> = Api::all(client.clone());
    let pods: Api<Pod> = Api::all(client.clone());
    let nodes: Api<Node> = Api::all(client.clone());

    let lp = ListParams::default();
    let deploys = deploys.list(&lp).await.map_err(|e| e.to_string())?.items;
    let stses = stses.list(&lp).await.map_err(|e| e.to_string())?.items;
    let rses = rses.list(&lp).await.map_err(|e| e.to_string())?.items;
    let pods = pods.list(&lp).await.map_err(|e| e.to_string())?.items;
    let node_list = nodes.list(&lp).await.ok().map(|l| l.items);

    Ok(build(&deploys, &stses, &rses, &pods, node_list.as_deref()))
}

/// Le calcul, séparé de la lecture pour être testable sur des objets construits à la main.
pub fn build(
    deploys: &[Deployment],
    stses: &[StatefulSet],
    rses: &[ReplicaSet],
    pods: &[Pod],
    nodes: Option<&[Node]>,
) -> Spread {
    let st = active();
    // ReplicaSet → Deployment, par `ownerReferences`, pour remonter un pod jusqu'au Deployment.
    let mut rs_owner: HashMap<(String, String), String> = HashMap::new();
    for rs in rses {
        let ns = rs.metadata.namespace.clone().unwrap_or_default();
        let name = rs.metadata.name.clone().unwrap_or_default();
        if let Some(owner) = rs
            .metadata
            .owner_references
            .as_ref()
            .and_then(|ors| ors.iter().find(|o| o.kind == "Deployment"))
        {
            rs_owner.insert((ns, name), owner.name.clone());
        }
    }

    // Les pods vivants par workload, comptés par node. Un pod en cours de suppression ne tient
    // plus sa place : il part, et le compter ferait apparaître une concentration qui se dissipe.
    let mut by_workload: HashMap<(String, String, String), WorkloadPods> = HashMap::new();
    for p in pods {
        let ns = p.metadata.namespace.clone().unwrap_or_default();
        if p.metadata.deletion_timestamp.is_some() {
            continue;
        }
        let phase = p.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
        if phase == "Succeeded" || phase == "Failed" {
            continue;
        }
        let Some((kind, name)) = workload_of(p, &ns, &rs_owner) else { continue };
        let entry = by_workload.entry((kind, ns, name)).or_default();
        match p.spec.as_ref().and_then(|s| s.node_name.clone()) {
            Some(node) if !node.is_empty() => {
                *entry.per_node.entry(node).or_insert(0) += 1;
                entry.running += 1;
            }
            _ => entry.pending += 1,
        }
    }

    let schedulable: Vec<&Node> = nodes
        .map(|list| list.iter().filter(|n| is_available(n)).collect())
        .unwrap_or_default();
    let nodes_readable = nodes.is_some();

    let mut placements = Vec::new();
    for (kind, namespace, name, desired, spec) in
        workloads(deploys, stses).into_iter()
    {
        let Some(found) = by_workload.get(&(kind.clone(), namespace.clone(), name.clone())) else {
            continue;
        };
        // Un workload à un seul replica n'a pas de répartition : sa disponibilité est un choix
        // assumé, pas un accident de placement.
        if desired <= 1 && found.running + found.pending <= 1 {
            continue;
        }
        let guard = guard_of(spec.as_ref());
        let eligible = nodes_readable.then(|| {
            let n = schedulable
                .iter()
                .filter(|node| accepts(node, spec.as_ref()))
                .count();
            // Les nodes qui portent déjà ce workload sont éligibles par constat, même quand le
            // filtre ne les retient pas : ils ont accepté ces pods.
            n.max(found.per_node.len())
        });
        let (worst_node, worst_count) = found
            .per_node
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(n, c)| (n.clone(), *c))
            .unwrap_or_default();

        let mut placement = Placement {
            kind: kind.clone(),
            namespace,
            name,
            running: found.running,
            desired,
            nodes: found.per_node.len(),
            eligible,
            worst_node,
            worst_count,
            pending: found.pending,
            guard,
            hints: Vec::new(),
        };
        placement.hints = judge(&placement, st);
        placements.push(placement);
    }

    placements.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then(a.kind.cmp(&b.kind))
            .then(a.name.cmp(&b.name))
    });
    Spread {
        examined: placements.len(),
        placements,
        nodes_readable,
        schedulable_nodes: schedulable.len(),
    }
}

/// Les constats d'un placement. L'ordre est celui de la gravité : ce qu'on perd, puis pourquoi
/// c'est arrivé.
fn judge(p: &Placement, st: &'static crate::lang::Strings) -> Vec<Hint> {
    let mut out = Vec::new();
    let eligible = p.eligible.unwrap_or(0).to_string();

    if p.single_point() {
        out.push(Hint {
            level: HintLevel::Danger,
            text: fill(
                st.spread_single_point,
                &[
                    ("n", &p.running.to_string()),
                    ("node", &p.worst_node),
                    ("eligible", &eligible),
                ],
            ),
        });
    } else if p.concentrated() {
        out.push(Hint {
            level: HintLevel::Warn,
            text: fill(
                st.spread_concentrated,
                &[
                    ("k", &p.worst_count.to_string()),
                    ("n", &p.running.to_string()),
                    ("node", &p.worst_node),
                    ("nodes", &p.nodes.to_string()),
                    ("eligible", &eligible),
                ],
            ),
        });
    }

    // Le pourquoi n'accompagne que ce qui a déjà été signalé : un workload bien réparti sans
    // anti-affinité est bien réparti, et le lui reprocher remplirait la vue de lignes sans objet.
    if !out.is_empty() {
        if p.guard.absent() {
            out.push(Hint { level: HintLevel::Info, text: st.spread_no_guard.to_string() });
        } else if p.guard.hard() && p.worst_count > 1 {
            out.push(Hint { level: HintLevel::Warn, text: st.spread_hard_guard_violated.to_string() });
        } else if p.guard.preferred_anti_affinity {
            out.push(Hint { level: HintLevel::Info, text: st.spread_preferred_only.to_string() });
        } else {
            out.push(Hint { level: HintLevel::Info, text: st.spread_guard_declared.to_string() });
        }
    }

    // Des pods sans node avec une règle dure et plus de replicas que de nodes éligibles : aucun
    // scheduler ne résoudra ça, et le workload restera incomplet jusqu'à ce qu'on arbitre.
    if p.pending > 0 && p.guard.hard() {
        if let Some(eligible_n) = p.eligible {
            if p.desired as usize > eligible_n {
                out.push(Hint {
                    level: HintLevel::Danger,
                    text: fill(
                        st.spread_impossible,
                        &[
                            ("pending", &p.pending.to_string()),
                            ("desired", &p.desired.to_string()),
                            ("eligible", &eligible_n.to_string()),
                        ],
                    ),
                });
            }
        }
    }

    out
}

#[derive(Default)]
struct WorkloadPods {
    per_node: BTreeMap<String, usize>,
    running: usize,
    pending: usize,
}

/// `(kind, namespace, name, replicas, template spec)` des workloads dont la répartition a un sens.
///
/// Les DaemonSets sont dehors : un pod par node est leur définition, pas une concentration. Les
/// Jobs aussi : un parallélisme qui partage un node ne coûte pas une indisponibilité.
fn workloads(
    deploys: &[Deployment],
    stses: &[StatefulSet],
) -> Vec<(String, String, String, i32, Option<PodSpec>)> {
    let mut out = Vec::new();
    for d in deploys {
        out.push((
            "Deployment".to_string(),
            d.metadata.namespace.clone().unwrap_or_default(),
            d.metadata.name.clone().unwrap_or_default(),
            d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1),
            d.spec.as_ref().and_then(|s| s.template.spec.clone()),
        ));
    }
    for s in stses {
        out.push((
            "StatefulSet".to_string(),
            s.metadata.namespace.clone().unwrap_or_default(),
            s.metadata.name.clone().unwrap_or_default(),
            s.spec.as_ref().and_then(|sp| sp.replicas).unwrap_or(1),
            s.spec.as_ref().and_then(|sp| sp.template.spec.clone()),
        ));
    }
    out
}

/// Le workload d'un pod : son `ownerReferences`, un cran plus haut quand c'est un ReplicaSet.
fn workload_of(
    p: &Pod,
    namespace: &str,
    rs_owner: &HashMap<(String, String), String>,
) -> Option<(String, String)> {
    let owner = p
        .metadata
        .owner_references
        .as_ref()?
        .iter()
        .find(|o| matches!(o.kind.as_str(), "ReplicaSet" | "StatefulSet"))?;
    match owner.kind.as_str() {
        "StatefulSet" => Some(("StatefulSet".to_string(), owner.name.clone())),
        _ => rs_owner
            .get(&(namespace.to_string(), owner.name.clone()))
            .map(|d| ("Deployment".to_string(), d.clone())),
    }
}

/// Ce que le template demande pour écarter ses replicas par node.
fn guard_of(spec: Option<&PodSpec>) -> Guard {
    let mut guard = Guard::default();
    let Some(spec) = spec else { return guard };

    if let Some(anti) = spec
        .affinity
        .as_ref()
        .and_then(|a| a.pod_anti_affinity.as_ref())
    {
        if let Some(required) = &anti.required_during_scheduling_ignored_during_execution {
            if required.iter().any(|t| t.topology_key == HOSTNAME_KEY) {
                guard.required_anti_affinity = true;
            }
        }
        if let Some(preferred) = &anti.preferred_during_scheduling_ignored_during_execution {
            if preferred
                .iter()
                .any(|t| t.pod_affinity_term.topology_key == HOSTNAME_KEY)
            {
                guard.preferred_anti_affinity = true;
            }
        }
    }

    for c in spec.topology_spread_constraints.iter().flatten() {
        if c.topology_key != HOSTNAME_KEY {
            continue;
        }
        guard.topology_spread = true;
        // `maxSkew: 1` en `DoNotSchedule` est aussi dur qu'une anti-affinité requise dès que les
        // replicas tiennent sur les nodes éligibles ; au-delà de 1, l'écart toléré est justement
        // ce qui produit deux replicas sur un node sans rien violer.
        if c.when_unsatisfiable == "DoNotSchedule" && c.max_skew <= 1 {
            guard.topology_hard = true;
        }
    }
    guard
}

/// Un node qui peut recevoir des pods aujourd'hui : `Ready` et non cordonné.
fn is_available(n: &Node) -> bool {
    let ready = n
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .map(|c| c.status == "True")
        .unwrap_or(false);
    let cordoned = n.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false);
    ready && !cordoned
}

/// Vrai quand ce node satisfait le `nodeSelector` du template et que ses taints bloquantes sont
/// tolérées. Les `nodeAffinity` ne sont pas évaluées — voir l'en-tête du module.
fn accepts(node: &Node, spec: Option<&PodSpec>) -> bool {
    let Some(spec) = spec else { return true };
    let labels = node.metadata.labels.clone().unwrap_or_default();
    for (k, v) in spec.node_selector.iter().flatten() {
        if labels.get(k) != Some(v) {
            return false;
        }
    }
    let empty: Vec<Toleration> = Vec::new();
    let tolerations = spec.tolerations.as_ref().unwrap_or(&empty);
    for taint in node.spec.as_ref().and_then(|s| s.taints.as_ref()).into_iter().flatten() {
        if !matches!(taint.effect.as_str(), "NoSchedule" | "NoExecute") {
            continue;
        }
        if !tolerations.iter().any(|t| tolerates(t, taint)) {
            return false;
        }
    }
    true
}

/// La règle de `kubectl`: un `effect` vide vaut tous les effets, un `key` vide avec l'opérateur
/// `Exists` tolère tout, et `Equal` — l'opérateur par défaut — compare la valeur.
fn tolerates(t: &Toleration, taint: &Taint) -> bool {
    if let Some(effect) = t.effect.as_deref() {
        if !effect.is_empty() && effect != taint.effect {
            return false;
        }
    }
    let operator = t.operator.as_deref().unwrap_or("Equal");
    let key = t.key.as_deref().unwrap_or("");
    if key.is_empty() {
        return operator == "Exists";
    }
    if key != taint.key {
        return false;
    }
    match operator {
        "Exists" => true,
        _ => t.value.as_deref().unwrap_or("") == taint.value.as_deref().unwrap_or(""),
    }
}

/// Les namespaces touchés par au moins un constat, pour la ligne de résumé.
pub fn namespaces(spread: &Spread) -> BTreeSet<String> {
    spread
        .findings()
        .iter()
        .map(|p| p.namespace.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(name: &str, labels: Value, taints: Value) -> Node {
        serde_json::from_value(json!({
            "metadata": { "name": name, "labels": labels },
            "spec": { "taints": taints },
            "status": { "conditions": [{ "type": "Ready", "status": "True" }] },
        }))
        .unwrap()
    }

    fn plain_node(name: &str) -> Node {
        node(name, json!({}), json!([]))
    }

    fn deployment(name: &str, replicas: i32, spec: Value) -> Deployment {
        serde_json::from_value(json!({
            "metadata": { "name": name, "namespace": "ns" },
            "spec": {
                "replicas": replicas,
                "selector": { "matchLabels": { "app": name } },
                "template": { "metadata": { "labels": { "app": name } }, "spec": spec },
            },
        }))
        .unwrap()
    }

    fn replicaset(name: &str, deployment: &str) -> ReplicaSet {
        serde_json::from_value(json!({
            "metadata": {
                "name": name,
                "namespace": "ns",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "Deployment",
                    "name": deployment, "uid": "u",
                }],
            },
            "spec": { "selector": { "matchLabels": { "app": deployment } } },
        }))
        .unwrap()
    }

    fn pod(name: &str, rs: &str, node_name: Option<&str>) -> Pod {
        serde_json::from_value(json!({
            "metadata": {
                "name": name,
                "namespace": "ns",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": rs, "uid": "u",
                }],
            },
            "spec": { "nodeName": node_name },
            "status": { "phase": "Running" },
        }))
        .unwrap()
    }

    use serde_json::Value;

    #[test]
    fn two_replicas_on_one_node_of_three_is_a_single_point() {
        let deploys = vec![deployment("web", 2, json!({ "containers": [] }))];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), pod("web-1-b", "web-1", Some("n1"))];
        let nodes = vec![plain_node("n1"), plain_node("n2"), plain_node("n3")];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        let p = &spread.placements[0];
        assert_eq!(p.running, 2);
        assert_eq!(p.worst_count, 2);
        assert_eq!(p.eligible, Some(3));
        assert!(p.single_point());
        assert_eq!(p.level(), HintLevel::Danger);
        // Rien dans le template ne demandait qu'ils s'écartent : le constat le dit.
        assert!(p.guard.absent());
        assert_eq!(p.hints.len(), 2);
    }

    #[test]
    fn six_replicas_two_per_node_is_a_balanced_spread() {
        let deploys = vec![deployment("web", 6, json!({ "containers": [] }))];
        let rses = vec![replicaset("web-1", "web")];
        let pods: Vec<Pod> = ["n1", "n1", "n2", "n2", "n3", "n3"]
            .iter()
            .enumerate()
            .map(|(i, n)| pod(&format!("web-1-{i}"), "web-1", Some(n)))
            .collect();
        let nodes = vec![plain_node("n1"), plain_node("n2"), plain_node("n3")];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        let p = &spread.placements[0];
        assert_eq!(p.worst_count, 2);
        assert_eq!(p.balanced_max(), Some(2));
        assert!(!p.concentrated());
        assert!(p.hints.is_empty());
        assert_eq!(spread.concentrations(), 0);
    }

    #[test]
    fn a_single_eligible_node_is_not_a_bad_spread() {
        // Deux replicas, trois nodes, mais deux portent un taint que le template ne tolère pas : ce
        // workload n'avait qu'un node où aller, et on ne le lui reproche pas.
        let deploys = vec![deployment("web", 2, json!({ "containers": [] }))];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), pod("web-1-b", "web-1", Some("n1"))];
        let taint = json!([{ "key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule" }]);
        let nodes = vec![
            plain_node("n1"),
            node("n2", json!({}), taint.clone()),
            node("n3", json!({}), taint),
        ];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        let p = &spread.placements[0];
        assert_eq!(p.eligible, Some(1));
        assert!(!p.single_point());
        assert!(!p.concentrated());
        assert!(p.hints.is_empty());
    }

    #[test]
    fn a_node_selector_narrows_the_eligible_set() {
        let deploys = vec![deployment(
            "web",
            2,
            json!({ "containers": [], "nodeSelector": { "pool": "edge" } }),
        )];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), pod("web-1-b", "web-1", Some("n1"))];
        let nodes = vec![
            node("n1", json!({ "pool": "edge" }), json!([])),
            plain_node("n2"),
            plain_node("n3"),
        ];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        assert_eq!(spread.placements[0].eligible, Some(1));
        assert!(spread.placements[0].hints.is_empty());
    }

    #[test]
    fn a_preferred_anti_affinity_is_named_as_the_reason() {
        let anti = json!({
            "containers": [],
            "affinity": { "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [{
                    "weight": 100,
                    "podAffinityTerm": {
                        "topologyKey": "kubernetes.io/hostname",
                        "labelSelector": { "matchLabels": { "app": "web" } },
                    },
                }],
            }},
        });
        let deploys = vec![deployment("web", 2, anti)];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), pod("web-1-b", "web-1", Some("n1"))];
        let nodes = vec![plain_node("n1"), plain_node("n2")];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        let p = &spread.placements[0];
        assert!(p.guard.preferred_anti_affinity);
        assert!(!p.guard.hard());
        assert!(p.single_point());
        assert!(p.hints.iter().any(|h| h.level == HintLevel::Danger));
    }

    #[test]
    fn a_hard_rule_that_cannot_be_satisfied_is_reported() {
        let anti = json!({
            "containers": [],
            "topologySpreadConstraints": [{
                "maxSkew": 1,
                "topologyKey": "kubernetes.io/hostname",
                "whenUnsatisfiable": "DoNotSchedule",
                "labelSelector": { "matchLabels": { "app": "web" } },
            }],
        });
        let deploys = vec![deployment("web", 3, anti)];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![
            pod("web-1-a", "web-1", Some("n1")),
            pod("web-1-b", "web-1", Some("n2")),
            pod("web-1-c", "web-1", None),
        ];
        let nodes = vec![plain_node("n1"), plain_node("n2")];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        let p = &spread.placements[0];
        assert!(p.guard.topology_hard);
        assert_eq!(p.pending, 1);
        assert!(p
            .hints
            .iter()
            .any(|h| h.level == HintLevel::Danger && h.text.contains("3")));
    }

    #[test]
    fn unreadable_nodes_describe_without_judging() {
        let deploys = vec![deployment("web", 2, json!({ "containers": [] }))];
        let rses = vec![replicaset("web-1", "web")];
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), pod("web-1-b", "web-1", Some("n1"))];

        let spread = build(&deploys, &[], &rses, &pods, None);
        let p = &spread.placements[0];
        assert!(!spread.nodes_readable);
        assert_eq!(p.eligible, None);
        assert_eq!(p.balanced_max(), None);
        assert!(!p.single_point());
        assert!(p.hints.is_empty());
    }

    #[test]
    fn a_terminating_pod_does_not_hold_its_place() {
        let deploys = vec![deployment("web", 2, json!({ "containers": [] }))];
        let rses = vec![replicaset("web-1", "web")];
        let mut leaving = pod("web-1-b", "web-1", Some("n1"));
        leaving.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        let pods = vec![pod("web-1-a", "web-1", Some("n1")), leaving];
        let nodes = vec![plain_node("n1"), plain_node("n2")];

        let spread = build(&deploys, &[], &rses, &pods, Some(&nodes));
        // Un seul pod compte, donc plus de concentration à signaler.
        assert_eq!(spread.placements[0].running, 1);
        assert!(spread.placements[0].hints.is_empty());
    }

    #[test]
    fn a_statefulset_is_read_through_its_own_owner_reference() {
        let sts: StatefulSet = serde_json::from_value(json!({
            "metadata": { "name": "db", "namespace": "ns" },
            "spec": {
                "replicas": 2,
                "serviceName": "db",
                "selector": { "matchLabels": { "app": "db" } },
                "template": { "metadata": { "labels": { "app": "db" } }, "spec": { "containers": [] } },
            },
        }))
        .unwrap();
        let mut p0: Pod = serde_json::from_value(json!({
            "metadata": {
                "name": "db-0", "namespace": "ns",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "StatefulSet", "name": "db", "uid": "u",
                }],
            },
            "spec": { "nodeName": "n1" },
            "status": { "phase": "Running" },
        }))
        .unwrap();
        let mut p1 = p0.clone();
        p1.metadata.name = Some("db-1".to_string());
        p0.metadata.name = Some("db-0".to_string());
        let nodes = vec![plain_node("n1"), plain_node("n2")];

        let spread = build(&[], &[sts], &[], &[p0, p1], Some(&nodes));
        assert_eq!(spread.placements[0].kind, "StatefulSet");
        assert!(spread.placements[0].single_point());
    }
}
