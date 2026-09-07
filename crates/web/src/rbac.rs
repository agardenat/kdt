//! La vue RBAC : qui peut faire quoi sur ce cluster, et par quel chemin.
//!
//! Ce que cette vue apporte n'est pas la liste des RoleBindings — `kubectl get rolebindings -A` la
//! donne — mais le **score** et le **graphe**. Un Role seul n'accorde rien tant qu'il n'est pas lié,
//! et le même ClusterRole est anodin en RoleBinding namespacée et critique en ClusterRoleBinding :
//! la sévérité se calcule donc par liaison, à partir des règles résolues, des sujets et du
//! namespace. C'est `kdt::rbac` qui la calcule, ici comme dans le TUI.
//!
//! # Les quatre lectures
//!
//! Le même graphe se lit par quatre bouts, et c'est le serveur qui construit l'arbre parce qu'il
//! est le seul à avoir les arêtes : la liste d'audit à plat, l'identité et tout ce qu'elle cumule,
//! la liaison dépliée, et le rôle — la seule lecture qui montre un ClusterRole re-accordé namespace
//! par namespace comme **un** nœud, et non comme dix lignes sans rapport.
//!
//! # Portée
//!
//! Une portée narrows ce qui est **montré**, jamais ce qui est **lu** : une arête d'agrégation, un
//! compte de re-liaisons ou un « personne ne lie ce rôle » calculés sur une liste partielle seraient
//! faux. La règle de ce qu'un namespace contient — ses RoleBindings, plus les liaisons accordées à
//! ses ServiceAccounts — est celle de `kdt::rbac::binding_in_ns`.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use kdt::rbac::{
    binding_in_ns, build_rbac_rows, default_folded, join_or_star, record_for_row, role_in_ns,
    roles_reached_in_ns, RbacBinding, RbacGraph, RbacNode, RbacOrient, RbacRow, RbacState,
    RbacSubjectNode, RoleEntry, SaEntry, Severity,
};
use serde::Deserialize;

use crate::api::session_client;
use crate::AppState;

#[derive(Deserialize)]
pub struct RbacQuery {
    /// La portée : un namespace, ou vide pour tout le cluster.
    #[serde(default)]
    ns: String,
    /// Par quel bout le graphe est lu. C'est le `t` du TUI.
    #[serde(default)]
    orient: RbacOrient,
    /// Le plancher de sévérité. Sur un vrai cluster, tout afficher revient à ne rien montrer :
    /// l'essentiel des liaisons est de la plomberie en lecture seule.
    #[serde(default)]
    min_sev: Severity,
}

/// Le graphe RBAC du cluster, en lignes d'arbre.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RbacQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let scope = query.ns.trim().to_string();
    let ns = (!scope.is_empty()).then_some(scope.as_str());

    let shared = kdt::rbac::new_rbac_state();
    // La liste par défaut des namespaces où une liaison locale escalade tout le cluster. Le TUI y
    // ajoute ce que sa configuration déclare ; kdt-web n'a pas cette configuration, et une liste
    // inventée ici ferait diverger les deux scores.
    let critical = kdt::rbac::critical_namespaces(&[]);
    kdt::rbac::fetch_rbac(client, critical, shared.clone()).await;
    let inventory: RbacState = shared.lock().expect("rbac poisoned").clone();

    let subjects = kdt::rbac::build_subjects(&inventory.bindings, &inventory.service_accounts);
    let order = inventory.role_order();
    let graph = RbacGraph {
        bindings: &inventory.bindings,
        roles: &inventory.roles,
        service_accounts: &inventory.service_accounts,
        subjects: &subjects,
        role_order: &order,
    };

    // Déplié : le pliage est un état de la personne qui regarde. Chaque ligne porte en revanche le
    // pli que kdt poserait, pour que le navigateur n'ait pas à redire quelle branche mérite d'être
    // ouverte — sur un vrai cluster l'arbre des sujets fait des milliers de lignes.
    let nodes = build_rbac_rows(&graph, query.orient, query.min_sev, ns, &HashSet::new());
    let rows: Vec<serde_json::Value> = nodes.iter().map(|node| row_json(&graph, node)).collect();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": counts_json(&inventory, ns),
        // Une liste de ServiceAccounts illisible change ce que la vue peut affirmer : tant que
        // c'est vrai, aucun « ce compte n'existe pas » n'est prononcé nulle part.
        "sa_degraded": inventory.sa_degraded,
        "scope": scope,
        "error": inventory.error,
    }))
    .into_response()
}

/// Les comptes du titre, dans la portée demandée.
///
/// Sous une portée ils décrivent ce que la portée contient : annoncer les totaux du cluster sur une
/// liste réduite décrirait une vue que personne ne regarde.
fn counts_json(s: &RbacState, ns: Option<&str>) -> serde_json::Value {
    let mut by_sev = [0usize; 5];
    let (bindings, roles, sas) = match ns {
        None => {
            for b in &s.bindings {
                by_sev[b.severity as usize] += 1;
            }
            (s.bindings.len(), s.roles.len(), s.service_accounts.len())
        }
        Some(ns) => {
            let mut n_bind = 0usize;
            for b in s.bindings.iter().filter(|b| binding_in_ns(b, ns)) {
                by_sev[b.severity as usize] += 1;
                n_bind += 1;
            }
            let reached = roles_reached_in_ns(&s.bindings, ns);
            let n_roles = s
                .roles
                .iter()
                .enumerate()
                .filter(|(ri, r)| role_in_ns(r, *ri, &reached, ns))
                .count();
            let n_sa = s.service_accounts.iter().filter(|sa| sa.namespace == ns).count();
            (n_bind, n_roles, n_sa)
        }
    };
    serde_json::json!({
        "bindings": bindings,
        "roles": roles,
        "service_accounts": sas,
        "info": by_sev[Severity::Info as usize],
        "low": by_sev[Severity::Low as usize],
        "medium": by_sev[Severity::Medium as usize],
        "high": by_sev[Severity::High as usize],
        "critical": by_sev[Severity::Critical as usize],
    })
}

/// Une ligne de l'arbre : ce qu'elle désigne, sa place, et ce que kdt en dit.
fn row_json(g: &RbacGraph, node: &RbacNode) -> serde_json::Value {
    let mut value = match &node.row {
        RbacRow::Subject { idx, .. } => subject_json(g, &g.subjects[*idx]),
        RbacRow::Binding { idx, .. } => binding_json(g, &g.bindings[*idx]),
        RbacRow::Role { idx, .. } => role_json(g, &g.roles[*idx], "role"),
        RbacRow::Contributor { idx, .. } => role_json(g, &g.roles[*idx], "contributor"),
        RbacRow::NsGroup { role, namespace, .. } => {
            let n = g
                .bindings
                .iter()
                .filter(|b| {
                    b.role_idx == Some(*role)
                        && matches!(&b.scope, kdt::rbac::Scope::Namespace(x) if x == namespace)
                })
                .count();
            serde_json::json!({
                "row": "nsgroup",
                "namespace": namespace,
                "role_name": g.roles[*role].name,
                "bindings": n,
            })
        }
        RbacRow::Rule { role, rule, .. } => {
            let rl = &g.roles[*role].rules[*rule];
            serde_json::json!({
                "row": "rule",
                "role_name": g.roles[*role].name,
                "verbs": join_or_star(&rl.verbs),
                "resources": join_or_star(&rl.resources),
                "api_groups": join_or_star(&rl.api_groups),
                "resource_names": rl.resource_names,
            })
        }
        RbacRow::SubjectLeaf { binding, subject, .. } => {
            let b = &g.bindings[*binding];
            let s = &b.subjects[*subject];
            let sa = b
                .sa_idx
                .get(*subject)
                .copied()
                .flatten()
                .and_then(|i| g.service_accounts.get(i));
            serde_json::json!({
                "row": "subject-leaf",
                "kind": s.kind,
                "name": s.name,
                "label": s.label(),
                "short_label": s.short_label(),
                // Un sujet qui nomme un ServiceAccount que personne n'a créé n'accorde rien
                // aujourd'hui : la ligne le dit, plutôt que de ressembler à n'importe quel autre.
                "missing": sa.map(|x| !x.exists).unwrap_or(false),
            })
        }
    };

    if let Some(o) = value.as_object_mut() {
        o.insert("uid".into(), node.uid.clone().into());
        o.insert("depth".into(), node.row.depth().into());
        o.insert("has_children".into(), node.row.has_children().into());
        // Le pli que kdt poserait : tout ce dont le pire nœud est sous HIGH se referme. Un pli posé
        // à la main gagne toujours.
        o.insert("fold_default".into(), fold_default(g, &node.row).into());
        // La clé de pli est l'identité du **nœud**, pas son chemin : un ClusterRole atteint par deux
        // liaisons se replie d'un seul geste, partout où il apparaît.
        o.insert(
            "fold_key".into(),
            match &node.fold_key {
                Some(k) => k.clone().into(),
                None => serde_json::Value::Null,
            },
        );
        o.insert(
            "record".into(),
            serde_json::to_value(record_for_row(g, node)).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn fold_default(g: &RbacGraph, row: &RbacRow) -> bool {
    match row {
        RbacRow::Subject { idx, .. } => g.subjects.get(*idx).is_none_or(|n| default_folded(n.severity)),
        RbacRow::Binding { idx, .. } => g.bindings.get(*idx).is_none_or(|b| default_folded(b.severity)),
        RbacRow::Role { idx, .. } => g.roles.get(*idx).is_none_or(|r| default_folded(r.severity)),
        // Un groupe par namespace n'est émis que lorsqu'il a de quoi le remplir.
        _ => false,
    }
}

fn binding_json(g: &RbacGraph, b: &RbacBinding) -> serde_json::Value {
    let mut value = serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(o) = value.as_object_mut() {
        o.insert("row".into(), "binding".into());
        o.insert("scope_label".into(), b.scope.label().into());
        // Une liaison namespacée dans un namespace critique mérite la même attention qu'une
        // liaison cluster : un pied dans la porte y escalade partout.
        o.insert("scope_alarming".into(), b.scope_alarming().into());
        o.insert("role_label".into(), b.role_ref.label().into());
        o.insert("subject_label".into(), b.subject_label().into());
        o.insert("provenance_label".into(), b.provenance.label().into());
        o.insert("sev_label".into(), b.severity.label().into());
        o.insert("sev_icon".into(), b.severity.icon().into());
        o.insert("risk_top".into(), b.risk_top().into());
        o.insert("risk_tags".into(), b.risk_tags().into());
        o.insert(
            "subject_rows".into(),
            b.subjects
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let missing = b
                        .sa_idx
                        .get(i)
                        .copied()
                        .flatten()
                        .and_then(|x| g.service_accounts.get(x))
                        .map(|sa| !sa.exists)
                        .unwrap_or(false);
                    serde_json::json!({
                        "label": s.label(),
                        "short_label": s.short_label(),
                        "kind": s.kind,
                        "missing": missing,
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
        o.insert("rule_rows".into(), rules_json(&b.rules));
    }
    value
}

fn role_json(g: &RbacGraph, r: &RoleEntry, row: &str) -> serde_json::Value {
    let mut value = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(o) = value.as_object_mut() {
        o.insert("row".into(), row.into());
        o.insert("kind_label".into(), r.kind.label().into());
        o.insert("kind_short".into(), r.kind.short().into());
        o.insert("sev_label".into(), r.severity.label().into());
        o.insert("sev_icon".into(), r.severity.icon().into());
        o.insert("provenance_label".into(), r.provenance.label().into());
        // Les deux états que seule cette lecture montre : une définition re-accordée namespace par
        // namespace, et une que personne ne lie.
        o.insert("is_template".into(), r.is_template().into());
        o.insert("is_unbound".into(), r.is_unbound().into());
        // Les arêtes d'agrégation résolues en noms : le navigateur reçoit des index dans un graphe
        // qu'il n'a pas, et une arête redessinée à partir des labels serait une seconde
        // implémentation de la règle.
        o.insert(
            "aggregates_names".into(),
            r.aggregates
                .iter()
                .filter_map(|&i| g.roles.get(i))
                .map(|c| serde_json::json!({ "name": c.name, "rules": c.rules.len() }))
                .collect::<Vec<_>>()
                .into(),
        );
        o.insert(
            "aggregates_into_names".into(),
            r.aggregates_into
                .iter()
                .filter_map(|&i| g.roles.get(i))
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .into(),
        );
        o.insert("rule_rows".into(), rules_json(&r.rules));
    }
    value
}

fn subject_json(g: &RbacGraph, n: &RbacSubjectNode) -> serde_json::Value {
    let sa: Option<&SaEntry> = n.sa.and_then(|i| g.service_accounts.get(i));
    let mut value = serde_json::to_value(n).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(o) = value.as_object_mut() {
        o.insert("row".into(), "subject".into());
        o.insert("short_label".into(), kdt::rbac::short_identity(&n.label).into());
        o.insert("sev_label".into(), n.severity.label().into());
        o.insert("sev_icon".into(), n.severity.icon().into());
        // `missing` n'est vrai que si la liste des ServiceAccounts a été lue : `sa_degraded` la
        // rend inconnue, et affirmer une absence sur une lecture refusée serait une fausse alerte.
        o.insert("missing".into(), sa.map(|s| !s.exists).unwrap_or(false).into());
        o.insert(
            "sa".into(),
            match sa {
                Some(s) => serde_json::json!({
                    "exists": s.exists,
                    "automount": s.automount,
                    "secrets": s.secrets,
                    "image_pull_secrets": s.image_pull_secrets,
                    "provenance_label": s.provenance.label(),
                    "provenance": s.provenance,
                    "source": s.source,
                    "age": s.age,
                }),
                None => serde_json::Value::Null,
            },
        );
        // Les grants de cette identité, résolus ici : le navigateur n'a que des index.
        o.insert(
            "grants".into(),
            n.bindings
                .iter()
                .filter_map(|&bi| g.bindings.get(bi))
                .map(|b| {
                    serde_json::json!({
                        "severity": b.severity,
                        "sev_label": b.severity.label(),
                        "sev_icon": b.severity.icon(),
                        "role_label": b.role_ref.label(),
                        "scope_label": b.scope.label(),
                        "risk_top": b.risk_top(),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
    }
    value
}

fn rules_json(rules: &[kdt::rbac::PolicyRule]) -> serde_json::Value {
    rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "verbs": join_or_star(&r.verbs),
                "resources": join_or_star(&r.resources),
                "api_groups": join_or_star(&r.api_groups),
                "resource_names": r.resource_names,
            })
        })
        .collect::<Vec<_>>()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::rbac::{Finding, PolicyRule, RoleKind, RoleRef, Scope, Subject};

    fn binding() -> RbacBinding {
        RbacBinding {
            scope: Scope::ClusterWide,
            binding_kind: "ClusterRoleBinding".into(),
            binding_name: "ci-admin".into(),
            subjects: vec![Subject {
                kind: "ServiceAccount".into(),
                name: "ci".into(),
                namespace: Some("build".into()),
            }],
            role_ref: RoleRef { kind: "ClusterRole".into(), name: "cluster-admin".into() },
            rules: vec![PolicyRule {
                api_groups: vec!["*".into()],
                resources: vec!["*".into()],
                verbs: vec!["*".into()],
                resource_names: vec![],
            }],
            via_clusterrole: true,
            aggregated: false,
            provenance: kdt::rbac::Provenance::Kubectl,
            source: None,
            severity: Severity::Critical,
            findings: vec![Finding {
                sev: Severity::Critical,
                tag: "cluster-admin",
                detail: "accorde tout, partout".into(),
            }],
            age: "12d".into(),
            role_idx: None,
            sa_idx: vec![None],
        }
    }

    fn graph<'a>(
        bindings: &'a [RbacBinding],
        roles: &'a [RoleEntry],
        sas: &'a [SaEntry],
        subjects: &'a [RbacSubjectNode],
        order: &'a [usize],
    ) -> RbacGraph<'a> {
        RbacGraph { bindings, roles, service_accounts: sas, subjects, role_order: order }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`. En renommer une côté serveur se
    // verrait ici plutôt qu'à l'écran, sous la forme d'une colonne vide.
    #[test]
    fn une_ligne_de_liaison_porte_ce_que_le_navigateur_lit() {
        let bindings = vec![binding()];
        let (roles, sas, subjects, order) = (vec![], vec![], vec![], vec![]);
        let g = graph(&bindings, &roles, &sas, &subjects, &order);
        let nodes = build_rbac_rows(&g, RbacOrient::Flat, Severity::Info, None, &HashSet::new());
        let v = row_json(&g, &nodes[0]);

        assert_eq!(v["row"], "binding");
        assert_eq!(v["uid"], "ClusterRoleBinding|/ci-admin");
        assert_eq!(v["depth"], 0);
        assert_eq!(v["sev_label"], "CRIT");
        assert_eq!(v["scope_label"], "cluster");
        assert_eq!(v["role_label"], "cluster-admin (CRole)");
        assert_eq!(v["subject_label"], "sa:build/ci");
        assert_eq!(v["provenance_label"], "kubectl");
        assert_eq!(v["risk_top"], "cluster-admin");
        // Une liaison critique ne se replie pas : c'est celle qu'on est venu voir.
        assert_eq!(v["fold_default"], false);
        assert_eq!(v["record"]["kind"], "ClusterRoleBinding");
        assert_eq!(v["rule_rows"][0]["verbs"], "*");
    }

    // Le plancher de sévérité écarte le bruit, et il est appliqué côté serveur : la liaison qui
    // reste doit être exactement celle que le TUI garderait.
    #[test]
    fn le_plancher_de_severite_ecarte_ce_qui_est_dessous() {
        let mut low = binding();
        low.severity = Severity::Low;
        low.binding_name = "reader".into();
        let bindings = vec![binding(), low];
        let (roles, sas, subjects, order) = (vec![], vec![], vec![], vec![]);
        let g = graph(&bindings, &roles, &sas, &subjects, &order);
        let nodes = build_rbac_rows(&g, RbacOrient::Flat, Severity::High, None, &HashSet::new());
        assert_eq!(nodes.len(), 1);
        assert_eq!(row_json(&g, &nodes[0])["binding_name"], "ci-admin");
    }

    // Un rôle que personne ne lie n'accorde rien aujourd'hui, et un ClusterRole re-accordé dans
    // plusieurs namespaces est un modèle : les deux états que seule cette lecture montre.
    #[test]
    fn un_role_dit_s_il_est_modele_ou_orphelin() {
        let role = RoleEntry {
            kind: RoleKind::ClusterRole,
            namespace: String::new(),
            name: "ns-owner".into(),
            rules: vec![],
            own_rules: 0,
            aggregated: false,
            aggregates: vec![],
            aggregates_into: vec![],
            aggregation_partial: false,
            bound_cluster: 0,
            bound_namespaces: vec!["a".into(), "b".into()],
            provenance: kdt::rbac::Provenance::Bootstrap,
            source: None,
            age: "3d".into(),
            severity: Severity::Medium,
            findings: vec![],
        };
        let roles = vec![role];
        let (bindings, sas, subjects) = (vec![], vec![], vec![]);
        let order = vec![0usize];
        let g = graph(&bindings, &roles, &sas, &subjects, &order);
        let nodes = build_rbac_rows(&g, RbacOrient::Role, Severity::Info, None, &HashSet::new());
        let v = row_json(&g, &nodes[0]);
        assert_eq!(v["row"], "role");
        assert_eq!(v["is_template"], true);
        assert_eq!(v["is_unbound"], false);
        assert_eq!(v["kind_short"], "CRole");
        assert_eq!(v["provenance_label"], "rbac-defaults");
    }
}
