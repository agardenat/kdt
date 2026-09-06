//! Ce que ce cluster sait faire : quels add-ons y sont installés.
//!
//! Une vue Argo CD sur un cluster sans Argo CD n'a rien à montrer, et la proposer fait perdre du
//! temps à qui la choisit avant de découvrir qu'elle est vide. La question « est-ce installé ? »
//! est un fait sur le cluster, pas une décision d'affichage : elle vit donc ici, avec le reste du
//! métier, et non dans l'interface qui s'en sert pour composer son menu.
//!
//! # La sonde
//!
//! Un seul appel — la liste des groupes d'API servis — et non une découverte par kind. Sonder
//! chaque kind coûterait une requête par add-on, et l'absence d'un groupe est déjà la réponse :
//! un CRD ne peut pas exister sans que son groupe soit servi.
//!
//! `/apis` est couvert par le rôle `system:discovery`, lié à `system:authenticated` : la sonde
//! aboutit donc sans droit particulier, y compris pour quelqu'un qui ne peut lire aucun objet.
//!
//! # Une sonde en échec n'est pas un cluster nu
//!
//! [`detect`] rend un `Result`, et c'est le cœur de ce module. Un apiserver injoignable et un
//! cluster sans le moindre add-on donneraient sinon la même réponse — tout à `false` — et le
//! symptôme serait un menu amputé : « où est passée la vue Flux ? » pour un simple problème de
//! réseau. L'appelant doit pouvoir choisir de ne rien filtrer plutôt que de filtrer sur une
//! réponse qu'il n'a pas eue.
//!
//! # Ce qui n'est pas ici
//!
//! Les vues qui reposent sur les objets natifs de Kubernetes — évènements, workloads, capacité,
//! stockage, RBAC, network policies, diagnostic. Elles répondent sur tout cluster, il n'y a rien
//! à détecter. Une `NetworkPolicy` native existe partout ; que Cilium ou Calico soient là en plus
//! change ce que la vue montre, pas le fait qu'elle ait quelque chose à dire.

use std::collections::HashSet;

use kube::Client;

/// Les add-ons détectés sur le cluster.
///
/// Chaque champ est nommé d'après la vue qu'il commande, pas d'après le produit : c'est ce que
/// l'appelant a besoin de savoir.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Capabilities {
    pub flux: bool,
    pub argocd: bool,
    pub velero: bool,
    /// cert-manager.
    pub certs: bool,
    pub kyverno: bool,
    /// kdt-identity, ou Rancher — la vue d'identité a plusieurs sources.
    pub identity: bool,
    pub k8ssandra: bool,
    pub rancher: bool,
}

/// Le groupe d'API dont la présence suffit à conclure qu'un add-on est là.
///
/// Un groupe servi veut dire que ses CRD sont enregistrés. Cela ne promet pas qu'il y ait le
/// moindre objet dedans, ni que le controller tourne — mais c'est exactement la question posée :
/// une vue Flux sur un cluster qui a les CRD et zéro Kustomization a quelque chose à dire (rien
/// n'est déployé), alors que sur un cluster sans les CRD elle n'a même pas de sujet.
const GROUPS: &[(&str, &[&str])] = &[
    // Les trois groupes de Flux : les avoir tous les trois n'est pas requis, un seul suffit à
    // dire que Flux est là — une installation réduite au source-controller reste une installation.
    (
        "flux",
        &[
            "kustomize.toolkit.fluxcd.io",
            "source.toolkit.fluxcd.io",
            "helm.toolkit.fluxcd.io",
        ],
    ),
    ("argocd", &["argoproj.io"]),
    ("velero", &["velero.io"]),
    ("certs", &["cert-manager.io"]),
    ("kyverno", &["kyverno.io"]),
    ("identity", &["identity.kdt.sh", "management.cattle.io"]),
    ("k8ssandra", &["k8ssandra.io"]),
    ("rancher", &["management.cattle.io"]),
];

/// Interroge le cluster sur les groupes d'API qu'il sert.
///
/// L'erreur est rendue plutôt qu'avalée : « je n'ai pas pu demander » et « il n'y a rien » sont
/// deux réponses différentes, et les confondre ferait disparaître des vues pour cause de réseau.
pub async fn detect(client: &Client) -> Result<Capabilities, String> {
    let groups = client
        .list_api_groups()
        .await
        .map_err(crate::edit::api_error_text)?;
    let served: HashSet<&str> = groups.groups.iter().map(|g| g.name.as_str()).collect();
    Ok(from_served(&served))
}

/// La traduction des groupes servis en vues disponibles.
///
/// Séparée de la sonde pour être testable sans cluster : c'est la table qui compte, et une entrée
/// mal orthographiée ne se verrait autrement qu'en production, sous la forme d'une vue qui a
/// silencieusement disparu du menu.
fn from_served(served: &HashSet<&str>) -> Capabilities {
    let has = |view: &str| {
        GROUPS
            .iter()
            .find(|(name, _)| *name == view)
            .is_some_and(|(_, groups)| groups.iter().any(|g| served.contains(g)))
    };
    Capabilities {
        flux: has("flux"),
        argocd: has("argocd"),
        velero: has("velero"),
        certs: has("certs"),
        kyverno: has("kyverno"),
        identity: has("identity"),
        k8ssandra: has("k8ssandra"),
        rancher: has("rancher"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected(groups: &[&str]) -> Capabilities {
        from_served(&groups.iter().copied().collect())
    }

    #[test]
    fn a_cluster_with_flux_and_no_argo_offers_flux_only() {
        let caps = detected(&["kustomize.toolkit.fluxcd.io", "source.toolkit.fluxcd.io"]);
        assert!(caps.flux);
        assert!(!caps.argocd);
    }

    #[test]
    fn one_flux_group_is_enough() {
        // Une installation réduite au source-controller est une installation : exiger les trois
        // groupes ferait disparaître la vue d'un cluster qui a bel et bien Flux.
        assert!(detected(&["source.toolkit.fluxcd.io"]).flux);
    }

    #[test]
    fn rancher_also_answers_for_the_identity_view() {
        // La vue d'identité a deux sources, et Rancher en est une : un cluster Rancher sans
        // kdt-identity a quand même des identités à montrer.
        let caps = detected(&["management.cattle.io"]);
        assert!(caps.identity);
        assert!(caps.rancher);
        assert!(!caps.flux);
    }

    #[test]
    fn a_bare_cluster_offers_no_addon_view() {
        assert_eq!(detected(&["apps", "batch"]), Capabilities::default());
    }

    #[test]
    fn nothing_installed_is_a_real_answer_of_its_own() {
        // Le pendant du `Result` de `detect` : ce `Default` est un verdict — « ce cluster n'a
        // aucun add-on » — et non le repli d'une sonde qui n'a pas abouti, lequel n'existe plus.
        assert!(!Capabilities::default().flux);
        assert_eq!(detected(&[]), Capabilities::default());
    }
}
