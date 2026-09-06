//! kdt en bibliothèque : le métier, sans le terminal.
//!
//! Le binaire `kdt` est un consommateur de ce crate ; `kdt-web` en est un autre. Le partage passe
//! par ici plutôt que par une copie, pour que les deux disent la même chose du même cluster : les
//! verdicts sont ce que kdt apporte, et deux implémentations finiraient par diverger sans que
//! personne s'en aperçoive.
//!
//! # Ce que la feature `tui` recouvre
//!
//! Trois modules dessinent dans un terminal — [`ui`], [`splash`], [`glyphs`] — et sont les seuls à
//! dépendre de `ratatui`. Ils sont derrière la feature `tui`, active par défaut, pour qu'un
//! consommateur qui n'a pas de terminal ne les compile pas.
//!
//! [`exec`] n'en fait pas partie, bien qu'il rende la main à `kubectl exec` : [`identity`] et
//! [`portfwd`] s'en servent pour décrire une cible, indépendamment de qui affiche quoi.
//!
//! # Ce qui n'a pas bougé
//!
//! Aucun fichier n'a été déplacé, et le binaire garde son nom et sa version au même endroit du
//! `Cargo.toml` — c'est là que les scripts de packaging les lisent.

pub mod ai;
pub mod argocd;
pub mod capacity;
pub mod certmanager;
pub mod cli;
pub mod clip;
pub mod config;
pub mod configmaps;
pub mod connect;
pub mod delete;
pub mod diagnostic;
pub mod edit;
pub mod enrich;
pub mod events;
pub mod exec;
pub mod extract;
pub mod flux;
pub mod identity;
pub mod k8ssandra;
pub mod kyverno;
pub mod lang;
pub mod mgmtapi;
pub mod namespaces;
pub mod netpol;
pub mod nodeops;
pub mod nodetool;
pub mod pdf;
pub mod pods;
pub mod portfwd;
pub mod rancher;
pub mod rbac;
pub mod reflector;
pub mod repair;
pub mod secrets;
pub mod storage;
pub mod svc;
pub mod touch;
pub mod velero;
pub mod vulnerabilities;
pub mod yaml;

#[cfg(feature = "tui")]
pub mod glyphs;
#[cfg(feature = "tui")]
pub mod splash;
#[cfg(feature = "tui")]
pub mod ui;

use anyhow::Result;
use kube::Client;

/// Construit un client à partir du kubeconfig : un contexte explicite s'il est donné, sinon
/// inféré — compte de service dans le cluster, ou contexte courant.
///
/// Ne contacte rien : cette fonction lit des fichiers. C'est la raison d'être de l'écran de
/// démarrage du TUI, qui va vérifier visiblement que le cluster répond.
///
/// Rend aussi l'URL de l'apiserver, qui est ce qui rend un mauvais contexte évident.
pub async fn build_client(context: Option<&str>) -> Result<(Client, String)> {
    use kube::config::{Config, KubeConfigOptions};
    let config = match context {
        Some(ctx) => {
            let opts = KubeConfigOptions {
                context: Some(ctx.to_string()),
                ..KubeConfigOptions::default()
            };
            Config::from_kubeconfig(&opts).await?
        }
        None => Config::infer().await?,
    };
    let url = config.cluster_url.to_string();
    Ok((connect::build(config)?, url))
}

/// Les libellés (contexte, cluster) affichés dans le bandeau, lus dans le kubeconfig.
///
/// Retombe sur le nom du contexte quand le cluster ne peut pas être déterminé : un bandeau vide
/// serait moins utile qu'un bandeau approximatif, et le nom du contexte est ce que la personne a
/// tapé.
pub fn resolve_context_labels(explicit: Option<&str>) -> (String, String) {
    use kube::config::Kubeconfig;
    let kc = Kubeconfig::read().ok();
    let ctx_name = explicit
        .map(String::from)
        .or_else(|| kc.as_ref().and_then(|k| k.current_context.clone()))
        .unwrap_or_else(|| "default".to_string());
    let cluster = kc
        .as_ref()
        .and_then(|k| k.contexts.iter().find(|c| c.name == ctx_name))
        .and_then(|c| c.context.as_ref())
        .map(|c| c.cluster.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ctx_name.clone());
    (ctx_name, cluster)
}
