//! kdt-web : l'interface web de kdt, adossée à kdt-identity.
//!
//! Le serveur ne détient aucun accès au cluster qui lui soit propre. Chaque requête est servie
//! avec le credential de la personne connectée, obtenu du portail : l'apiserver voit `kdt:alice`
//! et ses groupes, et le RBAC du cluster s'applique tel quel.
//!
//! Le compte de service du pod n'a donc besoin d'aucun droit sur les ressources. Ce qui rend
//! kdt-web sensible, ce sont les credentials qu'on lui confie — pas ses propres pouvoirs, qui
//! sont nuls.

mod api;
mod auth;
mod certs;
mod config;
mod config_secrets;
mod flux;
mod identity;
mod lang;
mod objects;
mod portal;
mod rancher;
mod session;
mod workloads;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Arguments de kdt-web.
#[derive(Parser)]
#[command(name = "kdt-web", version, about = "Interface web de kdt")]
struct Args {
    /// Contexte du kubeconfig à viser.
    ///
    /// À donner systématiquement hors du cluster : le contexte courant n'est presque jamais
    /// celui qu'on vise, et rien ne signale l'erreur — kdt-web servirait un autre cluster que
    /// celui qu'on croit, sous une identité que ce cluster ne connaît pas.
    ///
    /// Sans effet dans un pod, où l'identité vient du compte de service.
    #[arg(long, env = "KDT_WEB_CONTEXT")]
    context: Option<String>,
}

use config::WebConfig;
use portal::Portal;
use session::Sessions;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WebConfig>,
    pub portal: Arc<Portal>,
    pub sessions: Arc<Sessions>,
    /// La configuration de base du client : l'adresse de l'apiserver et sa CA, sans identité.
    ///
    /// C'est le squelette dont chaque session tire son propre client en y posant son credential.
    /// Il vient du compte de service du pod, ou du kubeconfig hors cluster — dans les deux cas on
    /// ne garde **que** l'adresse et la CA, jamais l'identité qu'il portait.
    pub kube: kube::Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("installation du fournisseur cryptographique rustls");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();
    let config = WebConfig::from_env().context("configuration")?;

    // L'identité qu'apporte le kubeconfig — ou le compte de service — est retirée : elle ne doit
    // jamais servir à répondre à une requête. Ce qu'on garde est l'adresse de l'apiserver et la
    // CA qui le valide ; l'identité vient de la personne connectée, à chaque requête.
    let mut kube = match &args.context {
        Some(context) => {
            let options = kube::config::KubeConfigOptions {
                context: Some(context.clone()),
                ..Default::default()
            };
            kube::Config::from_kubeconfig(&options)
                .await
                .with_context(|| format!("contexte {context:?} du kubeconfig"))?
        }
        None => kube::Config::infer()
            .await
            .context("adresse de l'apiserver et CA du cluster")?,
    };
    kube.auth_info = Default::default();

    info!(
        apiserver = %kube.cluster_url,
        contexte = args.context.as_deref().unwrap_or("(inféré)"),
        portail = %config.portal_url,
        "kdt-web démarre"
    );
    if args.context.is_none() {
        // Dans un pod, c'est le cas nominal. Hors cluster, c'est presque toujours une erreur :
        // le contexte courant n'est pas celui qu'on vise, et l'adresse ci-dessus est la seule
        // chose qui le dise.
        warn!(
            apiserver = %kube.cluster_url,
            "aucun --context : vérifiez que cet apiserver est bien celui visé"
        );
    }
    if config.assets.is_none() {
        info!("aucun bundle à servir : seule l'API répond (mode développement)");
    }

    let state = AppState {
        config: Arc::new(config.clone()),
        portal: Arc::new(Portal::new(&config.portal_url)),
        sessions: Arc::new(Sessions::new(config.session_ttl)),
        kube,
    };

    let mut app = Router::new()
        .route("/auth/login", get(auth::login))
        .route(
            kdt_identity_api::portal::AUTHORIZE_CALLBACK_PATH,
            get(auth::callback),
        )
        .route("/auth/logout", post(auth::logout))
        .route("/api/v1/me", get(auth::me))
        .route("/api/v1/capabilities", get(api::capabilities))
        .route("/api/v1/events", get(api::events))
        .route("/api/v1/logs", get(api::logs))
        .route("/api/v1/status", get(api::status))
        .route("/api/v1/related", post(api::related))
        .route("/api/v1/flux", get(flux::tree))
        .route("/api/v1/flux/inventory", get(flux::inventory))
        .route("/api/v1/flux/logs", get(flux::logs))
        // Les deux seules routes qui écrivent sur le cluster. Elles écrivent sous l'identité de la
        // personne connectée, comme les lectures : le compte de service du pod n'a toujours aucun
        // droit, et c'est le RBAC du cluster qui dit qui peut réconcilier quoi.
        .route("/api/v1/flux/reconcile", post(flux::reconcile))
        .route("/api/v1/flux/suspend", post(flux::suspend))
        .route("/api/v1/workloads", get(workloads::list))
        .route("/api/v1/workloads/scale", post(workloads::scale))
        .route("/api/v1/workloads/restart", post(workloads::restart))
        .route("/api/v1/workloads/recycle", post(workloads::recycle))
        .route("/api/v1/secrets", get(config_secrets::secrets))
        // Séparée de la liste, et c'est tout l'intérêt : les valeurs ne partent que sur une
        // demande nommée, secret par secret, et cette requête-là laisse une trace.
        .route("/api/v1/secrets/reveal", get(config_secrets::reveal))
        .route("/api/v1/configmaps", get(config_secrets::configmaps))
        .route("/api/v1/identity", get(identity::list))
        // Une seule route pour les sept écritures de l'annuaire : elles ne se distinguent que par
        // l'action nommée dans le corps, et sept routes qui partagent la même résolution de cible
        // se seraient répété la même chose sept fois.
        .route("/api/v1/identity/write", post(identity::write))
        .route("/api/v1/rancher", get(rancher::list))
        .route("/api/v1/rancher/write", post(rancher::write))
        .route("/api/v1/certs", get(certs::list))
        // Les deux leviers de la chaîne : forcer la ré-émission, et relancer un cycle ACME bloqué
        // en supprimant la demande en cours.
        .route("/api/v1/certs/renew", post(certs::renew))
        .route("/api/v1/certs/acme-retry", post(certs::acme_retry))
        // Les gestes de kdt qui portent sur n'importe quel objet — `y`, `e`, `h`, `Ctrl-D`.
        // Ils ne connaissent aucune vue : chaque vue leur passe les coordonnées de sa ligne.
        .route("/api/v1/object/yaml", get(objects::yaml))
        .route("/api/v1/object/edit", get(objects::edit))
        .route("/api/v1/object/diff", post(objects::diff))
        .route("/api/v1/object/apply", post(objects::apply))
        .route("/api/v1/object/touch", post(objects::touch))
        // Le `Ctrl-D` de kdt, en deux temps : ce que les garde-fous trouvent, puis la suppression —
        // qui rejoue les garde-fous et refuse si le nom retapé n'est pas celui de l'objet.
        .route("/api/v1/object/delete-preflight", get(objects::delete_preflight))
        .route("/api/v1/object/delete", post(objects::delete))
        .route("/healthz", get(|| async { "ok" }));

    // Le bundle est servi par le même serveur que l'API, sous la même origine : le cookie de
    // session est `SameSite=Strict`, et une origine séparée pour le front ne le recevrait pas.
    if let Some(dir) = &config.assets {
        let index = format!("{dir}/index.html");
        app = app.fallback_service(
            tower_http::services::ServeDir::new(dir)
                // Une SPA a des routes que le disque ne connaît pas : `/events` n'est pas un
                // fichier. Tout ce qui n'existe pas retombe sur la page, qui saura quoi faire.
                .not_found_service(tower_http::services::ServeFile::new(index)),
        );
    }

    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("écoute sur {}", config.listen))?;
    info!(adresse = %config.listen, "kdt-web écoute");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .context("service HTTP")?;

    Ok(())
}

/// Arrêt propre sur SIGTERM et Ctrl-C.
///
/// Les sessions vivent en mémoire : les perdre est sans gravité, chacun se reconnecte. Ce qui
/// compte est de ne pas couper une requête en cours au milieu.
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => warn!(erreur = %e, "SIGTERM non écouté"),
        }
    };

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("arrêt demandé, les sessions ouvertes sont perdues");
}
