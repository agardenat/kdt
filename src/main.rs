//! Entry point: builds the kube client, sets up logging, and launches the TUI.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod ai;
mod cli;
mod clip;
mod config;
mod diagnostic;
mod enrich;
mod events;
mod extract;
mod flux;
mod lang;
mod pdf;
mod pods;
mod rbac;
mod ui;
mod vulnerabilities;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use kube::Client;
use tracing_subscriber::EnvFilter;

// Build a kube client from the kubeconfig: an explicit context if given, otherwise inferred
// (in-cluster service account or current kubeconfig context).
async fn build_client(context: Option<&str>) -> Result<Client> {
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
    Ok(Client::try_from(config)?)
}

// Resolve the log file path: explicit env var, then XDG state dir, HOME, finally /tmp.
fn log_file_path() -> PathBuf {
    if let Ok(p) = std::env::var("KDT_LOG").or_else(|_| std::env::var("KEV_LOG")) {
        return PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(home).join("kdt").join("kdt.log");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local").join("state").join("kdt").join("kdt.log");
    }
    PathBuf::from("/tmp/kdt.log")
}

fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(file) = std::fs::File::options().create(true).append(true).open(&path) {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(|| std::io::sink())
            .try_init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires a process-wide crypto provider to be installed before any TLS use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    init_logging();

    let args = cli::Args::parse();
    let client = build_client(args.context.as_deref()).await?;

    let ns = if args.all_namespaces { None } else { args.namespace.clone() };
    let ns_label = match &ns { Some(n) => n.clone(), None => "all".to_string() };
    let (ctx_label, cluster_label) = resolve_context_labels(args.context.as_deref());
    let buffer = events::new_buffer();
    let log_state = events::new_log_state();
    let status_state = events::new_status_state();
    let watcher = events::spawn_watcher(client.clone(), ns, buffer.clone(), args.buffer_size);

    let ai_state = ai::new_ai_state();
    let file_config = config::load();
    let app = ui::App::new(buffer, ns_label, ctx_label, cluster_label, client, log_state, status_state, ai_state, watcher, args.buffer_size, file_config);
    ui::run(app).await
}

// Resolve the (context, cluster) labels shown in the UI banner from the kubeconfig,
// falling back to the context name when the cluster cannot be determined.
fn resolve_context_labels(explicit: Option<&str>) -> (String, String) {
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