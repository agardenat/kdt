//! Point d'entrée du TUI : construit le client, installe les journaux, lance l'interface.
//!
//! Tout le métier vit dans la bibliothèque du même crate — voir `lib.rs`. Ce fichier n'a que ce
//! qu'un binaire a de particulier : l'allocateur, les journaux, et l'ordre de démarrage.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use kdt::{ai, cli, config, events, glyphs, lang, ui};

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
            .with_writer(std::io::sink)
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

    // Resolved here rather than in the TUI: `--probe-glyphs` prints and exits without ever building
    // an App, and it still has to print in the user's language.
    let file_config = config::load();
    lang::set_active(
        config::initial_language(&file_config)
            .or_else(config::system_language)
            .unwrap_or(ai::AiLanguage::Fr),
    );

    // Terminal characterisation: asks no cluster for anything.
    if args.probe_glyphs {
        glyphs::print_report()?;
        return Ok(());
    }

    let (client, api_url) = kdt::build_client(args.context.as_deref()).await?;

    let ns = if args.all_namespaces { None } else { args.namespace.clone() };
    let ns_label = match &ns { Some(n) => n.clone(), None => "all".to_string() };
    let (ctx_label, cluster_label) = kdt::resolve_context_labels(args.context.as_deref());
    let buffer = events::new_buffer();
    let log_state = events::new_log_state();
    let status_state = events::new_status_state();
    let watcher = events::spawn_watcher(client.clone(), ns, buffer.clone(), args.buffer_size);

    let ai_state = ai::new_ai_state();
    let app = ui::App::new(buffer, ns_label, ctx_label, cluster_label, api_url, client, log_state, status_state, ai_state, watcher, args.buffer_size, file_config, args.context.clone());
    ui::run(app).await
}
