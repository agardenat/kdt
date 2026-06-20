//! Command-line argument parsing (clap).

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version, about = "kdt — Kubernetes Diagnostic Tools")]
pub struct Args {
    #[arg(short = 'n', long)]
    pub namespace: Option<String>,

    #[arg(short = 'A', long)]
    pub all_namespaces: bool,

    #[arg(long)]
    pub context: Option<String>,

    #[arg(long, default_value_t = 5000)]
    pub buffer_size: usize,
}