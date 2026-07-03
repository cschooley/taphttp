use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "taphttp", about = "Headless TLS-terminating MITM proxy")]
pub struct Cli {
    /// Directory for CA keys, certs, and traffic logs
    #[arg(long, env = "TAPHTTP_DATA")]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy
    Start(StartArgs),
    /// Query captured traffic logs
    Logs(LogsArgs),
    /// Replay a captured request
    Replay(ReplayArgs),
    /// Manage the local CA certificate
    Ca(CaArgs),
}

#[derive(Args)]
pub struct StartArgs {
    /// Address to listen on
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// Write logs to sqlite in addition to JSON lines
    #[arg(long)]
    pub sqlite: bool,

    /// Only log requests matching this host (substring)
    #[arg(long)]
    pub filter_host: Option<String>,
}

#[derive(Args)]
pub struct LogsArgs {
    /// Filter by host (substring match)
    #[arg(long)]
    pub host: Option<String>,

    /// Filter by HTTP method
    #[arg(long)]
    pub method: Option<String>,

    /// Filter by status code
    #[arg(long)]
    pub status: Option<u16>,

    /// Show last N entries (default: 50)
    #[arg(short = 'n', long, default_value = "50")]
    pub limit: usize,

    /// Output raw JSON lines (default: pretty table)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Request ID to replay (from logs)
    pub id: String,

    /// Override request method
    #[arg(long)]
    pub method: Option<String>,

    /// Add or override a header (key:value)
    #[arg(long = "header", value_name = "KEY:VALUE")]
    pub headers: Vec<String>,

    /// Override request body
    #[arg(long)]
    pub body: Option<String>,
}

#[derive(Args)]
pub struct CaArgs {
    #[command(subcommand)]
    pub action: CaAction,
}

#[derive(Subcommand)]
pub enum CaAction {
    /// Print the CA cert path and install instructions
    Info,
    /// Print the CA cert in PEM format (pipe to trust store)
    Print,
}

pub fn data_dir(override_path: &Option<PathBuf>) -> Result<PathBuf> {
    let dir = match override_path {
        Some(p) => p.clone(),
        None => {
            let base = dirs::data_local_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(|| PathBuf::from("."));
            base.join("taphttp")
        }
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
