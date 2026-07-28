use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "taphttp", about = "Headless TLS-terminating MITM proxy")]
pub struct Cli {
    /// Directory for CA keys and SQLite database
    #[arg(long, env = "TAPHTTP_DATA")]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy
    Start(StartArgs),
    /// Show captured traffic from a log file
    Show(ShowArgs),
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

    /// Also write traffic log to this file
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Also write traffic log to SQLite in the data directory
    #[arg(long)]
    pub sqlite: bool,

    /// Only log requests matching this host (substring)
    #[arg(long)]
    pub filter_host: Option<String>,

    /// Unix socket path for the intercept hook (pauses each request/response)
    #[arg(long)]
    pub intercept_socket: Option<PathBuf>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Traffic log file to read
    pub file: PathBuf,

    /// Filter by host (substring match)
    #[arg(long)]
    pub host: Option<String>,

    /// Filter by HTTP method
    #[arg(long)]
    pub method: Option<String>,

    /// Filter by status code
    #[arg(long)]
    pub status: Option<u16>,

    /// Show last N entries (default: all)
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Output raw JSON lines (default: pretty table)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Request ID to replay (from a traffic log)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn data_dir_uses_override_path() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("custom");
        let result = data_dir(&Some(target.clone())).unwrap();
        assert_eq!(result, target);
        assert!(target.exists(), "data_dir should create the directory");
    }

    #[test]
    fn data_dir_creates_directory_if_missing() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        assert!(!nested.exists());
        data_dir(&Some(nested.clone())).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn data_dir_with_none_returns_system_path_ending_in_taphttp() {
        let result = data_dir(&None).unwrap();
        assert!(
            result.ends_with("taphttp"),
            "default data dir should end with 'taphttp', got: {}",
            result.display()
        );
    }
}
