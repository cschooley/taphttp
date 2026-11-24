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

    /// Also write traffic to SQLite (at --db). Implied by --api-listen,
    /// which serves history from it.
    #[arg(long)]
    pub sqlite: bool,

    /// SQLite database path, used when sqlite is on (--sqlite or
    /// --api-listen). Default: <data-dir>/traffic.db. Set it to keep the
    /// database off the volume holding the CA key.
    #[arg(long, env = "TAPHTTP_DB", value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Only log requests matching this host (substring)
    #[arg(long)]
    pub filter_host: Option<String>,

    /// Unix socket path for the intercept hook (pauses each request/response)
    #[arg(long)]
    pub intercept_socket: Option<PathBuf>,

    /// Also serve the lever API (HTTP + WebSocket feed) on this address,
    /// e.g. 127.0.0.1:8081. Consumed by the SPA and MCP server.
    #[arg(long)]
    pub api_listen: Option<String>,

    /// Lever API token file. If it exists its contents are the token;
    /// otherwise a token is generated and written there (mode 0600). The
    /// token is then not printed. Default: a fresh token each start, printed
    /// and written to <data-dir>/api-token.
    #[arg(long, env = "TAPHTTP_API_TOKEN_FILE", value_name = "PATH")]
    pub api_token_file: Option<PathBuf>,

    /// Proxy credentials file: one `user:password` per line (mode 0600).
    /// Clients must then authenticate, and the username is recorded as each
    /// exchange's `source`. Or set TAPHTTP_PROXY_AUTH to the same text.
    /// Never accepted as a CLI argument, where `ps` would show it.
    #[arg(long, value_name = "PATH")]
    pub proxy_auth_file: Option<PathBuf>,

    /// Only accept proxy clients from this IP or CIDR (repeatable).
    #[arg(long, value_name = "CIDR")]
    pub allow_client: Vec<String>,

    /// Serve the proxy listener over TLS (an HTTPS proxy), with a cert from
    /// taphttp's CA. Required, with proxy auth, for a non-loopback --listen.
    #[arg(long)]
    pub proxy_tls: bool,

    /// Serve the lever API over TLS, with a cert from taphttp's CA.
    /// Required for a non-loopback --api-listen.
    #[arg(long)]
    pub api_tls: bool,

    /// Name (DNS or IP) clients use to reach a TLS listener; added to its
    /// cert (repeatable). Needed when listening on 0.0.0.0 / ::.
    #[arg(long, value_name = "NAME")]
    pub tls_name: Vec<String>,

    /// Allow a non-loopback --listen without proxy auth and TLS. Only for a
    /// port nothing untrusted can reach (e.g. compose, published on 127.0.0.1).
    #[arg(long)]
    pub allow_open_proxy: bool,

    /// Allow a non-loopback --api-listen without TLS. Only for a private
    /// network (e.g. a compose network) or a tunnel interface.
    #[arg(long)]
    pub api_allow_plaintext: bool,

    /// Turn off the lever API's POST /send (new requests to any URL), for
    /// deployments that only observe and replay. /info reports it.
    #[arg(long)]
    pub api_no_send: bool,

    /// Stop after this: a duration (90s, 30m, 8h, 2d) or an RFC 3339 time.
    /// Requests are refused from then on and taphttp exits.
    #[arg(long, value_name = "WHEN")]
    pub expires: Option<String>,
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

    /// Traffic log to read the request from (the file given to
    /// `start --log-file`). The replay is recorded into the same file.
    /// Defaults to <data-dir>/traffic.jsonl.
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

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
