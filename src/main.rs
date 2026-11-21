mod api;
mod ca;
mod cli;
mod deploy;
mod history;
mod intercept;
mod proxy;
mod replay;
mod storage;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let data_dir = cli::data_dir(&cli.data_dir)?;

    match cli.command {
        Commands::Start(args) => proxy::run(args, data_dir).await,
        Commands::Show(args) => storage::show(args).await,
        Commands::Replay(args) => replay::run(args, data_dir).await,
        Commands::Ca(args) => ca::manage(args, data_dir).await,
    }
}
