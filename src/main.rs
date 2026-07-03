mod ca;
mod proxy;
mod storage;
mod replay;
mod cli;

use anyhow::Result;
use cli::{Cli, Commands};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let data_dir = cli::data_dir(&cli.data_dir)?;

    match cli.command {
        Commands::Start(args) => proxy::run(args, data_dir).await,
        Commands::Logs(args) => storage::query_logs(args, data_dir).await,
        Commands::Replay(args) => replay::run(args, data_dir).await,
        Commands::Ca(args) => ca::manage(args, data_dir).await,
    }
}
