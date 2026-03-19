mod cli;
mod config;
mod daemon;
mod ebpf_loader;
mod ipc;
mod nft;
mod state;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Daemon => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or("info"),
            )
            .init();
            daemon::run().await
        }
        cmd => ipc::client_request(cmd).await,
    }
}
