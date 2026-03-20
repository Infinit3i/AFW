use clap::Parser;
use afw::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Daemon => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or("info"),
            )
            .init();
            afw::daemon::run().await
        }
        cmd => afw::ipc::client_request(cmd).await,
    }
}
