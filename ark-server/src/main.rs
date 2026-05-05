mod add_user;
mod config;
mod init;
mod run;
mod singbox;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::TransportKind;

#[derive(Parser)]
#[command(
    name = "ark-server",
    about = "ArkTunnel server — masks proxy traffic as Bitcoin or Ethereum P2P",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new server: generate keys, write config, print the arktunnel:// URI.
    Init {
        /// Transport protocol to use.
        #[arg(long, default_value = "bip324")]
        transport: TransportKind,
        /// Override the server IP in the generated URI (auto-detected if omitted).
        #[arg(long)]
        server_ip: Option<String>,
    },
    /// Add a new user: generate a UUID, update config and sing-box, print the URI.
    #[command(name = "add-user")]
    AddUser,
    /// Run the server daemon (requires a prior `init`).
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { transport, server_ip } => {
            init::run_init(transport, server_ip).await?;
        }
        Commands::AddUser => {
            add_user::run_add_user()?;
        }
        Commands::Run => {
            run::run_server().await?;
        }
    }

    Ok(())
}
