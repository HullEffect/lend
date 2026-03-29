use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use tracing::error;

mod logging;
mod tunnel;
use tunnel::TunnelProtocol;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Temporarily share a local TCP or UDP service without port-forwarding",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Share a local service and print a connection token
    Share {
        /// Tunnel protocol to expose
        #[arg(value_name = "PROTOCOL")]
        protocol: TunnelProtocol,

        /// Service address to expose, e.g. localhost:3000
        #[arg(value_name = "SERVICE")]
        service: String,
    },
    /// Expose a shared service locally using a connection token
    Use {
        /// Protocol to expose locally
        #[arg(value_name = "PROTOCOL")]
        protocol: TunnelProtocol,

        /// Local bind address, e.g. 127.0.0.1:8080
        #[arg(value_name = "BIND")]
        bind: String,

        /// Connection token printed by `lend share`
        #[arg(value_name = "TOKEN")]
        token: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        error!(error = %error, "lend failed");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

async fn run() -> Result<()> {
    logging::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Share { protocol, service } => {
            // Machine that has the service running.
            tunnel::run_local_tunnel(protocol, &service).await?;
        }
        Command::Use {
            protocol,
            bind,
            token,
        } => {
            // Machine that listens locally and forwards traffic through the tunnel.
            tunnel::run_remote_tunnel(protocol, &bind, &token).await?;
        }
    }

    Ok(())
}
