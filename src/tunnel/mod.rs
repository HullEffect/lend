mod auth;
mod endpoint;
mod error;
mod lifecycle;
mod tcp;
mod udp;

use anyhow::{bail, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use error::TunnelError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
}

impl TunnelProtocol {
    pub(crate) fn alpn(self) -> &'static [u8] {
        match self {
            Self::Tcp => b"iroh-lend/tcp/0.1",
            Self::Udp => b"iroh-lend/udp/0.1",
        }
    }
}

pub(crate) fn ensure_protocol(expected: TunnelProtocol, actual: TunnelProtocol) -> Result<()> {
    if actual != expected {
        bail!(TunnelError::InvalidProtocol);
    }

    Ok(())
}

pub async fn run_local_tunnel(protocol: TunnelProtocol, service_addr: &str) -> Result<()> {
    match protocol {
        TunnelProtocol::Tcp => tcp::run_local_tunnel(service_addr).await,
        TunnelProtocol::Udp => udp::run_local_tunnel(service_addr).await,
    }
}

pub async fn run_remote_tunnel(
    protocol: TunnelProtocol,
    bind_addr: &str,
    token: &str,
) -> Result<()> {
    match protocol {
        TunnelProtocol::Tcp => tcp::run_remote_tunnel(bind_addr, token).await,
        TunnelProtocol::Udp => udp::run_remote_tunnel(bind_addr, token).await,
    }
}
