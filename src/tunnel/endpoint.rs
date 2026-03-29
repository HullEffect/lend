use anyhow::Result;
use iroh::{
    endpoint::{self, presets, Connection},
    EndpointAddr, RelayMode,
};
use tokio::time::{timeout, Duration};

use super::{
    auth::{authenticate_remote_connection, AuthSecret},
    error::{tunnel_error_kind, TunnelError},
    TunnelProtocol,
};

const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn bind_tunnel_endpoint(
    protocol: TunnelProtocol,
    relay_mode: RelayMode,
) -> Result<endpoint::Endpoint> {
    let endpoint = endpoint::Endpoint::builder(presets::N0)
        .alpns(vec![protocol.alpn().to_vec()])
        .relay_mode(relay_mode.clone())
        .bind()
        .await?;

    wait_until_online_if_needed(&endpoint, relay_mode).await;

    Ok(endpoint)
}

pub(crate) async fn connect_authenticated_peer(
    protocol: TunnelProtocol,
    endpoint: &endpoint::Endpoint,
    endpoint_addr: EndpointAddr,
    auth_secret: &AuthSecret,
) -> Result<Connection> {
    let connection = timeout(PEER_CONNECT_TIMEOUT, async {
        let connection = endpoint
            .connect(endpoint_addr, protocol.alpn())
            .await
            .map_err(map_connect_error)?;
        authenticate_remote_connection(&connection, auth_secret)
            .await
            .map_err(|error| {
                if matches!(tunnel_error_kind(&error), Some(TunnelError::UnavailablePeer)) {
                    TunnelError::UnavailablePeer.into()
                } else {
                    error
                }
            })?;
        Ok::<Connection, anyhow::Error>(connection)
    })
    .await
    .map_err(|_| anyhow::Error::from(TunnelError::UnavailablePeer))??;

    Ok(connection)
}

pub(crate) fn configured_relay_mode() -> RelayMode {
    match std::env::var("LEND_RELAY_MODE").ok().as_deref() {
        Some("disabled") => RelayMode::Disabled,
        _ => RelayMode::Default,
    }
}

pub(crate) async fn close_endpoint_if_needed(endpoint: &endpoint::Endpoint) {
    if !endpoint.is_closed() {
        endpoint.close().await;
    }
}

async fn wait_until_online_if_needed(endpoint: &endpoint::Endpoint, relay_mode: RelayMode) {
    if !matches!(relay_mode, RelayMode::Disabled) {
        endpoint.online().await;
    }
}

fn map_connect_error(error: iroh::endpoint::ConnectError) -> anyhow::Error {
    match error {
        iroh::endpoint::ConnectError::Connection { source, .. }
            if is_unavailable_connection_error(&source) =>
        {
            TunnelError::UnavailablePeer.into()
        }
        iroh::endpoint::ConnectError::Connecting { source, .. }
            if is_unavailable_connecting_error(&source) =>
        {
            TunnelError::UnavailablePeer.into()
        }
        other => other.into(),
    }
}

fn is_unavailable_connection_error(error: &iroh::endpoint::ConnectionError) -> bool {
    matches!(
        error,
        iroh::endpoint::ConnectionError::TimedOut
            | iroh::endpoint::ConnectionError::Reset
            | iroh::endpoint::ConnectionError::ConnectionClosed(_)
            | iroh::endpoint::ConnectionError::LocallyClosed
    )
}

fn is_unavailable_connecting_error(error: &iroh::endpoint::ConnectingError) -> bool {
    matches!(
        error,
        iroh::endpoint::ConnectingError::ConnectionError { source, .. }
            if is_unavailable_connection_error(source)
    )
}
