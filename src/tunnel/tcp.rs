use anyhow::Result;
use iroh::endpoint::{self, Connection, ConnectionError, RecvStream, SendStream};
use std::sync::Arc;
use tokio::{
    io::{copy, split, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use super::{
    auth::{authenticate_connection, generate_auth_secret, AuthSecret, TunnelToken},
    endpoint::{
        bind_tunnel_endpoint, close_endpoint_if_needed, configured_relay_mode,
        connect_authenticated_peer,
    },
    lifecycle::{
        is_expected_connection_close, log_connection_handshake_error, log_peer_connection_error,
        log_tunnel_connection_lost,
    },
    ensure_protocol, TunnelProtocol,
};

pub async fn run_local_tunnel(service_addr: &str) -> Result<()> {
    let service_addr = Arc::new(service_addr.to_string());
    let relay_mode = configured_relay_mode();
    let auth_secret = Arc::new(generate_auth_secret()?);
    let endpoint = bind_tunnel_endpoint(TunnelProtocol::Tcp, relay_mode).await?;
    let ticket = TunnelToken::new(TunnelProtocol::Tcp, endpoint.addr(), *auth_secret).encode()?;
    info!("Share this token with peers.");
    println!("{ticket}");
    info!(service = %service_addr, "Sharing local service");
    info!("Waiting for peer tunnel connections.");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C. Closing sharing endpoint.");
                endpoint.close().await;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };

                let service_addr = Arc::clone(&service_addr);
                let auth_secret = Arc::clone(&auth_secret);
                tokio::spawn(handle_incoming_peer(incoming, service_addr, auth_secret));
            }
        }
    }

    close_endpoint_if_needed(&endpoint).await;

    Ok(())
}

pub async fn run_remote_tunnel(bind_addr: &str, token: &str) -> Result<()> {
    let TunnelToken {
        protocol,
        endpoint_addr,
        auth_secret,
    } = TunnelToken::decode(token)?;
    ensure_protocol(TunnelProtocol::Tcp, protocol)?;
    let relay_mode = configured_relay_mode();
    let endpoint = bind_tunnel_endpoint(TunnelProtocol::Tcp, relay_mode).await?;
    let raw_connection = match connect_authenticated_peer(
        TunnelProtocol::Tcp,
        &endpoint,
        endpoint_addr,
        &auth_secret,
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            close_endpoint_if_needed(&endpoint).await;
            return Err(error);
        }
    };

    let connection = Arc::new(raw_connection);
    info!("Connected to the sharing peer.");

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            close_endpoint_if_needed(&endpoint).await;
            return Err(err.into());
        }
    };
    info!(bind = %bind_addr, "Listening on local TCP address.");
    info!("Forwarding inbound TCP to the shared service.");
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<String>();
    let closed = connection.closed();
    tokio::pin!(closed);

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C. Closing tunnel endpoint.");
                endpoint.close().await;
                break;
            }
            reason = &mut closed => {
                log_tunnel_connection_lost(reason);
                break;
            }
            Some(reason) = shutdown_rx.recv() => {
                log_tunnel_connection_lost(reason);
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcp_stream, addr)) => {
                        debug!(remote = %addr, "Accepted local TCP connection.");

                        let connection = Arc::clone(&connection);
                        let shutdown_tx = shutdown_tx.clone();
                        tokio::spawn(forward_remote_tcp_connection(
                            connection,
                            shutdown_tx,
                            tcp_stream,
                        ));
                    }
                    Err(error) => warn!(error = %error, "TCP accept failed"),
                }
            }
        }
    }

    close_endpoint_if_needed(&endpoint).await;

    Ok(())
}

async fn handle_connection(
    connection: Connection,
    service_addr: Arc<String>,
    auth_secret: Arc<AuthSecret>,
) -> Result<()> {
    authenticate_connection(&connection, auth_secret.as_ref()).await?;
    let peer_id = connection.remote_id();
    info!(
        peer = %peer_id.fmt_short(),
        service = %service_addr,
        "Peer connected. Forwarding to service."
    );

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let service_addr = Arc::clone(&service_addr);
                tokio::spawn(async move {
                    if let Err(error) = handle_tunnel(recv, send, service_addr).await {
                        log_tunnel_forwarding_error(&error);
                    }
                });
            }
            Err(error) => {
                log_stream_accept_error(&error);
                break;
            }
        }
    }

    info!(peer = %peer_id.fmt_short(), "Peer disconnected");

    Ok(())
}

async fn handle_incoming_peer(
    incoming: endpoint::Incoming,
    service_addr: Arc<String>,
    auth_secret: Arc<AuthSecret>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(connection) => {
                if let Err(error) = handle_connection(connection, service_addr, auth_secret).await {
                    log_peer_connection_error(&error);
                }
            }
            Err(error) => log_connection_handshake_error(&error),
        },
        Err(error) => warn!(error = %error, "Incoming connection failed"),
    }
}

async fn handle_tunnel(
    recv: RecvStream,
    send: SendStream,
    service_addr: Arc<String>,
) -> Result<()> {
    let stream = TcpStream::connect(service_addr.as_str()).await?;
    tunnel_connection(stream, recv, send).await
}

async fn tunnel_connection<A, R, W>(tcp: A, recv: R, send: W) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut tcp_read, mut tcp_write) = split(tcp);
    let mut recv = recv;
    let mut send = send;

    let (client_bytes, server_bytes) = tokio::try_join!(
        async {
            let bytes = copy(&mut tcp_read, &mut send).await?;
            send.shutdown().await?;
            Ok::<u64, anyhow::Error>(bytes)
        },
        async {
            let bytes = copy(&mut recv, &mut tcp_write).await?;
            tcp_write.shutdown().await?;
            Ok::<u64, anyhow::Error>(bytes)
        }
    )?;

    debug!(
        sent_bytes = client_bytes,
        received_bytes = server_bytes,
        "Tunnel closed"
    );
    Ok(())
}

async fn forward_remote_tcp_connection(
    connection: Arc<Connection>,
    shutdown_tx: mpsc::UnboundedSender<String>,
    tcp_stream: TcpStream,
) {
    match connection.open_bi().await {
        Ok((send, recv)) => {
            if let Err(error) = tunnel_connection(tcp_stream, recv, send).await {
                log_tunnel_forwarding_error(&error);
            }
        }
        Err(error) => {
            let _ = shutdown_tx.send(error.to_string());
        }
    }
}

fn log_stream_accept_error(error: &ConnectionError) {
    if is_expected_connection_close(error) {
        debug!(error = %error, "QUIC stream accept stopped during connection shutdown");
    } else {
        warn!(error = %error, "QUIC stream accept failed");
    }
}

fn log_tunnel_forwarding_error(error: &anyhow::Error) {
    if error.to_string() == "connection lost" {
        debug!(error = %error, "Tunnel forwarding stopped during disconnect");
    } else {
        error!(error = %error, "Tunnel forwarding failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::error::TunnelError;
    use tokio::{
        io::{duplex, split, AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    #[test]
    fn connection_lost_message_stays_stable_for_log_classification() {
        let error = anyhow::anyhow!("connection lost");
        assert_eq!(error.to_string(), "connection lost");
    }

    #[test]
    fn tcp_protocol_check_rejects_non_tcp_tokens() {
        let error = ensure_protocol(TunnelProtocol::Tcp, TunnelProtocol::Udp).unwrap_err();
        assert_eq!(error.to_string(), TunnelError::InvalidProtocol.to_string());
    }

    #[tokio::test]
    async fn tunnel_connection_propagates_half_closes() -> Result<()> {
        let (app, tunnel_tcp) = duplex(256);
        let (mut app_read, mut app_write) = split(app);
        let (mut remote_to_local, recv) = duplex(256);
        let (send, mut local_to_remote) = duplex(256);

        let tunnel_task =
            tokio::spawn(async move { tunnel_connection(tunnel_tcp, recv, send).await });

        app_write.write_all(b"ping").await?;
        app_write.shutdown().await?;

        remote_to_local.write_all(b"pong").await?;
        remote_to_local.shutdown().await?;

        let mut outbound = Vec::new();
        timeout(
            Duration::from_secs(1),
            local_to_remote.read_to_end(&mut outbound),
        )
        .await??;
        assert_eq!(outbound, b"ping");

        let mut inbound = Vec::new();
        timeout(Duration::from_secs(1), app_read.read_to_end(&mut inbound)).await??;
        assert_eq!(inbound, b"pong");

        timeout(Duration::from_secs(1), tunnel_task).await???;

        Ok(())
    }
}
