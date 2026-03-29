use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, bail, Result};
use iroh::endpoint::{self, Connection, ConnectionError, SendDatagramError};
use tokio::{
    net::{lookup_host, UdpSocket},
    signal,
    sync::{mpsc, watch},
    time::{self, Duration, Instant, MissedTickBehavior},
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

const UDP_FRAME_HEADER_LEN: usize = std::mem::size_of::<u64>();
const UDP_SOCKET_BUFFER_SIZE: usize = 65_536;
const DEFAULT_UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

pub async fn run_local_tunnel(service_addr: &str) -> Result<()> {
    let service_addr = resolve_udp_addr(service_addr).await?;
    let relay_mode = configured_relay_mode();
    let auth_secret = Arc::new(generate_auth_secret()?);
    let endpoint = bind_tunnel_endpoint(TunnelProtocol::Udp, relay_mode).await?;
    let ticket = TunnelToken::new(TunnelProtocol::Udp, endpoint.addr(), *auth_secret).encode()?;
    info!("Share this token with peers.");
    println!("{ticket}");
    info!(service = %service_addr, "Sharing local UDP service");
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
    ensure_protocol(TunnelProtocol::Udp, protocol)?;

    let relay_mode = configured_relay_mode();
    let endpoint = bind_tunnel_endpoint(TunnelProtocol::Udp, relay_mode).await?;
    let raw_connection = match connect_authenticated_peer(
        TunnelProtocol::Udp,
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

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => Arc::new(socket),
        Err(error) => {
            close_endpoint_if_needed(&endpoint).await;
            return Err(error.into());
        }
    };
    let connection = Arc::new(raw_connection);
    let flows = Arc::new(Mutex::new(UdpFlowRegistry::default()));
    let idle_timeout = udp_flow_idle_timeout();

    info!("Connected to the sharing peer.");
    info!(bind = %bind_addr, "Listening on local UDP address.");
    info!("Forwarding inbound UDP to the shared service.");

    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<String>();
    let closed = connection.closed();
    tokio::pin!(closed);

    tokio::spawn(forward_local_udp_datagrams(
        Arc::clone(&connection),
        Arc::clone(&socket),
        Arc::clone(&flows),
        shutdown_tx.clone(),
    ));
    tokio::spawn(forward_peer_udp_datagrams(
        Arc::clone(&connection),
        Arc::clone(&socket),
        Arc::clone(&flows),
        shutdown_tx,
    ));
    tokio::spawn(cleanup_local_udp_flows(
        Arc::clone(&connection),
        Arc::clone(&flows),
        idle_timeout,
    ));

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
        }
    }

    close_endpoint_if_needed(&endpoint).await;

    Ok(())
}

async fn handle_incoming_peer(
    incoming: endpoint::Incoming,
    service_addr: SocketAddr,
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

async fn handle_connection(
    connection: Connection,
    service_addr: SocketAddr,
    auth_secret: Arc<AuthSecret>,
) -> Result<()> {
    authenticate_connection(&connection, auth_secret.as_ref()).await?;
    let connection = Arc::new(connection);
    let peer_id = connection.remote_id();
    let flows = Arc::new(Mutex::new(PeerUdpFlowRegistry::default()));
    let idle_timeout = udp_flow_idle_timeout();
    let mut cleanup_tick = time::interval(udp_flow_cleanup_interval(idle_timeout));
    cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    info!(
        peer = %peer_id.fmt_short(),
        service = %service_addr,
        "Peer connected. Forwarding to service."
    );

    loop {
        tokio::select! {
            _ = cleanup_tick.tick() => {
                cleanup_expired_peer_udp_flows(&flows, idle_timeout);
            }
            read_result = connection.read_datagram() => {
                match read_result {
                    Ok(datagram) => {
                        let (flow_id, payload) = match decode_udp_frame(&datagram) {
                            Ok(frame) => frame,
                            Err(error) => {
                                warn!(error = %error, "Received invalid UDP tunnel datagram");
                                continue;
                            }
                        };

                        let socket = match get_or_create_peer_flow_socket(
                            Arc::clone(&connection),
                            Arc::clone(&flows),
                            service_addr,
                            flow_id,
                        )
                        .await
                        {
                            Ok(socket) => socket,
                            Err(error) => {
                                warn!(
                                    error = %error,
                                    peer = %peer_id.fmt_short(),
                                    flow_id,
                                    "Failed to create shared UDP flow"
                                );
                                continue;
                            }
                        };

                        if let Err(error) = socket.send(payload).await {
                            warn!(
                                error = %error,
                                peer = %peer_id.fmt_short(),
                                flow_id,
                                "UDP service send failed"
                            );
                        }
                    }
                    Err(error) => {
                        log_datagram_read_error(&error);
                        break;
                    }
                }
            }
        }
    }

    cleanup_all_peer_udp_flows(&flows);
    info!(peer = %peer_id.fmt_short(), "Peer disconnected");

    Ok(())
}

async fn forward_local_udp_datagrams(
    connection: Arc<Connection>,
    socket: Arc<UdpSocket>,
    flows: Arc<Mutex<UdpFlowRegistry>>,
    shutdown_tx: mpsc::UnboundedSender<String>,
) {
    let mut buffer = vec![0u8; UDP_SOCKET_BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((size, local_addr)) => {
                debug!(remote = %local_addr, bytes = size, "Accepted local UDP datagram.");
                let flow_id = {
                    let mut flows = flows.lock().expect("udp flow registry lock poisoned");
                    flows.flow_for_local_addr(local_addr, Instant::now())
                };
                let frame = encode_udp_frame(flow_id, &buffer[..size]);
                if let Err(error) = connection.send_datagram(frame.into()) {
                    match handle_udp_send_error(&error, "Local UDP forwarding") {
                        DatagramSendOutcome::Continue => {}
                        DatagramSendOutcome::Shutdown(reason) => {
                            let _ = shutdown_tx.send(reason);
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                warn!(error = %error, "Local UDP receive failed");
                let _ = shutdown_tx.send(error.to_string());
                break;
            }
        }
    }
}

async fn forward_peer_udp_datagrams(
    connection: Arc<Connection>,
    socket: Arc<UdpSocket>,
    flows: Arc<Mutex<UdpFlowRegistry>>,
    shutdown_tx: mpsc::UnboundedSender<String>,
) {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                let (flow_id, payload) = match decode_udp_frame(&datagram) {
                    Ok(frame) => frame,
                    Err(error) => {
                        warn!(error = %error, "Received invalid UDP tunnel datagram");
                        continue;
                    }
                };

                let local_addr = {
                    let mut flows = flows.lock().expect("udp flow registry lock poisoned");
                    flows.local_addr_for_flow(flow_id, Instant::now())
                };

                if let Some(local_addr) = local_addr {
                    if let Err(error) = socket.send_to(payload, local_addr).await {
                        warn!(
                            error = %error,
                            local_addr = %local_addr,
                            flow_id,
                            "UDP reply send failed"
                        );
                    }
                } else {
                    debug!(flow_id, "Dropping UDP datagram for unknown flow");
                }
            }
            Err(error) => {
                log_datagram_read_error(&error);
                let _ = shutdown_tx.send(error.to_string());
                break;
            }
        }
    }
}

async fn forward_service_udp_datagrams(
    flow_id: u64,
    connection: Arc<Connection>,
    socket: Arc<UdpSocket>,
    flows: Arc<Mutex<PeerUdpFlowRegistry>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buffer = vec![0u8; UDP_SOCKET_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            recv_result = socket.recv(&mut buffer) => {
                match recv_result {
                    Ok(size) => {
                        {
                            let mut flows =
                                flows.lock().expect("peer udp flow registry lock poisoned");
                            flows.touch(flow_id, Instant::now());
                        }

                        let frame = encode_udp_frame(flow_id, &buffer[..size]);
                        match connection.send_datagram(frame.into()) {
                            Ok(()) => continue,
                            Err(error) => match handle_udp_send_error(
                                &error,
                                "Service UDP forwarding",
                            ) {
                                DatagramSendOutcome::Continue => {}
                                DatagramSendOutcome::Shutdown(_) => break,
                            },
                        }
                    }
                    Err(error) => {
                        warn!(error = %error, flow_id, "Shared UDP flow receive failed");
                        break;
                    }
                }
            }
        }
    }
}

async fn bind_connected_udp_flow_socket(service_addr: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = match service_addr {
        SocketAddr::V4(addr) if addr.ip().is_loopback() => "127.0.0.1:0",
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(addr) if addr.ip().is_loopback() => "[::1]:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(service_addr).await?;
    Ok(socket)
}

async fn resolve_udp_addr(addr: &str) -> Result<SocketAddr> {
    lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| anyhow!("could not resolve UDP address: {addr}"))
}

fn encode_udp_frame(flow_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(UDP_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&flow_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_udp_frame(frame: &[u8]) -> Result<(u64, &[u8])> {
    if frame.len() < UDP_FRAME_HEADER_LEN {
        bail!("UDP tunnel datagram too short");
    }

    let (flow_id, payload) = frame.split_at(UDP_FRAME_HEADER_LEN);
    let flow_id = u64::from_be_bytes(flow_id.try_into().expect("flow id length"));
    Ok((flow_id, payload))
}

fn log_datagram_read_error(error: &ConnectionError) {
    if is_expected_connection_close(error) {
        debug!(error = %error, "QUIC datagram read stopped during connection shutdown");
    } else {
        warn!(error = %error, "QUIC datagram read failed");
    }
}

enum DatagramSendOutcome {
    Continue,
    Shutdown(String),
}

fn handle_udp_send_error(error: &SendDatagramError, context: &str) -> DatagramSendOutcome {
    match error {
        SendDatagramError::ConnectionLost(connection_error) => {
            debug!(error = %connection_error, "{context} stopped during disconnect");
            DatagramSendOutcome::Shutdown(connection_error.to_string())
        }
        SendDatagramError::TooLarge => {
            warn!(error = %error, "{context} dropped oversized UDP datagram");
            DatagramSendOutcome::Continue
        }
        SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
            error!(error = %error, "{context} failed");
            DatagramSendOutcome::Shutdown(error.to_string())
        }
    }
}

async fn get_or_create_peer_flow_socket(
    connection: Arc<Connection>,
    flows: Arc<Mutex<PeerUdpFlowRegistry>>,
    service_addr: SocketAddr,
    flow_id: u64,
) -> Result<Arc<UdpSocket>> {
    {
        let mut flows = flows
            .lock()
            .expect("peer udp flow registry lock poisoned");
        if let Some(socket) = flows.socket_for_flow(flow_id, Instant::now()) {
            return Ok(socket);
        }
    }

    let socket = Arc::new(bind_connected_udp_flow_socket(service_addr).await?);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    {
        let mut flows = flows
            .lock()
            .expect("peer udp flow registry lock poisoned");
        if let Some(existing) = flows.socket_for_flow(flow_id, Instant::now()) {
            return Ok(existing);
        }
        flows.insert(flow_id, Arc::clone(&socket), shutdown_tx, Instant::now());
    }

    tokio::spawn(forward_service_udp_datagrams(
        flow_id,
        connection,
        Arc::clone(&socket),
        Arc::clone(&flows),
        shutdown_rx,
    ));

    Ok(socket)
}

fn cleanup_expired_peer_udp_flows(
    flows: &Arc<Mutex<PeerUdpFlowRegistry>>,
    idle_timeout: Duration,
) {
    let expired = {
        let mut flows = flows
            .lock()
            .expect("peer udp flow registry lock poisoned");
        flows.remove_expired(Instant::now(), idle_timeout)
    };

    for flow in expired {
        let _ = flow.shutdown_tx.send(true);
        debug!(
            flow_id = flow.flow_id,
            "Expired idle shared UDP flow"
        );
    }
}

fn cleanup_all_peer_udp_flows(flows: &Arc<Mutex<PeerUdpFlowRegistry>>) {
    let flows = {
        let mut flows = flows
            .lock()
            .expect("peer udp flow registry lock poisoned");
        flows.remove_all()
    };

    for flow in flows {
        let _ = flow.shutdown_tx.send(true);
    }
}

async fn cleanup_local_udp_flows(
    connection: Arc<Connection>,
    flows: Arc<Mutex<UdpFlowRegistry>>,
    idle_timeout: Duration,
) {
    let mut cleanup_tick = time::interval(udp_flow_cleanup_interval(idle_timeout));
    cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let closed = connection.closed();
    tokio::pin!(closed);

    loop {
        tokio::select! {
            _ = cleanup_tick.tick() => {
                let expired = {
                    let mut flows = flows.lock().expect("udp flow registry lock poisoned");
                    flows.remove_expired(Instant::now(), idle_timeout)
                };

                for flow_id in expired {
                    debug!(flow_id, "Expired idle local UDP flow");
                }
            }
            _ = &mut closed => break,
        }
    }
}

fn udp_flow_idle_timeout() -> Duration {
    duration_from_env("LEND_UDP_IDLE_TIMEOUT_MS").unwrap_or(DEFAULT_UDP_SESSION_IDLE_TIMEOUT)
}

fn udp_flow_cleanup_interval(idle_timeout: Duration) -> Duration {
    duration_from_env("LEND_UDP_CLEANUP_INTERVAL_MS").unwrap_or_else(|| {
        let timeout_ms = idle_timeout.as_millis().clamp(200, 10_000) as u64;
        Duration::from_millis((timeout_ms / 2).clamp(100, 5_000))
            .min(DEFAULT_UDP_SESSION_CLEANUP_INTERVAL)
    })
}

fn duration_from_env(key: &str) -> Option<Duration> {
    let value = std::env::var(key).ok()?;
    let milliseconds = value.parse::<u64>().ok()?;
    Some(Duration::from_millis(milliseconds))
}

#[derive(Debug, Default)]
struct UdpFlowRegistry {
    next_flow_id: u64,
    local_addr_to_flow: HashMap<SocketAddr, LocalUdpFlow>,
    flow_to_local_addr: HashMap<u64, SocketAddr>,
}

impl UdpFlowRegistry {
    fn flow_for_local_addr(&mut self, local_addr: SocketAddr, now: Instant) -> u64 {
        if let Some(flow) = self.local_addr_to_flow.get_mut(&local_addr) {
            flow.last_seen = now;
            return flow.flow_id;
        }

        let flow_id = self.next_flow_id;
        self.next_flow_id = self.next_flow_id.saturating_add(1);
        self.local_addr_to_flow.insert(
            local_addr,
            LocalUdpFlow {
                flow_id,
                last_seen: now,
            },
        );
        self.flow_to_local_addr.insert(flow_id, local_addr);
        flow_id
    }

    fn local_addr_for_flow(&mut self, flow_id: u64, now: Instant) -> Option<SocketAddr> {
        let local_addr = self.flow_to_local_addr.get(&flow_id).copied()?;
        if let Some(flow) = self.local_addr_to_flow.get_mut(&local_addr) {
            flow.last_seen = now;
        }
        Some(local_addr)
    }

    fn remove_expired(&mut self, now: Instant, idle_timeout: Duration) -> Vec<u64> {
        let expired = self
            .local_addr_to_flow
            .iter()
            .filter_map(|(local_addr, flow)| {
                (now.saturating_duration_since(flow.last_seen) >= idle_timeout)
                    .then_some((*local_addr, flow.flow_id))
            })
            .collect::<Vec<_>>();

        for (local_addr, flow_id) in &expired {
            self.local_addr_to_flow.remove(local_addr);
            self.flow_to_local_addr.remove(flow_id);
        }

        expired
            .into_iter()
            .map(|(_, flow_id)| flow_id)
            .collect()
    }
}

#[derive(Debug)]
struct LocalUdpFlow {
    flow_id: u64,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct PeerUdpFlowRegistry {
    flows: HashMap<u64, PeerUdpFlow>,
}

impl PeerUdpFlowRegistry {
    fn socket_for_flow(&mut self, flow_id: u64, now: Instant) -> Option<Arc<UdpSocket>> {
        let flow = self.flows.get_mut(&flow_id)?;
        flow.last_seen = now;
        Some(Arc::clone(&flow.socket))
    }

    fn insert(
        &mut self,
        flow_id: u64,
        socket: Arc<UdpSocket>,
        shutdown_tx: watch::Sender<bool>,
        now: Instant,
    ) {
        self.flows.insert(
            flow_id,
            PeerUdpFlow {
                flow_id,
                socket,
                shutdown_tx,
                last_seen: now,
            },
        );
    }

    fn touch(&mut self, flow_id: u64, now: Instant) {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            flow.last_seen = now;
        }
    }

    fn remove_expired(&mut self, now: Instant, idle_timeout: Duration) -> Vec<PeerUdpFlow> {
        let expired_ids = self
            .flows
            .iter()
            .filter_map(|(flow_id, flow)| {
                (now.saturating_duration_since(flow.last_seen) >= idle_timeout)
                    .then_some(*flow_id)
            })
            .collect::<Vec<_>>();

        expired_ids
            .into_iter()
            .filter_map(|flow_id| self.flows.remove(&flow_id))
            .collect()
    }

    fn remove_all(&mut self) -> Vec<PeerUdpFlow> {
        self.flows.drain().map(|(_, flow)| flow).collect()
    }
}

#[derive(Debug)]
struct PeerUdpFlow {
    flow_id: u64,
    socket: Arc<UdpSocket>,
    shutdown_tx: watch::Sender<bool>,
    last_seen: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FLOW_ELAPSED: Duration = Duration::from_secs(5);
    const TEST_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

    #[test]
    fn udp_frame_roundtrips() -> Result<()> {
        let frame = encode_udp_frame(42, b"ping");
        let (flow_id, payload) = decode_udp_frame(&frame)?;
        assert_eq!(flow_id, 42);
        assert_eq!(payload, b"ping");
        Ok(())
    }

    #[test]
    fn udp_frame_rejects_short_payloads() {
        let error = decode_udp_frame(b"tiny").unwrap_err();
        assert_eq!(error.to_string(), "UDP tunnel datagram too short");
    }

    #[test]
    fn udp_flow_registry_reuses_local_addr_flows() {
        let mut flows = UdpFlowRegistry::default();
        let local_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let now = Instant::now();
        let first = flows.flow_for_local_addr(local_addr, now);
        let second = flows.flow_for_local_addr(local_addr, now);

        assert_eq!(first, second);
        assert_eq!(
            flows.local_addr_for_flow(first, now),
            Some(local_addr)
        );
    }

    #[test]
    fn udp_flow_registry_allocates_distinct_flows() {
        let mut flows = UdpFlowRegistry::default();
        let now = Instant::now();
        let first = flows.flow_for_local_addr("127.0.0.1:9000".parse().unwrap(), now);
        let second = flows.flow_for_local_addr("127.0.0.1:9001".parse().unwrap(), now);

        assert_ne!(first, second);
    }

    #[test]
    fn udp_flow_registry_expires_idle_flows() {
        let mut flows = UdpFlowRegistry::default();
        let now = Instant::now();
        let local_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let first = flows.flow_for_local_addr(local_addr, now);

        let expired = flows.remove_expired(now + TEST_FLOW_ELAPSED, TEST_IDLE_TIMEOUT);
        assert_eq!(expired, vec![first]);
        assert_eq!(flows.local_addr_for_flow(first, now), None);

        let second = flows.flow_for_local_addr(local_addr, now + TEST_FLOW_ELAPSED);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn peer_udp_flow_registry_expires_idle_flows() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let now = Instant::now();
        let mut flows = PeerUdpFlowRegistry::default();
        flows.insert(7, socket, shutdown_tx, now);

        let expired = flows.remove_expired(now + TEST_FLOW_ELAPSED, TEST_IDLE_TIMEOUT);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].flow_id, 7);
        Ok(())
    }
}
