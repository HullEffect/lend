use std::{process::Stdio, time::Duration};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, ChildStdout, Command},
    task::JoinHandle,
    time::{sleep, timeout},
};

const INDEX_HTML: &str = include_str!("./index.html");
const TUNNEL_TOKEN_PREFIX: &str = "lend_";
const AUTH_SECRET_LEN: usize = 32;
const FAST_UDP_IDLE_TIMEOUT_MS: &str = "300";
const FAST_UDP_CLEANUP_INTERVAL_MS: &str = "75";
const UDP_RESPONSE_BUFFER_SIZE: usize = 65_536;
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const UNAVAILABLE_PEER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TunnelProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TunnelToken {
    protocol: TunnelProtocol,
    endpoint_addr: EndpointAddr,
    auth_secret: [u8; AUTH_SECRET_LEN],
}

struct LendProcess {
    #[allow(dead_code)]
    child: Child,
    stdout: BufReader<ChildStdout>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_index_html_through_the_tunnel() -> Result<()> {
    let (service_addr, server_task) = spawn_static_http_server().await?;
    let mut share = spawn_lend(["share", "tcp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend(["use", "tcp", &bind_addr, &token]).await?;

    let response = fetch_with_retry(&bind_addr).await?;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Type: text/html; charset=utf-8"));
    assert!(
        response.ends_with(INDEX_HTML),
        "response body did not match served index.html:\n{response}"
    );

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_exits_when_the_sharing_peer_stops() -> Result<()> {
    let (service_addr, server_task) = spawn_static_http_server().await?;
    let mut share = spawn_lend(["share", "tcp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let mut connect = spawn_lend(["use", "tcp", &bind_addr, &token]).await?;

    let response = fetch_with_retry(&bind_addr).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    share.child.start_kill()?;
    let share_status = timeout(PROCESS_EXIT_TIMEOUT, share.child.wait()).await??;
    assert!(
        !share_status.success(),
        "share process unexpectedly exited successfully"
    );

    let post_shutdown_response = fetch_once(&bind_addr).await;
    assert!(
        matches!(&post_shutdown_response, Err(_))
            || matches!(
                &post_shutdown_response,
                Ok(response) if !response.starts_with("HTTP/1.1 200 OK\r\n")
            ),
        "next attempted use should not succeed after the sharing peer stops: {post_shutdown_response:?}"
    );

    let connect_status = timeout(PROCESS_EXIT_TIMEOUT, connect.child.wait()).await??;
    assert!(
        connect_status.success(),
        "connect process should exit cleanly when the sharing peer goes away"
    );

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_token_is_rejected() -> Result<()> {
    let (service_addr, server_task) = spawn_static_http_server().await?;
    let mut share = spawn_lend(["share", "tcp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;
    let tampered = tamper_auth_secret(&token)?;

    let bind_addr = reserve_local_addr().await?;
    let mut connect = spawn_lend(["use", "tcp", &bind_addr, &tampered]).await?;

    let status = timeout(PROCESS_EXIT_TIMEOUT, connect.child.wait()).await??;
    assert!(
        !status.success(),
        "connect should fail when the token auth secret is tampered"
    );

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_peer_token_fails_within_connect_timeout() -> Result<()> {
    let (service_addr, server_task) = spawn_static_http_server().await?;
    let mut share = spawn_lend(["share", "tcp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    share.child.start_kill()?;
    let _ = timeout(PROCESS_EXIT_TIMEOUT, share.child.wait()).await??;

    let bind_addr = reserve_local_addr().await?;
    let mut connect = spawn_lend(["use", "tcp", &bind_addr, &token]).await?;

    let status = timeout(UNAVAILABLE_PEER_TIMEOUT, connect.child.wait()).await??;
    assert!(
        !status.success(),
        "connect should fail once the sharing peer is unavailable"
    );

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_token_is_logged_through_tracing() -> Result<()> {
    let bind_addr = reserve_local_addr().await?;
    let output = run_lend_output(["use", "tcp", &bind_addr, "lend_not-a-token"]).await?;

    assert!(
        !output.status.success(),
        "connect should fail when the token is malformed"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lend failed"),
        "expected traced error log, got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("invalid connection token"),
        "expected invalid token message, got stderr:\n{stderr}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echoes_udp_datagrams_through_the_tunnel() -> Result<()> {
    let (service_addr, server_task) = spawn_udp_echo_server().await?;
    let mut share = spawn_lend(["share", "udp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend(["use", "udp", &bind_addr, &token]).await?;

    let response = exchange_udp_with_retry(&bind_addr, b"ping over udp").await?;
    assert_eq!(response, b"ping over udp");

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handles_many_simultaneous_tcp_connections() -> Result<()> {
    let (service_addr, server_task) = spawn_static_http_server().await?;
    let mut share = spawn_lend(["share", "tcp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend(["use", "tcp", &bind_addr, &token]).await?;

    let warmup = fetch_with_retry(&bind_addr).await?;
    assert!(warmup.starts_with("HTTP/1.1 200 OK\r\n"));

    let tasks = (0..16)
        .map(|_| {
            let bind_addr = bind_addr.clone();
            tokio::spawn(async move { fetch_once(&bind_addr).await })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        let response = task.await??;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(INDEX_HTML));
    }

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_multiple_connecting_peers_do_not_collide() -> Result<()> {
    let (service_addr, server_task) = spawn_udp_echo_server().await?;
    let mut share = spawn_lend(["share", "udp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr_one = reserve_local_addr().await?;
    let bind_addr_two = reserve_local_addr().await?;
    let _connect_one = spawn_lend(["use", "udp", &bind_addr_one, &token]).await?;
    let _connect_two = spawn_lend(["use", "udp", &bind_addr_two, &token]).await?;

    let first = exchange_udp_with_retry(&bind_addr_one, b"peer one").await?;
    let second = exchange_udp_with_retry(&bind_addr_two, b"peer two").await?;

    assert_eq!(first, b"peer one");
    assert_eq!(second, b"peer two");

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handles_many_simultaneous_udp_clients() -> Result<()> {
    let (service_addr, server_task) = spawn_udp_echo_server().await?;
    let mut share = spawn_lend(["share", "udp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend(["use", "udp", &bind_addr, &token]).await?;

    let tasks = (0..16)
        .map(|index| {
            let bind_addr = bind_addr.clone();
            tokio::spawn(async move {
                let payload = format!("udp client {index}").into_bytes();
                let response = exchange_udp_with_retry(&bind_addr, &payload).await?;
                Ok::<_, anyhow::Error>((payload, response))
            })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        let (payload, response) = task.await??;
        assert_eq!(response, payload);
    }

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_sessions_continue_working_after_idle_cleanup() -> Result<()> {
    let (service_addr, server_task) = spawn_udp_echo_server().await?;
    let mut share = spawn_lend_with_env(
        &["share", "udp", &service_addr],
        &[
            ("LEND_UDP_IDLE_TIMEOUT_MS", FAST_UDP_IDLE_TIMEOUT_MS),
            ("LEND_UDP_CLEANUP_INTERVAL_MS", FAST_UDP_CLEANUP_INTERVAL_MS),
        ],
    )
    .await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend_with_env(
        &["use", "udp", &bind_addr, &token],
        &[
            ("LEND_UDP_IDLE_TIMEOUT_MS", FAST_UDP_IDLE_TIMEOUT_MS),
            ("LEND_UDP_CLEANUP_INTERVAL_MS", FAST_UDP_CLEANUP_INTERVAL_MS),
        ],
    )
    .await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let first = exchange_udp_with_retry_on_socket(&socket, &bind_addr, b"before cleanup").await?;
    assert_eq!(first, b"before cleanup");

    sleep(Duration::from_millis(900)).await;

    let second = exchange_udp_with_retry_on_socket(&socket, &bind_addr, b"after cleanup").await?;
    assert_eq!(second, b"after cleanup");

    server_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_udp_datagrams_are_dropped_without_breaking_the_tunnel() -> Result<()> {
    let (service_addr, server_task) = spawn_udp_echo_server().await?;
    let mut share = spawn_lend(["share", "udp", &service_addr]).await?;
    let token = read_token(&mut share.stdout).await?;

    let bind_addr = reserve_local_addr().await?;
    let _connect = spawn_lend(["use", "udp", &bind_addr, &token]).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let oversized_payload = vec![0x5a; 2 * 1024];
    assert_udp_drop(&socket, &bind_addr, &oversized_payload).await?;

    let response = exchange_udp_with_retry_on_socket(&socket, &bind_addr, b"still healthy").await?;
    assert_eq!(response, b"still healthy");

    server_task.abort();

    Ok(())
}

async fn spawn_lend<const N: usize>(args: [&str; N]) -> Result<LendProcess> {
    spawn_lend_with_env(&args, &[]).await
}

async fn run_lend_output<const N: usize>(args: [&str; N]) -> Result<std::process::Output> {
    let binary = lend_binary_path();
    let owned_args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let output = timeout(PROCESS_EXIT_TIMEOUT, tokio::task::spawn_blocking(move || {
        std::process::Command::new(binary)
            .args(&owned_args)
            .env("LEND_RELAY_MODE", "disabled")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
    }))
    .await???;

    Ok(output)
}

fn lend_binary_path() -> std::path::PathBuf {
    let fallback = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(format!("lend{}", std::env::consts::EXE_SUFFIX));
    if fallback.exists() {
        return fallback;
    }

    std::path::PathBuf::from(env!("CARGO_BIN_EXE_lend"))
}

async fn spawn_lend_with_env(args: &[&str], envs: &[(&str, &str)]) -> Result<LendProcess> {
    let mut command = Command::new(lend_binary_path());
    command
        .args(args)
        .env("LEND_RELAY_MODE", "disabled")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    for (key, value) in envs {
        command.env(key, value);
    }

    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture child stdout"))?;
    Ok(LendProcess {
        child,
        stdout: BufReader::new(stdout),
    })
}

async fn read_token(stdout: &mut BufReader<ChildStdout>) -> Result<String> {
    wait_for_line(stdout, "stdout", |line| {
        line.starts_with(TUNNEL_TOKEN_PREFIX)
    })
    .await
}

async fn wait_for_line<R, F>(
    reader: &mut BufReader<R>,
    stream_name: &str,
    mut predicate: F,
) -> Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
    F: FnMut(&str) -> bool,
{
    let mut transcript = Vec::new();

    loop {
        let mut line = String::new();
        let bytes = timeout(Duration::from_secs(15), reader.read_line(&mut line)).await??;

        if bytes == 0 {
            bail!(
                "process exited before expected output.\nCaptured {stream_name}:\n{}",
                transcript.join("\n")
            );
        }

        let trimmed = line.trim();
        transcript.push(trimmed.to_string());

        if predicate(trimmed) {
            return Ok(trimmed.to_string());
        }
    }
}

async fn reserve_local_addr() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

async fn spawn_static_http_server() -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();

    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    INDEX_HTML.len(),
                    INDEX_HTML
                );

                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    Ok((addr, task))
}

async fn spawn_udp_echo_server() -> Result<(String, JoinHandle<()>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();

    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_536];

        loop {
            let (size, remote_addr) = match socket.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(_) => break,
            };

            let _ = socket.send_to(&buffer[..size], remote_addr).await;
        }
    });

    Ok((addr, task))
}

async fn fetch_with_retry(bind_addr: &str) -> Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last_error = None;

    while tokio::time::Instant::now() < deadline {
        match fetch_once(bind_addr).await {
            Ok(response) => return Ok(response),
            Err(err) => {
                last_error = Some(err);
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("timed out waiting for tunnel response")))
}

async fn fetch_once(bind_addr: &str) -> Result<String> {
    let mut stream = TcpStream::connect(bind_addr).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

async fn exchange_udp_with_retry(bind_addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    exchange_udp_with_retry_on_socket(&socket, bind_addr, payload).await
}

async fn exchange_udp_with_retry_on_socket(
    socket: &UdpSocket,
    bind_addr: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last_error = None;

    while tokio::time::Instant::now() < deadline {
        match exchange_udp_once_with_socket(socket, bind_addr, payload).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                last_error = Some(error);
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("timed out waiting for UDP tunnel response")))
}

async fn exchange_udp_once_with_socket(
    socket: &UdpSocket,
    bind_addr: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    socket.send_to(payload, bind_addr).await?;

    let mut response = vec![0u8; payload.len() + 1024];
    let (size, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut response)).await??;
    response.truncate(size);
    Ok(response)
}

async fn assert_udp_drop(socket: &UdpSocket, bind_addr: &str, payload: &[u8]) -> Result<()> {
    socket.send_to(payload, bind_addr).await?;

    let mut response = vec![0u8; UDP_RESPONSE_BUFFER_SIZE];
    match timeout(Duration::from_secs(1), socket.recv_from(&mut response)).await {
        Ok(Ok((size, _))) => bail!(
            "expected oversized UDP datagram to be dropped, but received {size} byte reply"
        ),
        // Windows can surface a dropped UDP exchange as WSAECONNRESET / ConnectionReset.
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Ok(()),
    }
}

fn tamper_auth_secret(token: &str) -> Result<String> {
    let payload = token
        .strip_prefix(TUNNEL_TOKEN_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("invalid tunnel token prefix"))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload)?;
    let mut token: TunnelToken = postcard::from_bytes(&decoded)?;
    token.auth_secret[0] ^= 0xff;
    let encoded = postcard::to_stdvec(&token)?;
    Ok(format!(
        "{TUNNEL_TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(encoded)
    ))
}
