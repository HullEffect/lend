use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use getrandom::fill as fill_random;
use iroh::{
    endpoint::{Connection, ConnectionError},
    EndpointAddr,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    time::{timeout, Duration},
};

use super::{error::TunnelError, TunnelProtocol};

pub(crate) const AUTH_SECRET_LEN: usize = 32;
pub(crate) const AUTH_OK: u8 = 1;
pub(crate) const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_INVALID_TOKEN: u32 = 1;
const TOKEN_PREFIX: &str = "lend_";

pub(crate) type AuthSecret = [u8; AUTH_SECRET_LEN];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TunnelToken {
    pub(crate) protocol: TunnelProtocol,
    pub(crate) endpoint_addr: EndpointAddr,
    pub(crate) auth_secret: AuthSecret,
}

impl TunnelToken {
    pub(crate) fn new(
        protocol: TunnelProtocol,
        endpoint_addr: EndpointAddr,
        auth_secret: AuthSecret,
    ) -> Self {
        Self {
            protocol,
            endpoint_addr,
            auth_secret,
        }
    }

    pub(crate) fn encode(&self) -> Result<String> {
        let payload = postcard::to_stdvec(self)?;
        Ok(format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(payload)))
    }

    pub(crate) fn decode(token: &str) -> Result<Self> {
        let payload = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(TunnelError::InvalidConnectionToken)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TunnelError::InvalidConnectionToken)?;
        postcard::from_bytes(&decoded).map_err(|_| TunnelError::InvalidConnectionToken.into())
    }
}

pub(crate) async fn authenticate_connection(
    connection: &Connection,
    expected_secret: &AuthSecret,
) -> Result<()> {
    let (mut send, mut recv) = timeout(AUTH_TIMEOUT, connection.accept_bi()).await??;
    let mut provided_secret = [0u8; AUTH_SECRET_LEN];
    timeout(AUTH_TIMEOUT, recv.read_exact(&mut provided_secret)).await??;

    if !bool::from(provided_secret.ct_eq(expected_secret)) {
        connection.close(CLOSE_INVALID_TOKEN.into(), b"invalid auth secret");
        bail!(TunnelError::InvalidConnectionToken);
    }

    timeout(AUTH_TIMEOUT, send.write_all(&[AUTH_OK])).await??;
    send.shutdown().await?;

    Ok(())
}

pub(crate) async fn authenticate_remote_connection(
    connection: &Connection,
    auth_secret: &AuthSecret,
) -> Result<()> {
    let (mut send, mut recv) = timeout(AUTH_TIMEOUT, connection.open_bi()).await??;
    timeout(AUTH_TIMEOUT, send.write_all(auth_secret)).await??;
    send.shutdown().await?;

    let mut ack = [0u8; 1];
    let closed = connection.closed();
    tokio::pin!(closed);
    tokio::select! {
        result = timeout(AUTH_TIMEOUT, recv.read_exact(&mut ack)) => {
            result??;
        }
        reason = &mut closed => {
            return Err(map_remote_auth_close_reason(reason));
        }
    }
    if ack[0] != AUTH_OK {
        bail!("unexpected authentication response: {}", ack[0]);
    }

    Ok(())
}

pub(crate) fn generate_auth_secret() -> Result<AuthSecret> {
    let mut secret = [0u8; AUTH_SECRET_LEN];
    fill_random(&mut secret)?;
    Ok(secret)
}

fn map_remote_auth_close_reason(reason: ConnectionError) -> anyhow::Error {
    match reason {
        ConnectionError::ApplicationClosed(app_close)
            if app_close.error_code == CLOSE_INVALID_TOKEN.into() =>
        {
            TunnelError::InvalidConnectionToken.into()
        }
        ConnectionError::TimedOut
        | ConnectionError::Reset
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::LocallyClosed => TunnelError::UnavailablePeer.into(),
        other => anyhow::anyhow!(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_token_roundtrips() -> Result<()> {
        let token = TunnelToken::new(
            TunnelProtocol::Tcp,
            EndpointAddr::new(iroh::SecretKey::from_bytes(&[7; 32]).public())
                .with_ip_addr("127.0.0.1:7777".parse().unwrap())
                .with_relay_url("https://relay.example.test".parse().unwrap()),
            [42; AUTH_SECRET_LEN],
        );

        let encoded = token.encode()?;
        assert!(encoded.starts_with(TOKEN_PREFIX));
        assert!(encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')));
        let decoded = TunnelToken::decode(&encoded)?;

        assert_eq!(decoded, token);
        Ok(())
    }

    #[test]
    fn subtle_constant_time_eq_detects_equal_and_unequal_values() {
        assert!(bool::from([1u8, 2, 3].ct_eq(&[1u8, 2, 3])));
        assert!(!bool::from([1u8, 2, 3].ct_eq(&[1u8, 2, 4])));
    }

    #[test]
    fn auth_rejection_message_stays_stable_for_log_classification() {
        let error = anyhow::anyhow!(TunnelError::InvalidConnectionToken);
        assert_eq!(error.to_string(), TunnelError::InvalidConnectionToken.to_string());
    }

    #[test]
    fn malformed_token_encoding_returns_friendly_error() {
        let error = TunnelToken::decode("lend_not+base64").unwrap_err();
        assert_eq!(error.to_string(), TunnelError::InvalidConnectionToken.to_string());
    }

    #[test]
    fn malformed_token_payload_returns_friendly_error() {
        let encoded = format!(
            "{TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode([1u8, 2, 3, 4, 5])
        );
        let error = TunnelToken::decode(&encoded).unwrap_err();
        assert_eq!(error.to_string(), TunnelError::InvalidConnectionToken.to_string());
    }
}
