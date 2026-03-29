use iroh::endpoint::{ConnectingError, ConnectionError};
use tracing::{debug, error, warn};

use super::error::{tunnel_error_kind, TunnelError};

pub(crate) fn is_expected_connection_close(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
            | ConnectionError::LocallyClosed
    )
}

pub(crate) fn log_peer_connection_error(error: &anyhow::Error) {
    if matches!(tunnel_error_kind(error), Some(TunnelError::InvalidConnectionToken)) {
        warn!(error = %error, "Peer connection rejected");
    } else {
        error!(error = %error, "Peer connection failed");
    }
}

pub(crate) fn log_connection_handshake_error(error: &ConnectingError) {
    if matches!(
        error,
        ConnectingError::ConnectionError {
            source: ConnectionError::TimedOut,
            ..
        }
    ) {
        debug!(error = %error, "Connection handshake timed out");
    } else {
        warn!(error = %error, "Connection handshake failed");
    }
}

pub(crate) fn log_tunnel_connection_lost(reason: impl std::fmt::Display) {
    warn!(error = %reason, "Tunnel connection lost. Exiting.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_connection_close_detection_matches_shutdown_variants() {
        assert!(is_expected_connection_close(
            &ConnectionError::LocallyClosed
        ));
        assert!(!is_expected_connection_close(&ConnectionError::TimedOut));
    }
}
