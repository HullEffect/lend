use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelError {
    InvalidConnectionToken,
    UnavailablePeer,
    InvalidProtocol,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConnectionToken => f.write_str("invalid connection token"),
            Self::UnavailablePeer => f.write_str("sharing peer unavailable"),
            Self::InvalidProtocol => {
                f.write_str("tunnel token protocol does not match the requested tunnel mode")
            }
        }
    }
}

impl std::error::Error for TunnelError {}

pub(crate) fn tunnel_error_kind(error: &anyhow::Error) -> Option<TunnelError> {
    error.downcast_ref::<TunnelError>().copied()
}
