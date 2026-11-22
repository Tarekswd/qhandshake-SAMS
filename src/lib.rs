//! QHandshake: an experimental, TLS 1.3-modelled, server-authenticated hybrid key exchange.
//!
//! RESEARCH PROTOTYPE. Not TLS, not interoperable with TLS, not independently reviewed.
//! Do not use it to protect real data. See `../docs/` and `../spec/` for the protocol and threat model.

pub mod codec;
pub mod crypto;
pub mod handshake;
pub mod record;
pub mod transport;

pub use crypto::Group;
pub use handshake::{Client, ClientState, Server, ServerState};
pub use record::Session;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("decode error: {0}")]
    Decode(&'static str),
    #[error("illegal parameter: {0}")]
    IllegalParameter(&'static str),
    #[error("unexpected message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("handshake failure: {0}")]
    HandshakeFailure(&'static str),
    #[error("server signature verification failed")]
    BadSignature,
    #[error("decrypt error: {0}")]
    DecryptError(&'static str),
    #[error("unsupported protocol version")]
    ProtocolVersion,
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    #[error("connection already failed")]
    Poisoned,
    #[error("peer aborted the handshake with alert {0}")]
    PeerAlert(u8),
}

impl Error {
    /// Alert code sent to the peer before closing (values follow RFC 8446 section 6 for familiarity).
    pub fn alert_code(&self) -> u8 {
        match self {
            Error::UnexpectedMessage(_) => 10,
            Error::HandshakeFailure(_) => 40,
            Error::IllegalParameter(_) => 47,
            Error::Decode(_) => 50,
            Error::BadSignature | Error::DecryptError(_) => 51,
            Error::ProtocolVersion => 70,
            Error::Config(_) | Error::Poisoned | Error::PeerAlert(_) => 80,
        }
    }
}

pub struct ClientConfig {
    /// Groups to offer, most preferred first. A key share is sent for every offered group
    /// (no HelloRetryRequest), so each extra group costs bytes and CPU.
    pub offer: Vec<Group>,
    /// Pinned server Ed25519 public key (raw-public-key authentication, cf. RFC 7250).
    pub server_key: ed25519_dalek::VerifyingKey,
    /// Abort unless the negotiated group includes ML-KEM.
    pub require_pq: bool,
}

pub struct ServerConfig {
    /// Acceptable groups, server preference first.
    pub accept: Vec<Group>,
    pub signing_key: ed25519_dalek::SigningKey,
}

fn validate_groups(g: &[Group]) -> Result<(), Error> {
    if g.is_empty() || g.len() > 3 {
        return Err(Error::Config("group list must contain 1-3 groups"));
    }
    if (1..g.len()).any(|i| g[..i].contains(&g[i])) {
        return Err(Error::Config("duplicate group"));
    }
    Ok(())
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), Error> {
        validate_groups(&self.offer)?;
        if self.require_pq && !self.offer.iter().any(|g| g.is_post_quantum()) {
            return Err(Error::Config(
                "require_pq set but no post-quantum group offered",
            ));
        }
        Ok(())
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), Error> {
        validate_groups(&self.accept)
    }
}

/// Generate a fresh Ed25519 identity from the OS RNG.
pub fn generate_identity() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng))
}
