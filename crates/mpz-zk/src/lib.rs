//! Implementations of zero-knowledge protocols.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

pub mod quicksilver;
pub mod vope;

/// A vope error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VOPEError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("sender error: {0}")]
    SenderError(Box<dyn std::error::Error + Send + Sync>),
    #[error("receiver error: {0}")]
    ReceiverError(Box<dyn std::error::Error + Send + Sync>),
}

/// A zk error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ZKError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("prover error: {0}")]
    ProverError(Box<dyn std::error::Error + Send + Sync>),
    #[error("verifier error: {0}")]
    VerifierError(Box<dyn std::error::Error + Send + Sync>),
}
