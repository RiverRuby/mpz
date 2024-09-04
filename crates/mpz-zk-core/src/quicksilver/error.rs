//! Errors in QuickSilver.
use mpz_circuits::CircuitError;

/// Errors that can occur during proving
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum QsProverError {
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("invalid inputs")]
    InvalidInputs,
}

/// Errors that can occur during verifying
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum QsVerifierError {
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("invalid inputs")]
    InvalidInputs,
}
