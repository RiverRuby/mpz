use mpz_circuits::CircuitError;

use crate::ZKError;

/// Prover error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ProverError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_zk_core::quicksilver::QsProverError),
    #[error(transparent)]
    OTError(#[from] mpz_ot::OTError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error(transparent)]
    VOPEError(#[from] crate::vope::error::ReceiverError),
}

/// Verifier error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_zk_core::quicksilver::QsVerifierError),
    #[error(transparent)]
    OTError(#[from] mpz_ot::OTError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error(transparent)]
    VOPEError(#[from] crate::vope::error::SenderError),
}

impl From<ProverError> for ZKError {
    fn from(err: ProverError) -> Self {
        match err {
            ProverError::IOError(e) => e.into(),
            e => ZKError::ProverError(Box::new(e)),
        }
    }
}

impl From<VerifierError> for ZKError {
    fn from(err: VerifierError) -> Self {
        match err {
            VerifierError::IOError(e) => e.into(),
            e => ZKError::VerifierError(Box::new(e)),
        }
    }
}
