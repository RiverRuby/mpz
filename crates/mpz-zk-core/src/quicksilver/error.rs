//! Errors in QuickSilver.

/// Errors that can occur during proving
#[derive(Debug, thiserror::Error)]
#[error("invalid inputs: expect {0}")]
pub struct QsProverError(pub String);

/// Errors that can occur during verifying
#[derive(Debug, thiserror::Error)]
#[error("invalid inputs: expect {0}")]
pub struct QsVerifierError(pub String);
