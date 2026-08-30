//! Error types for `zktrace-verifier`.

use thiserror::Error;

/// Errors that can occur during zero-knowledge receipt or proof verification.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Proof deserialization or cryptographic format failure.
    #[error("Invalid proof encoding: {0}")]
    InvalidProofEncoding(String),

    /// Verifying key decoding failure.
    #[error("Invalid verifying key: {0}")]
    InvalidVerifyingKey(String),

    /// Public input formatting or field conversion failure.
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Cryptographic pairing or Groth16 verification execution error.
    #[error("Verification execution error: {0}")]
    ExecutionError(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] zktrace_core::error::CoreError),
}

/// Convenience result alias for verifier operations.
pub type VerifierResult<T> = Result<T, VerifierError>;
