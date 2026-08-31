//! Error types for `zktrace-prover`.

use thiserror::Error;

/// Errors that can occur during zero-knowledge trusted setup, witness generation, or proof creation.
#[derive(Debug, Error)]
pub enum ProverError {
    /// Error during Groth16 circuit synthesis or proving.
    #[error("Groth16 proving error: {0}")]
    Groth16ProvingError(String),

    /// Trusted setup key generation or parsing failure.
    #[error("Setup parameter error: {0}")]
    SetupError(String),

    /// Witness synthesis error.
    #[error("Witness synthesis failed: {0}")]
    WitnessError(String),

    /// Policy compliance violation encountered during witness generation.
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] zktrace_core::error::CoreError),

    /// Circuit error.
    #[error("Circuit error: {0}")]
    Circuit(#[from] zktrace_circuits::error::CircuitError),
}

/// Convenience result alias for prover operations.
pub type ProverResult<T> = Result<T, ProverError>;
