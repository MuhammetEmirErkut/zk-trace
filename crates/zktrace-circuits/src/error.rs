//! Circuit error definitions for `zktrace-circuits`.

use thiserror::Error;

/// Error during zero-knowledge circuit synthesis or constraint enforcement.
#[derive(Debug, Error)]
pub enum CircuitError {
    /// R1CS synthesis error.
    #[error("R1CS synthesis error: {0}")]
    SynthesisError(String),

    /// Missing witness assignment for private wire.
    #[error("Missing witness: {0}")]
    MissingWitness(String),

    /// Parameter constraint violation inside circuit.
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Merkle authentication path failure inside circuit.
    #[error("Merkle path verification failed: {0}")]
    MerklePathError(String),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] zktrace_core::error::CoreError),
}

/// Convenience result alias for circuit operations.
pub type CircuitResult<T> = Result<T, CircuitError>;
