//! Error types for the `zktrace-core` crate.

use thiserror::Error;

/// Top-level error type for ZKTrace core cryptographic and data operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Error during finite field element conversion or parsing.
    #[error("Field error: {0}")]
    FieldError(String),

    /// Error during cryptographic hashing or sponge operations.
    #[error("Hash error: {0}")]
    HashError(String),

    /// Error during Merkle tree operations or proof verification.
    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    /// Error during canonical serialization or deserialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Policy constraint violation or parsing error.
    #[error("Policy error: {0}")]
    PolicyError(String),

    /// Invalid execution event or parameter structure.
    #[error("Execution error: {0}")]
    ExecutionError(String),

    /// Cryptographic proof or verification failure.
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// General internal or unexpected error.
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Convenience type alias for `Result<T, CoreError>`.
pub type CoreResult<T> = Result<T, CoreError>;
