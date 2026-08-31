//! Error types for `zktrace-ledger`.

use thiserror::Error;

/// Errors that can occur during cryptographic ledger operations, persistence, or bundle export.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Merkle tree capacity or indexing failure.
    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    /// Storage I/O or persistence error.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Bundle packaging or extraction failure.
    #[error("Bundle error: {0}")]
    BundleError(String),

    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] zktrace_core::error::CoreError),
}

/// Convenience result alias for ledger operations.
pub type LedgerResult<T> = Result<T, LedgerError>;
