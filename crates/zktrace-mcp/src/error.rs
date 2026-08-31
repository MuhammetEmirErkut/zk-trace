//! Error types for `zktrace-mcp`.

use thiserror::Error;

/// Errors that can occur during MCP JSON-RPC proxying, protocol parsing, or interception.
#[derive(Debug, Error)]
pub enum McpError {
    /// Invalid JSON-RPC 2.0 format or message encoding.
    #[error("JSON-RPC error: {0}")]
    JsonRpcError(String),

    /// Policy constraint violation (tool blocked or out-of-bounds parameter).
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Process I/O or transport stream error.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Prover engine error during proof creation.
    #[error("Prover error: {0}")]
    Prover(#[from] zktrace_prover::error::ProverError),

    /// Ledger engine error during commit.
    #[error("Ledger error: {0}")]
    Ledger(#[from] zktrace_ledger::error::LedgerError),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] zktrace_core::error::CoreError),
}

/// Convenience result alias for MCP operations.
pub type McpResult<T> = Result<T, McpError>;
