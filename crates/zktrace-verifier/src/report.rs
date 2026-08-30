//! Structured verification reports and verdict statuses for auditors.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Outcome status of an audit receipt verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationVerdict {
    /// Receipt is cryptographically sound, policy-compliant, and ledger-verified.
    Valid,
    /// Groth16 zero-knowledge proof verification failed mathematically.
    InvalidProof,
    /// Policy root committed in the proof does not match expected active policy.
    PolicyRootMismatch,
    /// Merkle inclusion proof failed against committed ledger root.
    MerkleInclusionFailed,
    /// Execution timestamp violated timestamp window constraints.
    TimestampExpired,
    /// Execution digest mismatch.
    ExecutionDigestMismatch,
}

/// Detailed cryptographic verification report produced by the verifier engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Unique receipt ID being audited.
    pub receipt_id: Uuid,
    /// Primary verification verdict.
    pub verdict: VerificationVerdict,
    /// Summary boolean: `true` if all checks passed.
    pub is_valid: bool,
    /// Whether the Groth16 zero-knowledge proof passed pairing checks.
    pub proof_verified: bool,
    /// Whether the committed policy root matched the expected active policy.
    pub policy_root_matched: bool,
    /// Whether the Merkle tree inclusion path was mathematically sound.
    pub merkle_inclusion_verified: bool,
    /// Whether the timestamp window constraint was met.
    pub timestamp_valid: bool,
    /// Execution digest commitment in hex.
    pub execution_digest_hex: String,
    /// Policy root commitment in hex.
    pub policy_root_hex: String,
    /// Verification latency in microseconds (µs).
    pub duration_micros: u64,
    /// Detailed audit explanation or error trace.
    pub details: String,
}

impl VerificationReport {
    /// Serializes the verification report to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
