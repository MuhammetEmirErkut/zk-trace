//! Portable `.zktrace` audit bundle format for sharing cryptographically verifiable receipts.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zktrace_core::crypto::field::{deserialize_fr, serialize_fr, Fr};
use zktrace_core::crypto::MerkleProof;
use zktrace_core::types::execution::ExecutionEvent;
use zktrace_core::types::receipt::AuditReceipt;

use crate::error::{LedgerError, LedgerResult};

/// A self-contained, portable `.zktrace` audit bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditBundle {
    /// Bundle format specification version.
    pub version: u32,
    /// Unique bundle UUID.
    pub bundle_id: Uuid,
    /// UTC timestamp of creation.
    pub created_at: i64,
    /// Starting leaf index in the ledger.
    pub start_index: usize,
    /// Total number of execution events contained in this bundle.
    pub leaf_count: usize,
    /// The Merkle ledger root commitment covering all leaves up to this bundle.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub ledger_root: Fr,
    /// List of verified execution events.
    pub events: Vec<ExecutionEvent>,
    /// Corresponding Zero-Knowledge audit receipts.
    pub receipts: Vec<AuditReceipt>,
    /// Merkle inclusion proofs for each event against `ledger_root`.
    pub inclusion_proofs: Vec<MerkleProof>,
}

impl AuditBundle {
    /// Creates a new `AuditBundle`.
    pub fn new(
        start_index: usize,
        ledger_root: Fr,
        events: Vec<ExecutionEvent>,
        receipts: Vec<AuditReceipt>,
        inclusion_proofs: Vec<MerkleProof>,
    ) -> Self {
        let count = events.len();
        Self {
            version: 1,
            bundle_id: Uuid::new_v4(),
            created_at: Utc::now().timestamp(),
            start_index,
            leaf_count: count,
            ledger_root,
            events,
            receipts,
            inclusion_proofs,
        }
    }

    /// Serializes bundle to pretty-printed JSON.
    pub fn to_json(&self) -> LedgerResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            LedgerError::BundleError(format!("Failed to serialize bundle to JSON: {}", e))
        })
    }

    /// Deserializes bundle from JSON string.
    pub fn from_json(json_str: &str) -> LedgerResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            LedgerError::BundleError(format!("Failed to parse bundle from JSON: {}", e))
        })
    }

    /// Serializes bundle into compact binary format.
    pub fn to_bytes(&self) -> LedgerResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            LedgerError::BundleError(format!("Failed to binary serialize bundle: {}", e))
        })
    }

    /// Deserializes bundle from compact binary bytes.
    pub fn from_bytes(bytes: &[u8]) -> LedgerResult<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            LedgerError::BundleError(format!("Failed to binary deserialize bundle: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_json_and_binary_roundtrip() {
        let bundle = AuditBundle::new(0, Fr::from(100u64), vec![], vec![], vec![]);

        let json = bundle.to_json().unwrap();
        let parsed_json = AuditBundle::from_json(&json).unwrap();
        assert_eq!(bundle, parsed_json);

        let bytes = bundle.to_bytes().unwrap();
        let parsed_bytes = AuditBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle, parsed_bytes);
    }
}
