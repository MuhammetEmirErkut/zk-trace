//! Cryptographic audit receipts, public inputs, and verification containers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::field::{deserialize_fr, serialize_fr, Fr};
use crate::crypto::merkle::MerkleProof;
use crate::error::{CoreError, CoreResult};

/// Serialized raw bytes for a zero-knowledge proof (Groth16 $\pi = (A \in \mathbb{G}_1, B \in \mathbb{G}_2, C \in \mathbb{G}_1)$).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBytes {
    /// Proof data encoded as a `0x`-prefixed hex string for JSON and CLI interoperability.
    pub proof_hex: String,
}

impl ProofBytes {
    /// Creates a `ProofBytes` container from raw byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            proof_hex: format!("0x{}", hex::encode(bytes)),
        }
    }

    /// Decodes the proof into a raw byte vector.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let clean = self
            .proof_hex
            .trim()
            .strip_prefix("0x")
            .unwrap_or(self.proof_hex.trim());
        hex::decode(clean).map_err(|e| {
            CoreError::SerializationError(format!("Invalid proof hex string: {}", e))
        })
    }
}

/// Public inputs exposed to the Zero-Knowledge verifier.
///
/// These inputs correspond 1-to-1 with the public wires of the ZKTrace policy circuit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Committed Merkle root of the active policy specification $R_{\text{policy}}$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub policy_root_hash: Fr,
    /// Cryptographic digest of the execution event $D$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub execution_digest: Fr,
    /// Public identity commitment hash of the agent.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub agent_pubkey_hash: Fr,
    /// Session nonce / identifier.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub session_id: Fr,
    /// Timestamp window constraint.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub timestamp_window: Fr,
}

impl PublicInputs {
    /// Converts public inputs into an ordered list of $\mathbb{F}_r$ field elements for Arkworks verification.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        vec![
            self.policy_root_hash,
            self.execution_digest,
            self.agent_pubkey_hash,
            self.session_id,
            self.timestamp_window,
        ]
    }
}

/// A complete, standalone `.zktrace` cryptographic audit receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReceipt {
    /// Unique receipt identifier.
    pub receipt_id: Uuid,
    /// Execution event ID this receipt proves.
    pub event_id: Uuid,
    /// Public inputs verified by the proof.
    pub public_inputs: PublicInputs,
    /// Succinct zero-knowledge execution proof.
    pub proof: ProofBytes,
    /// Merkle inclusion proof in the append-only execution ledger.
    pub merkle_inclusion: Option<MerkleProof>,
    /// The ledger root at the time of proof issuance.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub ledger_root: Fr,
    /// Creation timestamp (UTC seconds).
    pub timestamp: i64,
}

impl AuditReceipt {
    /// Serializes the audit receipt into a formatted JSON string.
    pub fn to_json(&self) -> CoreResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::SerializationError(format!("Failed to serialize receipt to JSON: {}", e)))
    }

    /// Deserializes an audit receipt from a JSON string.
    pub fn from_json(json_str: &str) -> CoreResult<Self> {
        serde_json::from_str(json_str)
            .map_err(|e| CoreError::SerializationError(format!("Failed to parse receipt from JSON: {}", e)))
    }

    /// Serializes the audit receipt into compact binary format.
    pub fn to_binary(&self) -> CoreResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| CoreError::SerializationError(format!("Failed to binary serialize receipt: {}", e)))
    }

    /// Deserializes an audit receipt from compact binary bytes.
    pub fn from_binary(bytes: &[u8]) -> CoreResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| CoreError::SerializationError(format!("Failed to binary deserialize receipt: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_json_and_binary_roundtrip() {
        let public_inputs = PublicInputs {
            policy_root_hash: Fr::from(100u64),
            execution_digest: Fr::from(200u64),
            agent_pubkey_hash: Fr::from(300u64),
            session_id: Fr::from(400u64),
            timestamp_window: Fr::from(500u64),
        };

        let dummy_proof = ProofBytes::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let receipt = AuditReceipt {
            receipt_id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            public_inputs,
            proof: dummy_proof,
            merkle_inclusion: None,
            ledger_root: Fr::from(999u64),
            timestamp: 1725000000,
        };

        // JSON roundtrip
        let json = receipt.to_json().expect("JSON export failed");
        let parsed_json = AuditReceipt::from_json(&json).expect("JSON import failed");
        assert_eq!(receipt, parsed_json);

        // Binary roundtrip
        let bin = receipt.to_binary().expect("Binary export failed");
        let parsed_bin = AuditReceipt::from_binary(&bin).expect("Binary import failed");
        assert_eq!(receipt, parsed_bin);
    }
}
