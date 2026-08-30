//! Execution events, tool invocations, and execution digests.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::field::{deserialize_fr, fr_to_hex, serialize_fr, Fr};
use crate::crypto::poseidon::{poseidon_hash_bytes, poseidon_hash_many};

/// Identity commitment representing the executing AI Agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Agent identifier or service account name.
    pub agent_id: String,
    /// Public identity commitment hash $\text{Poseidon}(\text{AgentPubKey} \parallel \text{Org})$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub pubkey_hash: Fr,
    /// Enterprise organization / tenant name.
    pub organization: String,
}

impl AgentIdentity {
    /// Constructs a new agent identity with a derived public commitment hash.
    pub fn new(agent_id: impl Into<String>, organization: impl Into<String>) -> Self {
        let a_id = agent_id.into();
        let org = organization.into();
        let seed = format!("{}:{}", a_id, org);
        let pubkey_hash = poseidon_hash_bytes(seed.as_bytes());
        Self {
            agent_id: a_id,
            pubkey_hash,
            organization: org,
        }
    }
}

/// Status outcome of an MCP tool invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    /// Execution succeeded within policy constraints.
    Success = 0,
    /// Execution was rejected due to policy constraint violation.
    PolicyViolation = 1,
    /// Tool execution raised an internal error.
    ExecutionFailed = 2,
    /// Tool invocation timed out.
    Timeout = 3,
}

/// Cryptographic digest representing an individual tool execution.
///
/// $D = \text{Poseidon}(\text{ToolID}, \text{ParamDigest}, \text{ResultCode}, \text{Timestamp}, \text{SessionID})$
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDigest {
    /// Tool ID hash $\mathbb{F}_r$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub tool_id_hash: Fr,
    /// Parameter commitment digest $\mathbb{F}_r$ (computed without revealing raw PII).
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub param_digest: Fr,
    /// Numerical result code ($0 = \text{success}$).
    pub result_code: u32,
    /// UTC timestamp (seconds).
    pub timestamp: i64,
    /// Unique execution session nonce.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub session_id: Fr,
}

impl ExecutionDigest {
    /// Computes the single $\mathbb{F}_r$ commitment for this execution digest.
    pub fn compute_commitment(&self) -> Fr {
        let ts_fr = Fr::from(self.timestamp as u64);
        let rc_fr = Fr::from(self.result_code as u64);
        poseidon_hash_many(&[
            self.tool_id_hash,
            self.param_digest,
            rc_fr,
            ts_fr,
            self.session_id,
        ])
    }
}

/// A complete logged execution event ready for zero-knowledge witness generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEvent {
    /// Unique execution event UUID.
    pub event_id: Uuid,
    /// Session identifier.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub session_id: Fr,
    /// Identity of the executing agent.
    pub agent: AgentIdentity,
    /// Target MCP tool name.
    pub tool_name: String,
    /// Sanitized / PII-masked tool parameters (for auditor reference).
    pub masked_parameters: serde_json::Value,
    /// Cryptographic digest of raw parameters $\text{Poseidon}(\text{raw\_json})$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub raw_param_digest: Fr,
    /// Execution status outcome.
    pub status: ExecutionStatus,
    /// Cryptographic execution digest.
    pub digest: ExecutionDigest,
    /// UTC timestamp of occurrence.
    pub timestamp: i64,
}

impl ExecutionEvent {
    /// Creates a new execution event.
    pub fn new(
        agent: AgentIdentity,
        session_id: Fr,
        tool_name: impl Into<String>,
        raw_params_json: &[u8],
        masked_parameters: serde_json::Value,
        status: ExecutionStatus,
    ) -> Self {
        let name = tool_name.into();
        let tool_id_hash = poseidon_hash_bytes(name.as_bytes());
        let raw_param_digest = poseidon_hash_bytes(raw_params_json);
        let timestamp = Utc::now().timestamp();
        let result_code = status as u32;

        let digest = ExecutionDigest {
            tool_id_hash,
            param_digest: raw_param_digest,
            result_code,
            timestamp,
            session_id,
        };

        Self {
            event_id: Uuid::new_v4(),
            session_id,
            agent,
            tool_name: name,
            masked_parameters,
            raw_param_digest,
            status,
            digest,
            timestamp,
        }
    }

    /// Computes the leaf hash to be inserted into the append-only Merkle ledger:
    /// $L = \text{Poseidon}(\text{AgentPubKeyHash}, \text{SessionID}, \text{DigestCommitment})$
    pub fn compute_ledger_leaf(&self) -> Fr {
        let digest_commitment = self.digest.compute_commitment();
        poseidon_hash_many(&[
            self.agent.pubkey_hash,
            self.session_id,
            digest_commitment,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_event_leaf_computation() {
        let agent = AgentIdentity::new("agent_alpha_01", "enterprise_corp");
        let session_id = Fr::from(1001u64);
        let raw_json = br#"{"query":"SELECT id FROM payments WHERE amount < 500"}"#;
        let masked = serde_json::json!({"query": "SELECT id FROM payments WHERE amount < [MASKED]"});

        let event = ExecutionEvent::new(
            agent,
            session_id,
            "postgres_query",
            raw_json,
            masked,
            ExecutionStatus::Success,
        );

        let leaf1 = event.compute_ledger_leaf();
        let leaf2 = event.compute_ledger_leaf();
        assert_eq!(leaf1, leaf2);
        assert_ne!(leaf1, Fr::from(0u64));
    }
}
