//! Groth16 Prover engine producing succinct cryptographic audit receipts.

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use uuid::Uuid;
use zktrace_core::crypto::{Fr, MerkleProof};
use zktrace_core::types::execution::ExecutionEvent;
use zktrace_core::types::policy::PolicyTree;
use zktrace_core::types::receipt::{AuditReceipt, ProofBytes, PublicInputs};

use crate::error::{ProverError, ProverResult};
use crate::setup::ProverKeys;
use crate::witness::WitnessSynthesizer;

/// High-performance Groth16 Zero-Knowledge Prover for ZKTrace.
pub struct ZKTraceProver {
    /// Active proving and verifying keys.
    pub keys: ProverKeys,
    /// Policy tree depth supported by this prover instance.
    pub tree_depth: usize,
    /// Default timestamp validity window (seconds).
    pub timestamp_window_secs: u64,
}

impl ZKTraceProver {
    /// Creates a new `ZKTraceProver` with initialized keys.
    pub fn new(keys: ProverKeys, tree_depth: usize) -> Self {
        Self {
            keys,
            tree_depth,
            timestamp_window_secs: 3600,
        }
    }

    /// Generates a complete cryptographic `AuditReceipt` for an execution event against a policy tree.
    pub fn prove_execution(
        &self,
        event: &ExecutionEvent,
        policy_tree: &PolicyTree,
        raw_prompt: Option<&[u8]>,
        merkle_inclusion: Option<MerkleProof>,
        ledger_root: Fr,
    ) -> ProverResult<AuditReceipt> {
        // 1. Synthesize R1CS witness and public inputs
        let circuit = WitnessSynthesizer::synthesize(
            event,
            policy_tree,
            self.tree_depth,
            raw_prompt,
            self.timestamp_window_secs,
        )?;

        // Extract public inputs before moving circuit into prover
        let policy_root_hash = circuit.policy_root_hash.ok_or_else(|| {
            ProverError::WitnessError("Missing policy root in synthesized circuit".to_string())
        })?;
        let execution_digest = circuit.execution_digest.ok_or_else(|| {
            ProverError::WitnessError("Missing execution digest in synthesized circuit".to_string())
        })?;
        let agent_pubkey_hash = circuit.agent_pubkey_hash.ok_or_else(|| {
            ProverError::WitnessError("Missing agent pubkey in synthesized circuit".to_string())
        })?;
        let session_id = circuit.session_id.ok_or_else(|| {
            ProverError::WitnessError("Missing session id in synthesized circuit".to_string())
        })?;
        let timestamp_window = circuit.timestamp_window.ok_or_else(|| {
            ProverError::WitnessError("Missing timestamp window in synthesized circuit".to_string())
        })?;

        let public_inputs = PublicInputs {
            policy_root_hash,
            execution_digest,
            agent_pubkey_hash,
            session_id,
            timestamp_window,
        };

        // 2. Generate Groth16 zero-knowledge proof
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(&self.keys.pk, circuit, &mut rng)
            .map_err(|e| ProverError::Groth16ProvingError(format!("Proof creation failed: {}", e)))?;

        // 3. Serialize proof to canonical compressed bytes
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ProverError::Serialization(format!("Proof serialization failed: {}", e)))?;

        let receipt = AuditReceipt {
            receipt_id: Uuid::new_v4(),
            event_id: event.event_id,
            public_inputs,
            proof: ProofBytes::from_bytes(&proof_bytes),
            merkle_inclusion,
            ledger_root,
            timestamp: event.timestamp,
        };

        Ok(receipt)
    }
}
