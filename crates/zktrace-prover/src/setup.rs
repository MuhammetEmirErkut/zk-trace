//! Trusted setup parameter generator and proving/verifying key management.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use zktrace_circuits::circuit::ExecutionPolicyCircuit;
use zktrace_core::crypto::{Fr, MerkleTree};

use crate::error::{ProverError, ProverResult};

/// Container holding the Groth16 Proving Key and Verifying Key for BN254.
#[derive(Clone)]
pub struct ProverKeys {
    /// Proving Key used by the AI Agent / ZKTrace sidecar proxy.
    pub pk: ProvingKey<Bn254>,
    /// Verifying Key distributed to auditors and verifier SDKs.
    pub vk: VerifyingKey<Bn254>,
}

impl ProverKeys {
    /// Generates deterministic Groth16 CRS / SRS parameters for the `ExecutionPolicyCircuit`.
    ///
    /// Uses a seeded cryptographically secure PRNG for reproducible testing and development setups.
    pub fn generate_deterministic(policy_tree_depth: usize) -> ProverResult<Self> {
        let mut rng = StdRng::seed_from_u64(0x5a4b3c2d1e0f);

        // Construct dummy template circuit for R1CS structure extraction
        let mut dummy_tree = MerkleTree::new(policy_tree_depth);
        dummy_tree.insert(Fr::from(1u64)).map_err(|e| {
            ProverError::SetupError(format!("Failed to build template tree: {}", e))
        })?;
        let dummy_proof = dummy_tree.generate_proof(0).map_err(|e| {
            ProverError::SetupError(format!("Failed to build template proof: {}", e))
        })?;

        let template_circuit = ExecutionPolicyCircuit {
            policy_root_hash: Some(dummy_tree.root()),
            execution_digest: Some(Fr::from(1u64)),
            agent_pubkey_hash: Some(Fr::from(1u64)),
            session_id: Some(Fr::from(1u64)),
            timestamp_window: Some(Fr::from(100_000u64)),
            tool_id_hash: Some(Fr::from(1u64)),
            param_digest: Some(Fr::from(1u64)),
            raw_prompt_hash: Some(Fr::from(1u64)),
            rule_leaf: Some(Fr::from(1u64)),
            policy_proof: Some(dummy_proof),
            param_value: Some(10),
            param_max_bound: Some(100),
            result_code: Some(0),
            timestamp: Some(50_000),
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(template_circuit, &mut rng)
            .map_err(|e| ProverError::SetupError(format!("Groth16 setup failed: {}", e)))?;

        Ok(Self { pk, vk })
    }

    /// Serializes the `ProvingKey` into canonical compressed bytes.
    pub fn serialize_pk(&self) -> ProverResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.pk
            .serialize_compressed(&mut bytes)
            .map_err(|e| ProverError::Serialization(format!("PK serialization failed: {}", e)))?;
        Ok(bytes)
    }

    /// Deserializes a `ProvingKey` from canonical compressed bytes.
    pub fn deserialize_pk(bytes: &[u8]) -> ProverResult<ProvingKey<Bn254>> {
        ProvingKey::<Bn254>::deserialize_compressed(bytes)
            .map_err(|e| ProverError::Serialization(format!("PK deserialization failed: {}", e)))
    }

    /// Serializes the `VerifyingKey` into canonical compressed bytes.
    pub fn serialize_vk(&self) -> ProverResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.vk
            .serialize_compressed(&mut bytes)
            .map_err(|e| ProverError::Serialization(format!("VK serialization failed: {}", e)))?;
        Ok(bytes)
    }

    /// Deserializes a `VerifyingKey` from canonical compressed bytes.
    pub fn deserialize_vk(bytes: &[u8]) -> ProverResult<VerifyingKey<Bn254>> {
        VerifyingKey::<Bn254>::deserialize_compressed(bytes)
            .map_err(|e| ProverError::Serialization(format!("VK deserialization failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_key_generation_and_serde() {
        let keys = ProverKeys::generate_deterministic(4).expect("Setup generation must succeed");

        let pk_bytes = keys.serialize_pk().expect("PK serialize failed");
        let vk_bytes = keys.serialize_vk().expect("VK serialize failed");

        assert!(!pk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());

        let recovered_pk = ProverKeys::deserialize_pk(&pk_bytes).expect("PK deserialize failed");
        let recovered_vk = ProverKeys::deserialize_vk(&vk_bytes).expect("VK deserialize failed");

        assert_eq!(keys.vk, recovered_vk);
        assert_eq!(keys.pk, recovered_pk);
    }
}
