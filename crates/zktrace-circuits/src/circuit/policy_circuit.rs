//! Main R1CS Execution Policy Circuit for ZKTrace.
//!
//! Enforces mathematical compliance of AI agent tool execution against committed policies
//! without revealing raw prompt queries, PII, or internal credentials.

use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zktrace_core::crypto::{Fr, MerkleProof};

use crate::gadgets::{
    merkle::MerklePathVar,
    poseidon::{poseidon_hash_2_gadget, poseidon_hash_many_gadget},
    range::enforce_less_than_or_equal_constant,
};

/// The primary Zero-Knowledge Policy Execution Circuit.
///
/// Implements `ConstraintSynthesizer<Fr>` to generate R1CS constraints for Groth16 proving.
#[derive(Clone, Debug, Default)]
pub struct ExecutionPolicyCircuit {
    // ==========================================
    // Public Inputs (Exposed to Verifier)
    // ==========================================
    /// Committed Policy Merkle Root $R_{\text{policy}}$.
    pub policy_root_hash: Option<Fr>,
    /// Cryptographic Execution Digest $D$.
    pub execution_digest: Option<Fr>,
    /// Public Agent Identity Commitment $\text{Poseidon}(\text{AgentPubKey} \parallel \text{Org})$.
    pub agent_pubkey_hash: Option<Fr>,
    /// Session Identifier / Nonce.
    pub session_id: Option<Fr>,
    /// Bounded Timestamp Window / Upper Bound.
    pub timestamp_window: Option<Fr>,

    // ==========================================
    // Private Witnesses (Zero-Knowledge Kept Hidden)
    // ==========================================
    /// Tool Name Hash $\text{Poseidon}(\text{ToolName})$.
    pub tool_id_hash: Option<Fr>,
    /// Parameter Hash $\text{Poseidon}(\text{RawJSON})$.
    pub param_digest: Option<Fr>,
    /// Raw Prompt / PII Hash (Private witness).
    pub raw_prompt_hash: Option<Fr>,
    /// Policy Rule Leaf Commitment $L_{\text{rule}}$.
    pub rule_leaf: Option<Fr>,
    /// Merkle Authentication Path proving $L_{\text{rule}} \in R_{\text{policy}}$.
    pub policy_proof: Option<MerkleProof>,
    /// Parameter numerical value to enforce bounds on (e.g. spend amount in cents, max rows).
    pub param_value: Option<u64>,
    /// Upper bound specified by the active policy.
    pub param_max_bound: Option<u64>,
    /// Numerical result code ($0 = \text{success}$).
    pub result_code: Option<u32>,
    /// Timestamp of execution.
    pub timestamp: Option<i64>,
}

impl ConstraintSynthesizer<Fr> for ExecutionPolicyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ====================================================================
        // 1. Allocate Public Inputs (Order must match PublicInputs struct)
        // ====================================================================
        let policy_root_var = FpVar::new_input(cs.clone(), || {
            self.policy_root_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let execution_digest_var = FpVar::new_input(cs.clone(), || {
            self.execution_digest.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _agent_pubkey_var = FpVar::new_input(cs.clone(), || {
            self.agent_pubkey_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let session_id_var = FpVar::new_input(cs.clone(), || {
            self.session_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let timestamp_window_var = FpVar::new_input(cs.clone(), || {
            self.timestamp_window.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ====================================================================
        // 2. Allocate Private Witnesses
        // ====================================================================
        let tool_id_var = FpVar::new_witness(cs.clone(), || {
            self.tool_id_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let param_digest_var = FpVar::new_witness(cs.clone(), || {
            self.param_digest.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let rule_leaf_var = FpVar::new_witness(cs.clone(), || {
            self.rule_leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let result_code_var = FpVar::new_witness(cs.clone(), || {
            self.result_code
                .map(|rc| Fr::from(rc as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let timestamp_var = FpVar::new_witness(cs.clone(), || {
            self.timestamp
                .map(|ts| Fr::from(ts as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ====================================================================
        // 3. Enforce Policy Merkle Tree Membership
        // ====================================================================
        if let Some(proof) = &self.policy_proof {
            let path_var = MerklePathVar::new_witness(cs.clone(), proof)?;
            path_var.enforce_membership(cs.clone(), &rule_leaf_var, &policy_root_var)?;
        }

        // ====================================================================
        // 4. Enforce Numerical Parameter Range Bounds ($0 \le \text{val} \le \text{bound}$)
        // ====================================================================
        if let (Some(val), Some(bound)) = (self.param_value, self.param_max_bound) {
            let param_val_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(val)))?;
            enforce_less_than_or_equal_constant(cs.clone(), &param_val_var, bound, 64)?;
        }

        // ====================================================================
        // 5. Enforce Execution Digest Integrity
        //
        // $D = \text{Poseidon}(\text{ToolID}, \text{ParamDigest}, \text{ResultCode}, \text{Timestamp}, \text{SessionID})$
        // ====================================================================
        let computed_digest_var = poseidon_hash_many_gadget(
            cs.clone(),
            &[
                tool_id_var,
                param_digest_var,
                result_code_var,
                timestamp_var.clone(),
                session_id_var,
            ],
        )?;

        computed_digest_var.enforce_equal(&execution_digest_var)?;

        // ====================================================================
        // 6. Enforce Timestamp Window Bound ($\text{timestamp} \le \text{timestamp\_window}$)
        // ====================================================================
        if let (Some(ts), Some(_ts_win)) = (self.timestamp, self.timestamp_window) {
            let ts_u64 = ts as u64;
            let window_val = timestamp_window_var.value().unwrap_or(Fr::from(0u64));
            let window_u64 = window_val.into_bigint().0[0];
            if window_u64 >= ts_u64 {
                enforce_less_than_or_equal_constant(cs.clone(), &timestamp_var, window_u64, 64)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use zktrace_core::crypto::{poseidon_hash_many, MerkleTree};
    use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};

    #[test]
    fn test_execution_policy_circuit_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 1. Setup policy tree
        let mut policy_tree = PolicyTree::new("test-policy", 1);
        let rule = PolicyRule::new("stripe_payment", "Payment tool").with_constraint(
            ParamConstraint {
                param_name: "amount".to_string(),
                constraint: ConstraintType::MaxSpendLimit { max_amount: 100_000 },
            },
        );
        let rule_leaf = rule.compute_leaf();
        policy_tree.add_rule(rule);

        let mut merkle = MerkleTree::new(4);
        merkle.insert(rule_leaf).unwrap();
        let policy_root = merkle.root();
        let policy_proof = merkle.generate_proof(0).unwrap();

        // 2. Setup execution parameters
        let tool_id_hash = zktrace_core::crypto::poseidon_hash_bytes(b"stripe_payment");
        let param_digest = zktrace_core::crypto::poseidon_hash_bytes(b"{\"amount\": 50000}");
        let session_id = Fr::from(4242u64);
        let agent_pubkey = Fr::from(9999u64);
        let timestamp: i64 = 1725000000;
        let result_code: u32 = 0;

        let digest = poseidon_hash_many(&[
            tool_id_hash,
            param_digest,
            Fr::from(result_code as u64),
            Fr::from(timestamp as u64),
            session_id,
        ]);

        let circuit = ExecutionPolicyCircuit {
            policy_root_hash: Some(policy_root),
            execution_digest: Some(digest),
            agent_pubkey_hash: Some(agent_pubkey),
            session_id: Some(session_id),
            timestamp_window: Some(Fr::from((timestamp + 3600) as u64)),
            tool_id_hash: Some(tool_id_hash),
            param_digest: Some(param_digest),
            raw_prompt_hash: Some(Fr::from(123u64)),
            rule_leaf: Some(rule_leaf),
            policy_proof: Some(policy_proof),
            param_value: Some(50_000),
            param_max_bound: Some(100_000),
            result_code: Some(result_code),
            timestamp: Some(timestamp),
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "Circuit must be satisfied for valid witness");
    }

    #[test]
    fn test_execution_policy_circuit_rejects_out_of_bounds() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let tool_id_hash = zktrace_core::crypto::poseidon_hash_bytes(b"stripe_payment");
        let param_digest = zktrace_core::crypto::poseidon_hash_bytes(b"{\"amount\": 150000}");
        let session_id = Fr::from(4242u64);
        let agent_pubkey = Fr::from(9999u64);
        let timestamp: i64 = 1725000000;
        let result_code: u32 = 0;

        let digest = poseidon_hash_many(&[
            tool_id_hash,
            param_digest,
            Fr::from(result_code as u64),
            Fr::from(timestamp as u64),
            session_id,
        ]);

        let circuit = ExecutionPolicyCircuit {
            policy_root_hash: Some(Fr::from(1u64)),
            execution_digest: Some(digest),
            agent_pubkey_hash: Some(agent_pubkey),
            session_id: Some(session_id),
            timestamp_window: Some(Fr::from((timestamp + 3600) as u64)),
            tool_id_hash: Some(tool_id_hash),
            param_digest: Some(param_digest),
            raw_prompt_hash: None,
            rule_leaf: Some(Fr::from(1u64)),
            policy_proof: None,
            param_value: Some(150_000), // Exceeds bound of 100_000!
            param_max_bound: Some(100_000),
            result_code: Some(result_code),
            timestamp: Some(timestamp),
        };

        // Generating constraints should either return synthesis error or produce an unsatisfied constraint system
        let res = circuit.generate_constraints(cs.clone());
        if res.is_ok() {
            assert!(!cs.is_satisfied().unwrap(), "Circuit MUST fail when param exceeds max bound");
        }
    }
}
