//! Runtime witness generator transforming execution events and policy trees into R1CS circuits.

use zktrace_circuits::circuit::ExecutionPolicyCircuit;
use zktrace_core::crypto::{poseidon_hash_bytes, Fr, MerkleTree};
use zktrace_core::types::execution::ExecutionEvent;
use zktrace_core::types::policy::{ConstraintType, PolicyTree};

use crate::error::{ProverError, ProverResult};

/// Automated witness synthesis engine.
pub struct WitnessSynthesizer;

impl WitnessSynthesizer {
    /// Synthesizes an `ExecutionPolicyCircuit` from a runtime `ExecutionEvent` and `PolicyTree`.
    pub fn synthesize(
        event: &ExecutionEvent,
        policy_tree: &PolicyTree,
        tree_depth: usize,
        raw_prompt: Option<&[u8]>,
        timestamp_window_secs: u64,
    ) -> ProverResult<ExecutionPolicyCircuit> {
        // 1. Find matching policy rule
        let rule = policy_tree.get_rule(&event.tool_name).ok_or_else(|| {
            ProverError::PolicyViolation(format!(
                "Tool '{}' is not whitelisted in policy '{}'",
                event.tool_name, policy_tree.policy_id
            ))
        })?;

        // 2. Build Policy Merkle Tree to obtain inclusion proof
        let mut merkle_tree = MerkleTree::new(tree_depth);
        let mut target_leaf_index = None;

        for (idx, r) in policy_tree.rules.iter().enumerate() {
            let leaf = r.compute_leaf();
            merkle_tree.insert(leaf).map_err(|e| {
                ProverError::WitnessError(format!("Failed to insert rule leaf: {}", e))
            })?;
            if r.tool_name == event.tool_name {
                target_leaf_index = Some(idx);
            }
        }

        let leaf_idx = target_leaf_index.ok_or_else(|| {
            ProverError::WitnessError("Target rule leaf index not found".to_string())
        })?;

        let policy_root = merkle_tree.root();
        let policy_proof = merkle_tree.generate_proof(leaf_idx).map_err(|e| {
            ProverError::WitnessError(format!("Failed to generate policy Merkle proof: {}", e))
        })?;

        // 3. Extract parameter constraints (e.g. max spend limit)
        let mut param_val = None;
        let mut param_max = None;

        for c in &rule.constraints {
            match &c.constraint {
                ConstraintType::MaxSpendLimit { max_amount } => {
                    param_max = Some(*max_amount);
                    // Extract from masked_parameters or raw params if available
                    if let Some(val) = event.masked_parameters.get(&c.param_name) {
                        if let Some(num) = val.as_u64() {
                            param_val = Some(num);
                        }
                    }
                }
                ConstraintType::NumericRange { min: _, max } => {
                    param_max = Some(*max);
                    if let Some(val) = event.masked_parameters.get(&c.param_name) {
                        if let Some(num) = val.as_u64() {
                            param_val = Some(num);
                        }
                    }
                }
                _ => {}
            }
        }

        // 4. Compute prompt hash if provided
        let raw_prompt_hash = raw_prompt.map(poseidon_hash_bytes);

        // 5. Compute public execution digest commitment
        let execution_digest = event.digest.compute_commitment();
        let timestamp_window = Fr::from((event.timestamp as u64) + timestamp_window_secs);

        Ok(ExecutionPolicyCircuit {
            policy_root_hash: Some(policy_root),
            execution_digest: Some(execution_digest),
            agent_pubkey_hash: Some(event.agent.pubkey_hash),
            session_id: Some(event.session_id),
            timestamp_window: Some(timestamp_window),
            tool_id_hash: Some(event.digest.tool_id_hash),
            param_digest: Some(event.raw_param_digest),
            raw_prompt_hash,
            rule_leaf: Some(rule.compute_leaf()),
            policy_proof: Some(policy_proof),
            param_value: param_val,
            param_max_bound: param_max,
            result_code: Some(event.digest.result_code),
            timestamp: Some(event.timestamp),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zktrace_core::types::execution::{AgentIdentity, ExecutionStatus};
    use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule};

    #[test]
    fn test_witness_synthesizer_success() {
        let agent = AgentIdentity::new("agent_test", "acme_corp");
        let session_id = Fr::from(5555u64);
        let raw_json = br#"{"amount": 2500}"#;
        let masked = serde_json::json!({"amount": 2500});

        let event = ExecutionEvent::new(
            agent,
            session_id,
            "sql_query",
            raw_json,
            masked,
            ExecutionStatus::Success,
        );

        let mut policy_tree = PolicyTree::new("test-policy", 1);
        let rule =
            PolicyRule::new("sql_query", "SQL query tool").with_constraint(ParamConstraint {
                param_name: "amount".to_string(),
                constraint: ConstraintType::MaxSpendLimit { max_amount: 10_000 },
            });
        policy_tree.add_rule(rule);

        let circuit = WitnessSynthesizer::synthesize(&event, &policy_tree, 4, None, 3600)
            .expect("Synthesis must succeed");

        assert!(circuit.policy_root_hash.is_some());
        assert_eq!(circuit.param_value, Some(2500));
        assert_eq!(circuit.param_max_bound, Some(10_000));
    }
}
