//! Integration and performance test suite for `zktrace-prover`.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use zktrace_core::crypto::{Fr, MerkleTree};
use zktrace_core::types::execution::{AgentIdentity, ExecutionEvent, ExecutionStatus};
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};
use zktrace_prover::prelude::*;

#[test]
fn test_end_to_end_proving_and_verification() {
    // 1. Generate trusted setup parameters
    let keys = ProverKeys::generate_deterministic(4).expect("Setup key generation failed");
    let prover = ZKTraceProver::new(keys.clone(), 4);

    // 2. Define policy
    let mut policy_tree = PolicyTree::new("enterprise-policy-prod", 1);
    let rule = PolicyRule::new("execute_payment", "Stripe payment gateway").with_constraint(
        ParamConstraint {
            param_name: "amount".to_string(),
            constraint: ConstraintType::MaxSpendLimit {
                max_amount: 100_000,
            },
        },
    );
    policy_tree.add_rule(rule);

    // 3. Create execution event
    let agent = AgentIdentity::new("finance-agent-01", "enterprise-corp");
    let session_id = Fr::from(123456u64);
    let raw_json = br#"{"recipient": "acct_999", "amount": 45000}"#;
    let masked_json = serde_json::json!({"amount": 45000});

    let event = ExecutionEvent::new(
        agent,
        session_id,
        "execute_payment",
        raw_json,
        masked_json,
        ExecutionStatus::Success,
    );

    // 4. Generate proof receipt
    let dummy_ledger_tree = MerkleTree::new(4);
    let ledger_root = dummy_ledger_tree.root();

    let receipt = prover
        .prove_execution(&event, &policy_tree, None, None, ledger_root)
        .expect("Proving failed");

    // 5. Verify proof mathematically using Arkworks Groth16
    let proof_raw = receipt.proof.to_bytes().expect("Proof decode failed");
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_raw[..])
        .expect("Proof deserialization failed");
    let public_inputs = receipt.public_inputs.to_field_elements();

    let is_valid = Groth16::<Bn254>::verify(&keys.vk, &public_inputs, &proof)
        .expect("Verification operation failed");

    assert!(is_valid, "Generated Groth16 proof MUST be valid");

    // 6. Test JSON receipt bundle export & import
    let json = receipt.to_json().expect("Receipt JSON export failed");
    let imported = zktrace_core::types::receipt::AuditReceipt::from_json(&json)
        .expect("Receipt JSON import failed");
    assert_eq!(receipt, imported);
}
