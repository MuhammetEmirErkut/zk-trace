//! Integration test suite for `zktrace-verifier`.

use zktrace_core::crypto::{Fr, MerkleTree};
use zktrace_core::types::execution::{AgentIdentity, ExecutionEvent, ExecutionStatus};
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};
use zktrace_prover::prelude::*;
use zktrace_verifier::prelude::*;

#[test]
fn test_instant_verifier_valid_receipt() {
    // 1. Setup Prover and Verifier
    let keys = ProverKeys::generate_deterministic(4).expect("Setup failed");
    let prover = ZKTraceProver::new(keys.clone(), 4);
    let verifier = ZKTraceVerifier::new(keys.vk);

    // 2. Setup Policy
    let mut policy = PolicyTree::new("prod-policy", 1);
    let rule = PolicyRule::new("query_database", "Read-only SQL").with_constraint(
        ParamConstraint {
            param_name: "max_rows".to_string(),
            constraint: ConstraintType::NumericRange { min: 1, max: 1000 },
        },
    );
    let rule_leaf = rule.compute_leaf();
    policy.add_rule(rule);

    let mut policy_merkle = MerkleTree::new(4);
    policy_merkle.insert(rule_leaf).unwrap();
    let expected_policy_root = policy_merkle.root();

    // 3. Execution event
    let agent = AgentIdentity::new("db-analyst-agent", "corp");
    let session_id = Fr::from(9999u64);
    let event = ExecutionEvent::new(
        agent,
        session_id,
        "query_database",
        br#"{"query": "SELECT * FROM analytics", "max_rows": 500}"#,
        serde_json::json!({"max_rows": 500}),
        ExecutionStatus::Success,
    );

    let ledger_tree = MerkleTree::new(4);
    let receipt = prover
        .prove_execution(&event, &policy, None, None, ledger_tree.root())
        .expect("Proving failed");

    // 4. Verify Receipt
    let report = verifier
        .verify_receipt(&receipt, Some(&expected_policy_root), None)
        .expect("Verification failed");

    assert!(report.is_valid);
    assert_eq!(report.verdict, VerificationVerdict::Valid);
    assert!(report.proof_verified);
    assert!(report.policy_root_matched);
    println!("Verified receipt in {} microseconds", report.duration_micros);
}

#[test]
fn test_instant_verifier_detects_policy_mismatch() {
    let keys = ProverKeys::generate_deterministic(4).unwrap();
    let prover = ZKTraceProver::new(keys.clone(), 4);
    let verifier = ZKTraceVerifier::new(keys.vk);

    let mut policy = PolicyTree::new("prod-policy", 1);
    let rule = PolicyRule::new("query_database", "Read-only SQL");
    policy.add_rule(rule);

    let agent = AgentIdentity::new("db-analyst-agent", "corp");
    let session_id = Fr::from(9999u64);
    let event = ExecutionEvent::new(
        agent,
        session_id,
        "query_database",
        b"{}",
        serde_json::json!({}),
        ExecutionStatus::Success,
    );

    let ledger_tree = MerkleTree::new(4);
    let receipt = prover
        .prove_execution(&event, &policy, None, None, ledger_tree.root())
        .unwrap();

    let wrong_policy_root = Fr::from(123456789u64);
    let report = verifier
        .verify_receipt(&receipt, Some(&wrong_policy_root), None)
        .unwrap();

    assert!(!report.is_valid);
    assert_eq!(report.verdict, VerificationVerdict::PolicyRootMismatch);
    assert!(!report.policy_root_matched);
}

#[test]
fn test_instant_verifier_detects_forged_proof() {
    let keys = ProverKeys::generate_deterministic(4).unwrap();
    let prover = ZKTraceProver::new(keys.clone(), 4);
    let verifier = ZKTraceVerifier::new(keys.vk);

    let mut policy = PolicyTree::new("prod-policy", 1);
    policy.add_rule(PolicyRule::new("tool_a", "desc"));

    let agent = AgentIdentity::new("agent", "corp");
    let event = ExecutionEvent::new(
        agent,
        Fr::from(1u64),
        "tool_a",
        b"{}",
        serde_json::json!({}),
        ExecutionStatus::Success,
    );

    let mut receipt = prover
        .prove_execution(&event, &policy, None, None, Fr::from(0u64))
        .unwrap();

    // Tamper with public inputs (change session ID)
    receipt.public_inputs.session_id = Fr::from(9999999u64);

    let report = verifier.verify_receipt(&receipt, None, None).unwrap();
    assert!(!report.is_valid);
    assert_eq!(report.verdict, VerificationVerdict::InvalidProof);
}
