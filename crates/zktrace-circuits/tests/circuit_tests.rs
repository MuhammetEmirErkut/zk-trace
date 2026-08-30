//! Integration test suite for ZKTrace policy circuits and constraint verification.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use zktrace_circuits::circuit::ExecutionPolicyCircuit;
use zktrace_core::crypto::{poseidon_hash_bytes, poseidon_hash_many, Fr, MerkleTree};
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};

#[test]
fn test_end_to_end_circuit_valid_execution() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    // 1. Setup policy tree with two rules
    let mut policy_tree = PolicyTree::new("enterprise-banking-policy", 1);
    let rule_payment = PolicyRule::new("bank_wire_transfer", "Wire transfer tool")
        .with_constraint(ParamConstraint {
            param_name: "amount".to_string(),
            constraint: ConstraintType::MaxSpendLimit { max_amount: 500_000 },
        });
    let rule_leaf = rule_payment.compute_leaf();
    policy_tree.add_rule(rule_payment);

    let mut merkle_tree = MerkleTree::new(4);
    merkle_tree.insert(rule_leaf).expect("Merkle insert must succeed");
    let policy_root = merkle_tree.root();
    let policy_proof = merkle_tree.generate_proof(0).expect("Proof generation must succeed");

    // 2. Setup execution context
    let tool_name = "bank_wire_transfer";
    let tool_id_hash = poseidon_hash_bytes(tool_name.as_bytes());
    let raw_param_json = br#"{"recipient": "ACC_998877", "amount": 250000}"#;
    let param_digest = poseidon_hash_bytes(raw_param_json);
    let session_id = Fr::from(987654u64);
    let agent_pubkey = Fr::from(11223344u64);
    let timestamp: i64 = 1725000500;
    let result_code: u32 = 0; // Success

    let execution_digest = poseidon_hash_many(&[
        tool_id_hash,
        param_digest,
        Fr::from(result_code as u64),
        Fr::from(timestamp as u64),
        session_id,
    ]);

    // 3. Construct circuit
    let circuit = ExecutionPolicyCircuit {
        policy_root_hash: Some(policy_root),
        execution_digest: Some(execution_digest),
        agent_pubkey_hash: Some(agent_pubkey),
        session_id: Some(session_id),
        timestamp_window: Some(Fr::from((timestamp + 3600) as u64)),
        tool_id_hash: Some(tool_id_hash),
        param_digest: Some(param_digest),
        raw_prompt_hash: Some(poseidon_hash_bytes(b"Transfer $2500 to supplier")),
        rule_leaf: Some(rule_leaf),
        policy_proof: Some(policy_proof),
        param_value: Some(250_000), // Within $5000 limit
        param_max_bound: Some(500_000),
        result_code: Some(result_code),
        timestamp: Some(timestamp),
    };

    // 4. Synthesize constraints and verify satisfaction
    circuit.generate_constraints(cs.clone()).expect("Synthesis must succeed");
    assert!(cs.is_satisfied().expect("Constraint satisfaction check"), "Circuit must be satisfied");

    // 5. Verify constraint count efficiency
    let num_constraints = cs.num_constraints();
    println!("Total R1CS constraints in ExecutionPolicyCircuit: {}", num_constraints);
    assert!(num_constraints > 0);
}

#[test]
fn test_circuit_rejects_forged_execution_digest() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let tool_id_hash = poseidon_hash_bytes(b"bank_wire_transfer");
    let param_digest = poseidon_hash_bytes(b"{\"amount\": 100}");
    let session_id = Fr::from(111u64);
    let agent_pubkey = Fr::from(222u64);
    let timestamp: i64 = 1725000000;
    let result_code: u32 = 0;

    let forged_digest = Fr::from(13371337u64); // Forged digest!

    let circuit = ExecutionPolicyCircuit {
        policy_root_hash: Some(Fr::from(1u64)),
        execution_digest: Some(forged_digest),
        agent_pubkey_hash: Some(agent_pubkey),
        session_id: Some(session_id),
        timestamp_window: Some(Fr::from((timestamp + 3600) as u64)),
        tool_id_hash: Some(tool_id_hash),
        param_digest: Some(param_digest),
        raw_prompt_hash: None,
        rule_leaf: Some(Fr::from(1u64)),
        policy_proof: None,
        param_value: Some(100),
        param_max_bound: Some(500),
        result_code: Some(result_code),
        timestamp: Some(timestamp),
    };

    circuit.generate_constraints(cs.clone()).expect("Synthesis");
    assert!(!cs.is_satisfied().expect("Check satisfaction"), "Circuit MUST reject forged digest");
}
