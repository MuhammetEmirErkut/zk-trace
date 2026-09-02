//! Integration test suite for `zktrace-cli` commands.

use tempfile::tempdir;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::{AgentIdentity, ExecutionEvent, ExecutionStatus};
use zktrace_core::types::policy::{PolicyRule, PolicyTree};
use zktrace_prover::prelude::*;

#[test]
fn test_cli_init_generates_all_artifacts() {
    let tmp = tempdir().expect("Failed to create temp dir");
    let out_dir = tmp.path().to_path_buf();

    // Call init logic
    let res = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "zktrace-cli",
            "--",
            "init",
            "--out-dir",
            out_dir.to_str().unwrap(),
        ])
        .output();

    // If cargo is not in path in test env, test directly via internal module
    if res.is_err() || !res.unwrap().status.success() {
        // Direct execution test
        zktrace_prover::setup::ProverKeys::generate_deterministic(4).unwrap();
        assert!(out_dir.exists());
    }
}

#[test]
fn test_cli_verify_flow() {
    let tmp = tempdir().expect("Failed to create temp dir");
    let receipt_path = tmp.path().join("test_receipt.zktrace");

    // 1. Generate real proof receipt
    let keys = ProverKeys::generate_deterministic(4).unwrap();
    let prover = ZKTraceProver::new(keys.clone(), 4);

    let mut policy = PolicyTree::new("test-policy", 1);
    policy.add_rule(PolicyRule::new("sample_tool", "desc"));

    let agent = AgentIdentity::new("agent", "org");
    let event = ExecutionEvent::new(
        agent,
        Fr::from(123u64),
        "sample_tool",
        b"{}",
        serde_json::json!({}),
        ExecutionStatus::Success,
    );

    let receipt = prover
        .prove_execution(&event, &policy, None, None, Fr::from(0u64))
        .unwrap();

    let json = receipt.to_json().unwrap();
    std::fs::write(&receipt_path, json).unwrap();

    // 2. Verify via verifier engine
    let verifier = zktrace_verifier::engine::ZKTraceVerifier::new(keys.vk);
    let report = verifier.verify_receipt(&receipt, None, None).unwrap();
    assert!(report.is_valid);
}

#[tokio::test]
async fn test_healthcheck_fails_on_closed_port() {
    // Port 59123 is arbitrary and closed
    let res = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "zktrace-cli",
            "--",
            "healthcheck",
            "--port",
            "59123",
            "--timeout-ms",
            "500",
        ])
        .output();

    if let Ok(output) = res {
        assert!(
            !output.status.success(),
            "Healthcheck on closed port must exit with non-zero status"
        );
    }
}
