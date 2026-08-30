//! End-to-End integration test suite for the complete ZKTrace audit lifecycle.

use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::AgentIdentity;
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};
use zktrace_ledger::ledger::CryptographicLedger;
use zktrace_mcp::interceptor::McpInterceptor;
use zktrace_mcp::proxy::{McpProxy, ProxyAction};
use zktrace_prover::engine::ZKTraceProver;
use zktrace_prover::setup::ProverKeys;
use zktrace_verifier::engine::ZKTraceVerifier;
use zktrace_verifier::report::VerificationVerdict;

#[tokio::test]
async fn test_full_enterprise_ai_agent_audit_lifecycle() {
    let tmp = tempdir().expect("Failed to create temp directory");
    let ledger_dir = tmp.path().join("ledger");

    // =========================================================================
    // Step 1: Enterprise Setup - Generate Cryptographic Parameters & Active Policy
    // =========================================================================
    let tree_depth = 4;
    let keys = ProverKeys::generate_deterministic(tree_depth).expect("Setup keygen failed");
    let prover = ZKTraceProver::new(keys.clone(), tree_depth);
    let verifier = ZKTraceVerifier::new(keys.vk.clone());

    let mut policy = PolicyTree::new("enterprise-agent-governance-v1", 1);
    let sql_rule = PolicyRule::new("execute_sql", "Read-only SQL queries on analytics warehouse")
        .with_constraint(ParamConstraint {
            param_name: "query_type".to_string(),
            constraint: ConstraintType::ReadOnlyOnly,
        });
    let stripe_rule = PolicyRule::new("charge_card", "Stripe payment gateway with $5,000 limit")
        .with_constraint(ParamConstraint {
            param_name: "amount_cents".to_string(),
            constraint: ConstraintType::MaxSpendLimit { max_amount: 500_000 },
        });

    policy.add_rule(sql_rule);
    policy.add_rule(stripe_rule);

    let policy_root = policy.compute_policy_root(tree_depth).expect("Policy root failed");

    // =========================================================================
    // Step 2: Initialize Disk-backed Cryptographic Ledger
    // =========================================================================
    let ledger = Arc::new(Mutex::new(
        CryptographicLedger::open_disk(&ledger_dir, tree_depth).expect("Ledger open failed"),
    ));

    // =========================================================================
    // Step 3: Launch MCP Transparent Proxy for AI Agent
    // =========================================================================
    let agent = AgentIdentity::new("autonomous_finance_agent_01", "enterprise_corp");
    let interceptor = Arc::new(McpInterceptor::new(agent, policy.clone(), prover, ledger.clone()));
    let session_id = Fr::from(0xbeefcafeu64);
    let proxy = McpProxy::new(interceptor, session_id);

    // =========================================================================
    // Step 4: Simulate AI Agent executing compliant tool calls
    // =========================================================================
    let tool_call_1_raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_sql","arguments":{"query_type":"SELECT","statement":"SELECT count(*) FROM orders;"}}}"#;
    let action_1 = proxy.handle_client_message(tool_call_1_raw).expect("Proxy message 1");

    match action_1 {
        ProxyAction::Forward { request: _, tool_call } => {
            let tc = tool_call.unwrap();
            proxy.on_tool_completed(&tc, true).await.expect("Audit 1 completed");
        }
        ProxyAction::Reject { .. } => panic!("Valid SQL query was rejected!"),
    }

    let tool_call_2_raw = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"charge_card","arguments":{"amount_cents":150000,"currency":"usd"}}}"#;
    let action_2 = proxy.handle_client_message(tool_call_2_raw).expect("Proxy message 2");

    match action_2 {
        ProxyAction::Forward { request: _, tool_call } => {
            let tc = tool_call.unwrap();
            proxy.on_tool_completed(&tc, true).await.expect("Audit 2 completed");
        }
        ProxyAction::Reject { .. } => panic!("Valid Stripe charge was rejected!"),
    }

    // =========================================================================
    // Step 5: Export Audit Bundle for Third-Party Auditors
    // =========================================================================
    let ledger_guard = ledger.lock().await;
    assert_eq!(ledger_guard.count(), 2);

    let bundle = ledger_guard.export_bundle(0, 10).expect("Export bundle failed");
    assert_eq!(bundle.leaf_count, 2);
    assert_eq!(bundle.receipts.len(), 2);

    let bundle_json = bundle.to_json().expect("Bundle JSON export failed");
    drop(ledger_guard);

    // =========================================================================
    // Step 6: Third-Party Auditor Verification (Zero-Knowledge & Privacy-Preserving)
    // =========================================================================
    let auditor_bundle = zktrace_ledger::bundle::AuditBundle::from_json(&bundle_json)
        .expect("Auditor bundle import failed");

    let reports = verifier
        .verify_batch(&auditor_bundle.receipts, Some(&policy_root), Some(&auditor_bundle.ledger_root))
        .expect("Auditor batch verification failed");

    assert_eq!(reports.len(), 2);
    for (i, report) in reports.iter().enumerate() {
        assert!(report.is_valid, "Receipt #{} must be cryptographically valid", i + 1);
        assert_eq!(report.verdict, VerificationVerdict::Valid);
        assert!(report.proof_verified);
        assert!(report.policy_root_matched);
        assert!(report.duration_micros < 50_000, "Verification must complete in milliseconds");
    }

    println!("🎉 Complete E2E Audit Lifecycle Verified Successfully!");
}
