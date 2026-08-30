//! Integration test suite for `zktrace-mcp`.

use std::sync::Arc;
use tokio::sync::Mutex;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::AgentIdentity;
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};
use zktrace_ledger::ledger::CryptographicLedger;
use zktrace_mcp::prelude::*;
use zktrace_prover::prelude::*;
use zktrace_verifier::prelude::*;

#[tokio::test]
async fn test_mcp_proxy_valid_flow_and_audit() {
    // 1. Setup Prover & Ledger
    let keys = ProverKeys::generate_deterministic(4).unwrap();
    let prover = ZKTraceProver::new(keys.clone(), 4);
    let ledger = Arc::new(Mutex::new(CryptographicLedger::open_in_memory(4)));

    // 2. Setup Policy
    let mut policy = PolicyTree::new("mcp-policy-prod", 1);
    let rule = PolicyRule::new("stripe_payment", "Payment tool").with_constraint(
        ParamConstraint {
            param_name: "amount".to_string(),
            constraint: ConstraintType::MaxSpendLimit { max_amount: 100_000 },
        },
    );
    policy.add_rule(rule);

    let agent = AgentIdentity::new("finance-agent-01", "enterprise");
    let interceptor = Arc::new(McpInterceptor::new(agent, policy.clone(), prover, ledger.clone()));
    let proxy = McpProxy::new(interceptor.clone(), Fr::from(9999u64));

    // 3. Process valid MCP JSON-RPC tool call
    let client_msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stripe_payment","arguments":{"amount":45000}}}"#;
    let action = proxy.handle_client_message(client_msg).expect("Handle message failed");

    match action {
        ProxyAction::Forward { request, tool_call } => {
            assert_eq!(request.method, "tools/call");
            let tc = tool_call.expect("Tool call extracted");
            assert_eq!(tc.name, "stripe_payment");

            // Complete tool invocation
            proxy.on_tool_completed(&tc, true).await.expect("Audit completed");
        }
        ProxyAction::Reject { .. } => panic!("Valid call was rejected!"),
    }

    // 4. Verify that the event and receipt were committed to the ledger
    let ledger_guard = ledger.lock().await;
    assert_eq!(ledger_guard.count(), 1);

    let bundle = ledger_guard.export_bundle(0, 1).unwrap();
    assert_eq!(bundle.receipts.len(), 1);

    // 5. Verify receipt using ZKTraceVerifier
    let verifier = ZKTraceVerifier::new(keys.vk);
    let report = verifier.verify_receipt(&bundle.receipts[0], None, None).unwrap();
    assert!(report.is_valid);
    assert_eq!(report.verdict, VerificationVerdict::Valid);
}

#[tokio::test]
async fn test_mcp_proxy_rejects_policy_violation() {
    let keys = ProverKeys::generate_deterministic(4).unwrap();
    let prover = ZKTraceProver::new(keys.clone(), 4);
    let ledger = Arc::new(Mutex::new(CryptographicLedger::open_in_memory(4)));

    let mut policy = PolicyTree::new("mcp-policy-prod", 1);
    let rule = PolicyRule::new("stripe_payment", "Payment tool").with_constraint(ParamConstraint {
        param_name: "amount".to_string(),
        constraint: ConstraintType::MaxSpendLimit {
            max_amount: 100_000,
        },
    });
    policy.add_rule(rule);

    let agent = AgentIdentity::new("finance-agent-01", "enterprise");
    let interceptor = Arc::new(McpInterceptor::new(agent, policy, prover, ledger.clone()));
    let proxy = McpProxy::new(interceptor, Fr::from(9999u64));

    // Tool call with amount 250,000 exceeding 100,000 limit!
    let client_msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stripe_payment","arguments":{"amount":250000}}}"#;
    let action = proxy.handle_client_message(client_msg).unwrap();

    match action {
        ProxyAction::Reject { response } => {
            assert!(response.error.is_some());
            let err = response.error.unwrap();
            assert_eq!(err.code, -32000);
            assert!(err.message.contains("Policy Violation"));
        }
        ProxyAction::Forward { .. } => panic!("Violation was forwarded instead of rejected!"),
    }
}
