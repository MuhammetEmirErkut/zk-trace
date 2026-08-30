//! Real-time MCP tool execution interceptor and cryptographic audit pipeline.

use std::sync::Arc;
use tokio::sync::Mutex;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::{AgentIdentity, ExecutionEvent, ExecutionStatus};
use zktrace_core::types::policy::{ConstraintType, PolicyTree};
use zktrace_core::types::receipt::AuditReceipt;
use zktrace_ledger::ledger::CryptographicLedger;
use zktrace_ledger::store::LedgerStorage;
use zktrace_prover::engine::ZKTraceProver;

use crate::error::{McpError, McpResult};
use crate::protocol::McpToolCallParams;

/// Real-time Zero-Knowledge audit interceptor for MCP tool calls.
pub struct McpInterceptor<S: LedgerStorage> {
    /// Public identity of the executing AI Agent.
    pub agent: AgentIdentity,
    /// Active policy tree enforcing governance and execution bounds.
    pub policy: PolicyTree,
    /// Zero-Knowledge prover engine.
    pub prover: ZKTraceProver,
    /// Append-only cryptographic ledger tracking verified receipts.
    pub ledger: Arc<Mutex<CryptographicLedger<S>>>,
}

impl<S: LedgerStorage> McpInterceptor<S> {
    /// Creates a new `McpInterceptor`.
    pub fn new(
        agent: AgentIdentity,
        policy: PolicyTree,
        prover: ZKTraceProver,
        ledger: Arc<Mutex<CryptographicLedger<S>>>,
    ) -> Self {
        Self {
            agent,
            policy,
            prover,
            ledger,
        }
    }

    /// Evaluates policy constraints on a tool invocation before execution.
    pub fn validate_policy(&self, tool_call: &McpToolCallParams) -> McpResult<()> {
        let rule = self
            .policy
            .get_rule(&tool_call.name)
            .ok_or_else(|| {
                McpError::PolicyViolation(format!(
                    "Tool '{}' is not permitted under active policy '{}'",
                    tool_call.name, self.policy.policy_id
                ))
            })?;

        for c in &rule.constraints {
            match &c.constraint {
                ConstraintType::MaxSpendLimit { max_amount } => {
                    if let Some(val) = tool_call.arguments.get(&c.param_name) {
                        if let Some(num) = val.as_u64() {
                            if num > *max_amount {
                                return Err(McpError::PolicyViolation(format!(
                                    "Parameter '{}' value {} exceeds maximum spend limit of {}",
                                    c.param_name, num, max_amount
                                )));
                            }
                        }
                    }
                }
                ConstraintType::NumericRange { min, max } => {
                    if let Some(val) = tool_call.arguments.get(&c.param_name) {
                        if let Some(num) = val.as_u64() {
                            if num < *min || num > *max {
                                return Err(McpError::PolicyViolation(format!(
                                    "Parameter '{}' value {} outside permitted range [{}, {}]",
                                    c.param_name, num, min, max
                                )));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Processes an intercepted tool call: synthesizes witness, generates ZK-SNARK proof,
    /// and commits the event leaf and receipt into the cryptographic ledger.
    pub async fn process_and_audit(
        &self,
        session_id: Fr,
        tool_call: &McpToolCallParams,
        raw_prompt: Option<&[u8]>,
        status: ExecutionStatus,
    ) -> McpResult<AuditReceipt> {
        let raw_json_bytes = serde_json::to_vec(&tool_call.arguments).unwrap_or_default();
        let masked_json = tool_call.arguments.clone();

        let event = ExecutionEvent::new(
            self.agent.clone(),
            session_id,
            &tool_call.name,
            &raw_json_bytes,
            masked_json,
            status,
        );

        let mut ledger_guard = self.ledger.lock().await;
        let current_root = ledger_guard.get_root();

        // Generate succinct Groth16 proof receipt
        let receipt = self.prover.prove_execution(
            &event,
            &self.policy,
            raw_prompt,
            None,
            current_root,
        )?;

        // Commit to ledger
        let (_leaf_idx, _new_root, _proof) = ledger_guard
            .append_execution(&event, Some(receipt.clone()))
            .map_err(McpError::Ledger)?;

        Ok(receipt)
    }
}
