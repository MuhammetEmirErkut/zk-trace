//! Stdio and stream-based transparent MCP JSON-RPC 2.0 proxy.

use std::sync::Arc;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::ExecutionStatus;
use zktrace_ledger::store::LedgerStorage;

use crate::error::McpResult;
use crate::interceptor::McpInterceptor;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, McpToolCallParams};

/// Routing action determined by the transparent proxy.
pub enum ProxyAction {
    /// Request is permitted and forwarded to the target MCP tool server.
    Forward {
        /// Parsed request to send upstream.
        request: JsonRpcRequest,
        /// Extracted tool call parameters if method is `tools/call`.
        tool_call: Option<McpToolCallParams>,
    },
    /// Request was blocked by active policy constraint violation.
    Reject {
        /// Error response returned directly to the AI agent.
        response: JsonRpcResponse,
    },
}

/// Transparent JSON-RPC 2.0 proxy for Model Context Protocol.
pub struct McpProxy<S: LedgerStorage> {
    /// Core audit interceptor.
    pub interceptor: Arc<McpInterceptor<S>>,
    /// Active session nonce.
    pub session_id: Fr,
}

impl<S: LedgerStorage> Clone for McpProxy<S> {
    fn clone(&self) -> Self {
        Self {
            interceptor: self.interceptor.clone(),
            session_id: self.session_id,
        }
    }
}

impl<S: LedgerStorage> McpProxy<S> {
    /// Creates a new `McpProxy`.
    pub fn new(interceptor: Arc<McpInterceptor<S>>, session_id: Fr) -> Self {
        Self {
            interceptor,
            session_id,
        }
    }

    /// Evaluates an incoming JSON-RPC line from an AI agent.
    pub fn handle_client_message(&self, line: &str) -> McpResult<ProxyAction> {
        let req = JsonRpcRequest::from_line(line)?;

        if let Some(tool_call) = req.extract_tool_call() {
            // Check policy bounds
            if let Err(e) = self.interceptor.validate_policy(&tool_call) {
                let err_resp = JsonRpcResponse::error(
                    req.id,
                    -32000,
                    format!("ZKTrace Policy Violation: {}", e),
                );
                return Ok(ProxyAction::Reject { response: err_resp });
            }

            return Ok(ProxyAction::Forward {
                request: req,
                tool_call: Some(tool_call),
            });
        }

        Ok(ProxyAction::Forward {
            request: req,
            tool_call: None,
        })
    }

    /// Handles an intercepted tool completion, triggering background proof generation and ledger logging.
    pub async fn on_tool_completed(
        &self,
        tool_call: &McpToolCallParams,
        success: bool,
    ) -> McpResult<()> {
        let status = if success {
            ExecutionStatus::Success
        } else {
            ExecutionStatus::ExecutionFailed
        };

        self.interceptor
            .process_and_audit(self.session_id, tool_call, None, status)
            .await?;

        Ok(())
    }
}
