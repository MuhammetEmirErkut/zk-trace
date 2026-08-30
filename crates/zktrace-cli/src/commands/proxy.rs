//! `zktrace proxy` command implementation.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use tokio::sync::Mutex;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::AgentIdentity;
use zktrace_core::types::policy::PolicyTree;
use zktrace_ledger::ledger::CryptographicLedger;
use zktrace_mcp::interceptor::McpInterceptor;
use zktrace_mcp::proxy::{McpProxy, ProxyAction};
use zktrace_prover::engine::ZKTraceProver;
use zktrace_prover::setup::ProverKeys;

/// Executes the `zktrace proxy` stdio middleware command.
pub async fn execute_proxy(
    policy_path: impl AsRef<Path>,
    ledger_dir: impl AsRef<Path>,
    agent_id: &str,
    org: &str,
) -> Result<()> {
    // 1. Load policy
    let p_path = policy_path.as_ref();
    let mut p_file = File::open(p_path)
        .with_context(|| format!("Failed to open policy file {:?}", p_path))?;
    let mut p_content = String::new();
    p_file.read_to_string(&mut p_content)?;
    let policy: PolicyTree = serde_json::from_str(&p_content)
        .with_context(|| "Failed to parse policy JSON")?;

    // 2. Open Ledger and Prover
    let ledger = Arc::new(Mutex::new(
        CryptographicLedger::open_disk(ledger_dir.as_ref(), 4)
            .map_err(|e| anyhow::anyhow!("Ledger init failed: {}", e))?,
    ));

    let keys = ProverKeys::generate_deterministic(4)
        .map_err(|e| anyhow::anyhow!("Setup failed: {}", e))?;
    let prover = ZKTraceProver::new(keys, 4);

    let agent = AgentIdentity::new(agent_id, org);
    let interceptor = Arc::new(McpInterceptor::new(agent, policy, prover, ledger));
    let session_id = Fr::from(rand::random::<u64>());
    let proxy = McpProxy::new(interceptor, session_id);

    eprintln!("🛡️ ZKTrace MCP Transparent Proxy started. Listening on stdio...");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        match proxy.handle_client_message(&line) {
            Ok(ProxyAction::Reject { response }) => {
                let resp_line = response.to_line().map_err(|e| anyhow::anyhow!("{}", e))?;
                stdout.write_all(resp_line.as_bytes())?;
                stdout.flush()?;
            }
            Ok(ProxyAction::Forward { request, tool_call }) => {
                // If it's a tool call, audit and generate proof
                if let Some(tc) = tool_call {
                    let req_line = format!("{}\n", serde_json::to_string(&request)?);
                    stdout.write_all(req_line.as_bytes())?;
                    stdout.flush()?;

                    // Background audit
                    let proxy_clone = proxy.clone();
                    tokio::spawn(async move {
                        let _ = proxy_clone.on_tool_completed(&tc, true).await;
                    });
                } else {
                    let req_line = format!("{}\n", serde_json::to_string(&request)?);
                    stdout.write_all(req_line.as_bytes())?;
                    stdout.flush()?;
                }
            }
            Err(e) => {
                eprintln!("Proxy message error: {}", e);
            }
        }
    }

    Ok(())
}

impl Clone for McpProxy<zktrace_ledger::store::DiskStore> {
    fn clone(&self) -> Self {
        Self {
            interceptor: self.interceptor.clone(),
            session_id: self.session_id,
        }
    }
}
