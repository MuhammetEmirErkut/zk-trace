//! # ZKTrace CLI Binary (`zktrace`)
//!
//! Enterprise Zero-Knowledge Cryptographic Audit Trail for AI Agents.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(
    name = "zktrace",
    about = "Zero-Knowledge Cryptographic Audit Trail for AI Agents (MCP)",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize local ZKTrace workspace, sample policy, and proving/verifying keys.
    Init {
        /// Directory to store configuration and cryptographic parameters.
        #[arg(short, long, default_value = "./.zktrace")]
        out_dir: PathBuf,
        /// Merkle tree depth (default 4 supports up to 16 policy rules).
        #[arg(short, long, default_value_t = 4)]
        tree_depth: usize,
    },

    /// Verify a `.zktrace` cryptographic audit receipt or bundle file.
    Verify {
        /// Path to receipt or bundle file (.json or .zktrace).
        file: PathBuf,
        /// Optional path to custom Verifying Key file.
        #[arg(long)]
        vk: Option<PathBuf>,
        /// Optional expected policy root commitment in hex format.
        #[arg(long)]
        expected_policy_root: Option<String>,
    },

    /// Export verified execution receipts from the local ledger into a portable bundle.
    Export {
        /// Path to the local ledger storage directory.
        #[arg(short, long, default_value = "./.zktrace/ledger")]
        ledger_dir: PathBuf,
        /// Path for the exported `.zktrace` bundle file.
        #[arg(short, long, default_value = "audit_trail.zktrace")]
        out: PathBuf,
        /// Number of events to export.
        #[arg(short, long, default_value_t = 1000)]
        count: usize,
    },

    /// Launch transparent Model Context Protocol (MCP) JSON-RPC proxy for AI Agents.
    Proxy {
        /// Path to active policy JSON file.
        #[arg(short, long, default_value = "./.zktrace/policy.json")]
        policy: PathBuf,
        /// Path to ledger storage directory.
        #[arg(short, long, default_value = "./.zktrace/ledger")]
        ledger_dir: PathBuf,
        /// Agent public identifier.
        #[arg(long, default_value = "ai_agent_prod_01")]
        agent: String,
        /// Organization / Tenant name.
        #[arg(long, default_value = "enterprise_tenant")]
        org: String,
    },

    /// Launch high-throughput HTTP REST API verifier server.
    Serve {
        /// HTTP server listening port.
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// Optional path to custom Verifying Key file.
        #[arg(long)]
        vk: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            out_dir,
            tree_depth,
        } => {
            commands::init::execute_init(out_dir, tree_depth)?;
        }
        Commands::Verify {
            file,
            vk,
            expected_policy_root,
        } => {
            commands::verify::execute_verify(file, vk.as_deref(), expected_policy_root.as_deref())?;
        }
        Commands::Export {
            ledger_dir,
            out,
            count,
        } => {
            commands::export::execute_export(ledger_dir, out, count)?;
        }
        Commands::Proxy {
            policy,
            ledger_dir,
            agent,
            org,
        } => {
            commands::proxy::execute_proxy(policy, ledger_dir, &agent, &org).await?;
        }
        Commands::Serve { port, vk } => {
            commands::server::execute_server(port, vk.as_deref()).await?;
        }
    }

    Ok(())
}
