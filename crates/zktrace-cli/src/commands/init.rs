//! `zktrace init` command implementation.

use anyhow::{Context, Result};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use zktrace_core::types::policy::{ConstraintType, ParamConstraint, PolicyRule, PolicyTree};
use zktrace_prover::setup::ProverKeys;

/// Executes the `zktrace init` command, setting up policy templates, CRS parameters, and ledger storage.
pub fn execute_init(output_dir: impl AsRef<Path>, tree_depth: usize) -> Result<()> {
    let dir = output_dir.as_ref();
    create_dir_all(dir).with_context(|| format!("Failed to create directory {:?}", dir))?;

    println!("⚡ Initializing ZKTrace environment in {:?}...", dir);

    // 1. Generate sample policy
    let mut policy = PolicyTree::new("enterprise-default-policy", 1);
    let rule_sql = PolicyRule::new("postgres_query", "Read-only database queries").with_constraint(
        ParamConstraint {
            param_name: "query_type".to_string(),
            constraint: ConstraintType::ReadOnlyOnly,
        },
    );
    let rule_stripe = PolicyRule::new("stripe_payment", "Stripe payment gateway").with_constraint(
        ParamConstraint {
            param_name: "amount".to_string(),
            constraint: ConstraintType::MaxSpendLimit {
                max_amount: 100_000,
            },
        },
    );
    policy.add_rule(rule_sql);
    policy.add_rule(rule_stripe);

    let policy_json = serde_json::to_string_pretty(&policy)?;
    let policy_path = dir.join("policy.json");
    let mut policy_file = File::create(&policy_path)?;
    policy_file.write_all(policy_json.as_bytes())?;
    println!("  📄 Policy template written to {:?}", policy_path);

    // 2. Generate deterministic CRS proving and verifying keys
    println!(
        "  🔑 Generating Groth16 CRS parameters (tree depth: {})...",
        tree_depth
    );
    let keys = ProverKeys::generate_deterministic(tree_depth)
        .map_err(|e| anyhow::anyhow!("Setup error: {}", e))?;

    let pk_bytes = keys.serialize_pk().map_err(|e| anyhow::anyhow!("{}", e))?;
    let vk_bytes = keys.serialize_vk().map_err(|e| anyhow::anyhow!("{}", e))?;

    let pk_path = dir.join("prover.pk");
    let vk_path = dir.join("verifier.vk");

    File::create(&pk_path)?.write_all(&pk_bytes)?;
    File::create(&vk_path)?.write_all(&vk_bytes)?;

    println!("  🔐 Proving Key saved to {:?}", pk_path);
    println!("  🛡️ Verifying Key saved to {:?}", vk_path);

    // 3. Create ledger directory
    let ledger_dir = dir.join("ledger");
    create_dir_all(&ledger_dir)?;
    println!("  📦 Append-only Ledger initialized at {:?}", ledger_dir);

    println!(
        "\n✅ ZKTrace successfully initialized! Ready to proxy or verify AI agent executions."
    );
    Ok(())
}
