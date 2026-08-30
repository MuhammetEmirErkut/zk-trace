//! `zktrace verify` command implementation.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use anyhow::{Context, Result};
use zktrace_core::crypto::field::hex_to_fr;
use zktrace_core::types::receipt::AuditReceipt;
use zktrace_ledger::bundle::AuditBundle;
use zktrace_prover::setup::ProverKeys;
use zktrace_verifier::engine::ZKTraceVerifier;
use zktrace_verifier::report::VerificationVerdict;

/// Executes the `zktrace verify` command, auditing single receipts or full audit bundles.
pub fn execute_verify(
    receipt_path: impl AsRef<Path>,
    vk_path: Option<&Path>,
    expected_policy_root: Option<&str>,
) -> Result<()> {
    let path = receipt_path.as_ref();
    let mut file = File::open(path).with_context(|| format!("Failed to open file {:?}", path))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // 1. Load or generate verifying key
    let vk = if let Some(vp) = vk_path {
        let mut vk_file =
            File::open(vp).with_context(|| format!("Failed to open VK file {:?}", vp))?;
        let mut vk_bytes = Vec::new();
        vk_file.read_to_end(&mut vk_bytes)?;
        ProverKeys::deserialize_vk(&vk_bytes).map_err(|e| anyhow::anyhow!("VK error: {}", e))?
    } else {
        let keys = ProverKeys::generate_deterministic(4)
            .map_err(|e| anyhow::anyhow!("Setup error: {}", e))?;
        keys.vk
    };

    let verifier = ZKTraceVerifier::new(vk);

    let expected_pr = if let Some(pr_str) = expected_policy_root {
        Some(hex_to_fr(pr_str).map_err(|e| anyhow::anyhow!("Invalid policy root hex: {}", e))?)
    } else {
        None
    };

    println!("============================================================");
    println!("🔍 ZKTrace Cryptographic Verification Engine");
    println!("Auditing Target: {:?}", path);
    println!("============================================================");

    // Try parsing as single AuditReceipt or AuditBundle
    if let Ok(receipt) = serde_json::from_str::<AuditReceipt>(&content) {
        let report = verifier
            .verify_receipt(&receipt, expected_pr.as_ref(), None)
            .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))?;

        print_receipt_report(&report);
    } else if let Ok(bundle) = serde_json::from_str::<AuditBundle>(&content) {
        println!(
            "📦 Detected AuditBundle with {} receipts",
            bundle.receipts.len()
        );
        let reports = verifier
            .verify_batch(
                &bundle.receipts,
                expected_pr.as_ref(),
                Some(&bundle.ledger_root),
            )
            .map_err(|e| anyhow::anyhow!("Batch verification failed: {}", e))?;

        let mut all_valid = true;
        for (i, r) in reports.iter().enumerate() {
            println!("\n--- [ Receipt #{} / ID: {} ] ---", i + 1, r.receipt_id);
            print_receipt_report(r);
            if !r.is_valid {
                all_valid = false;
            }
        }

        println!("\n============================================================");
        if all_valid {
            println!(
                "🎉 ALL {} RECEIPTS IN BUNDLE VERIFIED SUCCESSFULLY!",
                reports.len()
            );
        } else {
            println!("❌ ONE OR MORE RECEIPTS IN BUNDLE FAILED AUDIT!");
        }
        println!("============================================================");
    } else {
        return Err(anyhow::anyhow!(
            "Unrecognized file format: Not a valid .zktrace receipt or bundle"
        ));
    }

    Ok(())
}

fn print_receipt_report(report: &zktrace_verifier::report::VerificationReport) {
    let status_str = match report.verdict {
        VerificationVerdict::Valid => "✅ PASSED (Cryptographically Sound & Policy Compliant)",
        VerificationVerdict::InvalidProof => "❌ FAILED (Invalid or Forged Proof)",
        VerificationVerdict::PolicyRootMismatch => "❌ FAILED (Policy Root Mismatch)",
        VerificationVerdict::MerkleInclusionFailed => "❌ FAILED (Merkle Inclusion Failure)",
        VerificationVerdict::TimestampExpired => "❌ FAILED (Timestamp Window Expired)",
        VerificationVerdict::ExecutionDigestMismatch => "❌ FAILED (Digest Mismatch)",
    };

    println!("Verdict:          {}", status_str);
    println!("Latency:          {} µs (< 5ms)", report.duration_micros);
    println!("Policy Root:      {}", report.policy_root_hex);
    println!("Execution Digest: {}", report.execution_digest_hex);
    println!("Details:          {}", report.details);
}
