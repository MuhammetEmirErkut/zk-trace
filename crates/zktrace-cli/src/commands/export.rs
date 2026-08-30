//! `zktrace export` command implementation.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use anyhow::{Context, Result};
use zktrace_ledger::ledger::CryptographicLedger;

/// Executes the `zktrace export` command, packaging ledger receipts into a `.zktrace` bundle file.
pub fn execute_export(
    ledger_dir: impl AsRef<Path>,
    output_file: impl AsRef<Path>,
    count: usize,
) -> Result<()> {
    let ledger_path = ledger_dir.as_ref();
    println!("📦 Opening cryptographic ledger at {:?}...", ledger_path);

    let ledger = CryptographicLedger::open_disk(ledger_path, 4)
        .with_context(|| format!("Failed to open ledger at {:?}", ledger_path))?;

    let total = ledger.count();
    println!("  Total events in ledger: {}", total);

    let bundle = ledger.export_bundle(0, count)
        .map_err(|e| anyhow::anyhow!("Export failed: {}", e))?;

    let json = bundle.to_json()
        .map_err(|e| anyhow::anyhow!("JSON serialization failed: {}", e))?;

    let out_path = output_file.as_ref();
    let mut file = File::create(out_path)
        .with_context(|| format!("Failed to create export file {:?}", out_path))?;
    file.write_all(json.as_bytes())?;

    println!("✅ Exported {} receipts to bundle at {:?}", bundle.leaf_count, out_path);
    Ok(())
}
