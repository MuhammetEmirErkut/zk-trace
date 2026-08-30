//! Integration test suite for `zktrace-ledger`.

use tempfile::tempdir;
use zktrace_core::crypto::Fr;
use zktrace_core::types::execution::{AgentIdentity, ExecutionEvent, ExecutionStatus};
use zktrace_ledger::prelude::*;

#[test]
fn test_disk_store_persistence_and_reload() {
    let tmp = tempdir().expect("Failed to create temp dir");
    let store_path = tmp.path().to_path_buf();

    let root_initial;
    let event_id;

    // 1. Open disk ledger and append event
    {
        let mut ledger = CryptographicLedger::open_disk(&store_path, 4)
            .expect("Failed to open disk ledger");

        let agent = AgentIdentity::new("disk-agent", "corp");
        let event = ExecutionEvent::new(
            agent,
            Fr::from(42u64),
            "disk_tool",
            b"payload",
            serde_json::json!({}),
            ExecutionStatus::Success,
        );
        event_id = event.event_id;

        let (idx, root, proof) = ledger
            .append_execution(&event, None)
            .expect("Failed to append event");

        assert_eq!(idx, 0);
        assert!(proof.verify(&event.compute_ledger_leaf()));
        root_initial = root;
        assert_eq!(ledger.count(), 1);
    }

    // 2. Re-open disk ledger and ensure state was preserved
    {
        let ledger = CryptographicLedger::open_disk(&store_path, 4)
            .expect("Failed to reload disk ledger");

        assert_eq!(ledger.count(), 1);
        assert_eq!(ledger.get_root(), root_initial);

        let retrieved_event = ledger
            .get_event(&event_id)
            .expect("Failed to get event")
            .expect("Event must exist");
        assert_eq!(retrieved_event.tool_name, "disk_tool");

        let proof = ledger.get_inclusion_proof(0).expect("Proof generation failed");
        assert!(proof.verify(&retrieved_event.compute_ledger_leaf()));
    }
}

#[test]
fn test_bundle_export_and_import() {
    let mut ledger1 = CryptographicLedger::open_in_memory(4);

    for i in 0..5 {
        let agent = AgentIdentity::new(format!("agent-{}", i), "org");
        let event = ExecutionEvent::new(
            agent,
            Fr::from(i as u64),
            format!("tool_{}", i),
            b"args",
            serde_json::json!({}),
            ExecutionStatus::Success,
        );
        ledger1.append_execution(&event, None).unwrap();
    }

    let bundle = ledger1.export_bundle(0, 5).expect("Export failed");
    assert_eq!(bundle.leaf_count, 5);

    let bundle_json = bundle.to_json().expect("JSON export failed");
    let parsed_bundle = AuditBundle::from_json(&bundle_json).expect("JSON parse failed");

    let mut ledger2 = CryptographicLedger::open_in_memory(4);
    let imported_count = ledger2.import_bundle(&parsed_bundle).expect("Import failed");
    assert_eq!(imported_count, 5);
    assert_eq!(ledger1.get_root(), ledger2.get_root());
}
