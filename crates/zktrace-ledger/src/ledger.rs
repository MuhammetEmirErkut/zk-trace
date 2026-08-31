//! Core Cryptographic Append-Only Ledger engine backed by Poseidon Merkle Trees.

use std::path::Path;
use uuid::Uuid;
use zktrace_core::crypto::{Fr, MerkleProof, MerkleTree};
use zktrace_core::types::execution::ExecutionEvent;
use zktrace_core::types::receipt::AuditReceipt;

use crate::bundle::AuditBundle;
use crate::error::{LedgerError, LedgerResult};
use crate::store::{DiskStore, LedgerStorage, MemoryStore};

/// An append-only cryptographic ledger tracking AI Agent tool executions with rolling Merkle state roots.
pub struct CryptographicLedger<S: LedgerStorage> {
    tree: MerkleTree,
    storage: S,
    tree_depth: usize,
}

impl CryptographicLedger<MemoryStore> {
    /// Opens an in-memory cryptographic ledger with the given tree depth.
    pub fn open_in_memory(tree_depth: usize) -> Self {
        let tree = MerkleTree::new(tree_depth);
        let storage = MemoryStore::new();
        Self {
            tree,
            storage,
            tree_depth,
        }
    }
}

impl CryptographicLedger<DiskStore> {
    /// Opens or initializes a disk-persisted cryptographic ledger.
    pub fn open_disk(path: impl AsRef<Path>, tree_depth: usize) -> LedgerResult<Self> {
        let storage = DiskStore::open(path)?;
        let tree = if let Some(loaded_tree) = storage.load_tree()? {
            loaded_tree
        } else {
            MerkleTree::new(tree_depth)
        };

        Ok(Self {
            tree,
            storage,
            tree_depth,
        })
    }
}

impl<S: LedgerStorage> CryptographicLedger<S> {
    /// Appends an execution event and optional audit receipt to the ledger.
    ///
    /// Computes the execution leaf hash, inserts into the Merkle tree, updates the root,
    /// persists to storage, and returns `(leaf_index, new_ledger_root, inclusion_proof)`.
    pub fn append_execution(
        &mut self,
        event: &ExecutionEvent,
        receipt: Option<AuditReceipt>,
    ) -> LedgerResult<(usize, Fr, MerkleProof)> {
        let leaf = event.compute_ledger_leaf();
        let (leaf_index, root) = self
            .tree
            .insert(leaf)
            .map_err(|e| LedgerError::MerkleError(format!("Failed to insert leaf: {}", e)))?;

        self.storage.save_event(leaf_index, event)?;
        self.storage.save_tree(&self.tree)?;

        let inclusion_proof = self.tree.generate_proof(leaf_index).map_err(|e| {
            LedgerError::MerkleError(format!("Failed to generate inclusion proof: {}", e))
        })?;

        if let Some(mut r) = receipt {
            r.merkle_inclusion = Some(inclusion_proof.clone());
            r.ledger_root = root;
            self.storage.save_receipt(&event.event_id, &r)?;
        }

        Ok((leaf_index, root, inclusion_proof))
    }

    /// Returns the current Merkle root of the ledger.
    pub fn get_root(&self) -> Fr {
        self.tree.root()
    }

    /// Generates a cryptographic inclusion proof for a leaf index.
    pub fn get_inclusion_proof(&self, leaf_index: usize) -> LedgerResult<MerkleProof> {
        self.tree
            .generate_proof(leaf_index)
            .map_err(|e| LedgerError::MerkleError(format!("Failed to generate proof: {}", e)))
    }

    /// Retrieves an execution event by UUID.
    pub fn get_event(&self, event_id: &Uuid) -> LedgerResult<Option<ExecutionEvent>> {
        self.storage.get_event(event_id)
    }

    /// Retrieves an audit receipt by event UUID.
    pub fn get_receipt(&self, event_id: &Uuid) -> LedgerResult<Option<AuditReceipt>> {
        self.storage.get_receipt(event_id)
    }

    /// Returns the total number of committed execution events.
    pub fn count(&self) -> usize {
        self.storage.event_count()
    }

    /// Returns the configured Merkle tree depth.
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    /// Exports a portable `.zktrace` `AuditBundle` for a sequence of events.
    pub fn export_bundle(&self, start_idx: usize, count: usize) -> LedgerResult<AuditBundle> {
        let total = self.storage.event_count();
        let end_idx = (start_idx + count).min(total);

        let mut events = Vec::with_capacity(end_idx - start_idx);
        let mut receipts = Vec::new();
        let mut proofs = Vec::with_capacity(end_idx - start_idx);

        for idx in start_idx..end_idx {
            if let Some(event) = self.storage.get_event_by_index(idx)? {
                if let Some(receipt) = self.storage.get_receipt(&event.event_id)? {
                    receipts.push(receipt);
                }
                let proof = self.get_inclusion_proof(idx)?;
                proofs.push(proof);
                events.push(event);
            }
        }

        Ok(AuditBundle::new(
            start_idx,
            self.get_root(),
            events,
            receipts,
            proofs,
        ))
    }

    /// Imports an external `AuditBundle` into this ledger.
    pub fn import_bundle(&mut self, bundle: &AuditBundle) -> LedgerResult<usize> {
        let mut imported = 0;
        for (i, event) in bundle.events.iter().enumerate() {
            let receipt = bundle.receipts.get(i).cloned();
            self.append_execution(event, receipt)?;
            imported += 1;
        }
        Ok(imported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zktrace_core::types::execution::{AgentIdentity, ExecutionStatus};

    #[test]
    fn test_cryptographic_ledger_lifecycle() {
        let mut ledger = CryptographicLedger::open_in_memory(4);

        let agent = AgentIdentity::new("agent-1", "org-test");
        let event = ExecutionEvent::new(
            agent,
            Fr::from(100u64),
            "tool_sql",
            b"SELECT 1;",
            serde_json::json!({}),
            ExecutionStatus::Success,
        );

        let (idx, root, proof) = ledger
            .append_execution(&event, None)
            .expect("Append event failed");

        assert_eq!(idx, 0);
        assert_eq!(root, ledger.get_root());
        assert!(proof.verify(&event.compute_ledger_leaf()));
        assert_eq!(ledger.count(), 1);

        let bundle = ledger.export_bundle(0, 10).expect("Export bundle failed");
        assert_eq!(bundle.leaf_count, 1);
        assert_eq!(bundle.ledger_root, root);
    }
}
