//! Storage abstractions and persistent disk engine for the append-only ledger.

use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zktrace_core::crypto::MerkleTree;
use zktrace_core::types::execution::ExecutionEvent;
use zktrace_core::types::receipt::AuditReceipt;

use crate::error::{LedgerError, LedgerResult};

/// Common trait for storage engines backing the cryptographic ledger.
pub trait LedgerStorage: Send + Sync {
    /// Persists the active Merkle Tree structure.
    fn save_tree(&mut self, tree: &MerkleTree) -> LedgerResult<()>;
    /// Loads the persisted Merkle Tree if present.
    fn load_tree(&self) -> LedgerResult<Option<MerkleTree>>;
    /// Stores an execution event indexed by its sequential leaf position.
    fn save_event(&mut self, index: usize, event: &ExecutionEvent) -> LedgerResult<()>;
    /// Retrieves an execution event by its unique event UUID.
    fn get_event(&self, event_id: &Uuid) -> LedgerResult<Option<ExecutionEvent>>;
    /// Retrieves an execution event by its sequential leaf index.
    fn get_event_by_index(&self, index: usize) -> LedgerResult<Option<ExecutionEvent>>;
    /// Stores an audit receipt associated with an event.
    fn save_receipt(&mut self, event_id: &Uuid, receipt: &AuditReceipt) -> LedgerResult<()>;
    /// Retrieves an audit receipt by event UUID.
    fn get_receipt(&self, event_id: &Uuid) -> LedgerResult<Option<AuditReceipt>>;
    /// Returns the total number of stored events.
    fn event_count(&self) -> usize;
}

/// Ephemeral in-memory storage engine for testing and lightweight sessions.
#[derive(Clone, Default)]
pub struct MemoryStore {
    tree: Option<MerkleTree>,
    events: Vec<ExecutionEvent>,
    event_lookup: HashMap<Uuid, usize>,
    receipts: HashMap<Uuid, AuditReceipt>,
}

impl MemoryStore {
    /// Creates a new empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LedgerStorage for MemoryStore {
    fn save_tree(&mut self, tree: &MerkleTree) -> LedgerResult<()> {
        self.tree = Some(tree.clone());
        Ok(())
    }

    fn load_tree(&self) -> LedgerResult<Option<MerkleTree>> {
        Ok(self.tree.clone())
    }

    fn save_event(&mut self, index: usize, event: &ExecutionEvent) -> LedgerResult<()> {
        if index == self.events.len() {
            self.events.push(event.clone());
        } else if index < self.events.len() {
            self.events[index] = event.clone();
        } else {
            return Err(LedgerError::StorageError("Non-sequential event index".to_string()));
        }
        self.event_lookup.insert(event.event_id, index);
        Ok(())
    }

    fn get_event(&self, event_id: &Uuid) -> LedgerResult<Option<ExecutionEvent>> {
        if let Some(&idx) = self.event_lookup.get(event_id) {
            Ok(self.events.get(idx).cloned())
        } else {
            Ok(None)
        }
    }

    fn get_event_by_index(&self, index: usize) -> LedgerResult<Option<ExecutionEvent>> {
        Ok(self.events.get(index).cloned())
    }

    fn save_receipt(&mut self, event_id: &Uuid, receipt: &AuditReceipt) -> LedgerResult<()> {
        self.receipts.insert(*event_id, receipt.clone());
        Ok(())
    }

    fn get_receipt(&self, event_id: &Uuid) -> LedgerResult<Option<AuditReceipt>> {
        Ok(self.receipts.get(event_id).cloned())
    }

    fn event_count(&self) -> usize {
        self.events.len()
    }
}

/// Robust filesystem-backed persistent storage engine.
pub struct DiskStore {
    base_dir: PathBuf,
    events: Vec<ExecutionEvent>,
    event_lookup: HashMap<Uuid, usize>,
    receipts: HashMap<Uuid, AuditReceipt>,
    tree: Option<MerkleTree>,
}

impl DiskStore {
    /// Opens or initializes a `DiskStore` in the specified directory.
    pub fn open(path: impl AsRef<Path>) -> LedgerResult<Self> {
        let base_dir = path.as_ref().to_path_buf();
        create_dir_all(&base_dir).map_err(|e| {
            LedgerError::StorageError(format!("Failed to create storage dir: {}", e))
        })?;

        let mut store = Self {
            base_dir,
            events: Vec::new(),
            event_lookup: HashMap::new(),
            receipts: HashMap::new(),
            tree: None,
        };

        store.reload_from_disk()?;
        Ok(store)
    }

    fn reload_from_disk(&mut self) -> LedgerResult<()> {
        let tree_file = self.base_dir.join("tree.json");
        if tree_file.exists() {
            let mut file = File::open(&tree_file).map_err(|e| {
                LedgerError::StorageError(format!("Failed to open tree file: {}", e))
            })?;
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to read tree file: {}", e))
            })?;
            let tree: MerkleTree = serde_json::from_str(&content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to parse tree file: {}", e))
            })?;
            self.tree = Some(tree);
        }

        let events_file = self.base_dir.join("events.json");
        if events_file.exists() {
            let mut file = File::open(&events_file).map_err(|e| {
                LedgerError::StorageError(format!("Failed to open events file: {}", e))
            })?;
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to read events file: {}", e))
            })?;
            let events: Vec<ExecutionEvent> = serde_json::from_str(&content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to parse events file: {}", e))
            })?;
            for (idx, ev) in events.into_iter().enumerate() {
                self.event_lookup.insert(ev.event_id, idx);
                self.events.push(ev);
            }
        }

        let receipts_file = self.base_dir.join("receipts.json");
        if receipts_file.exists() {
            let mut file = File::open(&receipts_file).map_err(|e| {
                LedgerError::StorageError(format!("Failed to open receipts file: {}", e))
            })?;
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to read receipts file: {}", e))
            })?;
            let receipts: Vec<AuditReceipt> = serde_json::from_str(&content).map_err(|e| {
                LedgerError::StorageError(format!("Failed to parse receipts file: {}", e))
            })?;
            for r in receipts {
                self.receipts.insert(r.event_id, r);
            }
        }

        Ok(())
    }

    fn persist_all(&self) -> LedgerResult<()> {
        if let Some(tree) = &self.tree {
            let tree_json = serde_json::to_string_pretty(tree)
                .map_err(|e| LedgerError::Serialization(e.to_string()))?;
            let mut file = File::create(self.base_dir.join("tree.json")).map_err(|e| {
                LedgerError::StorageError(format!("Failed to write tree.json: {}", e))
            })?;
            file.write_all(tree_json.as_bytes()).map_err(|e| {
                LedgerError::StorageError(format!("Failed to flush tree.json: {}", e))
            })?;
        }

        let events_json = serde_json::to_string_pretty(&self.events)
            .map_err(|e| LedgerError::Serialization(e.to_string()))?;
        let mut file = File::create(self.base_dir.join("events.json")).map_err(|e| {
            LedgerError::StorageError(format!("Failed to write events.json: {}", e))
        })?;
        file.write_all(events_json.as_bytes()).map_err(|e| {
            LedgerError::StorageError(format!("Failed to flush events.json: {}", e))
        })?;

        let receipts_list: Vec<&AuditReceipt> = self.receipts.values().collect();
        let receipts_json = serde_json::to_string_pretty(&receipts_list)
            .map_err(|e| LedgerError::Serialization(e.to_string()))?;
        let mut file = File::create(self.base_dir.join("receipts.json")).map_err(|e| {
            LedgerError::StorageError(format!("Failed to write receipts.json: {}", e))
        })?;
        file.write_all(receipts_json.as_bytes()).map_err(|e| {
            LedgerError::StorageError(format!("Failed to flush receipts.json: {}", e))
        })?;

        Ok(())
    }
}

impl LedgerStorage for DiskStore {
    fn save_tree(&mut self, tree: &MerkleTree) -> LedgerResult<()> {
        self.tree = Some(tree.clone());
        self.persist_all()
    }

    fn load_tree(&self) -> LedgerResult<Option<MerkleTree>> {
        Ok(self.tree.clone())
    }

    fn save_event(&mut self, index: usize, event: &ExecutionEvent) -> LedgerResult<()> {
        if index == self.events.len() {
            self.events.push(event.clone());
        } else if index < self.events.len() {
            self.events[index] = event.clone();
        } else {
            return Err(LedgerError::StorageError("Non-sequential event index".to_string()));
        }
        self.event_lookup.insert(event.event_id, index);
        self.persist_all()
    }

    fn get_event(&self, event_id: &Uuid) -> LedgerResult<Option<ExecutionEvent>> {
        if let Some(&idx) = self.event_lookup.get(event_id) {
            Ok(self.events.get(idx).cloned())
        } else {
            Ok(None)
        }
    }

    fn get_event_by_index(&self, index: usize) -> LedgerResult<Option<ExecutionEvent>> {
        Ok(self.events.get(index).cloned())
    }

    fn save_receipt(&mut self, event_id: &Uuid, receipt: &AuditReceipt) -> LedgerResult<()> {
        self.receipts.insert(*event_id, receipt.clone());
        self.persist_all()
    }

    fn get_receipt(&self, event_id: &Uuid) -> LedgerResult<Option<AuditReceipt>> {
        Ok(self.receipts.get(event_id).cloned())
    }

    fn event_count(&self) -> usize {
        self.events.len()
    }
}
