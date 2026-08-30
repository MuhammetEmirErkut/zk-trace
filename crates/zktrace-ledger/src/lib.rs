//! # ZKTrace Ledger (`zktrace-ledger`)
//!
//! Immutable append-only cryptographic ledger engine backed by Incremental Poseidon Merkle Trees,
//! persistent disk storage, and `.zktrace` audit bundle packaging for the ZKTrace ecosystem.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod bundle;
pub mod error;
pub mod ledger;
pub mod store;

/// Common imports and storage types for cryptographic ledger operations.
pub mod prelude {
    pub use crate::bundle::AuditBundle;
    pub use crate::error::{LedgerError, LedgerResult};
    pub use crate::ledger::CryptographicLedger;
    pub use crate::store::{DiskStore, LedgerStorage, MemoryStore};
}

pub use prelude::*;
