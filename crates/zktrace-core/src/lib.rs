//! # ZKTrace Core (`zktrace-core`)
//!
//! Enterprise-grade cryptographic primitives, algebraic hashing over BN254 $\mathbb{F}_r$,
//! Incremental Merkle Trees, canonical serialization, and domain types for the ZKTrace
//! Zero-Knowledge AI Agent Audit Trail system.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod crypto;
pub mod error;
pub mod types;

/// Common imports and traits for convenient downstream use.
pub mod prelude {
    pub use crate::crypto::field::{
        biguint_to_fr, bytes32_to_fr, bytes_to_fr, canonical_deserialize, canonical_serialize,
        deserialize_fr, deserialize_opt_fr, fr_to_be_bytes, fr_to_biguint, fr_to_hex, hex_to_fr,
        serialize_fr, serialize_opt_fr, u64_to_fr, Fr,
    };
    pub use crate::crypto::merkle::{MerkleProof, MerkleProofStep, MerkleTree};
    pub use crate::crypto::poseidon::{
        generate_poseidon_parameters, poseidon_config_rate_2, poseidon_config_rate_4,
        poseidon_hash_1, poseidon_hash_2, poseidon_hash_bytes, poseidon_hash_many,
    };
    pub use crate::error::{CoreError, CoreResult};
    pub use crate::types::execution::{
        AgentIdentity, ExecutionDigest, ExecutionEvent, ExecutionStatus,
    };
    pub use crate::types::policy::{
        ConstraintType, ParamConstraint, PolicyCommitment, PolicyRule, PolicyTree,
    };
    pub use crate::types::receipt::{AuditReceipt, ProofBytes, PublicInputs};
}

pub use prelude::*;
