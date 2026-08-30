//! R1CS gadgets for cryptographic proofs and constraint enforcement.

pub mod merkle;
pub mod poseidon;
pub mod range;

pub use merkle::{MerklePathVar, MerkleProofStepVar};
pub use poseidon::{poseidon_hash_1_gadget, poseidon_hash_2_gadget, poseidon_hash_many_gadget};
pub use range::{enforce_in_range_constant, enforce_less_than_or_equal_constant};
