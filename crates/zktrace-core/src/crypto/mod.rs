//! Cryptographic primitives and field adapters for the ZKTrace ecosystem.

pub mod field;
pub mod merkle;
pub mod poseidon;

pub use field::{
    biguint_to_fr, bytes32_to_fr, bytes_to_fr, canonical_deserialize, canonical_serialize,
    deserialize_fr, deserialize_opt_fr, fr_to_be_bytes, fr_to_biguint, fr_to_hex, fr_to_u64,
    hex_to_fr, serialize_fr, serialize_opt_fr, u64_to_fr, Fr,
};
pub use merkle::{MerkleProof, MerkleProofStep, MerkleTree};
pub use poseidon::{
    generate_poseidon_parameters, poseidon_config_rate_2, poseidon_config_rate_4, poseidon_hash_1,
    poseidon_hash_2, poseidon_hash_bytes, poseidon_hash_many,
};
