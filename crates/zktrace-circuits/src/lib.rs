//! # ZKTrace Circuits (`zktrace-circuits`)
//!
//! R1CS Zero-Knowledge constraint circuits and gadgets for AI Agent policy execution
//! verification over BN254 $\mathbb{F}_r$ in the ZKTrace architecture.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod circuit;
pub mod error;
pub mod gadgets;

/// Common imports and circuit synthesizer traits for convenient downstream use.
pub mod prelude {
    pub use crate::circuit::ExecutionPolicyCircuit;
    pub use crate::error::{CircuitError, CircuitResult};
    pub use crate::gadgets::{
        enforce_in_range_constant, enforce_less_than_or_equal_constant, MerklePathVar,
        MerkleProofStepVar, poseidon_hash_1_gadget, poseidon_hash_2_gadget,
        poseidon_hash_many_gadget,
    };
    pub use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
}

pub use prelude::*;
