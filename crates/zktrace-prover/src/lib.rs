//! # ZKTrace Prover (`zktrace-prover`)
//!
//! High-performance Groth16 Zero-Knowledge Prover and automated witness synthesis engine
//! for generating verifiable audit receipts in the ZKTrace architecture.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod engine;
pub mod error;
pub mod setup;
pub mod witness;

/// Common imports for prover setup and proof generation.
pub mod prelude {
    pub use crate::engine::ZKTraceProver;
    pub use crate::error::{ProverError, ProverResult};
    pub use crate::setup::ProverKeys;
    pub use crate::witness::WitnessSynthesizer;
}

pub use prelude::*;
