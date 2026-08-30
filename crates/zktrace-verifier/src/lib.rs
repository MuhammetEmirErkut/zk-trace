//! # ZKTrace Verifier (`zktrace-verifier`)
//!
//! Ultra-fast sub-5ms Zero-Knowledge execution proof and cryptographic audit receipt
//! verification engine for auditors and verification SDKs in the ZKTrace ecosystem.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod engine;
pub mod error;
pub mod report;

/// Common imports and types for verifier operations.
pub mod prelude {
    pub use crate::engine::ZKTraceVerifier;
    pub use crate::error::{VerifierError, VerifierResult};
    pub use crate::report::{VerificationReport, VerificationVerdict};
}

pub use prelude::*;
