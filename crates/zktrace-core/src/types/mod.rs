//! Core domain types for policies, execution events, digests, and audit receipts.

pub mod execution;
pub mod policy;
pub mod receipt;

pub use execution::{AgentIdentity, ExecutionDigest, ExecutionEvent, ExecutionStatus};
pub use policy::{ConstraintType, ParamConstraint, PolicyCommitment, PolicyRule, PolicyTree};
pub use receipt::{AuditReceipt, ProofBytes, PublicInputs};
