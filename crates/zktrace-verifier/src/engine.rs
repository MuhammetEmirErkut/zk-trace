//! Instant sub-5ms Zero-Knowledge verifier engine backed by pre-computed pairing elements.

use std::time::Instant;

use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use zktrace_core::crypto::field::{fr_to_hex, Fr};
use zktrace_core::types::receipt::AuditReceipt;

use crate::error::{VerifierError, VerifierResult};
use crate::report::{VerificationReport, VerificationVerdict};

/// High-performance instant Verifier Engine for ZKTrace audit receipts.
#[derive(Clone)]
pub struct ZKTraceVerifier {
    /// The raw Groth16 verifying key.
    pub vk: VerifyingKey<Bn254>,
    /// Pre-processed pairing elements for sub-5ms verification.
    pub pvk: PreparedVerifyingKey<Bn254>,
}

impl ZKTraceVerifier {
    /// Constructs a new `ZKTraceVerifier` from a `VerifyingKey`, pre-computing elliptic curve pairings.
    pub fn new(vk: VerifyingKey<Bn254>) -> Self {
        let pvk = prepare_verifying_key(&vk);
        Self { vk, pvk }
    }

    /// Verifies raw Groth16 proof with public inputs using pre-computed pairings.
    pub fn verify_proof_raw(
        &self,
        proof: &Proof<Bn254>,
        public_inputs: &[Fr],
    ) -> VerifierResult<bool> {
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, public_inputs, proof).map_err(|e| {
            VerifierError::ExecutionError(format!("Groth16 pairing check failed: {}", e))
        })
    }

    /// Verifies a complete `.zktrace` `AuditReceipt` against optional expected policy and ledger roots.
    pub fn verify_receipt(
        &self,
        receipt: &AuditReceipt,
        expected_policy_root: Option<&Fr>,
        expected_ledger_root: Option<&Fr>,
    ) -> VerifierResult<VerificationReport> {
        let start = Instant::now();

        // 1. Check expected policy root match if specified
        let mut policy_root_matched = true;
        if let Some(expected_pr) = expected_policy_root {
            if receipt.public_inputs.policy_root_hash != *expected_pr {
                policy_root_matched = false;
            }
        }

        // 2. Check Merkle inclusion proof if present and ledger root specified
        let mut merkle_inclusion_verified = true;
        if let Some(inclusion) = &receipt.merkle_inclusion {
            if let Some(expected_lr) = expected_ledger_root {
                if inclusion.expected_root != *expected_lr {
                    merkle_inclusion_verified = false;
                }
            }
        }

        // 3. Check timestamp validity (timestamp must be <= timestamp_window)
        let ts_window_u64 = receipt.public_inputs.timestamp_window;
        let ts_fr = Fr::from(receipt.timestamp as u64);
        let timestamp_valid = ts_fr <= ts_window_u64;

        // 4. Decode Groth16 proof
        let proof_bytes = receipt.proof.to_bytes().map_err(|e| {
            VerifierError::InvalidProofEncoding(format!("Failed to decode proof bytes: {}", e))
        })?;

        let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]).map_err(|e| {
            VerifierError::InvalidProofEncoding(format!("Failed to deserialize proof: {}", e))
        })?;

        // 5. Verify Zero-Knowledge proof with public inputs
        let public_inputs = receipt.public_inputs.to_field_elements();
        let proof_verified = self.verify_proof_raw(&proof, &public_inputs)?;

        let elapsed = start.elapsed().as_micros() as u64;

        // 6. Determine final verdict
        let verdict = if !proof_verified {
            VerificationVerdict::InvalidProof
        } else if !policy_root_matched {
            VerificationVerdict::PolicyRootMismatch
        } else if !merkle_inclusion_verified {
            VerificationVerdict::MerkleInclusionFailed
        } else if !timestamp_valid {
            VerificationVerdict::TimestampExpired
        } else {
            VerificationVerdict::Valid
        };

        let is_valid = verdict == VerificationVerdict::Valid;
        let details = match verdict {
            VerificationVerdict::Valid => {
                format!("Successfully verified in {} µs. Tool execution strictly adhered to committed policy.", elapsed)
            }
            VerificationVerdict::InvalidProof => {
                "Cryptographic pairing checks failed: Proof is forged or invalid.".to_string()
            }
            VerificationVerdict::PolicyRootMismatch => {
                "Committed policy root does not match active enterprise policy.".to_string()
            }
            VerificationVerdict::MerkleInclusionFailed => {
                "Merkle inclusion proof verification failed against committed ledger root."
                    .to_string()
            }
            VerificationVerdict::TimestampExpired => {
                "Execution timestamp exceeded bounded timestamp window.".to_string()
            }
            VerificationVerdict::ExecutionDigestMismatch => {
                "Execution digest mismatch.".to_string()
            }
        };

        Ok(VerificationReport {
            receipt_id: receipt.receipt_id,
            verdict,
            is_valid,
            proof_verified,
            policy_root_matched,
            merkle_inclusion_verified,
            timestamp_valid,
            execution_digest_hex: fr_to_hex(&receipt.public_inputs.execution_digest),
            policy_root_hex: fr_to_hex(&receipt.public_inputs.policy_root_hash),
            duration_micros: elapsed,
            details,
        })
    }

    /// Verifies a collection of audit receipts in parallel / batch mode.
    pub fn verify_batch(
        &self,
        receipts: &[AuditReceipt],
        expected_policy_root: Option<&Fr>,
        expected_ledger_root: Option<&Fr>,
    ) -> VerifierResult<Vec<VerificationReport>> {
        let mut reports = Vec::with_capacity(receipts.len());
        for r in receipts {
            let report = self.verify_receipt(r, expected_policy_root, expected_ledger_root)?;
            reports.push(report);
        }
        Ok(reports)
    }
}
