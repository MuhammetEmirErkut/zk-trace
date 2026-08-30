//! Merkle authentication path verification gadget inside R1CS.

use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use zktrace_core::crypto::{Fr, MerkleProof, MerkleProofStep};

use crate::gadgets::poseidon::poseidon_hash_2_gadget;

/// Variable representation of a single Merkle proof step.
#[derive(Clone)]
pub struct MerkleProofStepVar {
    /// Sibling node hash variable.
    pub sibling: FpVar<Fr>,
    /// Boolean indicating if the sibling is the right child.
    pub is_right: Boolean<Fr>,
}

/// Variable representation of an entire Merkle inclusion path.
#[derive(Clone)]
pub struct MerklePathVar {
    /// Ordered steps from leaf to root.
    pub steps: Vec<MerkleProofStepVar>,
}

impl MerklePathVar {
    /// Allocates a new Merkle path witness from a native `MerkleProof`.
    pub fn new_witness(
        cs: ConstraintSystemRef<Fr>,
        proof: &MerkleProof,
    ) -> Result<Self, SynthesisError> {
        let mut steps_var = Vec::with_capacity(proof.steps.len());

        for step in &proof.steps {
            let sibling_var = FpVar::new_witness(cs.clone(), || Ok(step.sibling))?;
            let is_right_var = Boolean::new_witness(cs.clone(), || Ok(step.is_right))?;
            steps_var.push(MerkleProofStepVar {
                sibling: sibling_var,
                is_right: is_right_var,
            });
        }

        Ok(Self { steps: steps_var })
    }

    /// Computes the calculated Merkle root from a leaf variable along this path.
    pub fn compute_root(
        &self,
        cs: ConstraintSystemRef<Fr>,
        leaf: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let mut current = leaf.clone();

        for step in &self.steps {
            // If is_right is true: left = current, right = sibling
            // If is_right is false: left = sibling, right = current
            let left = step.is_right.select(&current, &step.sibling)?;
            let right = step.is_right.select(&step.sibling, &current)?;
            current = poseidon_hash_2_gadget(cs.clone(), &left, &right)?;
        }

        Ok(current)
    }

    /// Enforces that the calculated root from `leaf` matches the expected root variable.
    pub fn enforce_membership(
        &self,
        cs: ConstraintSystemRef<Fr>,
        leaf: &FpVar<Fr>,
        expected_root: &FpVar<Fr>,
    ) -> Result<(), SynthesisError> {
        let calculated_root = self.compute_root(cs, leaf)?;
        calculated_root.enforce_equal(expected_root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use zktrace_core::crypto::MerkleTree;

    #[test]
    fn test_merkle_path_gadget_valid() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut tree = MerkleTree::new(4);
        let leaf = Fr::from(999u64);
        tree.insert(leaf).unwrap();
        let expected_root = tree.root();
        let proof = tree.generate_proof(0).unwrap();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(expected_root)).unwrap();
        let path_var = MerklePathVar::new_witness(cs.clone(), &proof).unwrap();

        path_var
            .enforce_membership(cs.clone(), &leaf_var, &root_var)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_merkle_path_gadget_invalid_leaf() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut tree = MerkleTree::new(4);
        let leaf = Fr::from(999u64);
        tree.insert(leaf).unwrap();
        let expected_root = tree.root();
        let proof = tree.generate_proof(0).unwrap();

        let wrong_leaf = Fr::from(111u64);
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(wrong_leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(expected_root)).unwrap();
        let path_var = MerklePathVar::new_witness(cs.clone(), &proof).unwrap();

        path_var
            .enforce_membership(cs.clone(), &leaf_var, &root_var)
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
