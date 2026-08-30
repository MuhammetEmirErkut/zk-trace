//! Incremental Merkle Tree and Cryptographic Inclusion Proofs backed by Poseidon hashing.
//!
//! Provides logarithmic $O(\log N)$ inclusion proofs for tool execution events in the append-only ledger.

use serde::{Deserialize, Serialize};

use crate::crypto::field::{deserialize_fr, fr_to_hex, serialize_fr, Fr};
use crate::crypto::poseidon::poseidon_hash_2;
use crate::error::{CoreError, CoreResult};

/// Represents a single branch step in a Merkle inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    /// The sibling node hash at this tree level.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub sibling: Fr,
    /// `true` if the sibling is the right child, `false` if it is the left child.
    pub is_right: bool,
}

/// A complete Merkle inclusion proof for a specific leaf index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The zero-indexed position of the leaf in the tree.
    pub leaf_index: usize,
    /// The sequence of sibling hashes from leaf level up to the root.
    pub steps: Vec<MerkleProofStep>,
    /// The expected Merkle root against which this proof was generated.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub expected_root: Fr,
}

impl MerkleProof {
    /// Computes the root from the given leaf using this proof's authentication path.
    pub fn compute_root(&self, leaf: &Fr) -> Fr {
        let mut current = *leaf;
        for step in &self.steps {
            if step.is_right {
                current = poseidon_hash_2(current, step.sibling);
            } else {
                current = poseidon_hash_2(step.sibling, current);
            }
        }
        current
    }

    /// Verifies that the given leaf satisfies this inclusion proof against the committed root.
    pub fn verify(&self, leaf: &Fr) -> bool {
        let computed = self.compute_root(leaf);
        computed == self.expected_root
    }
}

/// An in-memory, fixed-depth or dynamic Incremental Merkle Tree over BN254 $\mathbb{F}_r$.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTree {
    /// The fixed depth of the Merkle Tree (supporting $2^{\text{depth}}$ maximum leaves).
    pub depth: usize,
    /// The list of committed leaf hashes.
    #[serde(
        serialize_with = "serialize_fr_vec",
        deserialize_with = "deserialize_fr_vec"
    )]
    pub leaves: Vec<Fr>,
    /// Precomputed zero hashes for each level of an empty subtree.
    #[serde(
        serialize_with = "serialize_fr_vec",
        deserialize_with = "deserialize_fr_vec"
    )]
    zero_hashes: Vec<Fr>,
}

/// Serializes a vector of field elements to hex strings for Serde.
pub fn serialize_fr_vec<S>(vec: &[Fr], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_vec: Vec<String> = vec.iter().map(fr_to_hex).collect();
    hex_vec.serialize(serializer)
}

/// Deserializes a vector of field elements from hex strings for Serde.
pub fn deserialize_fr_vec<'de, D>(deserializer: D) -> Result<Vec<Fr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_vec = Vec::<String>::deserialize(deserializer)?;
    let mut fr_vec = Vec::with_capacity(hex_vec.len());
    for s in hex_vec {
        let fr = crate::crypto::field::hex_to_fr(&s).map_err(serde::de::Error::custom)?;
        fr_vec.push(fr);
    }
    Ok(fr_vec)
}

impl MerkleTree {
    /// Creates a new Merkle Tree with the specified depth (e.g., depth 16 supports 65,536 leaves).
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 32, "Depth must be between 1 and 32");

        let mut zero_hashes = Vec::with_capacity(depth + 1);
        let mut current_zero = Fr::from(0u64);
        zero_hashes.push(current_zero);

        for _ in 0..depth {
            current_zero = poseidon_hash_2(current_zero, current_zero);
            zero_hashes.push(current_zero);
        }

        Self {
            depth,
            leaves: Vec::new(),
            zero_hashes,
        }
    }

    /// Appends a new leaf to the tree and returns its leaf index and updated Merkle root.
    pub fn insert(&mut self, leaf: Fr) -> CoreResult<(usize, Fr)> {
        let max_leaves = 1usize << self.depth;
        if self.leaves.len() >= max_leaves {
            return Err(CoreError::MerkleError(format!(
                "Merkle tree capacity exceeded (max {} leaves)",
                max_leaves
            )));
        }

        let index = self.leaves.len();
        self.leaves.push(leaf);
        let root = self.root();
        Ok((index, root))
    }

    /// Calculates the current root of the Merkle Tree.
    pub fn root(&self) -> Fr {
        if self.leaves.is_empty() {
            return self.zero_hashes[self.depth];
        }

        let mut current_level = self.leaves.clone();
        let mut level_depth = 0;

        while level_depth < self.depth {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 {
                    chunk[1]
                } else {
                    self.zero_hashes[level_depth]
                };
                next_level.push(poseidon_hash_2(left, right));
            }
            current_level = next_level;
            level_depth += 1;
        }

        current_level[0]
    }

    /// Generates a cryptographic inclusion proof for the leaf at `leaf_index`.
    pub fn generate_proof(&self, leaf_index: usize) -> CoreResult<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(CoreError::MerkleError(format!(
                "Leaf index {} out of bounds (tree size: {})",
                leaf_index,
                self.leaves.len()
            )));
        }

        let mut steps = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;
        let mut current_level = self.leaves.clone();

        for d in 0..self.depth {
            let is_right_child = (idx % 2) == 1;
            let sibling_idx = if is_right_child { idx - 1 } else { idx + 1 };

            let sibling_hash = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                self.zero_hashes[d]
            };

            steps.push(MerkleProofStep {
                sibling: sibling_hash,
                is_right: !is_right_child,
            });

            // Compute parent level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 {
                    chunk[1]
                } else {
                    self.zero_hashes[d]
                };
                next_level.push(poseidon_hash_2(left, right));
            }

            current_level = next_level;
            idx /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            steps,
            expected_root: self.root(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let tree = MerkleTree::new(4);
        let root = tree.root();
        assert_ne!(root, Fr::from(0u64));
    }

    #[test]
    fn test_insert_and_verify_single_leaf() {
        let mut tree = MerkleTree::new(4);
        let leaf = Fr::from(1337u64);
        let (idx, root) = tree.insert(leaf).expect("Insertion should succeed");

        assert_eq!(idx, 0);
        assert_eq!(root, tree.root());

        let proof = tree.generate_proof(0).expect("Proof generation should succeed");
        assert!(proof.verify(&leaf));

        let fake_leaf = Fr::from(9999u64);
        assert!(!proof.verify(&fake_leaf));
    }

    #[test]
    fn test_multiple_leaves_inclusion_proofs() {
        let mut tree = MerkleTree::new(5);
        let mut inserted_leaves = Vec::new();

        for i in 0..10 {
            let leaf = poseidon_hash_2(Fr::from(i as u64), Fr::from(100 + i as u64));
            tree.insert(leaf).expect("Insertion must succeed");
            inserted_leaves.push(leaf);
        }

        let root = tree.root();
        for (i, leaf) in inserted_leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).expect("Proof must generate");
            assert_eq!(proof.expected_root, root);
            assert!(proof.verify(leaf), "Inclusion proof must verify for leaf {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_serde() {
        let mut tree = MerkleTree::new(4);
        let leaf = Fr::from(42u64);
        tree.insert(leaf).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        let json = serde_json::to_string(&proof).expect("Proof serialization failed");
        let deserialized: MerkleProof = serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(proof, deserialized);
        assert!(deserialized.verify(&leaf));
    }
}
