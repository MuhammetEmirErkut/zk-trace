//! Policy rules, parameter constraints, and policy tree commitments.

use serde::{Deserialize, Serialize};

use crate::crypto::field::{deserialize_fr, fr_to_hex, serialize_fr, Fr};
use crate::crypto::merkle::MerkleTree;
use crate::crypto::poseidon::{poseidon_hash_2, poseidon_hash_bytes};
use crate::error::{CoreError, CoreResult};

/// Parameter constraint definition enforced by cryptographic circuits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum ConstraintType {
    /// Numerical value bounded between `min` and `max` (inclusive).
    NumericRange { min: u64, max: u64 },
    /// Exact hash match against an approved parameter commitment.
    ExactMatch {
        #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
        expected_hash: Fr,
    },
    /// Value must be a member of an approved whitelist hash set.
    Whitelist {
        #[serde(
            serialize_with = "crate::crypto::merkle::serialize_fr_vec",
            deserialize_with = "crate::crypto::merkle::deserialize_fr_vec"
        )]
        allowed_hashes: Vec<Fr>,
    },
    /// Execution spending limit in currency subunits (e.g. cents, satoshis).
    MaxSpendLimit { max_amount: u64 },
    /// Only read-only operations allowed (e.g., SELECT in SQL, GET in HTTP).
    ReadOnlyOnly,
}

/// A specific parameter constraint within a tool policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamConstraint {
    /// The name of the parameter (e.g. "budget", "query", "endpoint").
    pub param_name: String,
    /// The specific constraint type to enforce.
    pub constraint: ConstraintType,
}

/// A complete policy rule governing a specific MCP tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable tool identifier (e.g., "postgres_query", "stripe_charge").
    pub tool_name: String,
    /// Unique tool ID field element hash $\text{Poseidon}(\text{tool\_name})$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub tool_id_hash: Fr,
    /// Parameter constraints attached to this tool rule.
    pub constraints: Vec<ParamConstraint>,
    /// Optional natural language policy description.
    pub description: String,
}

impl PolicyRule {
    /// Creates a new policy rule, automatically computing the Poseidon hash for the tool name.
    pub fn new(tool_name: impl Into<String>, description: impl Into<String>) -> Self {
        let name = tool_name.into();
        let tool_id_hash = poseidon_hash_bytes(name.as_bytes());
        Self {
            tool_name: name,
            tool_id_hash,
            constraints: Vec::new(),
            description: description.into(),
        }
    }

    /// Adds a parameter constraint to this rule.
    pub fn with_constraint(mut self, constraint: ParamConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Computes the cryptographic leaf commitment for this policy rule:
    /// $L_{\text{rule}} = \text{Poseidon}(\text{tool\_id\_hash}, \text{constraints\_digest})$
    pub fn compute_leaf(&self) -> Fr {
        let constraints_json = serde_json::to_string(&self.constraints).unwrap_or_default();
        let constraints_hash = poseidon_hash_bytes(constraints_json.as_bytes());
        poseidon_hash_2(self.tool_id_hash, constraints_hash)
    }
}

/// A collection of policy rules committed into a Policy Merkle Tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyTree {
    /// Unique policy document identifier.
    pub policy_id: String,
    /// Policy semantic version.
    pub version: u32,
    /// List of approved policy rules.
    pub rules: Vec<PolicyRule>,
}

impl PolicyTree {
    /// Creates a new policy tree.
    pub fn new(policy_id: impl Into<String>, version: u32) -> Self {
        Self {
            policy_id: policy_id.into(),
            version,
            rules: Vec::new(),
        }
    }

    /// Adds an approved rule to the policy tree.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Computes the cryptographic policy root $R_{\text{policy}}$ from all rule leaves.
    pub fn compute_policy_root(&self, tree_depth: usize) -> CoreResult<Fr> {
        let mut tree = MerkleTree::new(tree_depth);
        for rule in &self.rules {
            let leaf = rule.compute_leaf();
            tree.insert(leaf)?;
        }
        Ok(tree.root())
    }

    /// Finds a rule by tool name.
    pub fn get_rule(&self, tool_name: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|r| r.tool_name == tool_name)
    }
}

/// Cryptographic commitment to an active policy specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCommitment {
    /// The Merkle root of the policy tree $R_{\text{policy}}$.
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub root_hash: Fr,
    /// Policy identifier.
    pub policy_id: String,
    /// Policy version.
    pub version: u32,
    /// UTC timestamp of policy creation.
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_rule_and_tree_root() {
        let mut tree = PolicyTree::new("enterprise-prod-policy", 1);

        let rule1 = PolicyRule::new("sql_query", "Read-only SQL queries on users db")
            .with_constraint(ParamConstraint {
                param_name: "query_type".to_string(),
                constraint: ConstraintType::ReadOnlyOnly,
            });

        let rule2 = PolicyRule::new("stripe_payment", "Payment tool bounded by $1000")
            .with_constraint(ParamConstraint {
                param_name: "amount".to_string(),
                constraint: ConstraintType::MaxSpendLimit {
                    max_amount: 100_000,
                },
            });

        tree.add_rule(rule1);
        tree.add_rule(rule2);

        let root = tree.compute_policy_root(4).expect("Root computation must succeed");
        assert_ne!(root, Fr::from(0u64));
    }
}
