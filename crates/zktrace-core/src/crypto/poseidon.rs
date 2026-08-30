//! Poseidon algebraic hash function implementation over the BN254 scalar field ($\mathbb{F}_r$).
//!
//! Poseidon is a ZK-friendly cryptographic permutation designed for efficient R1CS constraint
//! representation inside zero-knowledge circuits (requiring ~200 constraints per 2-to-1 hash
//! compared to ~25,000 constraints for SHA-256).

use std::sync::OnceLock;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha256};

use crate::crypto::field::{bytes_to_fr, Fr};
use crate::error::{CoreError, CoreResult};

/// Global cached configuration for 2-to-1 Poseidon permutation (t = 3, rate = 2, capacity = 1).
static POSEIDON_CONFIG_RATE_2: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

/// Global cached configuration for 4-to-1 Poseidon permutation (t = 5, rate = 4, capacity = 1).
static POSEIDON_CONFIG_RATE_4: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

/// Generates canonical, deterministic round constants and MDS matrix for Poseidon over BN254 Fr.
///
/// Uses a cryptographic pseudo-random sequence seeded with a domain string
/// ensuring standard, reproducible parameters without backdoor risks.
pub fn generate_poseidon_parameters(
    rate: usize,
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
) -> PoseidonConfig<Fr> {
    let t = rate + 1;
    let num_constants = (full_rounds + partial_rounds) * t;

    // Deterministically generate round constants using SHA-256 PRNG
    let mut round_constants = Vec::with_capacity(num_constants);
    for i in 0..num_constants {
        let mut hasher = Sha256::new();
        hasher.update(b"ZKTrace_Poseidon_BN254_RoundConstant_v1");
        hasher.update((i as u32).to_be_bytes());
        hasher.update((rate as u32).to_be_bytes());
        let digest = hasher.finalize();
        let c = Fr::from_be_bytes_mod_order(&digest);
        round_constants.push(c);
    }

    // Deterministically generate Cauchy/Hadamard MDS matrix
    let mut mds = vec![vec![Fr::ZERO; t]; t];
    let mut x_vals = Vec::with_capacity(t);
    let mut y_vals = Vec::with_capacity(t);

    for i in 0..t {
        let mut hasher_x = Sha256::new();
        hasher_x.update(b"ZKTrace_Poseidon_BN254_MDS_X_v1");
        hasher_x.update((i as u32).to_be_bytes());
        let dx = hasher_x.finalize();
        x_vals.push(Fr::from_be_bytes_mod_order(&dx));

        let mut hasher_y = Sha256::new();
        hasher_y.update(b"ZKTrace_Poseidon_BN254_MDS_Y_v1");
        hasher_y.update((i as u32).to_be_bytes());
        let dy = hasher_y.finalize();
        y_vals.push(Fr::from_be_bytes_mod_order(&dy));
    }

    for i in 0..t {
        for j in 0..t {
            // Cauchy matrix entry M_{i,j} = 1 / (x_i + y_j)
            let denom = x_vals[i] + y_vals[j];
            let entry = denom.inverse().unwrap_or(Fr::from((i * t + j + 1) as u64));
            mds[i][j] = entry;
        }
    }

    PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        round_constants,
        rate,
        1,
    )
}

/// Returns the standard 2-to-1 Poseidon sponge configuration ($t=3$, full_rounds=8, partial_rounds=57, $\alpha=5$).
pub fn poseidon_config_rate_2() -> &'static PoseidonConfig<Fr> {
    POSEIDON_CONFIG_RATE_2.get_or_init(|| generate_poseidon_parameters(2, 8, 57, 5))
}

/// Returns the standard 4-to-1 Poseidon sponge configuration ($t=5$, full_rounds=8, partial_rounds=60, $\alpha=5$).
pub fn poseidon_config_rate_4() -> &'static PoseidonConfig<Fr> {
    POSEIDON_CONFIG_RATE_4.get_or_init(|| generate_poseidon_parameters(4, 8, 60, 5))
}

/// Computes the 2-to-1 Poseidon hash of two field elements $H(L, R)$.
///
/// Primarily utilized for internal node hashing in the ZKTrace Merkle ledger.
pub fn poseidon_hash_2(left: Fr, right: Fr) -> Fr {
    let config = poseidon_config_rate_2();
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&[left, right]);
    sponge.squeeze_field_elements(1)[0]
}

/// Computes the Poseidon hash of a single field element $H(x)$.
pub fn poseidon_hash_1(val: Fr) -> Fr {
    let config = poseidon_config_rate_2();
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&val);
    sponge.squeeze_field_elements(1)[0]
}

/// Computes the Poseidon hash of an arbitrary sequence of field elements.
pub fn poseidon_hash_many(inputs: &[Fr]) -> Fr {
    if inputs.len() <= 2 {
        let config = poseidon_config_rate_2();
        let mut sponge = PoseidonSponge::new(config);
        sponge.absorb(&inputs);
        sponge.squeeze_field_elements(1)[0]
    } else {
        let config = poseidon_config_rate_4();
        let mut sponge = PoseidonSponge::new(config);
        sponge.absorb(&inputs);
        sponge.squeeze_field_elements(1)[0]
    }
}

/// Hashes raw byte slices (prompts, raw payloads, credentials) into a single $\mathbb{F}_r$ digest.
///
/// Encodes bytes into 31-byte field element chunks and applies the Poseidon sponge.
pub fn poseidon_hash_bytes(data: &[u8]) -> Fr {
    if data.is_empty() {
        return poseidon_hash_1(Fr::ZERO);
    }

    let chunks: Vec<Fr> = data
        .chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[1..1 + chunk.len()].copy_from_slice(chunk);
            Fr::from_be_bytes_mod_order(&buf)
        })
        .collect();

    poseidon_hash_many(&chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_2_deterministic() {
        let l = Fr::from(100u64);
        let r = Fr::from(200u64);
        let h1 = poseidon_hash_2(l, r);
        let h2 = poseidon_hash_2(l, r);
        assert_eq!(h1, h2);
        assert_ne!(h1, Fr::ZERO);

        let h3 = poseidon_hash_2(r, l);
        assert_ne!(h1, h3, "Poseidon hash must not be commutative");
    }

    #[test]
    fn test_poseidon_hash_many() {
        let inputs = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ];
        let h1 = poseidon_hash_many(&inputs);
        let h2 = poseidon_hash_many(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let payload_a = b"SELECT * FROM users WHERE tenant_id = 'org_123';";
        let payload_b = b"SELECT * FROM users WHERE tenant_id = 'org_456';";

        let h_a = poseidon_hash_bytes(payload_a);
        let h_b = poseidon_hash_bytes(payload_b);

        assert_ne!(h_a, h_b);
        assert_eq!(h_a, poseidon_hash_bytes(payload_a));
    }
}
