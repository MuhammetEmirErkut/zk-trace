//! Poseidon hashing gadgets inside R1CS constraint systems.

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::constraints::PoseidonSpongeVar,
};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use zktrace_core::crypto::{poseidon_config_rate_2, poseidon_config_rate_4, Fr};

/// Computes the 2-to-1 Poseidon hash of two variable field elements $H(L, R)$ inside the circuit.
pub fn poseidon_hash_2_gadget(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let config = poseidon_config_rate_2();
    let mut sponge_var = PoseidonSpongeVar::new(cs, config);
    sponge_var.absorb(&[left.clone(), right.clone()])?;
    let squeezed = sponge_var.squeeze_field_elements(1)?;
    Ok(squeezed[0].clone())
}

/// Computes the Poseidon hash of a single variable field element $H(x)$ inside the circuit.
pub fn poseidon_hash_1_gadget(
    cs: ConstraintSystemRef<Fr>,
    input: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let config = poseidon_config_rate_2();
    let mut sponge_var = PoseidonSpongeVar::new(cs, config);
    sponge_var.absorb(&[input.clone()])?;
    let squeezed = sponge_var.squeeze_field_elements(1)?;
    Ok(squeezed[0].clone())
}

/// Computes the Poseidon hash of multiple field element variables inside the circuit.
pub fn poseidon_hash_many_gadget(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    if inputs.len() <= 2 {
        let config = poseidon_config_rate_2();
        let mut sponge_var = PoseidonSpongeVar::new(cs, config);
        sponge_var.absorb(&inputs.to_vec())?;
        let squeezed = sponge_var.squeeze_field_elements(1)?;
        Ok(squeezed[0].clone())
    } else {
        let config = poseidon_config_rate_4();
        let mut sponge_var = PoseidonSpongeVar::new(cs, config);
        sponge_var.absorb(&inputs.to_vec())?;
        let squeezed = sponge_var.squeeze_field_elements(1)?;
        Ok(squeezed[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use zktrace_core::crypto::{poseidon_hash_2, poseidon_hash_many};

    #[test]
    fn test_poseidon_gadget_matches_native_2() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let l_val = Fr::from(12345u64);
        let r_val = Fr::from(67890u64);
        let expected = poseidon_hash_2(l_val, r_val);

        let l_var = FpVar::new_witness(cs.clone(), || Ok(l_val)).unwrap();
        let r_var = FpVar::new_witness(cs.clone(), || Ok(r_val)).unwrap();

        let res_var = poseidon_hash_2_gadget(cs.clone(), &l_var, &r_var).unwrap();

        assert_eq!(res_var.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_gadget_matches_native_many() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let vals = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let expected = poseidon_hash_many(&vals);

        let vars: Vec<FpVar<Fr>> = vals
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();

        let res_var = poseidon_hash_many_gadget(cs.clone(), &vars).unwrap();

        assert_eq!(res_var.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }
}
