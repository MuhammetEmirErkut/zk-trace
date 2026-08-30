//! R1CS gadgets for numerical bounds, range checks, and parameter inequalities.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use zktrace_core::crypto::Fr;

/// Enforces that a field element variable `val` satisfies $0 \le \text{val} \le \text{upper\_bound}$.
///
/// Uses binary bit decomposition on both $x$ and $(\text{upper\_bound} - x)$ up to `num_bits`
/// (typically 64 bits for standard integers/budgets), mathematically preventing field overflow.
pub fn enforce_less_than_or_equal_constant(
    cs: ConstraintSystemRef<Fr>,
    val: &FpVar<Fr>,
    upper_bound: u64,
    num_bits: usize,
) -> Result<(), SynthesisError> {
    assert!(num_bits <= 64, "Bit length must be <= 64 to avoid field overflow");

    // 1. Bit-decompose val to ensure val >= 0 and val < 2^num_bits
    let val_bits = val.to_bits_le()?;
    if val_bits.len() > num_bits {
        for bit in &val_bits[num_bits..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }
    }

    // 2. Compute difference diff = upper_bound - val
    let bound_var = FpVar::Constant(Fr::from(upper_bound));
    let diff = &bound_var - val;

    // 3. Allocate diff as witness bits and ensure sum of bits == diff
    let diff_val = diff.value().unwrap_or(Fr::from(0u64));
    let diff_u64 = diff_val.into_bigint().0[0];

    let mut diff_bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let bit_val = ((diff_u64 >> i) & 1) == 1;
        let b = Boolean::new_witness(cs.clone(), || Ok(bit_val))?;
        diff_bits.push(b);
    }

    // 4. Reconstruct diff from bits and enforce equality
    let mut reconstructed = FpVar::Constant(Fr::from(0u64));
    let mut coeff = Fr::from(1u64);
    for bit in diff_bits {
        let bit_fp = FpVar::from(bit);
        reconstructed += &bit_fp * coeff;
        coeff.double_in_place();
    }

    diff.enforce_equal(&reconstructed)?;

    Ok(())
}

/// Enforces that a field element variable `val` satisfies $\text{min} \le \text{val} \le \text{max}$.
pub fn enforce_in_range_constant(
    cs: ConstraintSystemRef<Fr>,
    val: &FpVar<Fr>,
    min: u64,
    max: u64,
    num_bits: usize,
) -> Result<(), SynthesisError> {
    assert!(min <= max, "min must be <= max");

    // Enforce val >= min: (val - min) is non-negative and < 2^num_bits
    let min_var = FpVar::Constant(Fr::from(min));
    let shifted = val - &min_var;
    let range_span = max - min;

    enforce_less_than_or_equal_constant(cs, &shifted, range_span, num_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_range_check_valid() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let val_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(500u64))).unwrap();

        enforce_less_than_or_equal_constant(cs.clone(), &val_var, 1000, 64).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_range_check_boundary_exact() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let val_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1000u64))).unwrap();

        enforce_less_than_or_equal_constant(cs.clone(), &val_var, 1000, 64).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_range_check_in_range() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let val_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(50u64))).unwrap();

        enforce_in_range_constant(cs.clone(), &val_var, 10, 100, 64).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
