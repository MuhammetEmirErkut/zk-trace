//! Finite field types and canonical conversion utilities for BN254.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// The primary scalar field for BN254 (alt_bn128) circuits and Poseidon hashing.
pub type Fr = ArkFr;

/// Converts a 64-bit unsigned integer into an `Fr` field element.
#[inline]
pub fn u64_to_fr(val: u64) -> Fr {
    Fr::from(val)
}

/// Converts an arbitrary byte slice into an `Fr` element via modular reduction.
///
/// Uses SHA-256 to hash arbitrary input bytes, then interprets the 32-byte digest
/// as a big-endian integer and reduces modulo the scalar field modulus $r$.
pub fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

/// Converts a 32-byte array directly to `Fr` via canonical scalar field reduction.
pub fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Serializes an `Fr` field element to a canonical 32-byte big-endian representation.
pub fn fr_to_be_bytes(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    let le_bytes = bigint.to_bytes_le();
    for (i, byte) in le_bytes.iter().enumerate().take(32) {
        bytes[31 - i] = *byte;
    }
    bytes
}

/// Serializes an `Fr` field element to a `0x`-prefixed 64-character hexadecimal string.
pub fn fr_to_hex(fr: &Fr) -> String {
    let bytes = fr_to_be_bytes(fr);
    format!("0x{}", hex::encode(bytes))
}

/// Parses a hexadecimal string (with or without `0x` prefix) into an `Fr` element.
pub fn hex_to_fr(hex_str: &str) -> CoreResult<Fr> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(clean).map_err(|e| {
        CoreError::FieldError(format!("Invalid hex string '{}': {}", hex_str, e))
    })?;

    if bytes.len() > 32 {
        return Err(CoreError::FieldError(format!(
            "Hex string byte length {} exceeds 32-byte field element capacity",
            bytes.len()
        )));
    }

    let mut padded = [0u8; 32];
    let offset = 32 - bytes.len();
    padded[offset..].copy_from_slice(&bytes);

    Ok(Fr::from_be_bytes_mod_order(&padded))
}

/// Converts a `BigUint` into an `Fr` element.
pub fn biguint_to_fr(big: &BigUint) -> Fr {
    let bytes = big.to_bytes_be();
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Converts an `Fr` element into a `BigUint`.
pub fn fr_to_biguint(fr: &Fr) -> BigUint {
    let bytes = fr_to_be_bytes(fr);
    BigUint::from_bytes_be(&bytes)
}

/// Custom Serde serializer for `Fr` field elements as `0x`-prefixed hex strings.
pub fn serialize_fr<S>(fr: &Fr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&fr_to_hex(fr))
}

/// Custom Serde deserializer for `Fr` field elements from hex strings or integer literals.
pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<Fr, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex_to_fr(&s).map_err(serde::de::Error::custom)
}

/// Custom Serde serializer for `Option<Fr>`.
pub fn serialize_opt_fr<S>(fr: &Option<Fr>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match fr {
        Some(val) => serializer.serialize_some(&fr_to_hex(val)),
        None => serializer.serialize_none(),
    }
}

/// Custom Serde deserializer for `Option<Fr>`.
pub fn deserialize_opt_fr<'de, D>(deserializer: D) -> Result<Option<Fr>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(s) => hex_to_fr(&s).map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Serializes any canonical Arkworks serializable object into bytes.
pub fn canonical_serialize<T: CanonicalSerialize>(item: &T) -> CoreResult<Vec<u8>> {
    let mut bytes = Vec::new();
    item.serialize_compressed(&mut bytes)
        .map_err(|e| CoreError::SerializationError(format!("Canonical serialization failed: {}", e)))?;
    Ok(bytes)
}

/// Deserializes any canonical Arkworks serializable object from bytes.
pub fn canonical_deserialize<T: CanonicalDeserialize>(bytes: &[u8]) -> CoreResult<T> {
    T::deserialize_compressed(bytes)
        .map_err(|e| CoreError::SerializationError(format!("Canonical deserialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn test_u64_conversion() {
        let val = 42u64;
        let fr = u64_to_fr(val);
        assert_eq!(fr, Fr::from(42u64));
    }

    #[test]
    fn test_hex_roundtrip() {
        let fr = Fr::from(12345678901234567890u128);
        let hex_str = fr_to_hex(&fr);
        assert!(hex_str.starts_with("0x"));
        let recovered = hex_to_fr(&hex_str).expect("Hex decoding should succeed");
        assert_eq!(fr, recovered);
    }

    #[test]
    fn test_bytes_to_fr_deterministic() {
        let input1 = b"test payload prompt";
        let input2 = b"test payload prompt";
        let input3 = b"different prompt";

        let fr1 = bytes_to_fr(input1);
        let fr2 = bytes_to_fr(input2);
        let fr3 = bytes_to_fr(input3);

        assert_eq!(fr1, fr2);
        assert_ne!(fr1, fr3);
    }

    #[test]
    fn test_biguint_roundtrip() {
        let orig = BigUint::from(987654321098765432109876543210u128);
        let fr = biguint_to_fr(&orig);
        let recovered = fr_to_biguint(&fr);
        assert_eq!(orig, recovered);
    }

    #[test]
    fn test_serde_fr() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
            field: Fr,
        }

        let obj = TestStruct {
            field: Fr::from(424242u64),
        };
        let json = serde_json::to_string(&obj).expect("Serialization to JSON should succeed");
        assert!(json.contains("0x"));

        let deserialized: TestStruct = serde_json::from_str(&json).expect("Deserialization should succeed");
        assert_eq!(obj, deserialized);
    }

    #[test]
    fn test_canonical_serde_roundtrip() {
        let fr = Fr::from(999999999u64);
        let bytes = canonical_serialize(&fr).expect("Serialization should succeed");
        let recovered: Fr = canonical_deserialize(&bytes).expect("Deserialization should succeed");
        assert_eq!(fr, recovered);
    }
}
