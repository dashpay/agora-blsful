//! Secure aggregation implementation for BLS signatures
//!
//! This module implements VerifySecure functionality to prevent rogue public key attacks
//! by using deterministic coefficients for each public key during aggregation.

use crate::*;
use sha2::{Digest, Sha256};

/// Convert a 32-byte big-endian hash to a scalar field element
///
/// This function:
/// 1. Copies the hash into a scalar representation
/// 2. Converts from big-endian to little-endian (as required by from_repr)
/// 3. Performs automatic modular reduction via from_repr
///
/// # Arguments
/// * `hash` - A 32-byte hash to convert to a scalar
///
/// # Returns
/// * `Ok(scalar)` - The scalar field element
/// * `Err` - If the representation is invalid or too small
fn hash32_to_scalar<C: BlsSignatureImpl>(
    hash: &[u8; 32],
) -> BlsResult<<<C as Pairing>::PublicKey as Group>::Scalar> {
    // Create a field element representation
    let mut repr = <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
    let repr_bytes = repr.as_mut();

    // Ensure we have enough space for the hash
    if repr_bytes.len() < 32 {
        return Err(BlsError::InvalidInputs(
            "Field representation too small for 32-byte hash".to_string(),
        ));
    }

    // Copy hash to the last 32 bytes of the representation
    let offset = repr_bytes.len() - 32;
    repr_bytes[offset..].copy_from_slice(hash);

    // Zero out any prefix bytes
    for byte in &mut repr_bytes[..offset] {
        *byte = 0;
    }

    // Reverse bytes since from_repr expects little-endian but hash is big-endian
    repr_bytes.reverse();

    // Create scalar from representation - this automatically reduces modulo field order
    <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr)
        .into_option()
        .ok_or_else(|| BlsError::InvalidInputs("Failed to create scalar from hash".to_string()))
}

/// Generate deterministic coefficients for secure aggregation
///
/// This implementation matches the C++ bls-signatures library for compatibility:
/// - Hash all sorted public keys with SHA-256
/// - For each key index i, compute SHA-256(i as u32 BE || base_hash)
/// - Interpret the resulting hash as a big-endian integer
/// - Reduce modulo the field order to get the coefficient
///
/// NOTE: This uses raw modular reduction without domain separation tags (DST)
/// to maintain exact compatibility with the C++ implementation. The C++ code
/// performs: bn_read_bin(hash) followed by bn_mod_basic(result, field_order)
#[allow(dead_code)]
fn hash_public_keys<C: BlsSignatureImpl>(
    public_keys: &[PublicKey<C>],
) -> BlsResult<Vec<<<C as Pairing>::PublicKey as Group>::Scalar>> {
    let (_, coefficients) = hash_public_keys_with_sorted(public_keys)?;
    Ok(coefficients)
}

/// Type alias for the result of hash_public_keys_with_sorted
type SortedKeysWithCoefficients<C> = (
    Vec<PublicKey<C>>,
    Vec<<<C as Pairing>::PublicKey as Group>::Scalar>,
);

/// Generate deterministic coefficients and return sorted keys for secure aggregation
///
/// Returns a tuple of (sorted_keys, coefficients) to avoid redundant sorting in callers
fn hash_public_keys_with_sorted<C: BlsSignatureImpl>(
    public_keys: &[PublicKey<C>],
) -> BlsResult<SortedKeysWithCoefficients<C>> {
    // Sort public keys by serialized bytes
    let mut sorted_keys = public_keys.to_vec();
    sorted_keys.sort_by(|a, b| a.0.to_bytes().as_ref().cmp(b.0.to_bytes().as_ref()));

    // Hash all sorted public keys
    let mut hasher = Sha256::new();
    for pk in &sorted_keys {
        hasher.update(pk.0.to_bytes().as_ref());
    }
    let base_hash: [u8; 32] = hasher.finalize().into();

    // Generate coefficients
    let mut coefficients = Vec::with_capacity(sorted_keys.len());

    for i in 0..sorted_keys.len() {
        // Create buffer: [4-byte BE index][32-byte hash]
        let mut hasher = Sha256::new();
        hasher.update((i as u32).to_be_bytes());
        hasher.update(base_hash);
        let hash: [u8; 32] = hasher.finalize().into();

        // Convert hash to scalar with modular reduction
        let scalar = hash32_to_scalar::<C>(&hash)?;

        // Check for zero coefficient (extremely unlikely)
        if scalar.is_zero().into() {
            return Err(BlsError::InvalidCoefficient);
        }

        coefficients.push(scalar);
    }

    Ok((sorted_keys, coefficients))
}

/// Internal implementation of secure aggregation with customizable serialization
#[inline]
fn aggregate_secure_internal<C: BlsSignatureImpl, F, H>(
    public_keys: &[PublicKey<C>],
    signatures: &[<C as Pairing>::Signature],
    serialize_fn: F,
    hash_fn: H,
) -> BlsResult<<C as Pairing>::Signature>
where
    F: Fn(&PublicKey<C>) -> Vec<u8>,
    H: FnOnce(
        &[PublicKey<C>],
    ) -> BlsResult<(
        Vec<PublicKey<C>>,
        Vec<<<C as Pairing>::PublicKey as Group>::Scalar>,
    )>,
{
    if public_keys.len() != signatures.len() {
        return Err(BlsError::InvalidInputs(
            "Mismatched array lengths".to_string(),
        ));
    }

    if public_keys.is_empty() {
        return Ok(<C as Pairing>::Signature::identity());
    }

    // Generate coefficients and get sorted keys
    let (sorted_keys, coefficients) = hash_fn(public_keys)?;

    // Create index mapping from original to sorted order
    let mut sorted_indices = Vec::with_capacity(sorted_keys.len());
    for sorted_key in &sorted_keys {
        let sorted_bytes = serialize_fn(sorted_key);
        let idx = public_keys
            .iter()
            .position(|k| serialize_fn(k) == sorted_bytes)
            .ok_or_else(|| BlsError::InvalidInputs("Key mismatch".to_string()))?;
        sorted_indices.push(idx);
    }

    // Aggregate signatures with coefficients: sig_agg = Σ(sig[i] * t[i])
    let mut aggregated_sig = <C as Pairing>::Signature::identity();
    for (i, idx) in sorted_indices.iter().enumerate() {
        aggregated_sig += signatures[*idx] * coefficients[i];
    }

    Ok(aggregated_sig)
}

/// Aggregate signatures using secure aggregation (prevents rogue key attacks)
pub fn aggregate_secure<C: BlsSignatureImpl>(
    public_keys: &[PublicKey<C>],
    signatures: &[<C as Pairing>::Signature],
) -> BlsResult<<C as Pairing>::Signature> {
    aggregate_secure_internal(
        public_keys,
        signatures,
        |pk| pk.0.to_bytes().as_ref().to_vec(),
        hash_public_keys_with_sorted,
    )
}

/// Internal implementation of verify_secure with customizable hashing
#[inline]
fn verify_secure_with_dst_internal<C: BlsSignatureImpl, B: AsRef<[u8]>, H>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    dst: &'static [u8],
    hash_fn: H,
) -> BlsResult<()>
where
    H: FnOnce(
        &[PublicKey<C>],
    ) -> BlsResult<(
        Vec<PublicKey<C>>,
        Vec<<<C as Pairing>::PublicKey as Group>::Scalar>,
    )>,
{
    // Handle empty case
    if public_keys.is_empty() {
        return if signature.is_identity().into() {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        };
    }

    // Generate coefficients and get sorted keys
    let (sorted_keys, coefficients) = hash_fn(public_keys)?;

    // Aggregate public keys with coefficients: pk_agg = Σ(pk[i] * t[i])
    let mut aggregated_pk = <C as Pairing>::PublicKey::identity();
    for (pk, coeff) in sorted_keys.iter().zip(coefficients.iter()) {
        aggregated_pk += pk.0 * *coeff;
    }

    // Perform standard verification
    <C as BlsSignatureCore>::core_verify(aggregated_pk, signature, msg.as_ref(), dst)
}

/// Internal verify using secure aggregation with specified DST
fn verify_secure_with_dst<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    dst: &'static [u8],
) -> BlsResult<()> {
    verify_secure_with_dst_internal(
        public_keys,
        signature,
        msg,
        dst,
        hash_public_keys_with_sorted,
    )
}

/// Verify using secure aggregation for Basic scheme
pub fn verify_secure_basic<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
) -> BlsResult<()> {
    verify_secure_with_dst::<C, B>(public_keys, signature, msg, <C as BlsSignatureBasic>::DST)
}

/// Verify using secure aggregation for Message Augmentation scheme
pub fn verify_secure_message_augmentation<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
) -> BlsResult<()> {
    verify_secure_with_dst::<C, B>(
        public_keys,
        signature,
        msg,
        <C as BlsSignatureMessageAugmentation>::DST,
    )
}

/// Verify using secure aggregation for Proof of Possession scheme
pub fn verify_secure_pop<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
) -> BlsResult<()> {
    verify_secure_with_dst::<C, B>(public_keys, signature, msg, <C as BlsSignaturePop>::SIG_DST)
}

// Legacy-aware secure aggregation functions

/// Type alias for the result of hash_public_keys_with_sorted_mode
type SortedKeysWithCoefficientsMode<C> = (
    Vec<PublicKey<C>>,
    Vec<<<C as Pairing>::PublicKey as Group>::Scalar>,
);

/// Generate deterministic coefficients and return sorted keys with legacy serialization support
///
/// Returns a tuple of (sorted_keys, coefficients) to avoid redundant sorting in callers
fn hash_public_keys_with_sorted_mode<C: BlsSignatureImpl>(
    public_keys: &[PublicKey<C>],
    format: SerializationFormat,
) -> BlsResult<SortedKeysWithCoefficientsMode<C>>
where
    C::PublicKey: LegacyG1Point,
{
    // Sort public keys by serialized bytes using the specified mode
    let mut sorted_pairs: Vec<(Vec<u8>, &PublicKey<C>)> = public_keys
        .iter()
        .map(|pk| (pk.to_bytes_with_mode(format), pk))
        .collect();
    sorted_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    // Hash all sorted public keys
    let mut hasher = Sha256::new();
    for (pk_bytes, _) in &sorted_pairs {
        hasher.update(pk_bytes);
    }
    let base_hash: [u8; 32] = hasher.finalize().into();

    // Generate coefficients
    let mut coefficients = Vec::with_capacity(sorted_pairs.len());

    for i in 0..sorted_pairs.len() {
        // Create buffer: [4-byte BE index][32-byte hash]
        let mut hasher = Sha256::new();
        hasher.update((i as u32).to_be_bytes());
        hasher.update(base_hash);
        let hash: [u8; 32] = hasher.finalize().into();

        // Convert hash to scalar with modular reduction
        let scalar = hash32_to_scalar::<C>(&hash)?;

        if scalar.is_zero().into() {
            return Err(BlsError::InvalidCoefficient);
        }

        coefficients.push(scalar);
    }

    // Return sorted keys and coefficients
    let sorted_keys = sorted_pairs.into_iter().map(|(_, pk)| *pk).collect();
    Ok((sorted_keys, coefficients))
}

/// Aggregate signatures using secure aggregation with legacy support
pub fn aggregate_secure_with_mode<C: BlsSignatureImpl>(
    public_keys: &[PublicKey<C>],
    signatures: &[<C as Pairing>::Signature],
    format: SerializationFormat,
) -> BlsResult<<C as Pairing>::Signature>
where
    C::PublicKey: LegacyG1Point,
{
    aggregate_secure_internal(
        public_keys,
        signatures,
        |pk| pk.to_bytes_with_mode(format),
        |keys| hash_public_keys_with_sorted_mode(keys, format),
    )
}

/// Internal verify using secure aggregation with specified DST and mode
fn verify_secure_with_dst_and_mode<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    dst: &'static [u8],
    format: SerializationFormat,
) -> BlsResult<()>
where
    C::PublicKey: LegacyG1Point,
{
    verify_secure_with_dst_internal(public_keys, signature, msg, dst, |keys| {
        hash_public_keys_with_sorted_mode(keys, format)
    })
}

/// Verify secure aggregation for Basic scheme with legacy support
pub fn verify_secure_basic_with_mode<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    format: SerializationFormat,
) -> BlsResult<()>
where
    C::PublicKey: LegacyG1Point,
{
    verify_secure_with_dst_and_mode::<C, B>(
        public_keys,
        signature,
        msg,
        <C as BlsSignatureBasic>::DST,
        format,
    )
}

/// Verify secure aggregation for MessageAugmentation scheme with legacy support
pub fn verify_secure_message_augmentation_with_mode<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    format: SerializationFormat,
) -> BlsResult<()>
where
    C::PublicKey: LegacyG1Point,
{
    verify_secure_with_dst_and_mode::<C, B>(
        public_keys,
        signature,
        msg,
        <C as BlsSignatureMessageAugmentation>::DST,
        format,
    )
}

/// Verify secure aggregation for ProofOfPossession scheme with legacy support
pub fn verify_secure_pop_with_mode<C: BlsSignatureImpl, B: AsRef<[u8]>>(
    public_keys: &[PublicKey<C>],
    signature: <C as Pairing>::Signature,
    msg: B,
    format: SerializationFormat,
) -> BlsResult<()>
where
    C::PublicKey: LegacyG1Point,
{
    verify_secure_with_dst_and_mode::<C, B>(
        public_keys,
        signature,
        msg,
        <C as BlsSignaturePop>::SIG_DST,
        format,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impls::Bls12381G1Impl;

    #[test]
    fn test_verify_secure_basic() {
        // Use deterministic keys
        let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
        let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[2u8; 32]);
        let sk3 = SecretKey::<Bls12381G1Impl>::from_hash(&[3u8; 32]);

        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);
        let pk3 = PublicKey::from(&sk3);

        let msg = b"test message";

        // Each signer creates their signature
        let sig1 = sk1.sign(SignatureSchemes::Basic, msg).unwrap();
        let sig2 = sk2.sign(SignatureSchemes::Basic, msg).unwrap();
        let sig3 = sk3.sign(SignatureSchemes::Basic, msg).unwrap();

        // Extract raw signatures
        let raw_sigs = vec![
            match sig1 {
                Signature::Basic(s) => s,
                _ => panic!("Expected Basic signature"),
            },
            match sig2 {
                Signature::Basic(s) => s,
                _ => panic!("Expected Basic signature"),
            },
            match sig3 {
                Signature::Basic(s) => s,
                _ => panic!("Expected Basic signature"),
            },
        ];

        // Use secure aggregation
        let agg_sig_raw = aggregate_secure::<Bls12381G1Impl>(&[pk1, pk2, pk3], &raw_sigs).unwrap();
        let agg_sig = Signature::Basic(agg_sig_raw);

        // Verify using secure aggregation
        assert!(agg_sig.verify_secure(&[pk1, pk2, pk3], msg).is_ok());

        // Should fail with wrong keys
        assert!(agg_sig.verify_secure(&[pk1, pk2], msg).is_err());

        // Should succeed with different order (keys are sorted internally)
        assert!(agg_sig.verify_secure(&[pk3, pk1, pk2], msg).is_ok());
    }

    #[test]
    fn test_coefficient_generation() {
        // Test that coefficients are deterministic
        let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[10u8; 32]);
        let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[20u8; 32]);

        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);

        let coeffs1 = hash_public_keys::<Bls12381G1Impl>(&[pk1, pk2]).unwrap();
        let coeffs2 = hash_public_keys::<Bls12381G1Impl>(&[pk1, pk2]).unwrap();

        assert_eq!(coeffs1.len(), 2);
        assert_eq!(coeffs2.len(), 2);

        // Coefficients should be deterministic
        assert_eq!(coeffs1[0], coeffs2[0]);
        assert_eq!(coeffs1[1], coeffs2[1]);
    }

    #[test]
    fn test_rogue_key_attack_protection() {
        // Test that verify_secure prevents rogue key attacks
        // In a rogue key attack, an attacker creates pk_rogue = -pk1 - pk2 + pk_attacker
        // This would make the aggregate key = pk_attacker in naive aggregation

        let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
        let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[2u8; 32]);
        let sk_attacker = SecretKey::<Bls12381G1Impl>::from_hash(&[99u8; 32]);

        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);

        // Attacker creates rogue key: pk_rogue = -pk1 - pk2 + pk_attacker
        let mut pk_rogue_raw = <Bls12381G1Impl as Pairing>::PublicKey::generator() * sk_attacker.0;
        pk_rogue_raw -= pk1.0;
        pk_rogue_raw -= pk2.0;
        let pk_rogue = PublicKey::<Bls12381G1Impl>(pk_rogue_raw);

        let msg = b"test message";

        // Attacker signs with their secret key
        let sig_attacker = sk_attacker.sign(SignatureSchemes::Basic, msg).unwrap();

        // In naive aggregation, this would verify because:
        // pk1 + pk2 + pk_rogue = pk1 + pk2 + (-pk1 - pk2 + pk_attacker) = pk_attacker
        // But with secure aggregation, each key gets a different coefficient

        let raw_sig = match sig_attacker {
            Signature::Basic(s) => s,
            _ => panic!("Expected Basic signature"),
        };

        // Create a fake aggregate signature (just the attacker's signature)
        let fake_agg_sig = Signature::Basic(raw_sig);

        // This should fail with verify_secure
        assert!(fake_agg_sig
            .verify_secure(&[pk1, pk2, pk_rogue], msg)
            .is_err());
    }

    #[test]
    fn test_empty_keys() {
        let empty_keys: Vec<PublicKey<Bls12381G1Impl>> = vec![];
        let identity_sig = <Bls12381G1Impl as Pairing>::Signature::identity();

        // Empty keys with identity signature should verify
        assert!(
            verify_secure_basic::<Bls12381G1Impl, _>(&empty_keys, identity_sig, b"msg").is_ok()
        );

        // Empty keys with non-identity signature should fail
        let sk = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
        let sig = sk.sign(SignatureSchemes::Basic, b"msg").unwrap();
        if let Signature::Basic(raw_sig) = sig {
            assert!(
                verify_secure_basic::<Bls12381G1Impl, _>(&empty_keys, raw_sig, b"msg").is_err()
            );
        }
    }

    #[test]
    fn test_multi_signature_aggregation() {
        // Test proper multi-signature scenario
        let signers: Vec<_> = (1..=5)
            .map(|i| {
                let sk = SecretKey::<Bls12381G1Impl>::from_hash(&[i as u8; 32]);
                let pk = PublicKey::from(&sk);
                (sk, pk)
            })
            .collect();

        let msg = b"important message to sign";

        // Each signer signs the message
        let signatures: Vec<_> = signers
            .iter()
            .map(
                |(sk, _)| match sk.sign(SignatureSchemes::Basic, msg).unwrap() {
                    Signature::Basic(s) => s,
                    _ => panic!("Expected Basic signature"),
                },
            )
            .collect();

        let public_keys: Vec<_> = signers.iter().map(|(_, pk)| *pk).collect();

        // Aggregate signatures securely
        let agg_sig = aggregate_secure::<Bls12381G1Impl>(&public_keys, &signatures).unwrap();
        let wrapped_sig = Signature::Basic(agg_sig);

        // Verify with all public keys
        assert!(wrapped_sig.verify_secure(&public_keys, msg).is_ok());

        // Should fail if we miss a public key
        assert!(wrapped_sig.verify_secure(&public_keys[..4], msg).is_err());

        // Should fail with wrong message
        assert!(wrapped_sig
            .verify_secure(&public_keys, b"wrong message")
            .is_err());
    }
}
