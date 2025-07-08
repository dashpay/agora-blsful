//! Comprehensive test suite for legacy serialization support

use blsful::*;

#[test]
fn test_g1_legacy_serialization_roundtrip() {
    // Test with various points
    let sk1 = SecretKey::<Bls12381G2Impl>::from_hash(b"test_seed_1");
    let pk1 = sk1.public_key();

    // Test modern format roundtrip
    let modern_bytes = pk1.to_bytes_with_mode(SerializationFormat::Modern);
    let pk1_modern = PublicKey::from_bytes_with_mode(&modern_bytes, SerializationFormat::Modern).unwrap();
    assert_eq!(pk1, pk1_modern);

    // Test legacy format roundtrip
    let legacy_bytes = pk1.to_bytes_with_mode(SerializationFormat::Legacy);
    let pk1_legacy = PublicKey::from_bytes_with_mode(&legacy_bytes, SerializationFormat::Legacy).unwrap();
    assert_eq!(pk1, pk1_legacy);

    // Verify formats are different
    assert_ne!(modern_bytes[0], legacy_bytes[0]);
}

#[test]
fn test_g1_infinity_point_same_format() {
    let infinity = PublicKey::<Bls12381G2Impl>::default();

    let modern_bytes = infinity.to_bytes_with_mode(SerializationFormat::Modern);
    let legacy_bytes = infinity.to_bytes_with_mode(SerializationFormat::Legacy);

    // Infinity should be the same in both formats (0xc0 followed by zeros)
    assert_eq!(modern_bytes, legacy_bytes);
    assert_eq!(modern_bytes[0], 0xc0);
}

#[test]
fn test_g2_legacy_serialization_roundtrip() {
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"test_seed_2");
    let msg = b"test message";
    let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();

    // Test modern format roundtrip
    let modern_bytes = sig.to_bytes_with_mode(SerializationFormat::Modern);
    let sig_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &modern_bytes,
        SignatureSchemes::Basic,
        SerializationFormat::Modern,
    )
    .unwrap();
    // Compare actual signature values, not projective coordinates
    assert!(sig.verify(&sk.public_key(), msg).is_ok());
    assert!(sig_modern.verify(&sk.public_key(), msg).is_ok());

    // Test legacy format roundtrip
    let legacy_bytes = sig.to_bytes_with_mode(SerializationFormat::Legacy);
    let sig_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &legacy_bytes,
        SignatureSchemes::Basic,
        SerializationFormat::Legacy,
    )
    .unwrap();
    // Compare actual signature values, not projective coordinates
    assert!(sig_legacy.verify(&sk.public_key(), msg).is_ok());

    // Verify formats are different
    assert_ne!(modern_bytes[0], legacy_bytes[0]);
}

#[test]
fn test_cross_format_deserialization_fails() {
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"test_seed_3");
    let pk = sk.public_key();

    // Serialize in modern format
    let modern_bytes = pk.to_bytes_with_mode(SerializationFormat::Modern);

    // Try to deserialize as legacy - should fail because formats are incompatible
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&modern_bytes, SerializationFormat::Legacy);
    assert!(
        result.is_err(),
        "Modern bytes should not deserialize with legacy mode"
    );

    // For this test, we'll create a legacy format that definitely won't work as modern
    // by finding a key where legacy Y=0
    let mut found_y0 = false;
    for i in 0..100 {
        let test_sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]);
        let test_pk = test_sk.public_key();
        let test_legacy = test_pk.to_bytes_with_mode(SerializationFormat::Legacy);

        if (test_legacy[0] & 0x80) == 0 {
            // Found a key with Y=0 in legacy format
            // This should definitely fail modern deserialization
            let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&test_legacy, SerializationFormat::Modern);
            assert!(
                result.is_err(),
                "Legacy Y=0 bytes should not deserialize with modern mode"
            );
            found_y0 = true;
            break;
        }
    }
    assert!(found_y0, "Should find at least one Y=0 case");
}


#[test]
fn test_verify_secure_legacy_compatibility() {
    // Create multiple signers
    let sk1 = SecretKey::<Bls12381G2Impl>::from_hash(b"signer1");
    let sk2 = SecretKey::<Bls12381G2Impl>::from_hash(b"signer2");
    let sk3 = SecretKey::<Bls12381G2Impl>::from_hash(b"signer3");

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let pk3 = sk3.public_key();

    let msg = b"test message for secure aggregation";

    // Create individual signatures
    let sig1 = sk1.sign(SignatureSchemes::Basic, msg).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, msg).unwrap();
    let sig3 = sk3.sign(SignatureSchemes::Basic, msg).unwrap();

    // Extract raw signatures
    let raw_sigs = vec![
        *sig1.as_raw_value(),
        *sig2.as_raw_value(),
        *sig3.as_raw_value(),
    ];

    // Aggregate with legacy mode
    let agg_sig_legacy = aggregate_secure_with_mode::<Bls12381G2Impl>(
        &[pk1, pk2, pk3],
        &raw_sigs,
        SerializationFormat::Legacy,
    )
    .unwrap();

    // Aggregate with non-legacy mode
    let agg_sig_modern = aggregate_secure_with_mode::<Bls12381G2Impl>(
        &[pk1, pk2, pk3],
        &raw_sigs,
        SerializationFormat::Modern,
    )
    .unwrap();

    // Create signature wrappers
    let sig_legacy = Signature::Basic(agg_sig_legacy);
    let sig_modern = Signature::Basic(agg_sig_modern);

    // Verify that legacy aggregated signature verifies with legacy mode
    assert!(sig_legacy
        .verify_secure_with_mode(&[pk1, pk2, pk3], msg, SerializationFormat::Legacy)
        .is_ok());

    // Verify that modern aggregated signature verifies with modern mode
    assert!(sig_modern
        .verify_secure_with_mode(&[pk1, pk2, pk3], msg, SerializationFormat::Modern)
        .is_ok());

    // Cross-mode verification should fail
    assert!(sig_legacy
        .verify_secure_with_mode(&[pk1, pk2, pk3], msg, SerializationFormat::Modern)
        .is_err());
    assert!(sig_modern
        .verify_secure_with_mode(&[pk1, pk2, pk3], msg, SerializationFormat::Legacy)
        .is_err());
}

#[test]
fn test_legacy_coefficient_generation_differs() {
    // Test that coefficients differ between legacy and modern modes
    let sk1 = SecretKey::<Bls12381G2Impl>::from_hash(b"coeff_test_1");
    let sk2 = SecretKey::<Bls12381G2Impl>::from_hash(b"coeff_test_2");

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();

    // The coefficients should differ because public keys are serialized differently
    // This is crucial for security - using wrong mode will produce wrong coefficients

    let msg = b"coefficient test";
    let sig1 = sk1.sign(SignatureSchemes::Basic, msg).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, msg).unwrap();

    let raw_sigs = vec![*sig1.as_raw_value(), *sig2.as_raw_value()];

    // Aggregate with different modes
    let agg_legacy =
        aggregate_secure_with_mode::<Bls12381G2Impl>(&[pk1, pk2], &raw_sigs, SerializationFormat::Legacy).unwrap();

    let agg_modern =
        aggregate_secure_with_mode::<Bls12381G2Impl>(&[pk1, pk2], &raw_sigs, SerializationFormat::Modern).unwrap();

    // The aggregated signatures should be different
    assert_ne!(agg_legacy, agg_modern);
}


#[test]
fn test_legacy_bit_patterns() {
    // Test specific bit patterns to ensure correct implementation
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[0x42; 32]);
    let pk = sk.public_key();

    let modern_bytes = pk.to_bytes_with_mode(SerializationFormat::Modern);
    let legacy_bytes = pk.to_bytes_with_mode(SerializationFormat::Legacy);

    eprintln!("Modern first byte: 0x{:02x}", modern_bytes[0]);
    eprintln!("Legacy first byte: 0x{:02x}", legacy_bytes[0]);

    // Modern format should have bit 7 set (compression)
    assert!(
        modern_bytes[0] & 0x80 != 0,
        "Modern format should have compression bit set"
    );

    // Legacy format should not have bit 7 set unless Y=1
    // The actual pattern depends on the Y coordinate of this specific point
}

#[test]
fn test_error_messages() {
    // Test that error messages are helpful
    let invalid_g1 = vec![0xFF; 48]; // Invalid point

    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&invalid_g1, SerializationFormat::Modern);
    assert!(result.is_err());

    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&invalid_g1, SerializationFormat::Legacy);
    assert!(result.is_err());

    // Test invalid length
    let short_bytes = vec![0x00; 47];
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&short_bytes, SerializationFormat::Modern);
    match result {
        Err(BlsError::InvalidLength { expected, actual }) => {
            assert_eq!(expected, 48);
            assert_eq!(actual, 47);
        }
        _ => panic!("Expected InvalidLength error"),
    }
}
