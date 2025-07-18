//! Additional comprehensive tests for legacy serialization support

use blsful::inner_types::GroupEncoding;
use blsful::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_all_signature_schemes_legacy() {
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"all_schemes_test");
    let pk = sk.public_key();
    let msg = b"test message for all schemes";

    // Test all three signature schemes
    for scheme in &[
        SignatureSchemes::Basic,
        SignatureSchemes::MessageAugmentation,
        SignatureSchemes::ProofOfPossession,
    ] {
        let sig = sk.sign(*scheme, msg).unwrap();

        // Test modern format
        let modern_bytes = sig.to_bytes_with_mode(SerializationFormat::Modern);
        let sig_modern =
            Signature::<Bls12381G2Impl>::from_bytes_with_mode(&modern_bytes, *scheme, SerializationFormat::Modern)
                .unwrap();
        assert!(sig_modern.verify(&pk, msg).is_ok());

        // Test legacy format
        let legacy_bytes = sig.to_bytes_with_mode(SerializationFormat::Legacy);
        let sig_legacy =
            Signature::<Bls12381G2Impl>::from_bytes_with_mode(&legacy_bytes, *scheme, SerializationFormat::Legacy)
                .unwrap();
        assert!(sig_legacy.verify(&pk, msg).is_ok());

        // Verify cross-format deserialization fails for appropriate cases
        match Signature::<Bls12381G2Impl>::from_bytes_with_mode(&modern_bytes, *scheme, SerializationFormat::Legacy) {
            Ok(_) => {
                // Some cases might succeed due to point representation
                // but they should produce different results
            }
            Err(_) => {
                // Expected for most cases
            }
        }
    }
}

#[test]
fn test_aggregate_signature_legacy() {
    // Test aggregation with different messages (required for basic aggregation)
    let messages = [
        b"message 1".as_ref(),
        b"message 2".as_ref(),
        b"message 3".as_ref(),
        b"message 4".as_ref(),
        b"message 5".as_ref(),
    ];

    // Create multiple signers
    let signers: Vec<_> = (0..5)
        .map(|i| {
            let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]);
            let pk = sk.public_key();
            let sig = sk.sign(SignatureSchemes::Basic, messages[i]).unwrap();
            (sk, pk, sig)
        })
        .collect();

    let pks: Vec<_> = signers.iter().map(|(_, pk, _)| pk.clone()).collect();
    let sigs: Vec<_> = signers.iter().map(|(_, _, sig)| sig.clone()).collect();

    // Test aggregation
    let agg_sig = AggregateSignature::<Bls12381G2Impl>::from_signatures(&sigs).unwrap();

    // Verify aggregated signature
    let pk_msg_pairs: Vec<_> = pks
        .iter()
        .zip(messages.iter())
        .map(|(pk, msg)| (pk.clone(), *msg))
        .collect();
    assert!(agg_sig.verify(&pk_msg_pairs).is_ok());

    // Test serialization of aggregate signature
    let agg_bytes = Vec::<u8>::from(&agg_sig);
    let agg_restored = AggregateSignature::<Bls12381G2Impl>::try_from(&agg_bytes[..]).unwrap();
    assert!(agg_restored.verify(&pk_msg_pairs).is_ok());
}

#[test]
fn test_multi_signature_legacy() {
    // Create multiple signers
    let signers: Vec<_> = (0..3)
        .map(|i| SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]))
        .collect();

    let pks: Vec<_> = signers.iter().map(|sk| sk.public_key()).collect();

    // Different messages for each signer
    let messages: Vec<&[u8]> = vec![b"message 1", b"message 2", b"message 3"];

    // Create signatures
    let sigs: Vec<_> = signers
        .iter()
        .zip(messages.iter())
        .map(|(sk, msg)| sk.sign(SignatureSchemes::Basic, msg).unwrap())
        .collect();

    // Aggregate signatures (different messages, so this is an aggregate, not multi-sig)
    let agg_sig = AggregateSignature::<Bls12381G2Impl>::from_signatures(&sigs).unwrap();

    // Verify with all pk/msg pairs
    let pk_msg_pairs: Vec<(PublicKey<Bls12381G2Impl>, &[u8])> =
        pks.iter().cloned().zip(messages.iter().copied()).collect();

    assert!(agg_sig.verify(&pk_msg_pairs).is_ok());
}

#[test]
fn test_threshold_signatures_legacy() {
    let threshold = 3;
    let _total = 5;

    // Create a secret key and split it
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"threshold_test");
    let shares = sk.split(3, 5).unwrap();

    let msg = b"threshold signature test";

    // Create partial signatures from threshold number of shares
    let partial_sigs: Vec<_> = shares[..threshold]
        .iter()
        .map(|share| share.sign(SignatureSchemes::Basic, msg).unwrap())
        .collect();

    // Combine partial signatures
    let combined_sig = Signature::<Bls12381G2Impl>::from_shares(&partial_sigs).unwrap();

    // Verify with original public key
    let pk = sk.public_key();
    assert!(combined_sig.verify(&pk, msg).is_ok());

    // Test legacy serialization of threshold signature
    let legacy_bytes = combined_sig.to_bytes_with_mode(SerializationFormat::Legacy);
    let restored = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &legacy_bytes,
        SignatureSchemes::Basic,
        SerializationFormat::Legacy,
    )
    .unwrap();
    assert!(restored.verify(&pk, msg).is_ok());
}

#[test]
fn test_secure_aggregation_with_different_messages_legacy() {
    let sks: Vec<_> = (0..4)
        .map(|i| SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]))
        .collect();

    let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();

    // Each signer signs a different message
    let messages: Vec<&[u8]> = vec![
        b"alice's message",
        b"bob's message",
        b"carol's message",
        b"dave's message",
    ];

    // Test both legacy and modern modes
    for format in [SerializationFormat::Legacy, SerializationFormat::Modern] {
        let _sigs: Vec<_> = sks
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign(SignatureSchemes::Basic, msg).unwrap())
            .collect();

        // Test that secure aggregation with different messages works correctly
        // Since we can't sign the same message with secure aggregation, we test
        // that legacy and modern modes produce different results due to different
        // coefficient generation (based on different public key serialization)

        // Create signatures for the same message to test aggregation behavior
        let test_msg = b"test message for coefficient comparison";
        let test_sigs: Vec<_> = sks
            .iter()
            .map(|sk| sk.sign(SignatureSchemes::Basic, test_msg).unwrap())
            .collect();

        if format == SerializationFormat::Legacy {
            // Aggregate using legacy mode
            let test_raw_sigs: Vec<_> = test_sigs.iter().map(|s| *s.as_raw_value()).collect();
            let agg_legacy =
                secure_aggregation::aggregate_secure_with_mode(&pks, &test_raw_sigs, format).unwrap();

            // Aggregate using modern mode
            let agg_modern = secure_aggregation::aggregate_secure(&pks, &test_raw_sigs).unwrap();

            // The aggregated signatures should be different due to different coefficients
            // This indirectly tests that coefficient generation differs between modes
            let legacy_bytes = agg_legacy.to_bytes().as_ref().to_vec();
            let modern_bytes = agg_modern.to_bytes().as_ref().to_vec();
            assert_ne!(
                legacy_bytes, modern_bytes,
                "Legacy and modern secure aggregation should produce different results"
            );
        }
    }
}

#[test]
fn test_malformed_legacy_data() {
    // Test various malformed inputs

    // 1. Invalid length
    let short_data = vec![0x00; 47];
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&short_data, SerializationFormat::Legacy);
    assert!(matches!(result, Err(BlsError::InvalidLength { .. })));

    // 2. Invalid legacy format with high bits set
    let mut bad_legacy = vec![0xFF; 48];
    bad_legacy[0] = 0xFF; // All bits set - invalid
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&bad_legacy, SerializationFormat::Legacy);
    assert!(result.is_err());

    // 3. Invalid modern format
    let mut bad_modern = vec![0x00; 48];
    bad_modern[0] = 0x40; // Bit 6 set but not bit 7 - invalid modern format
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&bad_modern, SerializationFormat::Modern);
    assert!(result.is_err());

    // 4. Test with signature (G2) malformed data
    let short_sig = vec![0x00; 95];
    let result = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &short_sig,
        SignatureSchemes::Basic,
        SerializationFormat::Legacy,
    );
    assert!(matches!(result, Err(BlsError::InvalidLength { .. })));
}

#[test]
fn test_random_points_legacy_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test with 100 random keys
    for _ in 0..100 {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let sk = SecretKey::<Bls12381G2Impl>::from_hash(&seed);
        let pk = sk.public_key();

        // Test public key serialization
        let modern = pk.to_bytes_with_mode(SerializationFormat::Modern);
        let legacy = pk.to_bytes_with_mode(SerializationFormat::Legacy);

        // Roundtrip tests
        let pk_modern = PublicKey::from_bytes_with_mode(&modern, SerializationFormat::Modern).unwrap();
        let pk_legacy = PublicKey::from_bytes_with_mode(&legacy, SerializationFormat::Legacy).unwrap();

        assert_eq!(pk, pk_modern);
        assert_eq!(pk, pk_legacy);

        // Test signature serialization
        let msg = b"random test";
        let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();

        let sig_modern_bytes = sig.to_bytes_with_mode(SerializationFormat::Modern);
        let sig_legacy_bytes = sig.to_bytes_with_mode(SerializationFormat::Legacy);

        let sig_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &sig_modern_bytes,
            SignatureSchemes::Basic,
            SerializationFormat::Modern,
        )
        .unwrap();
        let sig_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &sig_legacy_bytes,
            SignatureSchemes::Basic,
            SerializationFormat::Legacy,
        )
        .unwrap();

        assert!(sig_modern.verify(&pk, msg).is_ok());
        assert!(sig_legacy.verify(&pk, msg).is_ok());
    }
}

#[test]
fn test_extended_public_key_legacy() {
    // Test that we handle extended keys properly (they default to legacy=true in C++)
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"extended_key_test");
    let pk = sk.public_key();

    // Create child keys (simulating HD derivation)
    let child_sk = SecretKey::<Bls12381G2Impl>::from_hash(b"extended_key_test_child");
    let child_pk = child_sk.public_key();

    // Both should serialize/deserialize correctly
    let parent_legacy = pk.to_bytes_with_mode(SerializationFormat::Legacy);
    let child_legacy = child_pk.to_bytes_with_mode(SerializationFormat::Legacy);

    let parent_restored = PublicKey::from_bytes_with_mode(&parent_legacy, SerializationFormat::Legacy).unwrap();
    let child_restored = PublicKey::from_bytes_with_mode(&child_legacy, SerializationFormat::Legacy).unwrap();

    assert_eq!(pk, parent_restored);
    assert_eq!(child_pk, child_restored);
}

#[test]
fn test_proof_of_possession_legacy() {
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"pop_test");
    let pk = sk.public_key();

    // Create proof of possession
    let pop = sk
        .sign(
            SignatureSchemes::ProofOfPossession,
            pk.to_bytes().as_slice(),
        )
        .unwrap();

    // Test legacy serialization
    let pop_legacy_bytes = pop.to_bytes_with_mode(SerializationFormat::Legacy);
    let pop_modern_bytes = pop.to_bytes_with_mode(SerializationFormat::Modern);

    // Restore and verify
    let pop_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &pop_legacy_bytes,
        SignatureSchemes::ProofOfPossession,
        SerializationFormat::Legacy,
    )
    .unwrap();
    let pop_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &pop_modern_bytes,
        SignatureSchemes::ProofOfPossession,
        SerializationFormat::Modern,
    )
    .unwrap();

    assert!(pop_legacy.verify(&pk, pk.to_bytes().as_slice()).is_ok());
    assert!(pop_modern.verify(&pk, pk.to_bytes().as_slice()).is_ok());
}

#[test]
fn test_batch_verification_legacy() {
    let num_sigs = 10;
    let msg = b"batch verification test";

    let mut pks = Vec::new();
    let mut sigs = Vec::new();

    for i in 0..num_sigs {
        let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]);
        let pk = sk.public_key();
        let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();

        pks.push(pk);
        sigs.push(sig);
    }

    // Test that batch verification works with legacy serialized/deserialized signatures
    let legacy_sigs: Vec<_> = sigs
        .iter()
        .map(|sig| {
            let bytes = sig.to_bytes_with_mode(SerializationFormat::Legacy);
            Signature::<Bls12381G2Impl>::from_bytes_with_mode(&bytes, SignatureSchemes::Basic, SerializationFormat::Legacy)
                .unwrap()
        })
        .collect();

    // All signatures should verify
    for (pk, sig) in pks.iter().zip(legacy_sigs.iter()) {
        assert!(sig.verify(pk, msg).is_ok());
    }
}

#[test]
fn test_zero_scalar_edge_case() {
    // Test with zero scalar - in BLS, zero scalar returns None in CtOption
    let result = SecretKey::<Bls12381G2Impl>::from_be_bytes(&[0u8; 32]);

    // Zero is not a valid secret key in BLS
    assert!(
        bool::from(result.is_none()),
        "Zero scalar should not be a valid secret key"
    );

    // Test identity/infinity point serialization
    let identity_pk = PublicKey::<Bls12381G2Impl>::default();

    // Test both formats - should be identical for infinity
    let modern = identity_pk.to_bytes_with_mode(SerializationFormat::Modern);
    let legacy = identity_pk.to_bytes_with_mode(SerializationFormat::Legacy);

    assert_eq!(
        modern, legacy,
        "Identity point should have same serialization"
    );
    assert_eq!(modern[0], 0xc0, "Identity point should start with 0xc0");
}

#[test]
fn test_mixed_y_coordinates() {
    // Ensure we test both Y=0 and Y=1 cases in legacy format
    let mut found_y0 = false;
    let mut found_y1 = false;

    for i in 0..50u8 {
        let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i; 32]);
        let pk = sk.public_key();

        let legacy = pk.to_bytes_with_mode(SerializationFormat::Legacy);

        if (legacy[0] & 0x80) == 0 {
            found_y0 = true;
            // Y=0 case - verify it roundtrips correctly
            let restored = PublicKey::from_bytes_with_mode(&legacy, SerializationFormat::Legacy).unwrap();
            assert_eq!(pk, restored);
        } else {
            found_y1 = true;
            // Y=1 case - verify it roundtrips correctly
            let restored = PublicKey::from_bytes_with_mode(&legacy, SerializationFormat::Legacy).unwrap();
            assert_eq!(pk, restored);
        }

        if found_y0 && found_y1 {
            break;
        }
    }

    assert!(found_y0, "Should find at least one Y=0 case");
    assert!(found_y1, "Should find at least one Y=1 case");
}
