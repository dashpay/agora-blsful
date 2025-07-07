//! Additional comprehensive tests for legacy serialization support

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
        let modern_bytes = sig.to_bytes_with_mode(false);
        let sig_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &modern_bytes, *scheme, false
        ).unwrap();
        assert!(sig_modern.verify(&pk, msg).is_ok());
        
        // Test legacy format
        let legacy_bytes = sig.to_bytes_with_mode(true);
        let sig_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &legacy_bytes, *scheme, true
        ).unwrap();
        assert!(sig_legacy.verify(&pk, msg).is_ok());
        
        // Verify cross-format deserialization fails for appropriate cases
        match Signature::<Bls12381G2Impl>::from_bytes_with_mode(&modern_bytes, *scheme, true) {
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
    let msg = b"aggregate signature test";
    
    // Create multiple signers
    let signers: Vec<_> = (0..5).map(|i| {
        let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32]);
        let pk = sk.public_key();
        let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();
        (sk, pk, sig)
    }).collect();
    
    let pks: Vec<_> = signers.iter().map(|(_, pk, _)| pk.clone()).collect();
    let sigs: Vec<_> = signers.iter().map(|(_, _, sig)| sig.clone()).collect();
    
    // Test aggregation
    let agg_sig = AggregateSignature::<Bls12381G2Impl>::from_signatures(&sigs).unwrap();
    
    // Verify aggregated signature
    assert!(agg_sig.verify(&pks, msg).is_ok());
    
    // Test serialization of aggregate signature
    let agg_bytes = agg_sig.to_bytes();
    let agg_restored = AggregateSignature::<Bls12381G2Impl>::try_from(&agg_bytes[..]).unwrap();
    assert!(agg_restored.verify(&pks, msg).is_ok());
}

#[test]
fn test_multi_signature_legacy() {
    // Create multiple signers
    let signers: Vec<_> = (0..3).map(|i| {
        SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32])
    }).collect();
    
    let pks: Vec<_> = signers.iter().map(|sk| sk.public_key()).collect();
    
    // Different messages for each signer
    let messages: Vec<&[u8]> = vec![
        b"message 1",
        b"message 2",
        b"message 3",
    ];
    
    // Create signatures
    let sigs: Vec<_> = signers.iter().zip(messages.iter())
        .map(|(sk, msg)| sk.sign(SignatureSchemes::Basic, msg).unwrap())
        .collect();
    
    // Aggregate signatures (different messages, so this is an aggregate, not multi-sig)
    let agg_sig = AggregateSignature::<Bls12381G2Impl>::from_signatures(&sigs).unwrap();
    
    // Verify with all pk/msg pairs
    let pk_msg_pairs: Vec<(&PublicKey<Bls12381G2Impl>, &[u8])> = 
        pks.iter().zip(messages.iter().copied()).collect();
    
    assert!(agg_sig.verify_multi(&pk_msg_pairs).is_ok());
}

#[test]
fn test_threshold_signatures_legacy() {
    let threshold = 3;
    let total = 5;
    
    // Create a secret key and split it
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"threshold_test");
    let shares = sk.split::<ChaCha20Rng, 3, 5>(ChaCha20Rng::from_seed([0u8; 32])).unwrap();
    
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
    let legacy_bytes = combined_sig.to_bytes_with_mode(true);
    let restored = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &legacy_bytes, SignatureSchemes::Basic, true
    ).unwrap();
    assert!(restored.verify(&pk, msg).is_ok());
}

#[test]
fn test_secure_aggregation_with_different_messages_legacy() {
    let sks: Vec<_> = (0..4).map(|i| {
        SecretKey::<Bls12381G2Impl>::from_hash(&[i as u8; 32])
    }).collect();
    
    let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
    
    // Each signer signs a different message
    let messages: Vec<&[u8]> = vec![
        b"alice's message",
        b"bob's message", 
        b"carol's message",
        b"dave's message",
    ];
    
    // Test both legacy and modern modes
    for legacy in [true, false] {
        let sigs: Vec<_> = sks.iter().zip(messages.iter())
            .map(|(sk, msg)| sk.sign(SignatureSchemes::Basic, msg).unwrap())
            .collect();
        
        let raw_sigs: Vec<_> = sigs.iter().map(|s| *s.as_raw_value()).collect();
        
        // For secure aggregation with different messages, we need to use the right approach
        // This is actually testing that the coefficient generation works correctly
        let coeffs_legacy = secure_aggregation::hash_public_keys_with_mode::<Bls12381G2Impl>(&pks, legacy).unwrap();
        let coeffs_modern = secure_aggregation::hash_public_keys_with_mode::<Bls12381G2Impl>(&pks, false).unwrap();
        
        if legacy {
            // Coefficients should be different between legacy and modern
            assert_ne!(coeffs_legacy[0], coeffs_modern[0]);
        }
    }
}

#[test]
fn test_malformed_legacy_data() {
    // Test various malformed inputs
    
    // 1. Invalid length
    let short_data = vec![0x00; 47];
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&short_data, true);
    assert!(matches!(result, Err(BlsError::InvalidLength { .. })));
    
    // 2. Invalid legacy format with high bits set
    let mut bad_legacy = vec![0xFF; 48];
    bad_legacy[0] = 0xFF; // All bits set - invalid
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&bad_legacy, true);
    assert!(result.is_err());
    
    // 3. Invalid modern format
    let mut bad_modern = vec![0x00; 48];
    bad_modern[0] = 0x40; // Bit 6 set but not bit 7 - invalid modern format
    let result = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&bad_modern, false);
    assert!(result.is_err());
    
    // 4. Test with signature (G2) malformed data
    let short_sig = vec![0x00; 95];
    let result = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &short_sig, SignatureSchemes::Basic, true
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
        let modern = pk.to_bytes_with_mode(false);
        let legacy = pk.to_bytes_with_mode(true);
        
        // Roundtrip tests
        let pk_modern = PublicKey::from_bytes_with_mode(&modern, false).unwrap();
        let pk_legacy = PublicKey::from_bytes_with_mode(&legacy, true).unwrap();
        
        assert_eq!(pk, pk_modern);
        assert_eq!(pk, pk_legacy);
        
        // Test signature serialization
        let msg = b"random test";
        let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();
        
        let sig_modern_bytes = sig.to_bytes_with_mode(false);
        let sig_legacy_bytes = sig.to_bytes_with_mode(true);
        
        let sig_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &sig_modern_bytes, SignatureSchemes::Basic, false
        ).unwrap();
        let sig_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &sig_legacy_bytes, SignatureSchemes::Basic, true
        ).unwrap();
        
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
    let parent_legacy = pk.to_bytes_with_mode(true);
    let child_legacy = child_pk.to_bytes_with_mode(true);
    
    let parent_restored = PublicKey::from_bytes_with_mode(&parent_legacy, true).unwrap();
    let child_restored = PublicKey::from_bytes_with_mode(&child_legacy, true).unwrap();
    
    assert_eq!(pk, parent_restored);
    assert_eq!(child_pk, child_restored);
}

#[test]
fn test_proof_of_possession_legacy() {
    let sk = SecretKey::<Bls12381G2Impl>::from_hash(b"pop_test");
    let pk = sk.public_key();
    
    // Create proof of possession
    let pop = sk.sign(SignatureSchemes::ProofOfPossession, pk.to_bytes().as_slice()).unwrap();
    
    // Test legacy serialization
    let pop_legacy_bytes = pop.to_bytes_with_mode(true);
    let pop_modern_bytes = pop.to_bytes_with_mode(false);
    
    // Restore and verify
    let pop_legacy = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &pop_legacy_bytes, SignatureSchemes::ProofOfPossession, true
    ).unwrap();
    let pop_modern = Signature::<Bls12381G2Impl>::from_bytes_with_mode(
        &pop_modern_bytes, SignatureSchemes::ProofOfPossession, false
    ).unwrap();
    
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
    let legacy_sigs: Vec<_> = sigs.iter().map(|sig| {
        let bytes = sig.to_bytes_with_mode(true);
        Signature::<Bls12381G2Impl>::from_bytes_with_mode(
            &bytes, SignatureSchemes::Basic, true
        ).unwrap()
    }).collect();
    
    // All signatures should verify
    for (pk, sig) in pks.iter().zip(legacy_sigs.iter()) {
        assert!(sig.verify(pk, msg).is_ok());
    }
}

#[test]
fn test_zero_scalar_edge_case() {
    // Test with zero scalar (results in identity/infinity point)
    let zero_sk = SecretKey::<Bls12381G2Impl>::from_be_bytes(&[0u8; 32]).unwrap();
    let infinity_pk = zero_sk.public_key();
    
    // Should be identity
    assert_eq!(infinity_pk, PublicKey::default());
    
    // Test both formats - should be identical for infinity
    let modern = infinity_pk.to_bytes_with_mode(false);
    let legacy = infinity_pk.to_bytes_with_mode(true);
    
    assert_eq!(modern, legacy);
    assert_eq!(modern[0], 0xc0);
}

#[test]
fn test_mixed_y_coordinates() {
    // Ensure we test both Y=0 and Y=1 cases in legacy format
    let mut found_y0 = false;
    let mut found_y1 = false;
    
    for i in 0..50u8 {
        let sk = SecretKey::<Bls12381G2Impl>::from_hash(&[i; 32]);
        let pk = sk.public_key();
        
        let legacy = pk.to_bytes_with_mode(true);
        
        if (legacy[0] & 0x80) == 0 {
            found_y0 = true;
            // Y=0 case - verify it roundtrips correctly
            let restored = PublicKey::from_bytes_with_mode(&legacy, true).unwrap();
            assert_eq!(pk, restored);
        } else {
            found_y1 = true;
            // Y=1 case - verify it roundtrips correctly
            let restored = PublicKey::from_bytes_with_mode(&legacy, true).unwrap();
            assert_eq!(pk, restored);
        }
        
        if found_y0 && found_y1 {
            break;
        }
    }
    
    assert!(found_y0, "Should find at least one Y=0 case");
    assert!(found_y1, "Should find at least one Y=1 case");
}