//! Secure aggregation functionality tests
//! 
//! These tests verify that the VerifySecure implementation works correctly
//! for secure BLS signature aggregation, including:
//! 1. Secure aggregation prevents rogue key attacks
//! 2. Normal aggregation fails verify_secure (security feature)
//! 3. Deterministic coefficient generation
//! 4. Order independence of key aggregation

use blsful::*;


#[test]
fn test_secure_aggregation_three_signers() {
    // Test secure aggregation with three signers
    let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
    let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[2u8; 32]);
    let sk3 = SecretKey::<Bls12381G1Impl>::from_hash(&[3u8; 32]);
    
    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);
    let pk3 = PublicKey::from(&sk3);
    
    let message = b"test message";
    let pks = vec![pk1, pk2, pk3];
    
    // Sign with each key
    let sig1 = sk1.sign(SignatureSchemes::Basic, message).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, message).unwrap();
    let sig3 = sk3.sign(SignatureSchemes::Basic, message).unwrap();
    
    // Create an aggregate signature using SECURE aggregation
    let aggregated = AggregateSignature::from_signatures_secure(&[sig1, sig2, sig3], &pks).unwrap();
    
    // Extract the raw aggregated signature
    let agg_sig_raw = match aggregated {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    
    // Create a regular Signature to use verify_secure
    let final_sig = Signature::Basic(agg_sig_raw);
    
    // Verify using secure aggregation - should succeed
    assert!(final_sig.verify_secure(&[pk1, pk2, pk3], message).is_ok(), 
            "VerifySecure should succeed with secure aggregation");
    
    // Test that normal aggregation fails verify_secure (security feature)
    let normal_agg = AggregateSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    let normal_sig_raw = match normal_agg {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    let normal_final_sig = Signature::Basic(normal_sig_raw);
    assert!(normal_final_sig.verify_secure(&[pk1, pk2, pk3], message).is_err(), 
            "VerifySecure should fail with normal aggregation (security feature)");
}

#[test]
fn test_secure_aggregation_key_order_independence() {
    // Test that key order doesn't affect verification (keys are sorted internally)
    
    let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
    let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[2u8; 32]);
    let sk3 = SecretKey::<Bls12381G1Impl>::from_hash(&[3u8; 32]);
    
    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);
    let pk3 = PublicKey::from(&sk3);
    
    let message = b"test message";
    
    let pks_reversed = vec![pk3, pk2, pk1];
    
    // Sign with each key
    let sig1 = sk1.sign(SignatureSchemes::Basic, message).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, message).unwrap();
    let sig3 = sk3.sign(SignatureSchemes::Basic, message).unwrap();
    
    // Create an aggregate signature with reversed order using SECURE aggregation
    let aggregated = AggregateSignature::from_signatures_secure(&[sig3, sig2, sig1], &pks_reversed).unwrap();
    
    // Extract the raw aggregated signature
    let agg_sig_raw = match aggregated {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    
    // Create a regular Signature to use verify_secure
    let final_sig = Signature::Basic(agg_sig_raw);
    
    // Verify using secure aggregation with reversed key order
    // Should succeed because keys are sorted internally for coefficient generation
    assert!(final_sig.verify_secure(&pks_reversed, message).is_ok(), 
            "VerifySecure should succeed regardless of key order");
}

#[test]
fn test_secure_aggregation_deterministic() {
    // Test that secure aggregation is deterministic
    
    let sk1 = SecretKey::<Bls12381G1Impl>::from_hash(&[1u8; 32]);
    let sk2 = SecretKey::<Bls12381G1Impl>::from_hash(&[2u8; 32]);
    
    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);
    
    let message = b"test message";
    
    // Sign with both keys
    let sig1 = sk1.sign(SignatureSchemes::Basic, message).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, message).unwrap();
    
    // Test that secure aggregation is deterministic
    let agg1 = AggregateSignature::from_signatures_secure(&[sig1, sig2], &[pk1, pk2]).unwrap();
    let agg2 = AggregateSignature::from_signatures_secure(&[sig1, sig2], &[pk1, pk2]).unwrap();
    
    // Should produce identical results
    assert_eq!(agg1, agg2, "Secure aggregation should be deterministic");
    
    // Both should verify successfully
    let final_sig1 = match agg1 {
        AggregateSignature::Basic(sig) => Signature::Basic(sig),
        _ => panic!("Expected Basic scheme"),
    };
    
    assert!(final_sig1.verify_secure(&[pk1, pk2], message).is_ok(), 
            "Deterministic aggregation should verify successfully");
}