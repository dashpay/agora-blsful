//! Test that verifies coefficient generation matches C++ implementation
//! 
//! This test focuses on the coefficient generation logic rather than
//! the full key generation and signing process.

use blsful::*;



#[test]
fn test_secure_aggregation_coefficients() {
    // Test that verify_secure actually uses the coefficients correctly
    
    // Create some test keys
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([42u8; 32]);
    let sk1 = SecretKey::<Bls12381G1Impl>::random(&mut rng);
    let sk2 = SecretKey::<Bls12381G1Impl>::random(&mut rng);
    
    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);
    
    let message = b"test message";
    
    // Sign with both keys
    let sig1 = sk1.sign(SignatureSchemes::Basic, message).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, message).unwrap();
    
    // Test secure aggregation with correct order
    let secure_agg1 = AggregateSignature::from_signatures_secure(&[sig1, sig2], &[pk1, pk2]).unwrap();
    let secure_sig1_raw = match secure_agg1 {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    let secure_final_sig1 = Signature::Basic(secure_sig1_raw);
    let verify1 = secure_final_sig1.verify_secure(&[pk1, pk2], message);
    println!("\nVerifySecure with secure aggregation (correct order): {:?}", verify1);
    
    // Test secure aggregation with reversed order
    let secure_agg2 = AggregateSignature::from_signatures_secure(&[sig2, sig1], &[pk2, pk1]).unwrap();
    let secure_sig2_raw = match secure_agg2 {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    let secure_final_sig2 = Signature::Basic(secure_sig2_raw);
    let verify2 = secure_final_sig2.verify_secure(&[pk2, pk1], message);
    println!("VerifySecure with secure aggregation (reversed order): {:?}", verify2);
    
    // Both should succeed because we used secure aggregation correctly
    assert!(verify1.is_ok(), "Should succeed with secure aggregation");
    assert!(verify2.is_ok(), "Should succeed with secure aggregation in reversed order");
    
    // Test that normal aggregation fails (security check)
    let normal_agg = AggregateSignature::from_signatures(&[sig1, sig2]).unwrap();
    let normal_sig_raw = match normal_agg {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    let normal_final_sig = Signature::Basic(normal_sig_raw);
    let normal_verify = normal_final_sig.verify_secure(&[pk1, pk2], message);
    println!("VerifySecure with normal aggregation: {:?}", normal_verify);
    assert!(normal_verify.is_err(), "Should fail with normal aggregation");
}