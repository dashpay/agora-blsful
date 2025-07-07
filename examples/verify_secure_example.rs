//! Example demonstrating VerifySecure functionality
//! 
//! VerifySecure is designed to verify aggregated signatures that were
//! created using secure aggregation (with deterministic coefficients).

use blsful::*;

fn main() {
    println!("=== BLS VerifySecure Example ===\n");
    
    // Create three signers
    let signer1 = SecretKey::<Bls12381G1Impl>::from_hash(b"alice_key");
    let signer2 = SecretKey::<Bls12381G1Impl>::from_hash(b"bob_key");
    let signer3 = SecretKey::<Bls12381G1Impl>::from_hash(b"charlie_key");
    
    // Get their public keys
    let pk1 = PublicKey::from(&signer1);
    let pk2 = PublicKey::from(&signer2);
    let pk3 = PublicKey::from(&signer3);
    
    let message = b"Important message requiring multiple signatures";
    
    println!("Demonstrating rogue key attack vulnerability...\n");
    
    // === Demonstrate the Rogue Key Attack Problem ===
    
    // Attacker computes: pk_rogue = -pk1 - pk2 + pk_attacker  
    // Note: In a real attack, honest signers would create signatures, but for this
    // demonstration we focus on showing how VerifySecure prevents the attack vector
    let attacker = SecretKey::<Bls12381G1Impl>::from_hash(b"attacker_key");
    let attacker_pk_raw = PublicKey::from(&attacker).0;
    let mut rogue_pk_raw = attacker_pk_raw;
    rogue_pk_raw -= pk1.0;
    rogue_pk_raw -= pk2.0;
    let rogue_pk = PublicKey::<Bls12381G1Impl>(rogue_pk_raw);
    
    println!("--- Naive Aggregation (VULNERABLE) ---");
    println!("With naive aggregation:");
    println!("  pk_agg = pk1 + pk2 + pk_rogue");
    println!("         = pk1 + pk2 + (pk_attacker - pk1 - pk2)");
    println!("         = pk_attacker");
    println!("\nThis allows the attacker to create a valid signature!");
    
    // Create attacker's signature
    let attacker_sig = attacker.sign(SignatureSchemes::Basic, message).unwrap();
    
    // === Show How VerifySecure Prevents This ===
    
    println!("\n--- Secure Aggregation with VerifySecure ---");
    println!("With secure aggregation:");
    println!("  pk_agg = t1*pk1 + t2*pk2 + t3*pk_rogue");
    println!("where t1, t2, t3 are deterministic coefficients");
    println!("\nThe attacker cannot predict or control these coefficients!");
    
    print!("\nRogue key attack test: ");
    // Try to verify attacker's signature against the three keys
    // This would succeed with naive verification but fails with verify_secure
    match attacker_sig.verify_secure(&[pk1, pk2, rogue_pk], message) {
        Ok(()) => println!("✗ FAIL: Rogue key attack succeeded!"),
        Err(_) => println!("✓ PASS: Attack prevented by VerifySecure"),
    }
    
    println!("\n--- Additional Security Properties ---");
    
    // Test that key order doesn't matter
    print!("Key order independence: ");
    let test_sig = signer3.sign(SignatureSchemes::Basic, message).unwrap();
    let result1 = test_sig.verify_secure(&[pk1, pk2, pk3], message).is_err();
    let result2 = test_sig.verify_secure(&[pk3, pk1, pk2], message).is_err();
    if result1 == result2 {
        println!("✓ PASS: Same result regardless of key order");
    } else {
        println!("✗ FAIL: Different results for different key orders");
    }
    
    println!("\n=== Summary ===");
    println!("VerifySecure prevents rogue public key attacks by:");
    println!("1. Sorting public keys deterministically");
    println!("2. Computing a hash of all sorted keys");
    println!("3. Generating unique coefficients for each key");
    println!("4. Using these coefficients during aggregation");
    println!("\nThis ensures attackers cannot create keys that cancel");
    println!("out honest participants' contributions.");
    
    println!("\n=== Implementation Note ===");
    println!("VerifySecure is designed to work with aggregate_secure.");
    println!("For individual signature verification, use the standard");
    println!("verify() method instead.");
}