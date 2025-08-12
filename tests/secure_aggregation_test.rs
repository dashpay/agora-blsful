//! Secure aggregation functionality tests
//!
//! These tests verify that the VerifySecure implementation works correctly
//! for secure BLS signature aggregation, including:
//! 1. Secure aggregation prevents rogue key attacks
//! 2. Normal aggregation fails verify_secure (security feature)
//! 3. Deterministic coefficient generation
//! 4. Order independence of key aggregation

use blsful::*;
use blsful::SerializationFormat::Modern;

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
    assert!(
        final_sig.verify_secure(&[pk1, pk2, pk3], message).is_ok(),
        "VerifySecure should succeed with secure aggregation"
    );

    // Test that normal aggregation fails verify_secure (security feature)
    let normal_agg = AggregateSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    let normal_sig_raw = match normal_agg {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };
    let normal_final_sig = Signature::Basic(normal_sig_raw);
    assert!(
        normal_final_sig
            .verify_secure(&[pk1, pk2, pk3], message)
            .is_err(),
        "VerifySecure should fail with normal aggregation (security feature)"
    );
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
    let aggregated =
        AggregateSignature::from_signatures_secure(&[sig3, sig2, sig1], &pks_reversed).unwrap();

    // Extract the raw aggregated signature
    let agg_sig_raw = match aggregated {
        AggregateSignature::Basic(sig) => sig,
        _ => panic!("Expected Basic aggregate signature"),
    };

    // Create a regular Signature to use verify_secure
    let final_sig = Signature::Basic(agg_sig_raw);

    // Verify using secure aggregation with reversed key order
    // Should succeed because keys are sorted internally for coefficient generation
    assert!(
        final_sig.verify_secure(&pks_reversed, message).is_ok(),
        "VerifySecure should succeed regardless of key order"
    );
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

    assert!(
        final_sig1.verify_secure(&[pk1, pk2], message).is_ok(),
        "Deterministic aggregation should verify successfully"
    );
}

#[test]
fn test_large_scale_aggregate_signature_verification() {
    // Test data from production system with 57 signers
    // Using Bls12381G2Impl because public keys are 48 bytes (G1) and signature is 96 bytes (G2)
    let sig_hex = "8dd55fbe5a1d3393f431191c93d4f8f829cbb118e6a3ac501bd1fdc586769ad42a8adb48e79be1453978c595676f4a7d19bb1761807136b9055b1cd08f39256e14db62f213954a14fa5691c856194d5ae293a82409495b14e625a677d4e4f07f";
    let keys_hex = vec![
        "94792df22b5bee16fd1079ce20ca16f56c6880e23958ec5f28ba4a8d4a3e70de8f364441bf239206c6cee2b254dae4f9",
        "b41346168a93179db28bff78fdb5690d2d6e1cc2576e91d3a3b2143826d55419f9ebfea338c3261a5583be92fe30f9d3",
        "8139176c8f1f195ca77284dfc7a5313717c4beb6aec5001f4cf804a05b8d9e391556d93f447325d40b2bb8e536d61f9b",
        "b5e8fafbbabc4e5cb899bbee5dc5cd860c5aaf098f7ccc4019ce06b6ade9a3e08a20abb8fb5f297909b453580f128235",
        "86f925bb639e681242df5e77e11f0a95b3b5bc97b43434c455b9bbd343394816c5b7bf6016f170bc3558a84c7717021a",
        "b40821ffc45143cd4b8fb70024dbd266fa77d4d8afe3aea504fb6108726d04b093d21c894cf8dec8fd776dcb85bd2e92",
        "9081e8566e74790ba82b291627d7a612e76ccb7aeb1508b78162bc543c564161754446d28b6bb07a345420b72e34de54",
        "b3e83c6bc3491ca84c9f0cba810cb568f82b2b8ca7a533756049281d57abe1d6254ee4b2c5333e1ba4a307a5fed88884",
        "b24f4bf8a3ac575c77ed08a0737cf81d3ab36d263158b252dc58ed3b4bb3ac34f1185e501245b87bbbf4a69433e35509",
        "b6680ecb1d1594c89527c4cfddfd5b6d6df060cd9bde593568cf865664677c3d21c011e6805845406d09019e1780a5e2",
        "8de86a152b717509905c5a9e3ef7dff39bc37a2cba77c24627acbdf4d52a05a43c99100a892f20078849a6157d4b87f4",
        "b8bf3e18159ac3940b5213eacc4b166d75402950a0bf1a80c175ccb2e233dce132f2d741500fa3bf67ac0a5b21d9f9af",
        "9054b3cb64d47501632d239ed4d97d8a0f6a9485d6c46253b57989074544963ac6c38248c87f9b832517528b1cd15edd",
        "add3582dec46d08c1cdd0fdb2eca0d0a35b6a75f570e1b3e5751b7916e2948db298edd7d0190711840f723ff829b5cd8",
        "8e83c347035db55baa76873347e63883ad758e5358af5f4dbd7d03a5606a4f268457406d1c042efabf04504e26473355",
        "b949033f1b836cec66e675eb7d943ff04595a4e19d9e51b31d79cec9bf113e4d83f7f119201ab07488bb1f691b0b7e53",
        "8a6df10092db7c740117f1c3677b47b634d0234aa1d50c0edf96022b71506df6005465b15385a831e89a20de77abfdc7",
        "8cb4e0a319d9f80120746221e2caef48d5b8f376a31b0c379fa566efd6602ba7cb1e974d6786e475a37228cac5a59ae9",
        "a41789e6e874f8006db7b25676e44959aef5864dd1ecf7a4cf9ba21daaf76016b10a04e9f123abb5f10dbe072dfe6082",
        "835c00c9ef102e43cbce50511bff25c86cb225a547e053718a7007e3e750c6297f8f270b21e176102d5d90c51d88842a",
        "a3a8e612ccd3c4cf7554ba4c9e5090c9a15a4ff70b9a8cc742745891071e30904b171f59ee473fc1104483229453c659",
        "a114e45c089f23f710fe1e4ab942395d425420a98b86408baddfc462a2d0817b90ccb46b429bb27593c7e44c3a454a47",
        "90f116340f4159ccb144f89ba2fba539ee99fd95657a12cc04b59c510c3b03ac6f72fb2b099e001b69dc78060c9c8bd7",
        "85885252ded0ca7fe632a1163e0c8c64631a338a3a3591024114fda17f2ec6a0f3b5ae401efa86eafc4f07d8717cd4c7",
        "99464f857c07c15bcf36e89130580ae44a5519fab05a031c73a11846f2809387f5ead76f4ad88c3df0928f49bec53416",
        "8d6f95b3f2e522a21badac5569b62a09fbe860d302cd7389a35511c0211cdbdb0cb623c0dc40f8577fd172a62ec569ae",
        "91cdc4aab0fb071345a2f0cc16d3421be26fdcfa1272dc4e3134a651de646952eaf2ce6a60f23f1264382bf981641d28",
        "b01e88ee4dae968aae87fa1fb6155eab7c579ee044aac262932bbda42359ae40ec6b521f07b5d0ca728e89bd1198178c",
        "b74c08f2bb56045dfb040c22ff4f66ff86f041c4bd1c83344c8dc20656365b600826ca73c8343e995185f7954142143d",
        "8c261f446b125fd803d4cde523eb5e94d0d43f264e2808c52e389053c2e2825d275669b9d6fa622311ee1ca0e5b0e254",
        "874f109089daa0b2d90ce44ea34142a346bf8021511b1a2ade5375a129033fe0a63afa04b8add17e63447c6207bbe7e0",
        "b6d654143231e018c4a437d91541aee96f09a354c274ddc39aa4ecde14664b8b7276a8543f2a94e99da69718c6dfd099",
        "a0502712100efe522a9b23479149b4be3d4dc90521352fb83da4c675db3ba9986ba0b232224d32ad4bc61946cce0ff48",
        "b676aadf1bf29bbb705ddbabfe6813d5def89e8e8d2735c4f95864e942e2b46fbb55885bf5aa2bccca9b7d54ac39c510",
        "821b7458587d49bfad32c078a15c701607781cbe2317f16f2487bf44d66e1e6d0a64a7833a93ad1e2c4458313174d37e",
        "866149fe0b670b4b4178f60fb0c9a70dd0b0210e4fde98f327f0d0b3136fd0d0f695564a2b78b61f371940e3a67547a7",
        "97557572bc9845f625b68eee28f81b5b837d786aebcb68c0da96c08dcc3e289e194fbdb7f744b57542ab5ec3b5a9e26d",
        "91e3d989423514b70db6dcfc0944c77f6b9961b3df59e746913313eef244a40990af3b91059e65ce8d1d5455b322e50c",
        "ac8daac3e2885e478d87f2b10f1eee54d130492c6ef236a87a8ec35a43ffc391070732ee031ae0852b1d55101091d13a",
        "97c8942de54ad5f8184bafe0c159c7a0868d94cd384392ed56f3f60beaada261cbfca5bba336d53655f2c9c11949601f",
        "94c65fa8e3282f8d41032b8f4109c72fcfd062d1161c4547b0cf464660c518b33b77c1e9978ad3ee26b0bef6379032b9",
        "84e6c005eaaf61afad64e28ec3c9096ae5fc3ad23531642dc2fc3dc74ead78ba785cf6a7c22c965a127b9ab4a13b317d",
        "abb30c38ff064eab3b71b56d121b6df77de02e61f13e85fcb83a5a3f291b7a404d801e5aea748b3ecf5c3dcb988e1307",
        "95c8c598528fba3c0f91f0ee236994bb313139742b00353f426a1454a57f5d225454e4f405af421470fdea93bca64728",
        "adcc42086635d6bd863d149a573294868a64df7f4a94f8a78cb68b5ae43a54cb401fccda2da6698b63448e787465f54d",
        "a187e34ec0cc5671b0f6d3207a6449abbc257348e8de4f83cad160ab4baafd04cb8019f3e86d247ce7d6620094d13095",
        "8afd7178127f42f292d45c6fe9ab9896b95add0fbe8fcea71f470c80ea527ce56b3871d6e78bc4966a71addfa87b6ece",
        "b845f051390bfd3e39f1051ccbb8997d569ebdb1265d304c688e18731c3d072d60596e91be1d9e4aa210b075ad63c30f",
        "83080346326dfc221ba7dbf049e706e117e7bf9279e85fb001c92cf4e91a8cd1a5450e087b786c1091d0c3a181d11997",
        "898278320a3d3eaa665a35511e23138a03466a40e59108dea02b350cf84578582e04a278c7843f4fece154a9fe11c585",
        "a61327a26cd0b6fabb50faafbe6b80bef353f4d8ed05cff74e1ee8f47db490ff766729a5564c71408fb8a2be14831c8a",
        "b12d7fb96fd23512406e178e5ddbba9beddaa5ca3de925232ecf11af80db1fc85f513d21146f1e09a296c718d85e0261",
        "b029f581eb30513f6df061b721a47f51976ff4f620294bf32f968aef2ac61af8c8cfda5d126db097e3a275cfda5e26be",
        "8d1f1de62607e61bb5b16cb0dd0ffc3e389224eee37d87fccb74781676bb92ec9c641b361c22c5094a11a04d31c83e3e",
        "b3dd66573c30480719fd6a15f5d87b269f7f2972615ec184faddd3a93ee37fdc92c432e42af55f18b0e3f7cc5104b948",
        "b0cddc1fdbb24b1300a01abe4d24161e51d629b0b4e1a99729da557a51208ccf118c8f1e2cd059753d9ca1f8aa6f7551",
        "a8a5e1926ec1998c3d408bf1db126f5a6b649f434870a20b50e4e7a19451ac7819477e0295affd95eafa813c9d244c0c"
    ];

    let message_hex = "4245472f186d2abf726cfa63459ace22c12bebaa4f1041466db2135995c13406";
    // Convert hex strings to bytes
    let sig_bytes = hex::decode(sig_hex).expect("Invalid signature hex");
    let message_bytes = hex::decode(message_hex).expect("Invalid message hex");
    // Parse public keys
    let mut public_keys = Vec::new();
    for key_hex in keys_hex {
        let key_bytes = hex::decode(key_hex).expect("Invalid public key hex");
        let pk = PublicKey::<Bls12381G2Impl>::try_from(key_bytes.as_slice())
            .expect("Failed to deserialize public key");
        public_keys.push(pk);
    }

    let single_sig = Signature::from_bytes_with_mode(
        sig_bytes.as_slice(),
        SignatureSchemes::Basic,
        Modern,
    ).expect("Failed to create Signature from bytes");

    assert_eq!(sig_hex, hex::encode(single_sig.to_bytes_with_mode(SerializationFormat::Modern)));

    assert!(single_sig.verify_secure(&public_keys, &message_bytes).is_ok(),
        "Aggregate signature should verify successfully with secure aggregation"
    );

}