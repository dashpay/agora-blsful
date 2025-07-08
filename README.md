# BLS Signature Scheme

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0/MIT Licensed][license-image]

The blissful crate provides a production ready BLS signature implementation.

## Security Notes

This crate has received one security audit from Kudelski Security, with no significant findings. The audit report can be found [here](./audit/2024-15-02_LitProtoco_Crypto_Libraries_v1.1.pdf).
We'd like to thank [LIT Protocol](https://www.litprotocol.com/) for sponsoring this audit.

All operations are constant time unless explicity noted.

# [Documentation](https://docs.rs/blsful)
BLS signatures offer the smallest known signature size as well as other benefits like one round threshold signing and signature aggregation.

BLS signatures rely on pairing-friendly curves which have two fields for points. This library provides keys and signatures for both fields.

For example, most signatures occur in the G1 group requiring public keys in G2 so these are simply named `Signature` and `PublicKey`.
The variant type swaps the fields and thus is name `SignatureVt` and `PublicKeyVt`. Signature proofs of knowledge are supported using
the `proof_of_knowledge` method on `Signatures` which allow a signature holder to prove knowledge of a signature without revealing it.
The signed message is still disclosed. Given this is useful mainly for Signatures, it is not provided directly for multi-signatures or 
aggregated signatures.

This library supports threshold signatures in the form of `PartialSignature` generated from `SecretKeyShare` instead of a `SecretKey`.
`PartialSignature`s can be combined to make a full `Signature` assuming there are sufficient above the threshold. `SecretKeyShare`s can
be generated using shamir secret sharing from crates like [vsss-rs](https://docs.rs/vsss-rs) or using distributed key generation methods like
[gennaro-dkg](https://docs.rs/gennaro-dkg).

Multi-signatures are signatures that have been aggregated that were signed over the same message. This allowed for signature compression and very fast
verification assuming rogue key attacks have been taken into account using Proofs of Possession. For now this library only provides the proof of possession scheme
as this is the most widely used.

Aggregated signatures are signatures that have been aggregated that were signed over different messages. While verification isn't much faster for this,
it's still allows for signature compression.

# Examples

## Key operations

From random entropy source

```rust
let sk = SecretKey::<Bls12381G1Impl>::random(rand_core::OsRng);
let pk = PublicKey::from(&sk);
let pop = ProofOfPossession::new(&sk).expect("a proof of possession");
assert_eq!(pop.verify(pk).unwrap_u8(), 1u8);
```

From seed

```rust
let sk = SecretKey::<Bls12381G1Impl>::hash(b"seed phrase");
let pk = PublicKey::from(&sk);
```

Split a key into key shares

```rust
let shares = sk.split::<rand_core::OsRng, 3, 5>(rand_core::OsRng);
```

Restore a key from shares

```rust
let sk = SecretKey::<Bls12381G1Impl>::combine::<3, 5>(&shares);
```

## Signature operations

Create a signature
```rust
let sig = Signature::new(&sk, b"00000000-0000-0000-0000-000000000000").expect("a valid signature");
```

Verify a signature
```rust
assert_eq!(sig.verify(pk, b"00000000-0000-0000-0000-000000000000").unwrap_u8(), 1u8);
```

## Legacy Serialization Support

This library supports both modern (IETF standard) and legacy (Dash-compatible) BLS serialization formats.

### When to Use Legacy Mode

Use legacy mode when:
- Interoperating with Dash blockchain
- Working with data serialized by older BLS libraries (e.g., relic-based implementations)
- Maintaining backward compatibility with existing systems

### Serialization Examples

```rust
// Modern format (default)
let pk_bytes = public_key.to_bytes();
let pk = PublicKey::try_from(&pk_bytes[..]).unwrap();

// Legacy format
let pk_legacy_bytes = public_key.to_bytes_with_mode(true);
let pk = PublicKey::from_bytes_with_mode(&pk_legacy_bytes, true).unwrap();
```

### VerifySecure with Legacy Support

When using secure aggregation (VerifySecure), the serialization mode affects coefficient generation:

```rust
// Modern secure aggregation
let agg_sig = aggregate_secure(&public_keys, &signatures).unwrap();
assert!(agg_sig.verify_secure(&public_keys, msg).is_ok());

// Legacy secure aggregation
let agg_sig = aggregate_secure(&public_keys, &signatures).unwrap();
assert!(agg_sig.verify_secure_with_mode(&public_keys, msg, true).is_ok());
```

**Important**: Signatures aggregated with `legacy=true` must be verified with `legacy=true`. Mixing modes will cause verification failures.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

# References

1. [IETF Spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/blsful.svg
[crate-link]: https://crates.io/crates/blsful
[docs-image]: https://docs.rs/blsful/badge.svg
[docs-link]: https://docs.rs/blsful/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
