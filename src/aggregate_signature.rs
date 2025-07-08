use crate::impls::inner_types::*;
use crate::*;

/// Represents a BLS signature for multiple signatures that signed different messages
///
/// An aggregate signature combines multiple individual signatures into a single
/// signature. This is useful for compressing multiple signatures and allows for
/// efficient batch verification. Each signature in the aggregate can be for a
/// different message, unlike multi-signatures where all signatures are for the
/// same message.
///
/// # Example
/// ```
/// # use blsful::*;
/// # use blsful::impls::Bls12381G1Impl;
/// let sk1 = SecretKey::<Bls12381G1Impl>::random(rand_core::OsRng);
/// let sk2 = SecretKey::<Bls12381G1Impl>::random(rand_core::OsRng);
/// let pk1 = PublicKey::from(&sk1);
/// let pk2 = PublicKey::from(&sk2);
/// 
/// // Sign different messages
/// let sig1 = sk1.sign(SignatureSchemes::Basic, b"message 1").unwrap();
/// let sig2 = sk2.sign(SignatureSchemes::Basic, b"message 2").unwrap();
/// 
/// // Aggregate the signatures
/// let agg_sig = AggregateSignature::from_signatures(&[sig1, sig2]).unwrap();
/// 
/// // Verify the aggregate signature
/// let data = vec![(pk1, b"message 1".as_ref()), (pk2, b"message 2".as_ref())];
/// assert!(agg_sig.verify(&data).is_ok());
/// ```
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AggregateSignature<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession scheme
    ProofOfPossession(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<C: BlsSignatureImpl> Default for AggregateSignature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> Display for AggregateSignature<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for AggregateSignature<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for AggregateSignature<C> {}

impl<C: BlsSignatureImpl> Clone for AggregateSignature<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for AggregateSignature<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // This implementation requires that both signatures use the same scheme.
        // In constant-time code, mixing schemes should not occur.
        debug_assert!(
            matches!(
                (a, b),
                (Self::Basic(_), Self::Basic(_))
                    | (Self::MessageAugmentation(_), Self::MessageAugmentation(_))
                    | (Self::ProofOfPossession(_), Self::ProofOfPossession(_))
            ),
            "ConditionallySelectable requires aggregate signatures with matching schemes"
        );
        
        match (a, b) {
            (Self::Basic(a), Self::Basic(b)) => {
                Self::Basic(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            (Self::MessageAugmentation(a), Self::MessageAugmentation(b)) => {
                Self::MessageAugmentation(<C as Pairing>::Signature::conditional_select(
                    a, b, choice,
                ))
            }
            (Self::ProofOfPossession(a), Self::ProofOfPossession(b)) => {
                Self::ProofOfPossession(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            _ => {
                // For mismatched variants, always return a's variant
                // This maintains constant-time behavior but indicates a logic error
                *a
            }
        }
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[Signature<C>]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(sigs: &[Signature<C>]) -> Result<Self, Self::Error> {
        if sigs.len() < 2 {
            return Err(BlsError::InvalidSignature);
        }
        let mut g = <C as Pairing>::Signature::identity();
        for s in &sigs[1..] {
            if !s.same_scheme(&sigs[0]) {
                return Err(BlsError::InvalidSignatureScheme);
            }
            let ss = match s {
                Signature::Basic(sig) => sig,
                Signature::MessageAugmentation(sig) => sig,
                Signature::ProofOfPossession(sig) => sig,
            };
            g += ss;
        }
        match sigs[0] {
            Signature::Basic(s) => Ok(Self::Basic(g + s)),
            Signature::MessageAugmentation(s) => Ok(Self::MessageAugmentation(g + s)),
            Signature::ProofOfPossession(s) => Ok(Self::ProofOfPossession(g + s)),
        }
    }
}

impl_from_derivatives_generic!(AggregateSignature);

impl<C: BlsSignatureImpl> From<&AggregateSignature<C>> for Vec<u8> {
    fn from(value: &AggregateSignature<C>) -> Self {
        // This serialization should not fail for valid AggregateSignature types
        // as serde_bare serialization of simple enums is infallible
        serde_bare::to_vec(value).expect("aggregate signature serialization is infallible")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> AggregateSignature<C> {
    /// Accumulate multiple signatures into a single signature
    /// Verify fails if any signed message is a duplicate
    pub fn from_signatures<B: AsRef<[Signature<C>]>>(signatures: B) -> BlsResult<Self> {
        Self::try_from(signatures.as_ref())
    }

    /// Accumulate signatures using secure aggregation (prevents rogue key attacks)
    ///
    /// This method should be used when aggregating signatures from multiple signers
    /// for the same message. It applies deterministic coefficients to each signature
    /// to prevent rogue public key attacks.
    ///
    /// # Arguments
    /// * `signatures` - The signatures to aggregate (must all be for the same message)
    /// * `public_keys` - The public keys corresponding to each signature
    ///
    /// # Returns
    /// An aggregated signature that can be verified with `verify_secure`
    ///
    /// # Errors
    /// * `InvalidInputs` if array lengths don't match or are empty
    /// * `InvalidSignatureScheme` if signatures use different schemes
    pub fn from_signatures_secure<B: AsRef<[Signature<C>]>>(
        signatures: B,
        public_keys: &[PublicKey<C>],
    ) -> BlsResult<Self> {
        let sigs = signatures.as_ref();

        if sigs.len() != public_keys.len() {
            return Err(BlsError::InvalidInputs(
                "Mismatched array lengths".to_string(),
            ));
        }

        if sigs.is_empty() {
            return Err(BlsError::InvalidInputs(
                "Empty signatures array".to_string(),
            ));
        }

        // Check all signatures use the same scheme
        if !sigs.iter().skip(1).all(|s| s.same_scheme(&sigs[0])) {
            return Err(BlsError::InvalidSignatureScheme);
        }

        // Extract raw signatures
        let raw_sigs: Vec<<C as Pairing>::Signature> =
            sigs.iter().map(|s| *s.as_raw_value()).collect();

        // Use secure aggregation
        let agg_sig = aggregate_secure::<C>(public_keys, &raw_sigs)?;

        // Wrap in appropriate scheme
        match sigs[0] {
            Signature::Basic(_) => Ok(Self::Basic(agg_sig)),
            Signature::MessageAugmentation(_) => Ok(Self::MessageAugmentation(agg_sig)),
            Signature::ProofOfPossession(_) => Ok(Self::ProofOfPossession(agg_sig)),
        }
    }

    /// Verify the aggregated signature using the public keys
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKey<C>, B)]) -> BlsResult<()> {
        let ii = data.iter().map(|(pk, m)| (pk.0, m));
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::aggregate_verify(ii, *sig),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::aggregate_verify(ii, *sig)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::aggregate_verify(ii, *sig),
        }
    }
}
