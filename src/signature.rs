use crate::*;
use subtle::ConditionallySelectable;

/// A BLS signature wrapped in the appropriate scheme used to generate it
///
/// This enum represents a BLS signature that can be created using one of three
/// different schemes: Basic, MessageAugmentation, or ProofOfPossession.
/// The scheme used affects how the signature is created and verified.
///
/// # Example
/// ```
/// # use blsful::*;
/// # use blsful::impls::Bls12381G1Impl;
/// let sk = SecretKey::<Bls12381G1Impl>::random(rand_core::OsRng);
/// let msg = b"test message";
/// 
/// // Create a signature using the Basic scheme
/// let sig = sk.sign(SignatureSchemes::Basic, msg).unwrap();
/// 
/// // Verify the signature
/// let pk = PublicKey::from(&sk);
/// assert!(sig.verify(&pk, msg).is_ok());
/// ```
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Signature<C: BlsSignatureImpl> {
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

impl<C: BlsSignatureImpl> Default for Signature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> Display for Signature<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for Signature<C> {}

impl<C: BlsSignatureImpl> Clone for Signature<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> ConditionallySelectable for Signature<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // This implementation requires that both signatures use the same scheme.
        // In constant-time code, mixing schemes should not occur.
        debug_assert!(
            a.same_scheme(b),
            "ConditionallySelectable requires signatures with matching schemes"
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

impl_from_derivatives_generic!(Signature);

impl<C: BlsSignatureImpl> From<&Signature<C>> for Vec<u8> {
    fn from(value: &Signature<C>) -> Self {
        // This serialization should not fail for valid Signature types
        // as serde_bare serialization of simple enums is infallible
        serde_bare::to_vec(value).expect("signature serialization is infallible")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for Signature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> Signature<C> {
    /// Verify the signature using the public key
    pub fn verify<B: AsRef<[u8]>>(&self, pk: &PublicKey<C>, msg: B) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::verify(pk.0, *sig, msg),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, *sig, msg)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::verify(pk.0, *sig, msg),
        }
    }

    /// Determine if two signature were signed using the same scheme
    pub fn same_scheme(&self, &other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Basic(_), Self::Basic(_))
                | (Self::MessageAugmentation(_), Self::MessageAugmentation(_))
                | (Self::ProofOfPossession(_), Self::ProofOfPossession(_))
        )
    }

    /// Create a signature from shares
    pub fn from_shares(shares: &[SignatureShare<C>]) -> BlsResult<Self> {
        if !shares.iter().skip(1).all(|s| s.same_scheme(&shares[0])) {
            return Err(BlsError::InvalidSignatureScheme);
        }
        let points = shares
            .iter()
            .map(|s| *s.as_raw_value())
            .collect::<Vec<<C as Pairing>::SignatureShare>>();
        let sig = <C as BlsSignatureCore>::core_combine_signature_shares(&points)?;
        match shares[0] {
            SignatureShare::Basic(_) => Ok(Self::Basic(sig)),
            SignatureShare::MessageAugmentation(_) => Ok(Self::MessageAugmentation(sig)),
            SignatureShare::ProofOfPossession(_) => Ok(Self::ProofOfPossession(sig)),
        }
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::Signature {
        match self {
            Self::Basic(s) => s,
            Self::MessageAugmentation(s) => s,
            Self::ProofOfPossession(s) => s,
        }
    }

    /// Verify signature created by multiple signers (secure against rogue key attacks)
    pub fn verify_secure<B: AsRef<[u8]>>(
        &self,
        public_keys: &[PublicKey<C>],
        msg: B,
    ) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => {
                secure_aggregation::verify_secure_basic::<C, B>(public_keys, *sig, msg)
            }
            Self::MessageAugmentation(sig) => {
                secure_aggregation::verify_secure_message_augmentation::<C, B>(
                    public_keys,
                    *sig,
                    msg,
                )
            }
            Self::ProofOfPossession(sig) => {
                secure_aggregation::verify_secure_pop::<C, B>(public_keys, *sig, msg)
            }
        }
    }
}

// Legacy serialization support
impl<C: BlsSignatureImpl> Signature<C>
where
    C::Signature: LegacyG2Point,
{
    /// Serialize signature with specified serialization format
    ///
    /// # Arguments
    /// * `format` - The serialization format to use
    pub fn to_bytes_with_mode(&self, format: SerializationFormat) -> Vec<u8> {
        match format {
            SerializationFormat::Legacy => self.as_raw_value().serialize_g2(format).to_vec(),
            SerializationFormat::Modern => self.as_raw_value().to_bytes().as_ref().to_vec(),
        }
    }

    /// Deserialize signature with specified serialization format
    ///
    /// This method requires knowing which signature scheme was used when the
    /// signature was created. The scheme information is not encoded in the
    /// serialized bytes, so the caller must provide it.
    ///
    /// # Arguments
    /// * `bytes` - The serialized signature bytes (must be exactly 96 bytes)
    /// * `scheme` - The signature scheme that was used to create this signature
    /// * `format` - The serialization format of the input bytes
    ///
    /// # Errors
    /// * `InvalidLength` if bytes is not exactly 96 bytes
    /// * `DeserializationError` if the bytes are not a valid signature
    ///
    /// # Example
    /// ```
    /// # use blsful::*;
    /// # use blsful::impls::Bls12381G1Impl;
    /// let sk = SecretKey::<Bls12381G1Impl>::random(rand_core::OsRng);
    /// let sig = sk.sign(SignatureSchemes::Basic, b"message").unwrap();
    /// 
    /// // Serialize with legacy format
    /// let bytes = sig.to_bytes_with_mode(SerializationFormat::Legacy);
    /// 
    /// // Deserialize - must specify the same scheme (Basic)
    /// let restored = Signature::from_bytes_with_mode(
    ///     &bytes,
    ///     SignatureSchemes::Basic,  // Must match original scheme
    ///     SerializationFormat::Legacy
    /// ).unwrap();
    /// 
    /// assert_eq!(sig, restored);
    /// ```
    pub fn from_bytes_with_mode(
        bytes: &[u8],
        scheme: SignatureSchemes,
        format: SerializationFormat,
    ) -> BlsResult<Self> {
        if bytes.len() != 96 {
            return Err(BlsError::InvalidLength {
                expected: 96,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 96];
        array.copy_from_slice(bytes);

        let point = C::Signature::deserialize_g2(&array, format)?;

        match scheme {
            SignatureSchemes::Basic => Ok(Self::Basic(point)),
            SignatureSchemes::MessageAugmentation => Ok(Self::MessageAugmentation(point)),
            SignatureSchemes::ProofOfPossession => Ok(Self::ProofOfPossession(point)),
        }
    }


    /// Verify signature with legacy-aware secure aggregation
    pub fn verify_secure_with_mode<B: AsRef<[u8]>>(
        &self,
        public_keys: &[PublicKey<C>],
        msg: B,
        format: SerializationFormat,
    ) -> BlsResult<()>
    where
        C::PublicKey: LegacyG1Point,
    {
        match self {
            Self::Basic(sig) => {
                verify_secure_basic_with_mode::<C, B>(public_keys, *sig, msg, format)
            }
            Self::MessageAugmentation(sig) => {
                verify_secure_message_augmentation_with_mode::<C, B>(public_keys, *sig, msg, format)
            }
            Self::ProofOfPossession(sig) => {
                verify_secure_pop_with_mode::<C, B>(public_keys, *sig, msg, format)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::g1(Bls12381G1Impl, 49)]
    #[case::g2(Bls12381G2Impl, 97)]
    fn try_from<C: BlsSignatureImpl + PartialEq + Eq + fmt::Debug>(
        #[case] _c: C,
        #[case] expected_len: usize,
    ) {
        const TEST_MSG: &[u8] = b"test_try_from";

        let sk = SecretKey::<C>::from_hash(TEST_MSG);
        let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
        let sig_ma = sk
            .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
            .unwrap();
        let sig_pop = sk
            .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
            .unwrap();

        let test: Vec<u8> = sig_b.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_b2 = Signature::<C>::try_from(test);
        assert!(res_sig_b2.is_ok());
        assert_eq!(sig_b, res_sig_b2.unwrap());

        let test: Vec<u8> = sig_ma.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_ma2 = Signature::<C>::try_from(test);
        assert!(res_sig_ma2.is_ok());
        assert_eq!(sig_ma, res_sig_ma2.unwrap());

        let test: Vec<u8> = sig_pop.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_pop2 = Signature::<C>::try_from(test);
        assert!(res_sig_pop2.is_ok());
        assert_eq!(sig_pop, res_sig_pop2.unwrap());
    }
}
