use crate::impls::inner_types::*;
use crate::*;

/// A BLS public key
#[derive(Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicKey<C: BlsSignatureImpl>(
    /// The BLS public key raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> From<&SecretKey<C>> for PublicKey<C> {
    fn from(s: &SecretKey<C>) -> Self {
        Self(<C as Pairing>::PublicKey::generator() * s.0)
    }
}

impl<C: BlsSignatureImpl> Display for PublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for PublicKey<C> {}

impl<C: BlsSignatureImpl> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for PublicKey<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKey::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl_from_derivatives_generic!(PublicKey);

impl<C: BlsSignatureImpl> From<&PublicKey<C>> for Vec<u8> {
    fn from(value: &PublicKey<C>) -> Self {
        value.0.to_bytes().as_ref().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for PublicKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = C::PublicKey::default().to_bytes();
        let len = repr.as_ref().len();

        if len != value.len() {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }

        repr.as_mut().copy_from_slice(value);
        let key: Option<C::PublicKey> = C::PublicKey::from_bytes(&repr).into();
        key.map(Self)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid byte sequence".to_string()))
    }
}

impl<C: BlsSignatureImpl> PublicKey<C> {
    /// Encrypt a message using signcryption
    pub fn sign_crypt<B: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
    ) -> SignCryptCiphertext<C> {
        let dst = match scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };
        let (u, v, w) = <C as BlsSignCrypt>::seal(self.0, msg.as_ref(), dst);
        SignCryptCiphertext { u, v, w, scheme }
    }

    /// Encrypt a message using time lock encryption
    pub fn encrypt_time_lock<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
        id: D,
    ) -> BlsResult<TimeCryptCiphertext<C>> {
        let dst = match scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };
        let (u, v, w) = <C as BlsTimeCrypt>::seal(self.0, msg.as_ref(), id.as_ref(), dst)?;
        Ok(TimeCryptCiphertext { u, v, w, scheme })
    }

    /// Encrypt a message using ElGamal
    pub fn encrypt_key_el_gamal(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalCiphertext<C>> {
        let (c1, c2) = <C as BlsElGamal>::seal_scalar(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalCiphertext { c1, c2 })
    }

    /// Encrypt a message using ElGamal and generate a proof
    pub fn encrypt_key_el_gamal_with_proof(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalProof<C>> {
        let (c1, c2, message_proof, blinder_proof, challenge) =
            <C as BlsElGamal>::seal_scalar_with_proof(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalProof {
            ciphertext: ElGamalCiphertext { c1, c2 },
            message_proof,
            blinder_proof,
            challenge,
        })
    }

    /// Create a public key from secret shares
    pub fn from_shares(shares: &[PublicKeyShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}

// Legacy serialization support
impl<C: BlsSignatureImpl> PublicKey<C>
where
    C::PublicKey: LegacyG1Point,
{
    /// Serialize with legacy format support
    ///
    /// # Arguments
    /// * `legacy` - If true, uses legacy format; if false, uses modern format
    pub fn to_bytes_with_mode(&self, legacy: bool) -> Vec<u8> {
        if legacy {
            self.0.serialize_g1(true).to_vec()
        } else {
            self.to_bytes()
        }
    }

    /// Deserialize with legacy format support
    ///
    /// # Arguments
    /// * `bytes` - The bytes to deserialize
    /// * `legacy` - If true, expects legacy format; if false, expects modern format
    pub fn from_bytes_with_mode(bytes: &[u8], legacy: bool) -> BlsResult<Self> {
        if bytes.len() != 48 {
            return Err(BlsError::InvalidLength {
                expected: 48,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 48];
        array.copy_from_slice(bytes);

        let point = C::PublicKey::deserialize_g1(&array, legacy)?;
        Ok(Self(point))
    }

}

impl<C: BlsSignatureImpl> PublicKey<C> {
    /// Get the raw bytes of the public key (modern format)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().as_ref().to_vec()
    }
}
