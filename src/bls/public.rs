use crate::{BLSError, BlsResult, HashToCurve, PrivateKey, Signature, POP_DOMAIN, SIG_DOMAIN};

use ark_bls12_377::{Bls12_377, Fq12, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group, pairing::Pairing};
use ark_ff::{One, PrimeField};
use ark_serialize::{
    CanonicalDeserialize,
    CanonicalSerialize,
    Compress,
    SerializationError,
    Valid,
    Validate,
};

use std::{
    borrow::Borrow,
    io::{Read, Write},
    ops::Neg,
};

/// A BLS public key on G2
#[derive(Clone, Eq, Debug, PartialEq, Hash)]
pub struct PublicKey(pub(super) G2Projective);

impl From<G2Projective> for PublicKey {
    fn from(pk: G2Projective) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(pk: &PrivateKey) -> PublicKey {
        PublicKey::from(G2Projective::generator().mul_bigint(pk.as_ref().into_bigint()))
    }
}

impl AsRef<G2Projective> for PublicKey {
    fn as_ref(&self) -> &G2Projective {
        &self.0
    }
}

impl PublicKey {
    /// Sums the provided public keys to produce the aggregate public key.
    pub fn aggregate<P: Borrow<PublicKey>>(public_keys: impl IntoIterator<Item = P>) -> PublicKey {
        public_keys
            .into_iter()
            .map(|s| s.borrow().0)
            .sum::<G2Projective>()
            .into()
    }

    /// Verifies the provided signature against the message-extra_data pair using the
    /// `hash_to_g1` hasher.
    ///
    /// Uses the `SIG_DOMAIN` under the hood.
    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        self.verify_sig(SIG_DOMAIN, message, extra_data, signature, hash_to_g1)
    }

    /// Verifies the provided proof of possession signature against the message using the
    /// `hash_to_g1` hasher.
    ///
    /// Uses the `POP_DOMAIN` under the hood.
    pub fn verify_pop<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        self.verify_sig(POP_DOMAIN, &message, &[], signature, hash_to_g1)
    }

    fn verify_sig<H: HashToCurve<Output = G1Projective>>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        let mut g1s: Vec<<Bls12_377 as Pairing>::G1Prepared> = Vec::with_capacity(2);
        let mut g2s: Vec<<Bls12_377 as Pairing>::G2Prepared> = Vec::with_capacity(2);
        g1s.push(signature.as_ref().into_affine().into());
        g1s.push(
            hash_to_g1
                .hash(domain, message, extra_data)?
                .into_affine()
                .into(),
        );
        g2s.push(G2Affine::generator().neg().into());
        g2s.push(self.0.into_affine().into());

        let pairing = Bls12_377::multi_pairing(g1s, g2s);
        //if pairing == PairingOutput(Fq12::one()) {
        if pairing.0 == Fq12::one() {
            Ok(())
        } else {
            Err(BLSError::VerificationFailed)
        }
    }
}

impl Valid for PublicKey {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.into_affine().check()?;

        Ok(())
    }
}

impl CanonicalSerialize for PublicKey {
    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_compressed(writer)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_uncompressed(writer)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.into_affine().serialized_size(compress)
    }

	fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_with_mode(&mut writer, compress)
    }
}

impl CanonicalDeserialize for PublicKey {
    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize_compressed(reader)?.into_group(),
        ))
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize_uncompressed(reader)?.into_group(),
        ))
    }

    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize_with_mode(&mut reader, compress, validate)?.into_group(),
        ))
    }


}
