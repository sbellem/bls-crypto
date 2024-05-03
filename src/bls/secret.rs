use crate::{BLSError, HashToCurve, PublicKey, Signature, POP_DOMAIN, SIG_DOMAIN};

use ark_bls12_377::{Fr, G1Projective};
use ark_ec::Group;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

/// A Private Key using a pairing friendly curve's Fr point
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey(Fr);

impl From<Fr> for PrivateKey {
    fn from(sk: Fr) -> PrivateKey {
        PrivateKey(sk)
    }
}

impl AsRef<Fr> for PrivateKey {
    fn as_ref(&self) -> &Fr {
        &self.0
    }
}

impl PrivateKey {
    /// Generates a new private key from the provided RNG
    pub fn generate<R: Rng>(rng: &mut R) -> PrivateKey {
        PrivateKey(Fr::rand(rng))
    }

    /// Hashes the message/extra_data tuple with the provided `hash_to_g1` function
    /// and then signs it in the SIG_DOMAIN
    pub fn sign<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, BLSError> {
        self.sign_message(SIG_DOMAIN, message, extra_data, hash_to_g1)
    }

    /// Hashes the message with the provided `hash_to_g1` function
    /// and then signs it in the POP_DOMAIN
    pub fn sign_pop<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, BLSError> {
        self.sign_message(POP_DOMAIN, message, &[], hash_to_g1)
    }

    /// Hashes to G1 and signs the hash
    fn sign_message<H: HashToCurve<Output = G1Projective>>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, BLSError> {
        let hash = hash_to_g1.hash(domain, message, extra_data)?;
        Ok(self.sign_raw(&hash))
    }

    fn sign_raw(&self, message: &G1Projective) -> Signature {
        message.mul_bigint(self.as_ref().into_bigint()).into()
    }

    /// Converts the private key to a public key
    pub fn to_public(&self) -> PublicKey {
        PublicKey::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash_to_curve::try_and_increment::TryAndIncrement,
        hashers::{
            composite::{CompositeHasher, BHCRH},
            DirectHasher, Hasher,
        },
    };
    use ark_bls12_377::Config;
    use ark_ec::bls12::Bls12Config;
    use ark_std::{rand::Rng, test_rng};

    #[test]
    fn test_simple_sig() {
        let direct_hasher = DirectHasher;
        let composite_hasher = CompositeHasher::<BHCRH>::new().unwrap();
        test_simple_sig_with_hasher(direct_hasher);
        test_simple_sig_with_hasher(composite_hasher);
    }

    fn test_simple_sig_with_hasher<X: Hasher<Error = BLSError>>(hasher: X) {
        let rng = &mut test_rng();
        let try_and_increment =
            TryAndIncrement::<_, <Config as Bls12Config>::G1Config>::new(&hasher);
        for _ in 0..10 {
            let mut message: Vec<u8> = vec![];
            for _ in 0..32 {
                message.push(rng.gen());
            }
            let sk = PrivateKey::generate(rng);

            let sig = sk.sign(&message[..], &[], &try_and_increment).unwrap();
            let pk = sk.to_public();
            pk.verify(&message[..], &[], &sig, &try_and_increment)
                .unwrap();
            let message2 = b"goodbye";
            pk.verify(&message2[..], &[], &sig, &try_and_increment)
                .unwrap_err();
        }
    }

    #[test]
    fn test_pop() {
        let rng = &mut test_rng();
        let direct_hasher = DirectHasher;
        let try_and_increment =
            TryAndIncrement::<_, <Config as Bls12Config>::G1Config>::new(&direct_hasher);

        let sk = PrivateKey::generate(rng);
        let sk2 = PrivateKey::generate(rng);

        let pk = sk.to_public();
        let mut pk_bytes = vec![];
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let sig = sk.sign_pop(&pk_bytes, &try_and_increment).unwrap();

        let pk2 = sk2.to_public();
        pk.verify_pop(&pk_bytes, &sig, &try_and_increment).unwrap();
        pk2.verify_pop(&pk_bytes, &sig, &try_and_increment)
            .unwrap_err();
    }
}
