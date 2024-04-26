use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::{PrimeField, UniformRand, Zero};

// Same RNG for all tests
//pub fn rng() -> ark_std::rand::rngs::StdRng {
pub fn rng() -> impl ark_std::rand::Rng {
    ark_std::test_rng()
}

/// generate a keypair
pub fn keygen<E: Pairing>() -> (E::ScalarField, E::G2) {
    let rng = &mut rng();
    let generator = E::G2::generator();

    let secret_key = E::ScalarField::rand(rng);
    let pubkey = generator.mul_bigint(secret_key.into_bigint());
    (secret_key, pubkey)
}

/// generate N keypairs
pub fn keygen_mul<E: Pairing>(num: usize) -> (Vec<E::ScalarField>, Vec<E::G2>) {
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    for _ in 0..num {
        let (secret_key, public_key) = keygen::<E>();
        secret_keys.push(secret_key);
        public_keys.push(public_key);
    }
    (secret_keys, public_keys)
}

/// generate `num_batches` sets of keypair vectors, each `num_per_batch` size
#[allow(clippy::type_complexity)]
pub fn keygen_batch<E: Pairing>(
    num_batches: usize,
    num_per_batch: usize,
) -> (Vec<Vec<E::ScalarField>>, Vec<Vec<E::G2>>) {
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    (0..num_batches).for_each(|_| {
        let (secret_keys_i, public_keys_i) = keygen_mul::<E>(num_per_batch);
        secret_keys.push(secret_keys_i);
        public_keys.push(public_keys_i);
    });
    (secret_keys, public_keys)
}

/// sum the elements in the provided slice
pub fn sum<P: CurveGroup>(elements: &[P]) -> P {
    elements.iter().fold(P::zero(), |acc, key| acc + key)
}

/// N messages get signed by N committees of varying sizes
/// N aggregate signatures are returned
pub fn sign_batch<E: Pairing>(
    secret_keys: &[Vec<E::ScalarField>],
    messages: &[E::G1],
) -> Vec<E::G1> {
    secret_keys
        .iter()
        .zip(messages)
        .map(|(secret_keys, message)| {
            let (_, asig) = sign::<E>(*message, &secret_keys);
            asig
        })
        .collect::<Vec<_>>()
}

// signs a message with a vector of secret keys and returns the list of sigs + the agg sig
pub fn sign<E: Pairing>(
    message_hash: E::G1,
    secret_keys: &[E::ScalarField],
) -> (Vec<E::G1>, E::G1) {
    let sigs = secret_keys
        .iter()
        .map(|key| message_hash.mul_bigint(key.into_bigint()))
        .collect::<Vec<_>>();
    let asig = sigs
        .iter()
        .fold(E::G1::zero(), |acc, sig| acc + sig);
    (sigs, asig)
}
