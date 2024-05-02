/// Implementation of the `MapToGroup` algorithm (Paragraph
/// 3.3) of [this paper](https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf)
///
/// This method involves hashing the data along with a counter. If the hash can then be interpreted
/// as an elliptic curve point, it returns. If not, it increments the counter and tries again.
///
/// **This algorithm is not constant time**.
///
/// # Examples
///
/// Hashing the data requires instantiating a hasher, importing the `HashToCurve` trait
/// and calling the `hash` function
///
/// ```rust
/// use bls_crypto::{OUT_DOMAIN, hash_to_curve::{HashToCurve, try_and_increment::DIRECT_HASH_TO_G1}};
///
/// // Instantiate the lazily evaluated hasher to BLS 12-377.
/// let hasher = &*DIRECT_HASH_TO_G1;
///
/// // Hash the data. The domain must be exactly 8 bytes.
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// ```
///
/// Doing this manually requires importing the curves and instantiating the hashers as follows:
///
/// ```rust
/// use ark_bls12_377::g1::Config;
/// use bls_crypto::{
///     OUT_DOMAIN,
///     hashers::composite::{CompositeHasher, BHCRH}, // We'll use the Composite Hasher
///     hash_to_curve::{HashToCurve, try_and_increment::TryAndIncrement},
/// };
///
/// let composite_hasher = CompositeHasher::<BHCRH>::new().unwrap();
/// let hasher = TryAndIncrement::<_, Config>::new(&composite_hasher);
///
/// // hash the data as before
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
///
/// // You can also use the underlying struct's method to get the counter
/// let (hash, counter) = hasher.hash_with_attempt(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// assert_eq!(counter, 3);
/// ```
pub mod try_and_increment;
pub mod try_and_increment_cip22;
use crate::BLSError;
use ark_ec::{
    short_weierstrass::Affine,
    models::short_weierstrass::SWCurveConfig,
};
use ark_ff::{Field, Zero};
use ark_serialize::Flags;

/// Trait for hashing arbitrary data to a group element on an elliptic curve
pub trait HashToCurve {
    /// The type of the curve being used.
    type Output;

    /// Given a domain separator, a message and potentially some extra data, produces
    /// a hash of them which is a curve point.
    fn hash(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<Self::Output, BLSError>;
}

/// Given `n` bytes, it returns the value rounded to the nearest multiple of 256 bits (in bytes)
/// e.g. 1. given 48 = 384 bits, it will return 64 bytes (= 512 bits)
///      2. given 96 = 768 bits, it will return 96 bytes (no rounding needed since 768 is already a
///         multiple of 256)
pub fn hash_length(n: usize) -> usize {
    let bits = (n * 8) as f64 / 256.0;
    let rounded_bits = bits.ceil() * 256.0;
    rounded_bits as usize / 8
}

/// The bool signifies whether this is also an infinity point representation
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum YSignFlags {
    PositiveY(bool),
    NegativeY(bool),
}

impl YSignFlags {
    #[inline]
    pub fn from_y_sign(is_positive: bool) -> Self {
        if is_positive {
            YSignFlags::PositiveY(false)
        } else {
            YSignFlags::NegativeY(false)
        }
    }

    #[inline]
    pub fn is_infinity(&self) -> bool {
        matches!(
            self,
            YSignFlags::PositiveY(true) | YSignFlags::NegativeY(true)
        )
    }

    #[inline]
    pub fn is_positive(&self) -> Option<bool> {
        match self {
            YSignFlags::PositiveY(_) => Some(true),
            YSignFlags::NegativeY(_) => Some(false),
        }
    }
}

impl Default for YSignFlags {
    #[inline]
    fn default() -> Self {
        // NegativeY doesn't change the serialization
        YSignFlags::NegativeY(false)
    }
}

impl Flags for YSignFlags {
    const BIT_SIZE: usize = 2;

    #[inline]
    fn u8_bitmask(&self) -> u8 {
        let mut mask = 0;
        match self {
            YSignFlags::PositiveY(true) | YSignFlags::NegativeY(true) => mask |= 1 << 6,
            _ => (),
        }
        match self {
            YSignFlags::PositiveY(false) | YSignFlags::PositiveY(true) => mask |= 1 << 7,
            _ => (),
        }
        mask
    }

    #[inline]
    fn from_u8(value: u8) -> Option<Self> {
        let x_sign = (value >> 7) & 1 == 1;
        let is_infinity = (value >> 6) & 1 == 1;
        match x_sign {
            true => Some(YSignFlags::PositiveY(is_infinity)),
            false => Some(YSignFlags::NegativeY(is_infinity)),
        }
    }
}

pub fn from_random_bytes<P: SWCurveConfig>(bytes: &[u8]) -> Option<Affine<P>> {
    P::BaseField::from_random_bytes_with_flags::<YSignFlags>(bytes).and_then(|(x, flags)| {
        if x.is_zero() && flags.is_infinity() {
            Some(Affine::<P>::identity())
        } else if let Some(y_is_positve) = flags.is_positive() {
            Affine::<P>::get_point_from_x_unchecked(x, y_is_positve) // Unwrap is safe because it's not zero.
        } else {
            None
        }
    })
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hashers::{
        composite::{CompositeHasher, BHCRH},
        DirectHasher, Hasher,
    };
    use ark_bls12_377::Config;
    use ark_ec::{
        bls12::Bls12Config,
        models::short_weierstrass::SWCurveConfig,
        short_weierstrass::Projective, CurveGroup,
    };
    use ark_serialize::CanonicalSerialize;
    use rand::{Rng, RngCore};

    #[test]
    fn test_hash_length() {
        assert_eq!(hash_length(48), 64);
        assert_eq!(hash_length(96), 96);
    }

    #[test]
    fn hash_to_curve_direct_g1() {
        let h = DirectHasher;
        hash_to_curve_test::<<Config as Bls12Config>::G1Config, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g1() {
        let h = CompositeHasher::<BHCRH>::new().unwrap();
        hash_to_curve_test::<<Config as Bls12Config>::G1Config, _>(h)
    }

    #[test]
    fn hash_to_curve_direct_g2() {
        let h = DirectHasher;
        hash_to_curve_test::<<Config as Bls12Config>::G2Config, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g2() {
        let h = CompositeHasher::<BHCRH>::new().unwrap();
        hash_to_curve_test::<<Config as Bls12Config>::G2Config, _>(h)
    }

    fn hash_to_curve_test<P: SWCurveConfig, X: Hasher<Error = BLSError>>(h: X) {
        let hasher = TryAndIncrement::<X, P>::new(&h);
        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let _ = hasher.hash(&b"domain"[..], &input, &b"extra"[..]).unwrap();
        }
    }

    pub fn generate_test_data<R: Rng>(rng: &mut R) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let msg_size: u8 = rng.gen();
        let mut msg: Vec<u8> = vec![0; msg_size as usize];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }

        let mut domain = vec![0u8; 8];
        for i in domain.iter_mut() {
            *i = rng.gen();
        }

        let extra_data_size: u8 = rng.gen();
        let mut extra_data: Vec<u8> = vec![0; extra_data_size as usize];
        for i in extra_data.iter_mut() {
            *i = rng.gen();
        }

        (domain, msg, extra_data)
    }

    pub fn test_hash_to_group<P: SWCurveConfig, H: HashToCurve<Output = Projective<P>>>(
        hasher: &H,
        rng: &mut impl Rng,
        expected_hashes: Vec<Vec<u8>>,
    ) {
        for expected_hash in expected_hashes.into_iter() {
            let (domain, msg, extra_data) = generate_test_data(rng);
            let g = hasher.hash(&domain, &msg, &extra_data).unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize_compressed(&mut bytes).unwrap();
            assert_eq!(expected_hash, bytes);
        }
    }

    #[allow(dead_code)]
    pub fn test_hash_to_group_cip22<
        P: SWCurveConfig,
        H: HashToCurve<Output = Projective<P>>,
    >(
        hasher: &H,
        rng: &mut impl Rng,
        expected_hashes: Vec<Vec<u8>>,
    ) {
        for expected_hash in expected_hashes.into_iter() {
            let (domain, msg, extra_data) = generate_test_data(rng);
            let g = hasher.hash(&domain, &msg, &extra_data).unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize_compressed(&mut bytes).unwrap();
            assert_eq!(expected_hash, bytes);
        }
    }
}

#[cfg(all(test, feature = "compat"))]
mod compat_tests {
    #![allow(clippy::op_ref)]
    use super::*;
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hash_to_curve::try_and_increment_cip22::TryAndIncrementCIP22;
    use crate::hashers::{composite::COMPOSITE_HASHER, Hasher};
    use ark_bls12_377::Config;
    use ark_ec::{
        AffineRepr,
        bls12::{Bls12Config, G1Affine, G1Projective},
        models::short_weierstrass::SWCurveConfig,
        CurveConfig, CurveGroup,
    };
    use ark_ff::{Field, PrimeField};
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use ark_std::{end_timer, start_timer};
    use byteorder::WriteBytesExt;
    use log::trace;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    const RNG_SEED: [u8; 16] = [
        0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06,
        0x54,
    ];

    pub fn get_point_from_x_g1<P: Bls12Config>(
        x: <P::G1Config as CurveConfig>::BaseField,
        greatest: bool,
    ) -> Option<G1Affine<P>> {
        // Compute x^3 + ax + b
        let x3b = <P::G1Config as SWCurveConfig>::add_b(
            (x.square() * &x) + &<P::G1Config as SWCurveConfig>::mul_by_a(x),
        );

        x3b.sqrt().map(|y| {
            let negy = -y;

            let y = if (y < negy) ^ greatest { y } else { negy };
            G1Affine::<P>::new(x, y)
        })
    }

    fn compat_hasher<P: Bls12Config>(
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(G1Projective<P>, usize), BLSError> {
        const NUM_TRIES: usize = 256;
        const EXPECTED_TOTAL_BITS: usize = 512;
        const LAST_BYTE_MASK: u8 = 1;
        const GREATEST_MASK: u8 = 2;

        let hasher = &*COMPOSITE_HASHER;

        let fp_bits =
            //(((<P::Fp as PrimeField>::MODULUS_BITS as f64) / 8.0).ceil() as usize) * 8;
            (((P::Fp::MODULUS_BIT_SIZE as f64) / 8.0).ceil() as usize) * 8;
        let num_bits = fp_bits;
        let num_bytes = num_bits / 8;

        //round up to a multiple of 8
        let hash_fp_bits =
            //(((<P::Fp as PrimeField>::Config::MODULUS_BITS as f64) / 256.0).ceil() as usize) * 256;
            (((P::Fp::MODULUS_BIT_SIZE as f64) / 256.0).ceil() as usize) * 256;
        let hash_num_bits = hash_fp_bits;
        assert_eq!(hash_num_bits, EXPECTED_TOTAL_BITS);
        let hash_num_bytes = hash_num_bits / 8;
        let mut counter: [u8; 1] = [0; 1];
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let hash = hasher.hash(
                domain,
                &[&counter, extra_data, &message].concat(),
                hash_num_bytes,
            )?;
            let (possible_x, greatest) = {
                //zero out the last byte except the first bit, to get to a total of 377 bits
                let mut possible_x_bytes = hash[..num_bytes].to_vec();
                let possible_x_bytes_len = possible_x_bytes.len();
                let greatest =
                    (possible_x_bytes[possible_x_bytes_len - 1] & GREATEST_MASK) == GREATEST_MASK;
                possible_x_bytes[possible_x_bytes_len - 1] &= LAST_BYTE_MASK;
                //let possible_x = P::Fp::read(possible_x_bytes.as_slice());
                let possible_x = P::Fp::deserialize_compressed(possible_x_bytes.as_slice());
                if possible_x.is_err() {
                    continue;
                }

                (possible_x.unwrap(), greatest)
            };
            match get_point_from_x_g1::<P>(possible_x, greatest) {
                None => continue,
                Some(x) => {
                    trace!(
                        "succeeded hashing \"{}\" to G1 in {} tries",
                        hex::encode(message),
                        c
                    );
                    end_timer!(hash_loop_time);
                    let scaled = x.mul_by_cofactor();
                    if scaled.is_zero() {
                        continue;
                    }
                    return Ok((scaled.into(), c));
                }
            }
        }
        Err(BLSError::HashToCurveError)
    }

    fn generate_compat_expected_hashes(num_expected_hashes: usize) -> Vec<Vec<u8>> {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);

        let mut expected_hashes = vec![];
        for _ in 0..num_expected_hashes {
            let (domain, msg, extra_data) = super::test::generate_test_data(&mut rng);
            let expected_hash_point = compat_hasher::<Config>(&domain, &msg, &extra_data)
                .unwrap()
                .0;

            let mut expected_hash = vec![];
            expected_hash_point
                .into_affine()
                .serialize_compressed(&mut expected_hash)
                .unwrap();
            expected_hashes.push(expected_hash);
        }

        expected_hashes
    }

    #[test]
    fn test_hash_to_curve_g1() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = generate_compat_expected_hashes(1000);

        let hasher = TryAndIncrement::<_, <Config as Bls12Config>::G1Config>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher, &mut rng, expected_hashes)
    }

    /// Tests against hashes that were generated from commit 67aa80c1ce5ac5a4e2fe3377ba8b869e982a4f96,
    /// the version deployed before the Donut hardfork.
    #[test]
    fn test_hash_to_curve_g1_test_vectors() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = vec![
            "0ea229634d6ef1d42b501c72a04006a6de9478f2c0175e72a4ad84e324ed4307e2ffe7242a5d404e2b6ee325254a8f80",
            "725fc0ccc65dd532b377c2ad340c6108955a702fbaef448c421bbd4eca1c48ccd059173c9c4a273df6d5ec8904dc7e00",
            "ef37364053ba0bfadc41617826f1d7e90907964b6cf57a230d838f1b8191e9b07811eb339ba58a5af4dd2c3c856dfc80",
            "63fc300ae5371df42d0b18bec2c29ea8c800b15d45117f6082e9e15a2e3d847b0bc2ae336fe039cf0fca07d1e928f580",
            "d29142ea05dc3063095543efc0d7a690aba054d06dc93f31c2ab4fb42228532ab0e36d2f4b88fb28318fcad438a08c81",
            "bba4a6cc3fee1b0af65c436609f931a523eadc59dec3707964a87fda50ba593abdd864e3911e05d9ef73b6452d9a5900",
            "2dfa15095a8a8c93bd98b3287eec3a2d73cefe291bac820b929c1512273d51469ffead1c49d9929ad3a32e07bb614801",
            "83810764b46b08ae73e6198c42a7d456cb86e29f2294410fddf744d605834ccebce3c5951376228776a6487cc2575e80",
            "980d9ea537fe6ba2018cb55f2f371ac561e154eefd5da93dd37a078ef58f474e902e43996a798079b612c89c0c784f00",
            "66c6dd47e7ef88abb058a39bc9c41d9c15705536866c51b8171d0602b26245627410af9435e41dd28eceb6fa3db4a601",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        let hasher = TryAndIncrement::<_, <Config as Bls12Config>::G1Config>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher, &mut rng, expected_hashes)
    }

    /// Tests expected hashes after the Donut hardfork.
    #[test]
    fn test_hash_to_curve_g1_test_vectors_cip22() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = vec![
            "b4d56136e2c938c5a63efdd63f793df77d3dbfb65a582d2f87629c5ff1b06554330b2b34061e8d912ed063675c4f6500",
            "c492b327ae2476d337ae1c1d983fcaef280ab01a09aeff69c10f6b3ff6b16ba15ca87271f7dd2ccdce55728d2e7e1781",
            "04563b847f2662ebfced59fa4eea1adb2355fb8b797fe47b1d7292664f6700094f3e20bf09c195d981d0814c60518f81",
            "3cd5ba855353b7e23d66137a9b8a9233cff5767bca66060b0355a90d27307f1daba5983381e88614f644848078e68b80",
            "531b3cbb1309f337b1ae56dc2a970bc0c1a3aa0c2a33cf9dbe48a6ddf15395ae11d2d2ee74f8e3e2740d700b13469e81",
            "ab5dd5bdfc430cf0520f5eabea82a20ecfd743e772e8979382347dad827a98584c7bb5ff280647a707ad545de48a0a01",
            "f918b07224ef71ecc5f84b910e968b68c8355192cb0c2e351446f8919c2d3bd29fd1ed3baff7d7f2527125ac4e342001",
            "2cd59307431529e08eb0121a7037fb89d0b8060b00a87236652cc6f66daf9ed1b0d8be98c6fcfc5e540f002b6e6f0c80",
            "4bc62eb8baac9e275df526d409915c5af5e819e8468db21cbf08a595cc919659821640777845897f3201c5912c3b5e81",
            "74b9a0c52380c01a0011a99b5ab81a32d226a32e91a1bdf98348ddcd65f8ee1455ea25d053a46b1006bc12034e479580",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        let hasher = TryAndIncrementCIP22::<_, <Config as Bls12Config>::G1Config>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group_cip22(&hasher, &mut rng, expected_hashes)
    }
}

#[cfg(all(test, not(feature = "compat")))]
mod non_compat_tests {
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1;
    use crate::hashers::composite::COMPOSITE_HASHER;
    use ark_bls12_377::Config;
    use ark_ec::models::bls12::Bls12Config;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_hash_to_curve_g1() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let expected_hashes = vec![
            "a7e17c99126acf78536e64fffe88e1032d834b483584fe5757b1deafa493c97a132572c7825ca4f617f6bcef93b93980",
            "21e328cfedb263f8c815131cc42f0357ab0ba903d855a11de6e7bcd7e61375a818d1b093bcf9fce224536714efad5c80",
            "fcc8bc80a528b32762ad3b3f72d40b069083b833ad4b6e135040414e2634657e1cf1ec070235ba1425f350df8c585d81",
            "9b99c3cee5f7c486f962b1391b4108cd464b05bc24b2e488e9aa04f848467315ed70d83d3abfa63150564ad0c549c480",
            "9df1b6ba0e8d2a42866d78a90b5fdf56cea80b2ec588774ceb7cc4f414d7b49ca55f81169535a4c3a4c7c39148af3e81",
            "f365f54ba587b863d5d5ecef6a2932f4eb225c0cd2c4e727c3fa5b1a30fbcfa8e2a2e0d7a68476ee10d90b3b8846b400",
            "1cb6008bca08b85df6f9a87ca141533145ed88abb0bbace96f4b1ca42d15ba888d4948c21548207a0abd22d5c234d180",
            "1c529f631ddaffde7cbe62bbb8d48cc8dbe59b8548dc69b156d0568c7aae898d8051a3ef31ad17c60a85ad82203a9b81",
            "de54da7a8813a30c267d662d428e28520a159b51a9e226ceb663d460d9065b66a9586cb8b3a9ba0ef0e27c626f20dc00",
            "b68e1db4b648801676a79ac199eaf003757bf2a96cdbb804bfefe0484afdc0cc299d50d660221d1de374e92c44291200",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        super::test::test_hash_to_group(&*COMPOSITE_HASH_TO_G1, &mut rng, expected_hashes)
    }

    #[test]
    fn test_hash_to_curve_g2() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);

        let expected_hashes = vec![
            "9c76f364d39ce5747f475088f459a11cb32d39033245c039104dfe88a71047ea078d6f15ed9fc64539410167ffe1800020ec8138f9f8b03c675f4ff33d621c76f41784bf994aa8cf53b2e11961f4c77caaab6681dc29bb2f90e14ecd05a5f500",
            "ffb0b3275d2188bee71e0f626b2bc422ee4ce23692e6d329e085ec74413410cedd354d9571e9de149a286dc48ba83d012ad171f4280acbc3c3d946086fe2a0c9f56d271f0c9bb13e78774cb6244b2e84c24116d8ff76311cf2f76db741ab7200",
            "59af04e977ac914d077d1488639b90dfb5b723bf8516157b9ebc8b584a0f507f20c3b758284fe3c91bc93df86244a9017e06d3f930163642a3c85965aac19ea8a18b0bd08d7bd44e99e343acfe24f98ff6f2401432187a07dd97320f73fa7300",
            "5a1610b23a5a5be0ee255fcc766d0f6d384b3d51b4364d5587102e8905b7233fd5b274973451cb56ca69a945832c1000d0b2744278ffdf5cd33f11bcc4ecc5759b0d5b90f54d454909d73f49c1226e428acfb25995d83ba44826adb8158f1281",
            "d82143317b1a5b90e633a4a208129edd526f9137b9c47221c827aa6317be94cb1bc006ba8afce455be5bf51ee6f184011c535bee7ab3e954731a6a96edb3ea9a6c1d02916817147355a2406757023e27fb2f58fec61f37ddb6125c797bfa5780",
            "48bfa38e3c4a6a7de2a5c4b8c57671c7b1bfb2c225d89786cbcd065b2b7844b910b5cbfc334eff1956bc7245127d970154c38985b770d11994c20072a053f0f720028615753c9c42372580782dd49653b4c0fee2a8e88de1697678a505ffc980",
            "ddc0e29af05439bcb5157802afd9a112394fb190e0dda7b5c7852693da3b3403c911751c24b28af1d05e76326d1117007f14cc765d5c3e73adbbcf7a1d59cf58186d7b576d3e58ccafd2ea527bf31651f4b0d0ba44ee5b54ec6c86c2e1bf1b01",
            "ddc865ffe876a3e19c1401f784eaf88b50c4f04cfaadf7690173a33385cb5af899189478cdbc1abbe8d8a89768e411003a5000c7866f3a5648d7944e97bcbff87f89cd26045dc15494036ce4ce799de532438576bfe32389269a6e3a4ce98201",
            "8de37ce0a7105c14880d9201f2ac1c724e031904f9c88614fa414ad57f00c89e596fadb4f5151c84f4ea04d576931c008fc43faec79d0e300d2192a8e376b25f920f14f467f050e4f2869012fce196e9af5f2041889031e2bbe81c6b3d344480",
            "10341299c41179084a0bfee8b65bac0f48af827daad4f01d3e9925a3b0335736c5d13f44765fecec45941781da5a1000d0bb26a4faa4dc8060b0b2dd0cb6acce7dd10bd081dac7f263b97aec89d6434a55b31a65b3e25f59c40ea92887b03180",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();
        let hasher_g2 = TryAndIncrement::<_, <Config as Bls12Config>::G2Config>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher_g2, &mut rng, expected_hashes)
    }
}
