//! Utilities for hashing using a fixed-length CRHScheme. Consider using the re-exported
//! COMPOSITE_HASHER which is already instantiated with the Bowe Hopwood Pedersen CRH and
//! Blake2x as the XOF
use crate::{hashers::DirectHasher, BLSError, Hasher};

use ark_crypto_primitives::crh::{bowe_hopwood, pedersen, CRHScheme};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{Rng, SeedableRng};
use ark_ec::CurveConfig;
use ark_ed_on_bw6_761::EdwardsConfig;
use blake2s_simd::Params;
use once_cell::sync::Lazy;
use rand_chacha::ChaChaRng;

// Fix to get around leaking a private type in a public interface
mod window {
    use super::pedersen;

    /// The window which will be used with the Fixed Length CRH
    #[derive(Clone)]
    pub struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 93;
        const NUM_WINDOWS: usize = 560;
    }
}

/// Bowe Hopwood Pedersen CRH instantiated over Edwards BW6_761 with `WINDOW_SIZE = 93` and
/// `NUM_WINDOWS = 560`
#[allow(clippy::upper_case_acronyms)]
pub type BHCRH = bowe_hopwood::CRH::<EdwardsConfig, window::Window>;

/// Lazily evaluated composite hasher instantiated over the
/// Bowe-Hopwood-Pedersen CRH.
pub static COMPOSITE_HASHER: Lazy<CompositeHasher<BHCRH>> =
    Lazy::new(|| CompositeHasher::<BHCRH>::new().unwrap());

/// Uses the Bowe-Hopwood-Pedersen hash (instantiated with a prng) as a CRH and Blake2x as the XOF.
/// The CRH does _not_ use the domain or the output bytes.
#[derive(Clone, Debug)]
pub struct CompositeHasher<H: CRHScheme> {
    parameters: H::Parameters,
}

impl<H: CRHScheme> CompositeHasher<H> {
    /// Initializes the CRH and returns a new hasher
    pub fn new() -> Result<CompositeHasher<H>, BLSError> {
        Ok(CompositeHasher {
            parameters: Self::setup_crh()?,
        })
    }

    fn prng() -> impl Rng {
        let hash_result = Params::new()
            .hash_length(32)
            .personal(b"UL_prngs") // personalization
            .to_state()
            .update(b"ULTRALIGHT PRNG SEED") // message
            .finalize()
            .as_ref()
            .to_vec();
        let mut seed = [0; 32];
        seed.copy_from_slice(&hash_result[..32]);
        ChaChaRng::from_seed(seed)
    }

    /// Instantiates the CRH's parameters
    pub fn setup_crh() -> Result<H::Parameters, BLSError> {
        let mut rng = Self::prng();
        Ok(H::setup::<_>(&mut rng)?)
    }
}

impl<H: CRHScheme<Input = [u8], Output = <EdwardsConfig as CurveConfig>::BaseField>> Hasher for CompositeHasher<H> {
    type Error = BLSError;

    // TODO: Should we improve the trait design somehow? Seems like there's a bad abstraction
    // here if we do not use the 2 params
    fn crh(&self, _: &[u8], message: &[u8], _: usize) -> Result<Vec<u8>, Self::Error> {
        let x = H::evaluate(&self.parameters, message.to_vec().as_slice())?;
        let mut res = vec![];
        x.serialize_compressed(&mut res)?;

        Ok(res)
    }

    fn xof(
        &self,
        domain: &[u8],
        hashed_message: &[u8],
        xof_digest_length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        DirectHasher.xof(domain, hashed_message, xof_digest_length)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hashers::Hasher;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::any::type_name_of_val;

    #[test]
    fn test_crh_empty() {
        let msg: Vec<u8> = vec![];
        let hasher = &*COMPOSITE_HASHER;
        println!("{:?}", type_name_of_val(&hasher));
        let result = hasher.crh(&[], &msg, 96).unwrap();
        assert_eq!(hex::encode(result), "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }

    #[test]
    fn test_crh_random() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&[], &msg, 96).unwrap();
        assert_eq!(hex::encode(result), "b1de8d25e85f48cd8412b0225c2ee592ac181da2e8dfdb8bf1c446a193f8b62c4f35865c37689ac1b201ce8211b2d100")
    }

    #[test]
    fn test_xof_random_768() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x2d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&[], &msg, 96).unwrap();
        let xof_result = hasher.xof(b"ULforxof", &result, 768).unwrap();
        assert_eq!(hex::encode(xof_result), "4fbf7658baf19e5e75fc8ab3a638dc04fa5a806ea30549cc45d5e4112ab326bdfb8e0579b79bbc18a51f5e605a71b2edcdea13f551672a1df7121ae3e68004b65f44fc0dd0f24177b928cba65c3d9665372acadb3d5160237dd08fd4e48a911ec4cbfdbd77e0d9927925311d4832543a37c85f131a115f106276aae0563e0f4597d142220d8a3eb502db618babb59000ad1b6cbf24c4ee468dcaa736c7d96cbe21fbb0f03b20ae64e2a913db6125fb1ba0651a9c1865c8434b7155e192052f07e02eab3f82a9856906625438ca8db7b7f1539b6d17bd0cb0988d32ec4a8b9b203a9b29fc2e5d844b735b9247e4092c216c437ab4e718df840e73be59d94b8f7e7c4c063aa8a3d8270fc55e57eb785b89e81bebdc338cb233f0fab7532aa12b4e11a6f6afc0db946608298945a9c140439901b3b3f4ff8a1dbe9d2758d442ec3c25e483b638c0ad219147e1cea9b48e2249d638f923fce808b2e1bfefaa8b684c94ffdd32bda64f7a4286758e9c01bfbd7414cc44f63b74185fb2a1b26b72e6251b8a964e9efeb796e43e76627f800fe44e903e2187771d262817d8ae5ffd4de9e36ec31e105651b4f0b862c5843c309e0d53d449dcf37f1bce1b394b0bc22158dc8df3a31cf7ff1eabd2af46e7a7c28f05cfe799754b34e26c0056aa624cb33cfb57f5c554c4980958bf1c44a2dd6d5caca9809684b796cf1cb52095307760dac0d0e2c40a17e0d8e55a59a0fcd6c9ec7102eeb94992e95c6fbe6a828d15b4d115bdfeb511bfad0671c30b2e0a016db33ca590aab5e79df6c8adb4dd4be7c298d8cd431afbef1e2ef64a81c79919949b23f56d1d8cd0178835f5eaec395803b026e91c060345276baacae5c90884b971e4a3534c6cf5c79c1c657ab79f8aa1ba3b78d38cbb05717218155939547947350ae3ecd232b603b806389203b4cde25644411f8a4ce104f3e968d78b0086654e5d23e8094dbef44ef77fa6c48bd46b540164facf2527b31235a9b1e63bac0d7eeffc48a657576392243d082b8ee3da0eeb15427eff8f2228e2e2b1b801ade788bea880d8950e1abf019520b57534caa0");
    }

    #[test]
    fn test_xof_random_769() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x0d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&[], &msg, 96).unwrap();
        let xof_result = hasher.xof(b"ULforxof", &result, 769).unwrap();
        assert_eq!(hex::encode(xof_result), "ca1a937addbd81550bfcfad25c0bd96310c50583a377cbd69268da1e56c540704bcf798b06464072a468e6634cb31b366b1ae01875608a576fdb56cc12b2d235202ea63c907c2fc82d40c18414d64e6b215eedef6ec58dde0cda6abb90cd1009388f3b593697a3412488d3bd642f82cb73dc9f132125f48be5302e13865bff92926f2b070311780d2a3a4c03a2c6205266239d60e40ce903605c93577d50875934ddc3d977adeccd6ee0ee7ba2889fa699eb3952d3ad95fe2ebed7a2577827dd1905232597e29f27f32be8c5bb910452e8c6be4682f77e1138c0c0e5a2b076d8a9a1b344ba28267fd7762b2746605779de624549189766867bf50d103824f029ddd82daeaed5f6fe38a309599e4dc41534848b29f7f14e57e01f551acb5d6edd3a094cdceaa3a1d051b1c1b2196819d451de4c693cc88f5784a61717042669855b06efc873620ca13970363e1eceb554b52f2b5456505b4e25d6e4f1f24d7614d07c967ab2a1c1f3572bfa66d00bdddbd593723995bade52859fc289f62e3f58ffd7e1a3549e7f406b048cef0885de7d4c91a2003c17b2cab56b254e5345f68afd14db085ae2d3789917ea6095b824573fa93e732b1cecd4a41b66b4b7431994cc832dbc344e267d5d2206e756be7e5ce6f22b90c9096a66580bd87ee267940262ccc4d0e762e93591e38eece2a3cf79e5163ebdc35196cba51297cc4a0976e8f5141013ad955ab8f761a8df1d9ce433f24c26bbe9d18f34231bd4f9f2b941ce1d76fbfd465472f8d8625e39222e1f157e83a70d4873677d50ffd3cf4a36eaf824f7670338f11b86147b12ffb304e772036e269432648bb0f2af5cac55d135cadf4eff4c7345fe7589df5564a02a8bf6a742f2260c11be0fac6ec9d749b7a46fa5356a079680eed20fc5fdd5fdbb931775eb039a0035877cefa712de0e72b20b5c8cb7f0f89bf0eef6fd1b61b5f5ca60275af99e2c5463d44f18a5846fc8bfcc0e16decca54026880849d55fc0c7adb257c062e6168bd44f2e774a6efbfdcea60852e50ca6c126ed113b0d778726e562255c6c7534a6db47df6d57f9cd9140d201")
    }

    #[test]
    fn test_xof_random_96() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x2d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&[], &msg, 96).unwrap();
        let xof_result = hasher.xof(b"ULforxof", &result, 96).unwrap();
        assert_eq!(hex::encode(xof_result), "ad0793967c67e846f52488467426ecb1f2486130f8612eebc765c52a289053a467ba7ee8eda9daeabd39d5bba7675ed5545ad9b45f0f4d62f200a16e9ff6e9450720f352a5845178ba469bd45c84191f3265045593be58c5dda04ebf868efec4")
    }

    #[test]
    fn test_hash_random() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x2d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 9820 * 4 / 8];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.hash(b"ULforxof", &msg, 96).unwrap();
        assert_eq!(hex::encode(result), "c5b5d498a4fec2cc47e34c3d456b26e8a9bb33057a3d9cbe492c3b4425d758c0a680ef3350ee7233359fe362bc05f52a74caf23457a4481710eb05319365fd79900ff703940ab48ee8584d317efb15f70320561e6c38b1a7418d333839ba5eb9")
    }

    #[test]
    #[should_panic]
    fn test_invalid_message() {
        let hasher = &*COMPOSITE_HASHER;
        let mut rng = XorShiftRng::from_seed([
            0x2d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let mut msg: Vec<u8> = vec![0; 1_000_000];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let _result = hasher.hash(b"ULforxof", &msg, 96).unwrap();
    }
}
