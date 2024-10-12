use hpke::{aead::AesGcm256, kdf::HkdfSha512, kem::X25519HkdfSha256, Kem as KemTrait, Serializable};
use rand::{rngs::StdRng, SeedableRng};

use super::cas_hybrid::CASHybrid;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha512;

pub struct CASHPKE;

impl CASHybrid for CASHPKE {
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = Kem::gen_keypair(&mut csprng);
        (private_key.to_bytes().to_vec(), public_key.to_bytes().to_vec())
    }
}