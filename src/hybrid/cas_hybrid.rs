use hpke::{aead::AesGcm256, kdf::HkdfSha512, kem::X25519HkdfSha256, Kem as KemTrait,};

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha512;

pub trait CASHybrid {
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>);
    fn generate_info_str() -> Vec<u8>;
}