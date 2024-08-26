
use hpke::{aead::{AeadTag, AesGcm256}, kem::{self, X25519HkdfSha256}, Kem};
pub struct X25519Aes256Sha512EncryptResult {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub encapped_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub tag: Vec<u8>
}