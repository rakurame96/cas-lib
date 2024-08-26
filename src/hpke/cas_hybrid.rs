use hpke::{kem::{self, X25519HkdfSha256}, Kem};

use super::types::X25519Aes256Sha512EncryptResult;

pub trait CASHybrid {
    fn x25519_keypair() -> (<X25519HkdfSha256 as Kem>::PrivateKey, <X25519HkdfSha256 as Kem>::PublicKey);
    fn x25519_aes256_sha512_encrypt(info: Vec<u8>, to_encrypt: Vec<u8>, associated_data: Vec<u8>) -> X25519Aes256Sha512EncryptResult;
    fn x25519_aes256_sha512_decrypt(encapped_key: Vec<u8>, to_decrypt: Vec<u8>, private_key: Vec<u8>, tag: Vec<u8>, info: Vec<u8>, associated_data: Vec<u8>) -> Vec<u8>;
}