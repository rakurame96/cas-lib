use aes_gcm::Key;

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};

use super::cas_symmetric_encryption::{AesKeyFromX25519SharedSecret, CASAESEncryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAESEncryption for CASAES256 {
    fn generate_key() -> Vec<u8> {
        return Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }
    
    fn generate_nonce() -> Vec<u8> {
        let rng = &mut OsRng;
        let mut random_bytes = Vec::with_capacity(12);
        random_bytes.resize(12, 0);
        rng.fill_bytes(&mut random_bytes);
        random_bytes
    }
    
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
        result
    }
}

impl CASAESEncryption for CASAES128 {
    fn generate_key() -> Vec<u8> {
        return Aes128Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let mut aes_key: [u8; 16] = Default::default();
        aes_key.copy_from_slice(&shared_secret[..16]);
        let aes_key_slice = Key::<Aes128Gcm>::from_slice(&aes_key);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key_slice.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }
    
    fn generate_nonce() -> Vec<u8> {
        let rng = &mut OsRng;
        let mut random_bytes = Vec::with_capacity(12);
        random_bytes.resize(12, 0);
        rng.fill_bytes(&mut random_bytes);
        random_bytes
    }
    
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes128Gcm>::from_slice(&key_slice).to_vec();
        result
    }
}