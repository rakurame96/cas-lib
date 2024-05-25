
use std::sync::mpsc;

use aes_gcm::AeadCore;
use ascon_aead::{aead::{generic_array::GenericArray, Aead, KeyInit, OsRng}, Ascon128};

use super::cas_ascon_aead::{CASAsconAead};
pub struct AsconAead;

impl CASAsconAead for AsconAead {
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let ciphertext = cipher.encrypt(&nonce_generic_array, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn encrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = <AsconAead as CASAsconAead>::encrypt(key, nonce, plaintext);
            sender.send(ciphertext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let plaintext = cipher.decrypt(&nonce_generic_array, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn decrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = <AsconAead as CASAsconAead>::decrypt(key, nonce, ciphertext);
            sender.send(plaintext);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn generate_key() -> Vec<u8> {
        return Ascon128::generate_key(&mut OsRng).to_vec();
    }

    fn generate_key_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = <AsconAead as CASAsconAead>::generate_key();
            sender.send(key);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn generate_nonce() -> Vec<u8> {
        return Ascon128::generate_nonce(&mut OsRng).to_vec();
    }

    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = <AsconAead as CASAsconAead>::generate_nonce();
            sender.send(key);
        });
        let result = receiver.recv().unwrap();
        result
    }
}