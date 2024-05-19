use super::types::RSAKeyPairResult;

pub trait CASRSAEncryption {
    fn generate_rsa_keys(key_size: usize) -> RSAKeyPairResult;
    fn generate_rsa_keys_threadpool(key_size: usize) -> RSAKeyPairResult;
    fn encrypt_plaintext(public_key: String, plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_plaintext_threadpool(public_key: String, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(private_key: String, ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext_threadpool(private_key: String, ciphertext: Vec<u8>) -> Vec<u8>;
    fn sign(private_key: String, hash: Vec<u8>) -> Vec<u8>;
    fn sign_threadpool(private_key: String, hash: Vec<u8>) -> Vec<u8>;
    fn verify(public_key: String, hash: Vec<u8>, signed_text: Vec<u8>) -> bool;
    fn verify_threadpool(public_key: String, hash: Vec<u8>, signed_text: Vec<u8>) -> bool;
}
