extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Signer;
use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use rand_07::rngs::OsRng;

use super::cas_ed25519::Ed25519ByteSignature;

pub fn get_ed25519_key_pair() -> Vec<u8> {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let keypair_vec = keypair.to_bytes().to_vec();
    keypair_vec
}

pub fn ed25519_sign_with_key_pair(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> Ed25519ByteSignature {
    let keypair = Keypair::from_bytes(&key_pair).unwrap();
    let signature = keypair.sign(&message_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();
    let public_keypair_bytes = keypair.public.to_bytes().to_vec();
    let result = Ed25519ByteSignature {
        public_key: public_keypair_bytes,
        signature: signature_bytes
    };
    result
}

pub fn ed25519_verify_with_key_pair(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let keypair = Keypair::from_bytes(&key_pair).unwrap();
    let public_key = keypair.public;
    let signature = Signature::from_bytes(&signature).unwrap();
    return public_key.verify(&message, &signature).is_ok();
}

pub fn ed25519_verify_with_public_key(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let public_key_parsed = PublicKey::from_bytes(&public_key).unwrap();
    let signature_parsed = Signature::from_bytes(&signature).unwrap();
    return public_key_parsed
        .verify(&message, &signature_parsed)
        .is_ok();
}