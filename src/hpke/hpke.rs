use super::{cas_hybrid::CASHybrid, types::X25519Aes256Sha512EncryptResult};
use hpke::Kem;
use hpke::{
    aead::{AeadTag, AesGcm256},
    kdf::{HkdfSha384, HkdfSha512},
    kem::{self, X25519HkdfSha256},
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
pub struct CAShpke;

impl CASHybrid for CAShpke {
    fn x25519_keypair() -> (
        <X25519HkdfSha256 as Kem>::PrivateKey,
        <X25519HkdfSha256 as Kem>::PublicKey,
    ) {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut csprng);
        (private_key, public_key)
    }

    fn x25519_aes256_sha512_encrypt(
        info: Vec<u8>,
        mut to_encrypt: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> X25519Aes256Sha512EncryptResult {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = CAShpke::x25519_keypair();
        let (encapped_key, mut sender_ctx) =
            hpke::setup_sender::<AesGcm256, HkdfSha512, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &public_key,
                &info,
                &mut csprng,
            )
            .expect("invalid server pubkey!");
        let tag = sender_ctx
            .seal_in_place_detached(&mut to_encrypt, &associated_data)
            .expect("encryption failed!");
        X25519Aes256Sha512EncryptResult {
            private_key: private_key.to_bytes().to_vec(),
            public_key: public_key.to_bytes().to_vec(),
            encapped_key: encapped_key.to_bytes().to_vec(),
            encrypted_data: to_encrypt,
            tag: tag.to_bytes().to_vec(),
        }
    }

    fn x25519_aes256_sha512_decrypt(
        encapped_key: Vec<u8>,
        mut to_decrypt: Vec<u8>,
        private_key: Vec<u8>,
        tag: Vec<u8>,
        info: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Vec<u8> {
        let tag = AeadTag::<AesGcm256>::from_bytes(&tag).expect("could not deserialize AEAD tag!");

        let encapped_key = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&encapped_key)
            .expect("could not deserialize the encapsulated pubkey!");

        let private_key = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(&private_key)
            .expect("could not deserialize server privkey!");

        let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha512, X25519HkdfSha256>(
            &OpModeR::Base,
            &private_key,
            &encapped_key,
            &info,
        )
        .expect("failed to set up receiver!");
        receiver_ctx
            .open_in_place_detached(&mut to_decrypt, &associated_data, &tag)
            .expect("invalid ciphertext!");
        to_decrypt
    }
}


#[test]
fn encrypt_test() {
    let info = b"WelcomeHome".to_vec();
    let associated_data = b"associated".to_vec();
    let message = b"ToEncrypt".to_vec();
    let encrypt_result = CAShpke::x25519_aes256_sha512_encrypt(info.clone(), message.clone(), associated_data.clone());
    let decrypt_result = CAShpke::x25519_aes256_sha512_decrypt(encrypt_result.encapped_key, encrypt_result.encrypted_data, encrypt_result.private_key, encrypt_result.tag, info.clone(), associated_data.clone());
    assert_eq!(message, decrypt_result);
}