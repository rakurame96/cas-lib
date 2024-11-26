use argon2::password_hash::SaltString;
use pbkdf2::pbkdf2_hmac_array;
use rand::rngs::OsRng;
use sha3::Sha3_256;

use super::cas_password_hasher::Pbkdf2Result;

pub fn derivation(password_vec: Vec<u8>, number_of_iterations: u32) -> Pbkdf2Result {
    // Use Argon 2 salt and return the salt to the user so they can reuse it.
    let salt = SaltString::generate(&mut OsRng);
    let salt_binding = salt.to_string();
    let salt = salt_binding.as_bytes().to_vec();
    let key = pbkdf2_hmac_array::<Sha3_256, 32>(&password_vec, &salt, number_of_iterations).to_vec();
    return Pbkdf2Result {
        password: key,
        salt: salt
    }
}

pub fn derivation_with_salt(password_vec: Vec<u8>, number_of_iterations: u32, salt: Vec<u8>) -> Vec<u8> {
    let key = pbkdf2_hmac_array::<Sha3_256, 32>(&password_vec, &salt, number_of_iterations).to_vec();
    key
}
