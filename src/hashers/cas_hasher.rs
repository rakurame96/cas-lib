pub trait CASHasher {
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
    fn hash_512_threadpool(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_512_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
    fn hash_256_threadpool(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_256_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
}
