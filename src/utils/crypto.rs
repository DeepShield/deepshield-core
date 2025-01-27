use sha3::{Digest, Keccak256};
use ethers::types::{H160, H256, U256};
use hex;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn generate_secure_random() -> [u8; 32] {
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes).expect("Failed to generate random bytes");
    random_bytes
}

pub fn address_to_string(address: H160) -> String {
    format!("0x{:x}", address)
}

pub fn hash_to_string(hash: H256) -> String {
    format!("0x{:x}", hash)
} 