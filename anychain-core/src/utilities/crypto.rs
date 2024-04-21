use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

#[inline]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline]
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hash length of payload for addresses of filecoin.
// pub const PAYLOAD_HASH_LEN: usize = 20;

/// Returns a 20-byte address hash for given public key
// #[inline]
// pub fn blake2b_160(input: &[u8]) -> [u8; 20] {
//     let digest = blake2b_simd::Params::new()
//         .hash_length(PAYLOAD_HASH_LEN)
//         .to_state()
//         .update(input)
//         .finalize();
//
//     let mut hash = [0u8; 20];
//     hash.copy_from_slice(digest.as_bytes());
//     hash
// }
//
// /// Returns a 32-byte hash for given data
// #[inline]
// pub fn blake2b_256(ingest: &[u8]) -> [u8; 32] {
//     let digest = blake2b_simd::Params::new()
//         .hash_length(32)
//         .to_state()
//         .update(ingest)
//         .finalize();
//
//     let mut hash = [0u8; 32];
//     hash.clone_from_slice(digest.as_bytes());
//     hash
// }

pub fn checksum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(Sha256::digest(data)).to_vec()
}

pub fn hash160(bytes: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(bytes)).to_vec()
}

// Length of the checksum hash for string encodings.
// pub const CHECKSUM_HASH_LEN: usize = 4;
//
// /// Checksum calculates the 4 byte checksum hash
// pub fn blake2b_checksum(ingest: &[u8]) -> Vec<u8> {
//     blake2b_simd::Params::new()
//         .hash_length(CHECKSUM_HASH_LEN)
//         .to_state()
//         .update(ingest)
//         .finalize()
//         .as_bytes()
//         .to_vec()
// }
