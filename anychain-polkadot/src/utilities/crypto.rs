/// Returns a 32-byte hash for given data
#[inline]
pub fn blake2b_256(ingest: &[u8]) -> [u8; 32] {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(ingest)
        .finalize();

    let mut hash = [0u8; 32];
    hash.clone_from_slice(digest.as_bytes());
    hash
}
