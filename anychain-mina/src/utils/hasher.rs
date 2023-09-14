use serde::Serialize;
use sha2::{Digest, Sha256};

/// This trait can be implemented on any type that implements [serde::Serialize],
/// in order to provide a `digest()` function that returns a unique hash.
pub trait CryptoDigest: Serialize {
    /// The domain separation string to use in the hash.
    /// This is to distinguish hashes for different use-cases.
    /// With this approach, a type is linked to a single usecase.
    ///
    /// Warning: careful not to use the same separation string with
    /// two different types.
    const PREFIX: &'static [u8; 15];

    /// Returns the digest of `self`.
    /// Note: this is implemented as the SHA-256 of a prefix
    /// ("kimchi-circuit"), followed by the serialized gates.
    /// The gates are serialized using [BCS](https://github.com/diem/bcs).
    fn digest(&self) -> [u8; 32] {
        // compute the prefixed state lazily
        let mut hasher = Sha256::new();
        hasher.update(Self::PREFIX);
        hasher.update(
            &bcs::to_bytes(self).unwrap_or_else(|e| panic!("couldn't serialize the gate: {e}")),
        );
        hasher.finalize().into()
    }
}
