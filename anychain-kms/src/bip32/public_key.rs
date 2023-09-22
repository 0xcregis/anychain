//! Trait for deriving child keys on a given type.

use std::ops::Add;

use crate::bip32::{KeyFingerprint, PrivateKeyBytes, Result, KEY_SIZE};
use anychain_mina::CompressedPubKey;
use anychain_mina::MinaSecretKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::PrivateKey;
use crate::bip32::XpubSecp256k1;

/// Bytes which represent a public key.
///
/// Includes an extra byte for an SEC1 tag.
pub type PublicKeyBytes = [u8; KEY_SIZE + 1];

/// Trait for key types which can be derived using BIP32.
pub trait PublicKey: Sized {
    /// Initialize this key from bytes.
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self>;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> PublicKeyBytes;

    /// Derive a child key from a parent key and a provided tweak value.
    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self>;

    /// Compute a 4-byte key fingerprint for this public key.
    ///
    /// Default implementation uses `RIPEMD160(SHA256(public_key))`.
    fn fingerprint(&self) -> KeyFingerprint {
        let digest = Ripemd160::digest(Sha256::digest(self.to_bytes()));
        digest[..4].try_into().expect("digest truncated")
    }
}

impl PublicKey for libsecp256k1::PublicKey {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        Ok(libsecp256k1::PublicKey::parse_compressed(&bytes)?)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        libsecp256k1::PublicKey::serialize_compressed(self)
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let mut cpk = *self;
        cpk.tweak_add_assign(&libsecp256k1::SecretKey::from_bytes(&other)?)?;
        Ok(cpk)
    }
}

impl From<XpubSecp256k1> for libsecp256k1::PublicKey {
    fn from(xpub: XpubSecp256k1) -> libsecp256k1::PublicKey {
        libsecp256k1::PublicKey::from(&xpub)
    }
}

impl From<&XpubSecp256k1> for libsecp256k1::PublicKey {
    fn from(xpub: &XpubSecp256k1) -> libsecp256k1::PublicKey {
        *xpub.public_key()
    }
}

impl PublicKey for anychain_mina::MinaPublicKey {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        let compressed_pk = CompressedPubKey::from_bytes(&bytes)?;
        let address = compressed_pk.to_address();
        Ok(Self::from_address(&address)?)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(&self.into_compressed().to_bytes());
        bytes
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let tweak_sk = MinaSecretKey::from_bytes(&other)?;
        let tweak_pk = Self::from_secret_key(tweak_sk)?;
        let point = self.point().add(tweak_pk.into_point());
        Ok(Self::from_point_unsafe(point))
    }
}

#[cfg(test)]
mod tests {
    use crate::bip32::XprvSecp256k1;
    use hex_literal::hex;

    const SEED: [u8; 64] = hex!(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    );

    #[test]
    fn secp256k1_xprv_derivation() {
        let path = "m/0/2147483647'/1/2147483646'/2";
        let xprv = XprvSecp256k1::new_from_path(SEED, &path.parse().unwrap()).unwrap();

        assert_eq!(
            xprv.public_key(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".parse().unwrap()
        );
    }

    #[test]
    fn secp256k1_ffi_xpub_derivation() {
        let path = "m/0/2147483647'/1/2147483646'";
        let xprv = XprvSecp256k1::new_from_path(SEED, &path.parse().unwrap()).unwrap();
        let xpub = xprv.public_key().derive_child(2.into()).unwrap();

        assert_eq!(
            xpub,
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".parse().unwrap()
        );
    }
}
