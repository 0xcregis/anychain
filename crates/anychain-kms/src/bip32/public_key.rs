//! Trait for deriving child keys on a given type.

use crate::bip32::{KeyFingerprint, Result};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE as G, edwards::EdwardsPoint, scalar::Scalar,
};
use group::GroupEncoding;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::bip32::Error;

/// Trait for key types which can be derived using BIP32.
pub trait PublicKey: Sized {
    /// Initialize this key from bytes.
    fn from_bytes(bytes: Vec<u8>) -> Result<Self>;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Derive a child key from a parent key and a provided tweak value.
    fn derive_child(&self, tweak: Vec<u8>) -> Result<Self>;

    /// Compute a 4-byte key fingerprint for this public key.
    ///
    /// Default implementation uses `RIPEMD160(SHA256(public_key))`.
    fn fingerprint(&self) -> KeyFingerprint {
        let digest = Ripemd160::digest(Sha256::digest(self.to_bytes()));
        digest[..4].try_into().expect("digest truncated")
    }
}

impl PublicKey for libsecp256k1::PublicKey {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        match libsecp256k1::PublicKey::parse_slice(&bytes, None) {
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(Error::Crypto),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        libsecp256k1::PublicKey::serialize_compressed(self).to_vec()
    }

    fn derive_child(&self, tweak: Vec<u8>) -> Result<Self> {
        let mut cpk = *self;
        match cpk.tweak_add_assign(&libsecp256k1::SecretKey::parse_slice(&tweak).unwrap()) {
            Ok(_) => Ok(cpk),
            Err(_) => Err(Error::Crypto),
        }
    }
}

impl PublicKey for ed25519_dalek::PublicKey {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() == 32 {
            Ok(
                ed25519_dalek::PublicKey::from_bytes(&bytes)
                    .or(Err(crate::bip32::Error::Crypto))?,
            )
        } else if bytes.len() == 33 {
            Ok(ed25519_dalek::PublicKey::from_bytes(&bytes[1..])
                .or(Err(crate::bip32::Error::Crypto))?)
        } else {
            Err(crate::bip32::Error::Crypto)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn derive_child(&self, tweak: Vec<u8>) -> Result<Self> {
        let pk = self.as_bytes();
        let mut _tweak = [0u8; 32];
        _tweak.copy_from_slice(&tweak);
        let point = EdwardsPoint::from_bytes(pk).unwrap();
        let tweak = &Scalar::from_bytes_mod_order(_tweak) * G;
        let child = point + tweak;
        let child = child.to_bytes();
        Ok(ed25519_dalek::PublicKey::from_bytes(&child).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex_literal::hex;

    use crate::bip32::{extended_key::extended_public_key::XpubEd25519, DerivationPath};

    const SEED: [u8; 64] = hex!(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    );

    type XprvSecp256k1 = crate::bip32::ExtendedPrivateKey<libsecp256k1::SecretKey>;

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

    #[test]
    fn test_ed25519() {
        let xpub = "xpub661MyMwAqRbcGGrNUSVKfdjbzSrBSeah6YPb99PhpDyQRiYLKtC4RaASsF1k5xEW6u2tZZ1nb3A335ZbtNh9UJtwrNorMhmumn2X3r3dEn2";
        let xpub = XpubEd25519::from_str(xpub).unwrap();
        let path = DerivationPath::from_str("m/1/2/3").unwrap();
        let child = xpub.derive_from_path(&path).unwrap();
        let child = child.public_key().as_bytes();
        println!("{:?}", child);
    }
}
