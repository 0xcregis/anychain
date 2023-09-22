//! Trait for deriving child keys on a given type.

use std::ops::Add;

use anychain_mina::MinaSecretKey;

use crate::bip32::XprvSecp256k1;
use crate::bip32::{PublicKey, Result, KEY_SIZE};

/// Bytes which represent a private key.
pub type PrivateKeyBytes = [u8; KEY_SIZE];

/// Trait for key types which can be derived using BIP32.
pub trait PrivateKey: Sized {
    /// Public key type which corresponds to this private key.
    type PublicKey: PublicKey;

    /// Initialize this key from bytes.
    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self>;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> PrivateKeyBytes;

    /// Derive a child key from a parent key and the a provided tweak value,
    /// i.e. where `other` is referred to as "I sub L" in BIP32 and sourced
    /// from the left half of the HMAC-SHA-512 output.
    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self>;

    /// Get the [`Self::PublicKey`] that corresponds to this private key.
    fn public_key(&self) -> Self::PublicKey;
}

impl PrivateKey for libsecp256k1::SecretKey {
    type PublicKey = libsecp256k1::PublicKey;

    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self> {
        Ok(libsecp256k1::SecretKey::parse(bytes)?)
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        libsecp256k1::SecretKey::serialize(self)
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let mut csk = *self;
        let tweak = Self::from_bytes(&other)?;
        csk.tweak_add_assign(&tweak)?;
        Ok(csk)
    }

    fn public_key(&self) -> Self::PublicKey {
        libsecp256k1::PublicKey::from_secret_key(self)
    }
}

impl From<XprvSecp256k1> for libsecp256k1::SecretKey {
    fn from(xprv: XprvSecp256k1) -> libsecp256k1::SecretKey {
        libsecp256k1::SecretKey::from(&xprv)
    }
}

impl From<&XprvSecp256k1> for libsecp256k1::SecretKey {
    fn from(xprv: &XprvSecp256k1) -> libsecp256k1::SecretKey {
        *xprv.private_key()
    }
}

impl PrivateKey for anychain_mina::MinaSecretKey {
    type PublicKey = anychain_mina::MinaPublicKey;

    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self> {
        Ok(Self::from_bytes(bytes)?)
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&self.to_bytes());
        sk
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let tweak = Self::from_bytes(&other)?;
        let scalar = self.scalar().add(tweak.scalar());
        Ok(MinaSecretKey::new(scalar))
    }

    fn public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from_secret_key(self.clone()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::bip32::XprvSecp256k1;
    use hex_literal::hex;

    #[test]
    fn secp256k1_derivation() {
        let seed = hex!(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        );

        let path = "m/0/2147483647'/1/2147483646'/2";
        let xprv = XprvSecp256k1::new_from_path(seed, &path.parse().unwrap()).unwrap();

        assert_eq!(
            xprv,
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j".parse().unwrap()
        );
    }
}
