//! Trait for deriving child keys on a given type.

use crate::bip32::{PublicKey, Result, KEY_SIZE};

use crate::bip32::{Error, XprvSecp256k1};

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
        match libsecp256k1::SecretKey::parse(bytes) {
            Ok(sk) => Ok(sk),
            Err(_) => Err(Error::Crypto),
        }
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        libsecp256k1::SecretKey::serialize(self)
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let mut cpk = *self;
        match cpk.tweak_add_assign(&libsecp256k1::SecretKey::parse(&other).unwrap()) {
            Ok(_) => Ok(cpk),
            Err(_) => Err(Error::Crypto),
        }
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
        todo!()
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        todo!()
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        todo!()
    }

    fn public_key(&self) -> Self::PublicKey {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    //type XPrv = crate::bip32::ExtendedPrivateKey<k256::ecdsa::SigningKey>;

    type XPrv = crate::bip32::ExtendedPrivateKey<libsecp256k1::SecretKey>;

    #[test]
    fn secp256k1_derivation() {
        let seed = hex!(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        );

        let path = "m/0/2147483647'/1/2147483646'/2";
        let xprv = XPrv::new_from_path(seed, &path.parse().unwrap()).unwrap();

        assert_eq!(
            xprv,
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j".parse().unwrap()
        );
    }
}
