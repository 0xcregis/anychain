use crate::address::FilecoinAddress;
use crate::format::FilecoinFormat;
use anychain_core::{hex, Address, AddressError, PublicKey, PublicKeyError};
use bls_signatures::{self, Serialize};
use core::panic;
use core::{fmt, fmt::Display, str::FromStr};

/// Represents a filecoin secret key
#[derive(Debug, Clone, PartialEq)]
pub enum FilecoinSecretKey {
    Secp256k1(libsecp256k1::SecretKey),
    Bls(bls_signatures::PrivateKey),
}

/// Represents a filecoin public key
#[derive(Debug, Clone, PartialEq)]
pub enum FilecoinPublicKey {
    Secp256k1(libsecp256k1::PublicKey),
    Bls(bls_signatures::PublicKey),
}

impl PublicKey for FilecoinPublicKey {
    type SecretKey = FilecoinSecretKey;
    type Address = FilecoinAddress;
    type Format = FilecoinFormat;

    /// Returns the filecoin public key corresponding to the given secp256k1 secret key.
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        match secret_key {
            FilecoinSecretKey::Secp256k1(key) => {
                Self::Secp256k1(libsecp256k1::PublicKey::from_secret_key(key))
            }
            FilecoinSecretKey::Bls(key) => Self::Bls(key.public_key()),
        }
    }

    /// Returns the address of the corresponding filecoin public key.
    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, _format)
    }
}

impl FilecoinPublicKey {
    /// Returns a filecoin public key given an secp256k1 public key.
    pub fn from_secp256k1_public_key(public_key: libsecp256k1::PublicKey) -> Self {
        Self::Secp256k1(public_key)
    }

    /// Returns the secp256k1 public key of this filecoin public key
    pub fn to_secp256k1_public_key(&self) -> libsecp256k1::PublicKey {
        match self {
            Self::Secp256k1(key) => *key,
            _ => panic!("not an secp256k1 public key"),
        }
    }

    /// Returns a filecoin public key given a bls public key
    pub fn from_bls_public_key(public_key: bls_signatures::PublicKey) -> Self {
        Self::Bls(public_key)
    }

    /// Returns the bls public key of this filecoin public key
    pub fn to_bls_public_key(&self) -> bls_signatures::PublicKey {
        match self {
            Self::Bls(key) => *key,
            _ => panic!("not a bls public key"),
        }
    }
}

impl FromStr for FilecoinPublicKey {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        let mut s = public_key.to_string();
        let mut is_bls = false;
        if s.starts_with("secp256k1_pub_") {
            s = s[14..].to_string();
        } else if s.starts_with("bls_pub_") {
            s = s[8..].to_string();
            is_bls = true;
        } else {
            return Err(PublicKeyError::InvalidPrefix("".to_string()));
        }

        let stream = hex::decode(&s)?;
        match is_bls {
            true => {
                let key = bls_signatures::PublicKey::from_bytes(&stream).unwrap();
                Ok(Self::Bls(key))
            }
            false => {
                let key = libsecp256k1::PublicKey::parse_slice(&stream, None).map_err(|error| {
                    PublicKeyError::Crate("libsecp256k1", format!("{:?}", error))
                })?;
                Ok(Self::Secp256k1(key))
            }
        }
    }
}

impl Display for FilecoinPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1(key) => {
                let mut s = "secp256k1_pub_".to_string();
                s.push_str(&hex::encode(key.serialize()));
                write!(f, "{}", s)
            }
            Self::Bls(key) => {
                let mut s = "bls_pub_".to_string();
                s.push_str(&hex::encode(key.as_bytes()));
                write!(f, "{}", s)
            }
        }
    }
}
