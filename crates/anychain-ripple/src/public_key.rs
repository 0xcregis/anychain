use crate::{RippleAddress, RippleFormat};
use anychain_core::{hex, Address, AddressError, PublicKey, PublicKeyError};
use core::{fmt, str::FromStr};

/// Represents a Ripple public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipplePublicKey {
    /// The secp256k1 public key
    public_key: libsecp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    compressed: bool,
}

impl PublicKey for RipplePublicKey {
    type SecretKey = libsecp256k1::SecretKey;
    type Address = RippleAddress;
    type Format = RippleFormat;

    /// Returns a Ripple public key given an secp256k1 secret key.
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self {
            public_key: libsecp256k1::PublicKey::from_secret_key(secret_key),
            compressed: true,
        }
    }

    /// Returns a Ripple address corresponding to this Ripple public key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl RipplePublicKey {
    /// Returns a Ripple public key given an secp256k1 public key.
    pub fn from_secp256k1_public_key(
        public_key: libsecp256k1::PublicKey,
        compressed: bool,
    ) -> Self {
        Self {
            public_key,
            compressed,
        }
    }

    /// Returns the secp256k1 public key of this Ripple public key.
    pub fn to_secp256k1_public_key(&self) -> libsecp256k1::PublicKey {
        self.public_key
    }

    /// Serialize the Ripple public key as a vector of u8
    pub fn serialize(&self) -> Vec<u8> {
        match self.compressed {
            true => self.public_key.serialize_compressed().to_vec(),
            false => self.public_key.serialize().to_vec(),
        }
    }

    /// Returns `true` if the public key is in compressed form.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl FromStr for RipplePublicKey {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        let compressed = public_key.len() == 66;
        let p = hex::decode(public_key)
            .map_err(|error| PublicKeyError::Crate("hex", format!("{:?}", error)))?;
        let public_key = libsecp256k1::PublicKey::parse_slice(&p, None)
            .map_err(|error| PublicKeyError::Crate("libsecp256k1", format!("{:?}", error)))?;

        Ok(Self {
            public_key,
            compressed,
        })
    }
}

impl fmt::Display for RipplePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for s in &self.public_key.serialize_compressed()[..] {
                write!(f, "{:02x}", s)?;
            }
        } else {
            for s in &self.public_key.serialize()[..] {
                write!(f, "{:02x}", s)?;
            }
        }
        Ok(())
    }
}
