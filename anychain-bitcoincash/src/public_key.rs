use crate::{BitcoincashAddress, BitcoincashFormat, BitcoincashNetwork};
use anychain_core::{hex, libsecp256k1, Address, AddressError, PublicKey, PublicKeyError};
use core::{fmt, marker::PhantomData, str::FromStr};

/// Represents a Bitcoin cash public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoincashPublicKey<N: BitcoincashNetwork> {
    /// The ECDSA public key
    public_key: libsecp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    compressed: bool,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: BitcoincashNetwork> PublicKey for BitcoincashPublicKey<N> {
    type SecretKey = libsecp256k1::SecretKey;
    type Address = BitcoincashAddress<N>;
    type Format = BitcoincashFormat;

    /// Returns the address corresponding to the given public key.
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self {
            public_key: libsecp256k1::PublicKey::from_secret_key(secret_key),
            compressed: true,
            _network: PhantomData,
        }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl<N: BitcoincashNetwork> BitcoincashPublicKey<N> {
    /// Returns a public key given a secp256k1 public key.
    pub fn from_secp256k1_public_key(
        public_key: libsecp256k1::PublicKey,
        compressed: bool,
    ) -> Self {
        Self {
            public_key,
            compressed,
            _network: PhantomData,
        }
    }

    /// Returns the secp256k1 public key of the public key.
    pub fn to_secp256k1_public_key(&self) -> libsecp256k1::PublicKey {
        self.public_key
    }

    /// Returns `true` if the public key is in compressed form.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: BitcoincashNetwork> FromStr for BitcoincashPublicKey<N> {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            public_key: libsecp256k1::PublicKey::parse_slice(&hex::decode(public_key)?, None)?,
            compressed: public_key.len() == 66,
            _network: PhantomData,
        })
    }
}

impl<N: BitcoincashNetwork> fmt::Display for BitcoincashPublicKey<N> {
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
