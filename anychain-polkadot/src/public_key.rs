use crate::{PolkadotAddress, PolkadotFormat, PolkadotNetwork};
use anychain_core::{libsecp256k1, Address, PublicKey, PublicKeyError};
use std::{fmt::Display, marker::PhantomData, str::FromStr};

#[derive(Debug, Clone)]
pub struct PolkadotPublicKey<N: PolkadotNetwork> {
    key: libsecp256k1::PublicKey,
    _network: PhantomData<N>,
}

impl<N: PolkadotNetwork> PublicKey for PolkadotPublicKey<N> {
    type SecretKey = libsecp256k1::SecretKey;
    type Address = PolkadotAddress<N>;
    type Format = PolkadotFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self {
            key: libsecp256k1::PublicKey::from_secret_key(secret_key),
            _network: PhantomData::<N>,
        }
    }

    fn to_address(
        &self,
        format: &Self::Format,
    ) -> Result<Self::Address, anychain_core::AddressError> {
        Ok(Self::Address::from_public_key(self, format)?)
    }
}

impl<N: PolkadotNetwork> PolkadotPublicKey<N> {
    pub fn serialize(&self) -> Vec<u8> {
        self.key.serialize_compressed().to_vec()
    }
}

impl<N: PolkadotNetwork> FromStr for PolkadotPublicKey<N> {
    type Err = PublicKeyError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<N: PolkadotNetwork> Display for PolkadotPublicKey<N> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
