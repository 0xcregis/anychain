use crate::{PolkadotAddress, PolkadotFormat, PolkadotNetwork};
use anychain_core::{Address, PublicKey, PublicKeyError};
use sp_core::blake2_256;
use std::{fmt::Display, marker::PhantomData, str::FromStr};

pub enum PolkadotSecretKey {
    Secp256k1(libsecp256k1::SecretKey),
    Ed25519(ed25519_dalek::SecretKey),
}

#[derive(Debug, Clone)]
pub enum PublicKeyContent {
    Secp256k1(libsecp256k1::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

#[derive(Debug, Clone)]
pub struct PolkadotPublicKey<N: PolkadotNetwork> {
    pub key: PublicKeyContent,
    _network: PhantomData<N>,
}

impl<N: PolkadotNetwork> PublicKey for PolkadotPublicKey<N> {
    type SecretKey = PolkadotSecretKey;
    type Address = PolkadotAddress<N>;
    type Format = PolkadotFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        match secret_key {
            Self::SecretKey::Secp256k1(sk) => {
                let pk = libsecp256k1::PublicKey::from_secret_key(sk);
                let pk = PublicKeyContent::Secp256k1(pk);
                Self {
                    key: pk,
                    _network: PhantomData,
                }
            }
            Self::SecretKey::Ed25519(sk) => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(sk);
                let verifying_key = signing_key.verifying_key();
                let pk = PublicKeyContent::Ed25519(verifying_key);
                Self {
                    key: pk,
                    _network: PhantomData,
                }
            }
        }
    }

    fn to_address(
        &self,
        format: &Self::Format,
    ) -> Result<Self::Address, anychain_core::AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl<N: PolkadotNetwork> PolkadotPublicKey<N> {
    pub fn serialize(&self) -> Vec<u8> {
        match self.key {
            PublicKeyContent::Secp256k1(pk) => pk.serialize_compressed().to_vec(),
            PublicKeyContent::Ed25519(pk) => pk.to_bytes().to_vec(),
        }
    }

    pub fn address_payload(&self) -> Vec<u8> {
        match self.key {
            PublicKeyContent::Secp256k1(_) => blake2_256(&self.serialize()).to_vec(),
            PublicKeyContent::Ed25519(_) => self.serialize(),
        }
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
