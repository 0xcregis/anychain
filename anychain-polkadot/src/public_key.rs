use std::{str::FromStr, fmt::Display};
use anychain_core::{PublicKey, TransactionError};
use crate::{PolkadotAddress, PolkadotFormat};

#[derive(Debug, Clone)]
pub struct PolkadotPublicKey(ed25519_dalek_fiat::PublicKey);

impl PublicKey for PolkadotPublicKey {
    type SecretKey = ed25519_dalek_fiat::SecretKey;
    type Address = PolkadotAddress;
    type Format = PolkadotFormat;
    
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self(ed25519_dalek_fiat::PublicKey::from(secret_key))
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, anychain_core::AddressError> {

        todo!()



    }
}

impl FromStr for PolkadotPublicKey {
    type Err = TransactionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for PolkadotPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
