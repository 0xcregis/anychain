use std::{str::FromStr, fmt::Display};

use anychain_core::{Address, TransactionError};

use crate::{PolkadotFormat, PolkadotPublicKey};


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PolkadotAddress(String);


impl Address for PolkadotAddress {
    type SecretKey = ed25519_dalek_fiat::SecretKey;
    type PublicKey = PolkadotPublicKey;
    type Format = PolkadotFormat;
    
    fn from_secret_key(secret_key: &Self::SecretKey, format: &Self::Format) -> Result<Self, anychain_core::AddressError> {
        todo!()
    }

    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, anychain_core::AddressError> {
        todo!()
    }
}

impl FromStr for PolkadotAddress {
    type Err = TransactionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for PolkadotAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()       
    }
}