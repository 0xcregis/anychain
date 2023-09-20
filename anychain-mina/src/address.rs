use anychain_core::{Address, AddressError, PublicKey};

use crate::secret_key::MinaSecretKey;
use crate::{MinaFormat, MinaPublicKey};

use std::{fmt::Display, str::FromStr};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinaAddress(String);

impl Address for MinaAddress {
    type Format = MinaFormat;
    type PublicKey = MinaPublicKey;
    type SecretKey = MinaSecretKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        <Self::PublicKey as PublicKey>::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        Ok(Self(public_key.into_address()))
    }
}

impl FromStr for MinaAddress {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match MinaPublicKey::from_address(s) {
            Ok(_) => Ok(Self(s.to_string())),
            Err(e) => Err(AddressError::Crate("PubKeyError", format!("{:?}", e))),
        }
    }
}

impl Display for MinaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
