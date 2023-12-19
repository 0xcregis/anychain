use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a OpBNB mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OpBnb;

impl Network for OpBnb {
    const NAME: &'static str = "op bnb mainnet";
}

impl EthereumNetwork for OpBnb {
    const CHAIN_ID: u32 = 204;
    const NETWORK_ID: u32 = 204;
}

impl FromStr for OpBnb {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for OpBnb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
