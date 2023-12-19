use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a OKT testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OpBnbTestnet;

impl Network for OpBnbTestnet {
    const NAME: &'static str = "op bnb testnet";
}

impl EthereumNetwork for OpBnbTestnet {
    const CHAIN_ID: u32 = 5611;
    const NETWORK_ID: u32 = 5611;
}

impl FromStr for OpBnbTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for OpBnbTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
