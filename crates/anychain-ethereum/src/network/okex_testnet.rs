use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a OKT testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OkexTestnet;

impl Network for OkexTestnet {
    const NAME: &'static str = "okex chain testnet";
}

impl EthereumNetwork for OkexTestnet {
    const CHAIN_ID: u32 = 65;
    const NETWORK_ID: u32 = 65;
}

impl FromStr for OkexTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for OkexTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
