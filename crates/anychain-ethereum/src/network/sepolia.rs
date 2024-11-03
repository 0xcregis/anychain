use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an ETH testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Sepolia;

impl Network for Sepolia {
    const NAME: &'static str = "sepolia";
}

impl EthereumNetwork for Sepolia {
    const CHAIN_ID: u32 = 11155111;
    const NETWORK_ID: u32 = 11155111;
}

impl FromStr for Sepolia {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Sepolia {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
