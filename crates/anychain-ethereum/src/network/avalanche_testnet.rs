use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an AVAX testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct AvalancheTestnet;

impl Network for AvalancheTestnet {
    const NAME: &'static str = "avalanche testnet";
}

impl EthereumNetwork for AvalancheTestnet {
    const CHAIN_ID: u32 = 43113;
    const NETWORK_ID: u32 = 43113;
}

impl FromStr for AvalancheTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for AvalancheTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
