use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an ARB testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ArbitrumGoerli;

impl Network for ArbitrumGoerli {
    const NAME: &'static str = "arbitrum goerli";
}

impl EthereumNetwork for ArbitrumGoerli {
    const CHAIN_ID: u32 = 421613;
    const NETWORK_ID: u32 = 421613;
}

impl FromStr for ArbitrumGoerli {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for ArbitrumGoerli {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
