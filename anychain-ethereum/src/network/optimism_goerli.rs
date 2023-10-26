use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an OP testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OptimismGoerli;

impl Network for OptimismGoerli {
    const NAME: &'static str = "optimism goerli";
}

impl EthereumNetwork for OptimismGoerli {
    const CHAIN_ID: u32 = 420;
    const NETWORK_ID: u32 = 420;
}

impl FromStr for OptimismGoerli {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for OptimismGoerli {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
