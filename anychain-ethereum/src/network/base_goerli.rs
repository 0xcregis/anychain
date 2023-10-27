use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an BASE testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BaseGoerli;

impl Network for BaseGoerli {
    const NAME: &'static str = "base goerli";
}

impl EthereumNetwork for BaseGoerli {
    const CHAIN_ID: u32 = 84531;
    const NETWORK_ID: u32 = 84531;
}

impl FromStr for BaseGoerli {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for BaseGoerli {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
