use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an ETH mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Op;

impl Network for Op {
    const NAME: &'static str = "op";
}

impl EthereumNetwork for Op {
    const CHAIN_ID: u32 = 10;
    const NETWORK_ID: u32 = 10;
}

impl FromStr for Op {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
