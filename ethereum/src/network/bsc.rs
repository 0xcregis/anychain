use crate::network::EthereumNetwork;
use chainlib_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum test network (PoA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BSC;

impl Network for BSC {
    const NAME: &'static str = "BSC";
}

impl EthereumNetwork for BSC {
    const CHAIN_ID: u32 = 56;
    const NETWORK_ID: u32 = 56;
}

impl FromStr for BSC {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for BSC {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
