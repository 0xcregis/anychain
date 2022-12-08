use crate::network::EthereumNetwork;
use chainlib_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum test network (PoA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Heco;

impl Network for Heco {
    const NAME: &'static str = "heco";
}

impl EthereumNetwork for Heco {
    const CHAIN_ID: u32 = 128;
    const NETWORK_ID: u32 = 128;
}

impl FromStr for Heco {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Heco {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
