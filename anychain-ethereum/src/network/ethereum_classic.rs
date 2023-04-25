use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an ETC mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EthereumClassic;

impl Network for EthereumClassic {
    const NAME: &'static str = "ethereum classic";
}

impl EthereumNetwork for EthereumClassic {
    const CHAIN_ID: u32 = 61;
    const NETWORK_ID: u32 = 61;
}

impl FromStr for EthereumClassic {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for EthereumClassic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
