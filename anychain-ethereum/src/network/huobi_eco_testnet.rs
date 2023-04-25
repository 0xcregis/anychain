use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a HECO testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct HuobiEcoTestnet;

impl Network for HuobiEcoTestnet {
    const NAME: &'static str = "huobi eco testnet";
}

impl EthereumNetwork for HuobiEcoTestnet {
    const CHAIN_ID: u32 = 256;
    const NETWORK_ID: u32 = 256;
}

impl FromStr for HuobiEcoTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for HuobiEcoTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
