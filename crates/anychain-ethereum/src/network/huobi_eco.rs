use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an HECO mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct HuobiEco;

impl Network for HuobiEco {
    const NAME: &'static str = "huobi eco";
}

impl EthereumNetwork for HuobiEco {
    const CHAIN_ID: u32 = 128;
    const NETWORK_ID: u32 = 128;
}

impl FromStr for HuobiEco {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for HuobiEco {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
