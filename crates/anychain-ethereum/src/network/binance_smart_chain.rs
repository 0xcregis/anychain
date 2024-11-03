use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a BSC mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BinanceSmartChain;

impl Network for BinanceSmartChain {
    const NAME: &'static str = "binance smart chain";
}

impl EthereumNetwork for BinanceSmartChain {
    const CHAIN_ID: u32 = 56;
    const NETWORK_ID: u32 = 56;
}

impl FromStr for BinanceSmartChain {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for BinanceSmartChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
