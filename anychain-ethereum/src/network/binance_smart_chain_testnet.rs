use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents a BSC testnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BinanceSmartChainTestnet;

impl Network for BinanceSmartChainTestnet {
    const NAME: &'static str = "binance smart chain testnet";
}

impl EthereumNetwork for BinanceSmartChainTestnet {
    const CHAIN_ID: u32 = 97;
    const NETWORK_ID: u32 = 97;
}

impl FromStr for BinanceSmartChainTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for BinanceSmartChainTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
