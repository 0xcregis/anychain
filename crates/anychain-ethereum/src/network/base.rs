use crate::network::EthereumNetwork;
use anychain_core::{Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an BASE mainnet
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Base;

impl Network for Base {
    const NAME: &'static str = "base";
}

impl EthereumNetwork for Base {
    const CHAIN_ID: u32 = 8453;
    const NETWORK_ID: u32 = 8453;
}

impl FromStr for Base {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
