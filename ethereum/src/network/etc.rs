use crate::network::EthereumNetwork;
use chainlib_core::{ Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum main network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ETC;

impl Network for ETC {
    const NAME: &'static str = "ETC";
}

impl EthereumNetwork for ETC {
    const CHAIN_ID: u32 = 61;
    const NETWORK_ID: u32 = 61;
}

impl FromStr for ETC {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for ETC {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
