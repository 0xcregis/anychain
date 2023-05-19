use anychain_core::{Network, NetworkError};
use core::{fmt, str::FromStr};

use crate::BitcoincashNetwork;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Testnet;

impl Network for Testnet {
    const NAME: &'static str = "Bitcoin cash testnet";
}

impl BitcoincashNetwork for Testnet {
    fn prefix() -> &'static str {
        "bchtest"
    }

    fn legacy_prefix() -> u8 {
        0x6f
    }
}

impl FromStr for Testnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Testnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
