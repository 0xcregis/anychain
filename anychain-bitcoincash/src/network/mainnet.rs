use anychain_core::{Network, NetworkError};
use core::{fmt, str::FromStr};

use crate::BitcoincashNetwork;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mainnet;

impl Network for Mainnet {
    const NAME: &'static str = "Bitcoin cash mainnet";
}

impl BitcoincashNetwork for Mainnet {
    fn prefix() -> &'static str {
        "bitcoincash"
    }

    fn legacy_prefix() -> u8 {
        0
    }
}

impl FromStr for Mainnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Mainnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
