use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Litecoin;

impl Network for Litecoin {
    const NAME: &'static str = "litecoin";
}

impl BitcoinNetwork for Litecoin {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x30],
            BitcoinFormat::P2SH_P2WPKH => vec![0x32],
            f => panic!("Unsupported litecoin format {}", f),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x30, _) | (0x32, _) => Ok(Self),
            _ => Err(AddressError::Message(format!(
                "Invalid version byte {:#0x}, {:#0x} for network {}",
                prefix[0],
                prefix[1],
                Self::NAME,
            ))),
        }
    }
}

impl FromStr for Litecoin {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Litecoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
