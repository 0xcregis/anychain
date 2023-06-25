use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Bitcoin;

impl Network for Bitcoin {
    const NAME: &'static str = "bitcoin";
}

impl BitcoinNetwork for Bitcoin {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x00],
            BitcoinFormat::P2WSH => vec![0x00],
            BitcoinFormat::P2SH_P2WPKH => vec![0x05],
            BitcoinFormat::Bech32 => vec![0x62, 0x63],
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x05, _) | (0x62, 0x63) => Ok(Self),
            _ => Err(AddressError::Message(format!(
                "Invalid version byte {:#0x} for network {}",
                prefix[0],
                Self::NAME
            ))),
        }
    }
}

impl FromStr for Bitcoin {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Bitcoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
