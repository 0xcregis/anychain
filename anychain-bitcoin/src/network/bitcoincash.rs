use crate::{BitcoinFormat, BitcoinNetwork, Prefix};
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Bitcoincash;

impl Network for Bitcoincash {
    const NAME: &'static str = "bitcoin cash";
}

impl BitcoinNetwork for Bitcoincash {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: BitcoinFormat) -> Prefix {
        match format {
            BitcoinFormat::P2PKH => Prefix::Version(0x00),
            BitcoinFormat::P2WSH => Prefix::Version(0x00),
            BitcoinFormat::P2SH_P2WPKH => Prefix::Version(0x05),
            BitcoinFormat::Bech32 => Prefix::AddressPrefix("bc".to_string()),
            BitcoinFormat::CashAddr => Prefix::AddressPrefix("bitcoincash".to_string()),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: Prefix) -> Result<Self, AddressError> {
        match prefix {
            Prefix::Version(version) => match version {
                0x00 | 0x05 => Ok(Self),
                _ => Err(AddressError::Message(format!(
                    "Invalid version byte {:#0x} for network {}",
                    version,
                    Self::NAME,
                ))),
            },
            Prefix::AddressPrefix(prefix) => match prefix.as_str() {
                "bc" | "bitcoincash" => Ok(Self),
                _ => Err(AddressError::Message(format!(
                    "Invalid Bech32 or CashAddr prefix for network {}",
                    Self::NAME,
                ))),
            },
        }
    }
}

impl FromStr for Bitcoincash {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Bitcoincash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
