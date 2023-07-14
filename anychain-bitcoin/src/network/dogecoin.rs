use crate::{BitcoinFormat, BitcoinNetwork, Prefix};
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Dogecoin;

impl Network for Dogecoin {
    const NAME: &'static str = "dogecoin";
}

impl BitcoinNetwork for Dogecoin {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: BitcoinFormat) -> Result<Prefix, AddressError> {
        match format {
            BitcoinFormat::P2PKH => Ok(Prefix::Version(0x1e)),
            BitcoinFormat::P2WSH => Ok(Prefix::Version(0x00)),
            BitcoinFormat::P2SH_P2WPKH => Ok(Prefix::Version(0x16)),
            f => Err(AddressError::Message(format!(
                "{} does not support address format {}",
                Self::NAME,
                f,
            ))),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: Prefix) -> Result<Self, AddressError> {
        match prefix {
            Prefix::Version(version) => match version {
                0x1e | 0x16 => Ok(Self),
                _ => Err(AddressError::Message(format!(
                    "Invalid version byte {:#0x} for {} network",
                    version,
                    Self::NAME,
                ))),
            },
            _ => Err(AddressError::Message(format!(
                "{} does not support address format Bech32 or CashAddr",
                Self::NAME,
            ))),
        }
    }
}

impl FromStr for Dogecoin {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Dogecoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
