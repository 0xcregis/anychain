use crate::{BitcoinFormat, BitcoinNetwork, Prefix};
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BitcoinCashTestnet;

impl Network for BitcoinCashTestnet {
    const NAME: &'static str = "bitcoin cash testnet";
}

impl BitcoinNetwork for BitcoinCashTestnet {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: BitcoinFormat) -> Result<Prefix, AddressError> {
        match format {
            BitcoinFormat::P2PKH => Ok(Prefix::Version(0x6f)),
            BitcoinFormat::P2WSH => Ok(Prefix::Version(0x00)),
            BitcoinFormat::P2SH_P2WPKH => Ok(Prefix::Version(0xc4)),
            BitcoinFormat::Bech32 => Ok(Prefix::AddressPrefix("tb".to_string())),
            BitcoinFormat::CashAddr => Ok(Prefix::AddressPrefix("bchtest".to_string())),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: Prefix) -> Result<Self, AddressError> {
        match prefix {
            Prefix::Version(version) => match version {
                0x6f | 0xc4 => Ok(Self),
                _ => Err(AddressError::Message(format!(
                    "Invalid version byte {:#0x} for {} network",
                    version,
                    Self::NAME,
                ))),
            },
            Prefix::AddressPrefix(prefix) => match prefix.as_str() {
                "tb" | "bchtest" => Ok(Self),
                _ => Err(AddressError::Message(format!(
                    "Invalid Bech32 or CashAddr prefix for {} network",
                    Self::NAME,
                ))),
            },
        }
    }
}

impl FromStr for BitcoinCashTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for BitcoinCashTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
