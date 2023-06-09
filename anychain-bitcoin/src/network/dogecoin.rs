use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
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
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x1E],
            BitcoinFormat::P2SH_P2WPKH => vec![0x16],
            f => panic!("Unsupported dogecoin format {}", f),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x1E, _) | (0x16, _) => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(String::from_utf8(
                prefix.to_owned(),
            )?)),
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
