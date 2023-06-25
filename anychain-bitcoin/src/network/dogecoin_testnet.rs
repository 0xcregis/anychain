use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network, NetworkError};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct DogecoinTestnet;

impl Network for DogecoinTestnet {
    const NAME: &'static str = "dogecoin testnet";
}

pub static mut LOOP: u8 = 0;

impl BitcoinNetwork for DogecoinTestnet {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x71],
            BitcoinFormat::P2SH_P2WPKH => vec![0xC4],
            f => panic!("Unsupported dogecoin format {}", f),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x71, _) | (0xC4, _) => Ok(Self),
            _ => Err(AddressError::Message(format!(
                "Invalid version byte {:#0x} for network {}",
                prefix[0],
                Self::NAME
            ))),
        }
    }
}

impl FromStr for DogecoinTestnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for DogecoinTestnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
