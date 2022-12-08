use crate::network::BitcoinNetwork;
use chainlib_core::no_std::*;
use chainlib_core::{AddressError, Format};

use core::fmt;
use serde::Serialize;

/// Represents the format of a Bitcoin address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum BitcoinFormat {
    /// Pay-to-Pubkey Hash, e.g. 1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT
    P2PKH,
    /// Pay-to-Script Hash, e.g. 34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53
    //P2SH,
    /// Pay-to-Witness-Script Hash, e.g. bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
    P2WSH,
    /// SegWit Pay-to-Witness-Public-Key Hash, e.g. 34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53
    P2SH_P2WPKH,
    /// Bech32, e.g. bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx
    Bech32,
}

impl Format for BitcoinFormat {}

impl BitcoinFormat {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: BitcoinNetwork>(&self) -> Vec<u8> {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefix(String::from_utf8(prefix.to_vec())?));
        }
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x6F, _) => Ok(BitcoinFormat::P2PKH),
            (0x05, _) | (0xC4, _) => Ok(BitcoinFormat::P2SH_P2WPKH),
            (0x62, 0x63) | (0x74, 0x62) => Ok(BitcoinFormat::Bech32),
            _ => return Err(AddressError::InvalidPrefix(String::from_utf8(prefix.to_vec())?)),
        }
    }
}

impl fmt::Display for BitcoinFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BitcoinFormat::P2PKH => write!(f, "p2pkh"),
            BitcoinFormat::P2WSH => write!(f, "p2wsh"),
            BitcoinFormat::P2SH_P2WPKH => write!(f, "p2sh_p2wpkh"),
            BitcoinFormat::Bech32 => write!(f, "bech32"),
        }
    }
}
