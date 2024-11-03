use crate::Prefix;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Format};

use core::fmt;
use core::str::FromStr;
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
    /// CashAddr, e.g. bitcoincash:qpkxa3xypl6rfp4nzewh9xrqnv90n2yxrcr0pmwas4
    CashAddr,
}

impl Format for BitcoinFormat {}

impl BitcoinFormat {
    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: Prefix) -> Result<Self, AddressError> {
        match prefix {
            Prefix::AddressPrefix(prefix) => match prefix.as_str() {
                "bc" | "tb" | "ltc" | "tltc" => Ok(Self::Bech32),
                "bitcoincash" | "bchtest" => Ok(Self::CashAddr),
                _ => Err(AddressError::Message(format!(
                    "Unrecognized address prefix {}",
                    prefix,
                ))),
            },
            Prefix::Version(version) => match version {
                0x00 | 0x6f | 0x1e | 0x71 | 0x30 => Ok(Self::P2PKH),
                0x05 | 0xc4 | 0x16 | 0x32 | 0x3a => Ok(Self::P2SH_P2WPKH),
                _ => Err(AddressError::Message(format!(
                    "Unrecognized version byte {}",
                    version,
                ))),
            },
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
            BitcoinFormat::CashAddr => write!(f, "cash_addr"),
        }
    }
}

impl FromStr for BitcoinFormat {
    type Err = AddressError;

    fn from_str(format: &str) -> Result<Self, AddressError> {
        match format {
            "p2pkh" => Ok(BitcoinFormat::P2PKH),
            "p2sh_p2wpkh" => Ok(BitcoinFormat::P2SH_P2WPKH),
            "p2wsh" => Ok(BitcoinFormat::P2WSH),
            "bech32" => Ok(BitcoinFormat::Bech32),
            "cash_addr" => Ok(BitcoinFormat::CashAddr),
            _ => Err(AddressError::Message(format!(
                "Unrecognized bitcoin address format {}",
                format,
            ))),
        }
    }
}
