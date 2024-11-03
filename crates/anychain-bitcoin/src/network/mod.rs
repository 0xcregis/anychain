use crate::format::BitcoinFormat;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network};

pub mod bitcoin;
pub use self::bitcoin::*;

pub mod bitcoin_testnet;
pub use self::bitcoin_testnet::*;

pub mod bitcoincash;
pub use self::bitcoincash::*;

pub mod bitcoincash_testnet;
pub use self::bitcoincash_testnet::*;

pub mod litecoin;
pub use self::litecoin::*;

pub mod litecoin_testnet;
pub use self::litecoin_testnet::*;

pub mod dogecoin;
pub use self::dogecoin::*;

pub mod dogecoin_testnet;
pub use self::dogecoin_testnet::*;

/// The interface for a Bitcoin network.
pub trait BitcoinNetwork: Network {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: BitcoinFormat) -> Result<Prefix, AddressError>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: Prefix) -> Result<Self, AddressError>;
}

#[derive(Clone)]
pub enum Prefix {
    // address prefix of utxo compatible blockchains
    AddressPrefix(String),
    // version byte prepended to the hash160
    Version(u8),
}

impl Prefix {
    pub fn version(self) -> u8 {
        if let Self::Version(version) = self {
            version
        } else {
            panic!("Attempt to get version byte from an AddressPrefix");
        }
    }

    pub fn prefix(self) -> String {
        if let Self::AddressPrefix(prefix) = self {
            prefix
        } else {
            panic!("Attempt to get prefix from a version");
        }
    }

    pub fn from_version(version: u8) -> Self {
        Self::Version(version)
    }

    pub fn from_prefix(prefix: &str) -> Self {
        Self::AddressPrefix(prefix.to_string())
    }
}
