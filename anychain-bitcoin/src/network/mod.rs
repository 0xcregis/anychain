use crate::format::BitcoinFormat;
use anychain_core::no_std::*;
use anychain_core::{AddressError, Network};

pub mod bitcoin;
pub use self::bitcoin::*;

pub mod bitcoin_testnet;
pub use self::bitcoin_testnet::*;

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
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError>;
}
