use crate::format::BitcoinFormat;
use chainlib_core::no_std::*;
use chainlib_core::{AddressError, Network};

pub mod mainnet;
pub use self::mainnet::*;

pub mod testnet;
pub use self::testnet::*;

/// The interface for a Bitcoin network.
pub trait BitcoinNetwork: Network {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError>;
}
