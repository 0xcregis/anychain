pub mod mainnet;
pub use mainnet::*;

pub mod testnet;
pub use testnet::*;

use anychain_core::Network;

pub trait BitcoincashNetwork: Network {
    fn prefix() -> &'static str;
    fn legacy_prefix() -> u8;
}
