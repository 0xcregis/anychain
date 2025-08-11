use anychain_core::Network;

/// The interface for an Ethereum network.
pub trait EthereumNetwork: Network {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
}

pub mod mainnet;
pub mod testnet;

pub use mainnet::*;
pub use testnet::*;