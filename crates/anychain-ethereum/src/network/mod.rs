/// The interface for an Ethereum network.
#[derive(Clone, Send, Sync)]
pub trait EthereumNetwork {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
}

pub mod mainnet;
pub mod testnet;

pub use mainnet::*;
pub use testnet::*;