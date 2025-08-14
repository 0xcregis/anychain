pub trait EthereumNetwork: Copy + Clone + Send + Sync + 'static {
    const CHAIN_ID: u32;
}

pub mod mainnet;
pub mod testnet;

pub use mainnet::*;
pub use testnet::*;
