use anychain_core::Network;

pub mod ethereum;
pub use self::ethereum::*;

pub mod goerli;
pub use self::goerli::*;

pub mod ethereum_classic;
pub use self::ethereum_classic::*;

pub mod kotti;
pub use self::kotti::*;

pub mod polygon;
pub use self::polygon::*;

pub mod mumbai;
pub use self::mumbai::*;

pub mod huobi_eco;
pub use self::huobi_eco::*;

pub mod huobi_eco_testnet;
pub use self::huobi_eco_testnet::*;

pub mod binance_smart_chain;
pub use self::binance_smart_chain::*;

pub mod binance_smart_chain_testnet;
pub use self::binance_smart_chain_testnet::*;

/// The interface for an Ethereum network.
pub trait EthereumNetwork: Network {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
}
