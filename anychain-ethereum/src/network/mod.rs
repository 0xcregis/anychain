use anychain_core::Network;

pub mod ethereum;
pub use self::ethereum::*;

pub mod goerli;
pub use self::goerli::*;

pub mod sepolia;
pub use self::sepolia::*;

pub mod ethereum_classic;
pub use self::ethereum_classic::*;

pub mod kotti;
pub use self::kotti::*;

pub mod polygon;
pub use self::polygon::*;

pub mod mumbai;
pub use self::mumbai::*;

pub mod avalanche;
pub use self::avalanche::*;

pub mod avalanche_testnet;
pub use self::avalanche_testnet::*;

pub mod arbitrum;
pub use self::arbitrum::*;

pub mod arbitrum_goerli;
pub use self::arbitrum_goerli::*;

pub mod optimism;
pub use self::optimism::*;

pub mod optimism_goerli;
pub use self::optimism_goerli::*;

pub mod base;
pub use self::base::*;

pub mod base_goerli;
pub use self::base_goerli::*;

pub mod huobi_eco;
pub use self::huobi_eco::*;

pub mod huobi_eco_testnet;
pub use self::huobi_eco_testnet::*;

pub mod binance_smart_chain;
pub use self::binance_smart_chain::*;

pub mod binance_smart_chain_testnet;
pub use self::binance_smart_chain_testnet::*;

pub mod okex;
pub use self::okex::*;

pub mod okex_testnet;
pub use self::okex_testnet::*;

pub mod opbnb;
pub use self::opbnb::*;

pub mod opbnb_testnet;
pub use self::opbnb_testnet::*;

/// The interface for an Ethereum network.
pub trait EthereumNetwork: Network {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
}
