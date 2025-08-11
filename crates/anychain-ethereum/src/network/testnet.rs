use super::EthereumNetwork;

pub struct Sepolia; // ETH testnet
pub struct Goerli; // ETH testnet
pub struct Kotti; // ETC testnet
pub struct Mumbai; // Polygon testnet
pub struct Amoy; // Polygon testnet
pub struct ArbitrumGoerli;
pub struct AvalancheTestnet;
pub struct BaseGoerli;
pub struct BinanceSmartChainTestnet;
pub struct HuobiEcoTestnet;
pub struct OkexTestnet;
pub struct OpBnbTestnet;
pub struct OptimismGoerli;
pub struct LineaSepolia;
pub struct XlayerTestnet;


// ETH testnet
impl EthereumNetwork for Sepolia {
    const CHAIN_ID: u32 = 11155111;
    const NETWORK_ID: u32 = 11155111;
}

// ETH testnet
impl EthereumNetwork for Goerli {
    const CHAIN_ID: u32 = 5;
    const NETWORK_ID: u32 = 5;
}

// ETC testnet
impl EthereumNetwork for Kotti {
    const CHAIN_ID: u32 = 6;
    const NETWORK_ID: u32 = 6;
}

// Polygon testnet
impl EthereumNetwork for Mumbai {
    const CHAIN_ID: u32 = 80001;
    const NETWORK_ID: u32 = 80001;
}

// Polygon testnet
impl EthereumNetwork for Amoy {
    const CHAIN_ID: u32 = 80002;
    const NETWORK_ID: u32 = 80002;
}

impl EthereumNetwork for ArbitrumGoerli {
    const CHAIN_ID: u32 = 421613;
    const NETWORK_ID: u32 = 421613;
}

impl EthereumNetwork for AvalancheTestnet {
    const CHAIN_ID: u32 = 43113;
    const NETWORK_ID: u32 = 43113;
}

impl EthereumNetwork for BaseGoerli {
    const CHAIN_ID: u32 = 84531;
    const NETWORK_ID: u32 = 84531;
}

impl EthereumNetwork for BinanceSmartChainTestnet {
    const CHAIN_ID: u32 = 97;
    const NETWORK_ID: u32 = 97;
}

impl EthereumNetwork for HuobiEcoTestnet {
    const CHAIN_ID: u32 = 256;
    const NETWORK_ID: u32 = 256;
}

impl EthereumNetwork for OkexTestnet {
    const CHAIN_ID: u32 = 65;
    const NETWORK_ID: u32 = 65;
}

impl EthereumNetwork for OpBnbTestnet {
    const CHAIN_ID: u32 = 5611;
    const NETWORK_ID: u32 = 5611;
}

impl EthereumNetwork for OptimismGoerli {
    const CHAIN_ID: u32 = 420;
    const NETWORK_ID: u32 = 420;
}

impl EthereumNetwork for LineaSepolia {
    const CHAIN_ID: u32 = 59141;
    const NETWORK_ID: u32 = 59141;
}

impl EthereumNetwork for XlayerTestnet {
    const CHAIN_ID: u32 = 195;
    const NETWORK_ID: u32 = 195;
}