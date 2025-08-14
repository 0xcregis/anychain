use super::EthereumNetwork;

#[derive(Copy, Clone, Debug)]
pub struct Sepolia; // ETH testnet

#[derive(Copy, Clone, Debug)]
pub struct Goerli; // ETH testnet

#[derive(Copy, Clone, Debug)]
pub struct Kotti; // ETC testnet

#[derive(Copy, Clone, Debug)]
pub struct Mumbai; // Polygon testnet

#[derive(Copy, Clone, Debug)]
pub struct Amoy; // Polygon testnet

#[derive(Copy, Clone, Debug)]
pub struct ArbitrumGoerli;

#[derive(Copy, Clone, Debug)]
pub struct AvalancheTestnet;

#[derive(Copy, Clone, Debug)]
pub struct BaseGoerli;

#[derive(Copy, Clone, Debug)]
pub struct BinanceSmartChainTestnet;

#[derive(Copy, Clone, Debug)]
pub struct HuobiEcoTestnet;

#[derive(Copy, Clone, Debug)]
pub struct OkexTestnet;

#[derive(Copy, Clone, Debug)]
pub struct OpBnbTestnet;

#[derive(Copy, Clone, Debug)]
pub struct OptimismGoerli;

#[derive(Copy, Clone, Debug)]
pub struct LineaSepolia;

#[derive(Copy, Clone, Debug)]
pub struct XlayerTestnet;

#[derive(Copy, Clone, Debug)]
pub struct SeiTestnet;

#[derive(Copy, Clone, Debug)]
pub struct CroTestnet;

// ETH testnet
impl EthereumNetwork for Sepolia {
    const CHAIN_ID: u32 = 11155111;
}

// ETH testnet
impl EthereumNetwork for Goerli {
    const CHAIN_ID: u32 = 5;
}

// ETC testnet
impl EthereumNetwork for Kotti {
    const CHAIN_ID: u32 = 6;
}

// Polygon testnet
impl EthereumNetwork for Mumbai {
    const CHAIN_ID: u32 = 80001;
}

// Polygon testnet
impl EthereumNetwork for Amoy {
    const CHAIN_ID: u32 = 80002;
}

impl EthereumNetwork for ArbitrumGoerli {
    const CHAIN_ID: u32 = 421613;
}

impl EthereumNetwork for AvalancheTestnet {
    const CHAIN_ID: u32 = 43113;
}

impl EthereumNetwork for BaseGoerli {
    const CHAIN_ID: u32 = 84531;
}

impl EthereumNetwork for BinanceSmartChainTestnet {
    const CHAIN_ID: u32 = 97;
}

impl EthereumNetwork for HuobiEcoTestnet {
    const CHAIN_ID: u32 = 256;
}

impl EthereumNetwork for OkexTestnet {
    const CHAIN_ID: u32 = 65;
}

impl EthereumNetwork for OpBnbTestnet {
    const CHAIN_ID: u32 = 5611;
}

impl EthereumNetwork for OptimismGoerli {
    const CHAIN_ID: u32 = 420;
}

impl EthereumNetwork for LineaSepolia {
    const CHAIN_ID: u32 = 59141;
}

impl EthereumNetwork for XlayerTestnet {
    const CHAIN_ID: u32 = 195;
}

impl EthereumNetwork for SeiTestnet {
    const CHAIN_ID: u32 = 1328;
}

impl EthereumNetwork for CroTestnet {
    const CHAIN_ID: u32 = 338;
}
