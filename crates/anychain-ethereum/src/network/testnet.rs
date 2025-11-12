use super::EthereumNetwork;

#[derive(Copy, Clone, Debug)]
pub struct Sepolia; // ETH testnet

// ETH testnet
impl EthereumNetwork for Sepolia {
    const CHAIN_ID: u32 = 11155111;
}

#[derive(Copy, Clone, Debug)]
pub struct Goerli; // ETH testnet

// ETH testnet
impl EthereumNetwork for Goerli {
    const CHAIN_ID: u32 = 5;
}

#[derive(Copy, Clone, Debug)]
pub struct Kotti; // ETC testnet

// ETC testnet
impl EthereumNetwork for Kotti {
    const CHAIN_ID: u32 = 6;
}

#[derive(Copy, Clone, Debug)]
pub struct Mumbai; // Polygon testnet

// Polygon testnet
impl EthereumNetwork for Mumbai {
    const CHAIN_ID: u32 = 80001;
}

#[derive(Copy, Clone, Debug)]
pub struct Amoy; // Polygon testnet

// Polygon testnet
impl EthereumNetwork for Amoy {
    const CHAIN_ID: u32 = 80002;
}

#[derive(Copy, Clone, Debug)]
pub struct ArbitrumGoerli; // Arbitrum testnet

// Arbitrum testnet
impl EthereumNetwork for ArbitrumGoerli {
    const CHAIN_ID: u32 = 421613;
}

#[derive(Copy, Clone, Debug)]
pub struct AvalancheTestnet;

impl EthereumNetwork for AvalancheTestnet {
    const CHAIN_ID: u32 = 43113;
}

#[derive(Copy, Clone, Debug)]
pub struct BaseGoerli;

impl EthereumNetwork for BaseGoerli {
    const CHAIN_ID: u32 = 84531;
}

#[derive(Copy, Clone, Debug)]
pub struct BinanceSmartChainTestnet;

impl EthereumNetwork for BinanceSmartChainTestnet {
    const CHAIN_ID: u32 = 97;
}

#[derive(Copy, Clone, Debug)]
pub struct HuobiEcoTestnet;

impl EthereumNetwork for HuobiEcoTestnet {
    const CHAIN_ID: u32 = 256;
}

#[derive(Copy, Clone, Debug)]
pub struct OkexTestnet;

impl EthereumNetwork for OkexTestnet {
    const CHAIN_ID: u32 = 65;
}

#[derive(Copy, Clone, Debug)]
pub struct OpBnbTestnet;

impl EthereumNetwork for OpBnbTestnet {
    const CHAIN_ID: u32 = 5611;
}

#[derive(Copy, Clone, Debug)]
pub struct OptimismGoerli;

impl EthereumNetwork for OptimismGoerli {
    const CHAIN_ID: u32 = 420;
}

#[derive(Copy, Clone, Debug)]
pub struct LineaSepolia;

impl EthereumNetwork for LineaSepolia {
    const CHAIN_ID: u32 = 59141;
}

#[derive(Copy, Clone, Debug)]
pub struct XlayerTestnet;

impl EthereumNetwork for XlayerTestnet {
    const CHAIN_ID: u32 = 195;
}

#[derive(Copy, Clone, Debug)]
pub struct SeiTestnet;

impl EthereumNetwork for SeiTestnet {
    const CHAIN_ID: u32 = 1328;
}

#[derive(Copy, Clone, Debug)]
pub struct CroTestnet;

impl EthereumNetwork for CroTestnet {
    const CHAIN_ID: u32 = 338;
}

#[derive(Copy, Clone, Debug)]
pub struct MovaTestnet;

impl EthereumNetwork for MovaTestnet {
    const CHAIN_ID: u32 = 10323;
}

#[derive(Copy, Clone, Debug)]
pub struct InkTestnet;

impl EthereumNetwork for InkTestnet {
    const CHAIN_ID: u32 = 763373;
}
