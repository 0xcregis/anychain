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
pub struct AvalancheTestnet; // Avalanche testnet

// Avalanche testnet
impl EthereumNetwork for AvalancheTestnet {
    const CHAIN_ID: u32 = 43113;
}

#[derive(Copy, Clone, Debug)]
pub struct BaseGoerli; // Base testnet

// Base testnet
impl EthereumNetwork for BaseGoerli {
    const CHAIN_ID: u32 = 84531;
}

#[derive(Copy, Clone, Debug)]
pub struct BinanceSmartChainTestnet; // BinanceSmartChain testnet

// BinanceSmartChain testnet
impl EthereumNetwork for BinanceSmartChainTestnet {
    const CHAIN_ID: u32 = 97;
}

#[derive(Copy, Clone, Debug)]
pub struct HuobiEcoTestnet; // HuobiEco testnet

// HuobiEco testnet
impl EthereumNetwork for HuobiEcoTestnet {
    const CHAIN_ID: u32 = 256;
}

#[derive(Copy, Clone, Debug)]
pub struct OkexTestnet; // Okex testnet

// Okex testnet
impl EthereumNetwork for OkexTestnet {
    const CHAIN_ID: u32 = 65;
}

#[derive(Copy, Clone, Debug)]
pub struct OpBnbTestnet; // OpBnb testnet

// OpBnb testnet
impl EthereumNetwork for OpBnbTestnet {
    const CHAIN_ID: u32 = 5611;
}

#[derive(Copy, Clone, Debug)]
pub struct OptimismGoerli; // Optimism testnet

// Optimism testnet
impl EthereumNetwork for OptimismGoerli {
    const CHAIN_ID: u32 = 420;
}

#[derive(Copy, Clone, Debug)]
pub struct LineaSepolia; // Linea testnet

// Linea testnet
impl EthereumNetwork for LineaSepolia {
    const CHAIN_ID: u32 = 59141;
}

#[derive(Copy, Clone, Debug)]
pub struct XlayerTestnet; // Xlayer testnet

// Xlayer testnet
impl EthereumNetwork for XlayerTestnet {
    const CHAIN_ID: u32 = 195;
}

#[derive(Copy, Clone, Debug)]
pub struct SeiTestnet; // Sei testnet

// Sei testnet
impl EthereumNetwork for SeiTestnet {
    const CHAIN_ID: u32 = 1328;
}

#[derive(Copy, Clone, Debug)]
pub struct CroTestnet; // Cro testnet

// Cro testnet
impl EthereumNetwork for CroTestnet {
    const CHAIN_ID: u32 = 338;
}

#[derive(Copy, Clone, Debug)]
pub struct MovaTestnet; // Mova testnet

// Mova testnet
impl EthereumNetwork for MovaTestnet {
    const CHAIN_ID: u32 = 10323;
}

#[derive(Copy, Clone, Debug)]
pub struct InkTestnet; // Ink testnet

// Ink testnet
impl EthereumNetwork for InkTestnet {
    const CHAIN_ID: u32 = 763373;
}

#[derive(Copy, Clone, Debug)]
pub struct MorphTestnet; // Morph testnet

// Morph testnet
impl EthereumNetwork for MorphTestnet {
    const CHAIN_ID: u32 = 2710;
}
