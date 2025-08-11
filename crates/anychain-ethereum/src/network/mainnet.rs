use super::EthereumNetwork;

pub struct Ethereum;
pub struct EthereumClassic;
pub struct Polygon;
pub struct Arbitrum;
pub struct Avalanche;
pub struct Base;
pub struct BinanceSmartChain;
pub struct HuobiEco;
pub struct Okex;
pub struct OpBnb;
pub struct Optimism;
pub struct Linea;
pub struct Xlayer;


impl EthereumNetwork for Arbitrum {
    const CHAIN_ID: u32 = 42161;
    const NETWORK_ID: u32 = 42161;
}

impl EthereumNetwork for Avalanche {
    const CHAIN_ID: u32 = 43114;
    const NETWORK_ID: u32 = 43114;
}

impl EthereumNetwork for Base {
    const CHAIN_ID: u32 = 8453;
    const NETWORK_ID: u32 = 8453;
}

impl EthereumNetwork for BinanceSmartChain {
    const CHAIN_ID: u32 = 56;
    const NETWORK_ID: u32 = 56;
}

impl EthereumNetwork for EthereumClassic {
    const CHAIN_ID: u32 = 61;
    const NETWORK_ID: u32 = 61;
}

impl EthereumNetwork for Ethereum {
    const CHAIN_ID: u32 = 1;
    const NETWORK_ID: u32 = 1;
}

impl EthereumNetwork for HuobiEco {
    const CHAIN_ID: u32 = 128;
    const NETWORK_ID: u32 = 128;
}

impl EthereumNetwork for Okex {
    const CHAIN_ID: u32 = 66;
    const NETWORK_ID: u32 = 66;
}

impl EthereumNetwork for OpBnb {
    const CHAIN_ID: u32 = 204;
    const NETWORK_ID: u32 = 204;
}

impl EthereumNetwork for Optimism {
    const CHAIN_ID: u32 = 10;
    const NETWORK_ID: u32 = 10;
}

impl EthereumNetwork for Polygon {
    const CHAIN_ID: u32 = 137;
    const NETWORK_ID: u32 = 137;
}

impl EthereumNetwork for Linea {
    const CHAIN_ID: u32 = 59144;
    const NETWORK_ID: u32 = 59144;
}

impl EthereumNetwork for Xlayer {
    const CHAIN_ID: u32 = 196;
    const NETWORK_ID: u32 = 196;
}