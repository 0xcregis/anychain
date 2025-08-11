use super::EthereumNetwork;

#[derive(Copy, Clone, Debug)]
pub struct Ethereum;

#[derive(Copy, Clone, Debug)]
pub struct EthereumClassic;

#[derive(Copy, Clone, Debug)]
pub struct Polygon;

#[derive(Copy, Clone, Debug)]
pub struct Arbitrum;

#[derive(Copy, Clone, Debug)]
pub struct Avalanche;

#[derive(Copy, Clone, Debug)]
pub struct Base;

#[derive(Copy, Clone, Debug)]
pub struct BinanceSmartChain;

#[derive(Copy, Clone, Debug)]
pub struct HuobiEco;

#[derive(Copy, Clone, Debug)]
pub struct Okex;

#[derive(Copy, Clone, Debug)]
pub struct OpBnb;

#[derive(Copy, Clone, Debug)]
pub struct Optimism;

#[derive(Copy, Clone, Debug)]
pub struct Linea;

#[derive(Copy, Clone, Debug)]
pub struct Xlayer;

impl EthereumNetwork for Ethereum {
    const CHAIN_ID: u32 = 1;
    const NETWORK_ID: u32 = 1;
}

impl EthereumNetwork for EthereumClassic {
    const CHAIN_ID: u32 = 61;
    const NETWORK_ID: u32 = 61;
}

impl EthereumNetwork for Polygon {
    const CHAIN_ID: u32 = 137;
    const NETWORK_ID: u32 = 137;
}

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

impl EthereumNetwork for Linea {
    const CHAIN_ID: u32 = 59144;
    const NETWORK_ID: u32 = 59144;
}

impl EthereumNetwork for Xlayer {
    const CHAIN_ID: u32 = 196;
    const NETWORK_ID: u32 = 196;
}
