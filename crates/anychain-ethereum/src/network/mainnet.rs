use super::EthereumNetwork;

#[derive(Copy, Clone, Debug)]
pub struct Ethereum;

impl EthereumNetwork for Ethereum {
    const CHAIN_ID: u32 = 1;
}

#[derive(Copy, Clone, Debug)]
pub struct EthereumClassic;

impl EthereumNetwork for EthereumClassic {
    const CHAIN_ID: u32 = 61;
}

#[derive(Copy, Clone, Debug)]
pub struct Polygon;

impl EthereumNetwork for Polygon {
    const CHAIN_ID: u32 = 137;
}

#[derive(Copy, Clone, Debug)]
pub struct Arbitrum;

impl EthereumNetwork for Arbitrum {
    const CHAIN_ID: u32 = 42161;
}

#[derive(Copy, Clone, Debug)]
pub struct Avalanche;

impl EthereumNetwork for Avalanche {
    const CHAIN_ID: u32 = 43114;
}

#[derive(Copy, Clone, Debug)]
pub struct Base;

impl EthereumNetwork for Base {
    const CHAIN_ID: u32 = 8453;
}

#[derive(Copy, Clone, Debug)]
pub struct BinanceSmartChain;

impl EthereumNetwork for BinanceSmartChain {
    const CHAIN_ID: u32 = 56;
}

#[derive(Copy, Clone, Debug)]
pub struct HuobiEco;

impl EthereumNetwork for HuobiEco {
    const CHAIN_ID: u32 = 128;
}

#[derive(Copy, Clone, Debug)]
pub struct Okex;

impl EthereumNetwork for Okex {
    const CHAIN_ID: u32 = 66;
}

#[derive(Copy, Clone, Debug)]
pub struct OpBnb;

impl EthereumNetwork for OpBnb {
    const CHAIN_ID: u32 = 204;
}

#[derive(Copy, Clone, Debug)]
pub struct Optimism;

impl EthereumNetwork for Optimism {
    const CHAIN_ID: u32 = 10;
}

#[derive(Copy, Clone, Debug)]
pub struct Linea;

impl EthereumNetwork for Linea {
    const CHAIN_ID: u32 = 59144;
}

#[derive(Copy, Clone, Debug)]
pub struct Xlayer;

impl EthereumNetwork for Xlayer {
    const CHAIN_ID: u32 = 196;
}

#[derive(Copy, Clone, Debug)]
pub struct Sei;

impl EthereumNetwork for Sei {
    const CHAIN_ID: u32 = 1329;
}

#[derive(Copy, Clone, Debug)]
pub struct Cro;

impl EthereumNetwork for Cro {
    const CHAIN_ID: u32 = 25;
}

#[derive(Copy, Clone, Debug)]
pub struct Mova;

impl EthereumNetwork for Mova {
    const CHAIN_ID: u32 = 61900;
}

#[derive(Copy, Clone, Debug)]
pub struct Ink;

impl EthereumNetwork for Ink {
    const CHAIN_ID: u32 = 57073;
}

#[derive(Copy, Clone, Debug)]
pub struct Morph;

impl EthereumNetwork for Morph {
    const CHAIN_ID: u32 = 2818;
}
