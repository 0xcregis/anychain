use std::{str::FromStr, fmt::Display};

use anychain_core::{Network, NetworkError};
use crate::PolkadotNetwork;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Polkadot;

impl Network for Polkadot {
    const NAME: &'static str = "polkadot";
}

impl PolkadotNetwork for Polkadot {
    fn version() -> u8 {
        0x00
    }
}

impl FromStr for Polkadot {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Polkadot {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}