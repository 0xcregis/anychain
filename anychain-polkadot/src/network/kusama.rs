use std::{str::FromStr, fmt::Display};

use anychain_core::{Network, NetworkError};
use crate::PolkadotNetwork;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Kusama;

impl Network for Kusama {
    const NAME: &'static str = "kusama";
}

impl PolkadotNetwork for Kusama {
    fn version() -> u8 {
        0x02
    }
}

impl FromStr for Kusama {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Kusama {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}