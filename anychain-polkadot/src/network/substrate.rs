use std::{fmt::Display, str::FromStr};

use crate::PolkadotNetwork;
use anychain_core::{Network, NetworkError};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Substrate;

impl Network for Substrate {
    const NAME: &'static str = "substrate";
}

impl PolkadotNetwork for Substrate {
    fn version() -> u8 {
        0x2a
    }
}

impl FromStr for Substrate {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Substrate {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
