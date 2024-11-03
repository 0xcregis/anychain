use std::{fmt::Display, str::FromStr};

use crate::PolkadotNetwork;
use anychain_core::{Network, NetworkError};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Westend;

impl Network for Westend {
    const NAME: &'static str = "westend";
}

impl PolkadotNetwork for Westend {
    const VERSION: u8 = 0x2a;
    const PALLET_ASSET: u8 = 4;
    const TRANSFER_ALLOW_DEATH: u8 = 0;
    const TRANSFER_KEEP_ALIVE: u8 = 3;
}

impl FromStr for Westend {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Westend {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
