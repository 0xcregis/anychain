use std::{fmt::Display, str::FromStr};

use crate::PolkadotNetwork;
use anychain_core::{Network, NetworkError};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Kusama;

impl Network for Kusama {
    const NAME: &'static str = "kusama";
}

impl PolkadotNetwork for Kusama {
    const VERSION: u8 = 0x02;
    const PALLET_ASSET: u8 = 4;
    const TRANSFER_ALLOW_DEATH: u8 = 0;
    const TRANSFER_KEEP_ALIVE: u8 = 3;
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
