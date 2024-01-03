use std::{fmt::Display, str::FromStr};

use crate::PolkadotNetwork;
use anychain_core::{Network, NetworkError};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Rococo;

impl Network for Rococo {
    const NAME: &'static str = "rococo";
}

impl PolkadotNetwork for Rococo {
    const VERSION: u8 = 0x2a;
    const PALLET_ASSET: u8 = 4;
    const TRANSFER_ALLOW_DEATH: u8 = 0;
    const TRANSFER_KEEP_ALIVE: u8 = 3;
}

impl FromStr for Rococo {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Rococo {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
