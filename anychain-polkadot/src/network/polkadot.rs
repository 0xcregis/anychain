use std::{fmt::Display, str::FromStr};

use crate::PolkadotNetwork;
use anychain_core::{Network, NetworkError};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Polkadot;

impl Network for Polkadot {
    const NAME: &'static str = "polkadot";
}

impl PolkadotNetwork for Polkadot {
    const VERSION: u8 = 0x00;
    const PALLET_ASSET: u8 = 5;
    const TRANSFER_ALLOW_DEATH: u8 = 0;
    const TRANSFER_KEEP_ALIVE: u8 = 3;
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
