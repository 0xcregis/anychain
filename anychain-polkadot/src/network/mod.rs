mod polkadot;
mod kusama;

use anychain_core::Network;

pub trait PolkadotNetwork: Network {
    fn version() -> u8;
}
