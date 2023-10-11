mod polkadot;
pub use polkadot::*;

mod kusama;
pub use kusama::*;

use anychain_core::Network;

pub trait PolkadotNetwork: Network {
    fn version() -> u8;
}
