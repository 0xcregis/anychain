mod polkadot;
pub use polkadot::*;

mod kusama;
pub use kusama::*;

mod substrate;
pub use substrate::*;

use anychain_core::Network;

pub trait PolkadotNetwork: Network {
    fn version() -> u8;
}
