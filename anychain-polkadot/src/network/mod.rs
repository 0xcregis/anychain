mod polkadot;
pub use polkadot::*;

mod kusama;
pub use kusama::*;

mod westend;
pub use westend::*;

mod rococo;
pub use rococo::*;

use anychain_core::Network;

pub trait PolkadotNetwork: Network {
    const VERSION: u8;
    const PALLET_ASSET: u8;
    const TRANSFER_ALLOW_DEATH: u8;
    const TRANSFER_KEEP_ALIVE: u8;
}
