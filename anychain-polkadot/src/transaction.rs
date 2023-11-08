use crate::{PolkadotAddress, PolkadotNetwork};
use parity_scale_codec::Encode;


pub struct PolkadotTransactionParameters<N: PolkadotNetwork> {
    extrinsic_version: u8,
    spec_version: u32,
    tx_version: u32,
    genesis_hash: Vec<u8>,
    block_hash: Vec<u8>,
    from: PolkadotAddress<N>,
    to: PolkadotAddress<N>,



}

pub struct PolkadotTransaction<N: PolkadotNetwork> {
    pub params: PolkadotTransactionParameters<N>,
    pub signature: Vec<u8>
}
