use crate::{PolkadotAddress, PolkadotNetwork};


pub struct PolkadotTransactionParameters<N: PolkadotNetwork> {
    from: PolkadotAddress<N>,
    to: PolkadotAddress<N>,



}

pub struct PolkadotTransaction<N: PolkadotNetwork> {
    pub params: PolkadotTransactionParameters<N>,
    pub signature: Vec<u8>
}
