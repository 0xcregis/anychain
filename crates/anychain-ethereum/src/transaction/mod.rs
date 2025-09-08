pub mod contract;
pub mod eip1559;
pub mod eip3009;
pub mod eip7702;
pub mod legacy;

pub use contract::*;
pub use eip1559::*;
pub use eip3009::*;
pub use eip7702::*;
pub use legacy::*;

use anychain_core::{hex, TransactionId};
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for EthereumTransactionId {}

impl fmt::Display for EthereumTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}
