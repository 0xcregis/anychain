use anychain_core::Format;

use core::fmt;

/// Represents the format of a Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EthereumFormat {
    Standard,
}

impl Format for EthereumFormat {}

impl fmt::Display for EthereumFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}
