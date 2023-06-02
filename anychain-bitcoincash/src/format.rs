use anychain_core::Format;

use core::fmt;

/// Represents the format of a Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoincashFormat {
    /// CashAddr format
    CashAddr,
    /// Bitcoin P2PKH format
    Legacy,
}

impl Format for BitcoincashFormat {}

impl fmt::Display for BitcoincashFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CashAddr => write!(f, "CashAddr"),
            Self::Legacy => write!(f, "Legacy"),
        }
    }
}
