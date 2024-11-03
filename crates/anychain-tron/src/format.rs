use anychain_core::Format;

use core::fmt;
use serde::Serialize;

/// Represents the format of a Ethereum address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TronFormat {
    Standard,
}

impl Format for TronFormat {}

impl fmt::Display for TronFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TronFormat")
    }
}
