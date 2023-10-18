use anychain_core::Format;

use core::fmt;

/// Represents the format of a Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeoFormat {
    Standard,
}

impl Format for NeoFormat {}

impl fmt::Display for NeoFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}
