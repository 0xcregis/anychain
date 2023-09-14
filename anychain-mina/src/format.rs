use anychain_core::Format;

use core::fmt;

/// Represents the format of a Ripple address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MinaFormat {
    Standard,
}

impl Format for MinaFormat {}

impl fmt::Display for MinaFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}
