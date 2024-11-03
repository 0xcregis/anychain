use anychain_core::Format;

use core::fmt;

/// Represents the format of a Ripple address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RippleFormat {
    Standard,
}

impl Format for RippleFormat {}

impl fmt::Display for RippleFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}
