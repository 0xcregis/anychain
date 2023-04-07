use anychain_core::Format;

use core::fmt;
use serde::Serialize;

/// Represents the format of a Filecoin address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilecoinFormat {
    Base32,
}

impl Format for FilecoinFormat {}

impl fmt::Display for FilecoinFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Base32")
    }
}
