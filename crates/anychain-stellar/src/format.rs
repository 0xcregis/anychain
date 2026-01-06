use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StellarFormat {
    #[default]
    Standard,
}

impl Format for StellarFormat {}

impl fmt::Display for StellarFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(StellarFormat::Standard.to_string(), "Standard");
    }
}
