use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SolanaFormat {
    #[default]
    Standard,
}

impl Format for SolanaFormat {}

impl fmt::Display for SolanaFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(SolanaFormat::Standard.to_string(), "Standard");
    }
}
