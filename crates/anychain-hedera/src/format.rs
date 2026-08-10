use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HederaFormat {
    #[default]
    Standard,
}

impl Format for HederaFormat {}

impl fmt::Display for HederaFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(HederaFormat::Standard.to_string(), "Standard");
    }
}
