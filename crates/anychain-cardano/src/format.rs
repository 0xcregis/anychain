use crate::network::CardanoNetwork;
use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CardanoFormat {
    Base(CardanoNetwork),
    Enterprise(CardanoNetwork),
    Reward(CardanoNetwork),
    Byron(CardanoNetwork),
}
impl CardanoFormat {}

impl Default for CardanoFormat {
    fn default() -> Self {
        Self::Base(CardanoNetwork::default())
    }
}

impl Format for CardanoFormat {}

impl fmt::Display for CardanoFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CardanoFormat::Base(_) => write!(f, "base"),
            CardanoFormat::Enterprise(_) => write!(f, "enterprise"),
            CardanoFormat::Reward(_) => write!(f, "reward"),
            CardanoFormat::Byron(_) => write!(f, "byron"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(
            CardanoFormat::Base(CardanoNetwork::Mainnet).to_string(),
            "base"
        );
        assert_eq!(
            CardanoFormat::Enterprise(CardanoNetwork::Mainnet).to_string(),
            "enterprise"
        );
        assert_eq!(
            CardanoFormat::Reward(CardanoNetwork::Mainnet).to_string(),
            "reward"
        );
        assert_eq!(
            CardanoFormat::Byron(CardanoNetwork::Mainnet).to_string(),
            "byron"
        );
    }
}
