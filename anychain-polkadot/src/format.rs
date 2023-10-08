use std::fmt::Display;
use anychain_core::Format;


#[derive(Hash, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct PolkadotFormat;

impl Format for PolkadotFormat {}

impl Display for PolkadotFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}