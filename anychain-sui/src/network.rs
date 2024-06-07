use anychain_core::{
    no_std::{
        fmt::{Debug, Display},
        hash::Hash,
        FromStr,
    },
    Network, NetworkError,
};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct SuiNetwork;

impl Network for SuiNetwork {
    const NAME: &'static str = "sui";
}

impl FromStr for SuiNetwork {
    type Err = NetworkError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for SuiNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}
