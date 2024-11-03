use {
    crate::no_std::{
        fmt::{Debug, Display},
        hash::Hash,
        FromStr, String,
    },
    thiserror::Error,
};

/// The interface for a generic network.
pub trait Network:
    Copy + Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
    const NAME: &'static str;
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid extended private key prefix: {0}")]
    InvalidExtendedPrivateKeyPrefix(String),

    #[error("invalid extended public key prefix: {0}")]
    InvalidExtendedPublicKeyPrefix(String),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),
}
