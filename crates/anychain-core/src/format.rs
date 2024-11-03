use {
    crate::no_std::{
        fmt::{Debug, Display},
        hash::Hash,
        String, Vec,
    },
    thiserror::Error,
};

/// The interface for a generic format.
pub trait Format:
    Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error("invalid address prefix: {0:?}")]
    InvalidPrefix(Vec<u8>),

    #[error("invalid version bytes: {0:?}")]
    InvalidVersionBytes(Vec<u8>),

    #[error("unsupported derivation path for the format: {0}")]
    UnsupportedDerivationPath(String),
}
