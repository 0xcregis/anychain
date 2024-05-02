use crate::{
    format::Format,
    no_std::{
        fmt::{Debug, Display},
        hash::Hash,
        FromStr, String,
    },
    public_key::{PublicKey, PublicKeyError},
};

/// The interface for a generic address.
pub trait Address:
    'static + Clone + Debug + Display + FromStr + Hash + PartialEq + Eq + Send + Sized + Sync
{
    type SecretKey;
    type Format: Format;
    type PublicKey: PublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError>;

    /// Returns the address corresponding to the given public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError>;

    fn is_valid(address: &str) -> bool {
        Self::from_str(address).is_ok()
    }
}

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("{0:}: {1:}")]
    Crate(&'static str, String),

    #[error("invalid format conversion from {0:} to {1:}")]
    IncompatibleFormats(String, String),

    #[error("invalid address: {0:}")]
    InvalidAddress(String),

    #[error("invalid byte length: {0:}")]
    InvalidByteLength(usize),

    #[error("invalid character length: {0:}")]
    InvalidCharacterLength(usize),

    #[error("invalid address checksum: {{ expected: {0:}, found: {1:} }}")]
    InvalidChecksum(String, String),

    #[error("invalid network: {{ expected: {0}, found: {1} }}")]
    InvalidNetwork(String, String),

    #[error("invalid address prefix: {0:}")]
    InvalidPrefix(String),

    #[error("invalid address prefix length: {0:?}")]
    InvalidPrefixLength(usize),

    #[error("{0}")]
    Message(String),

    #[error("missing public spend key and/or public view key")]
    MissingPublicKey,

    #[error("{0}")]
    PublicKeyError(PublicKeyError),
}

impl From<crate::no_std::io::Error> for AddressError {
    fn from(error: crate::no_std::io::Error) -> Self {
        AddressError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<crate::no_std::FromUtf8Error> for AddressError {
    fn from(error: crate::no_std::FromUtf8Error) -> Self {
        AddressError::Crate("crate::no_std", format!("{:?}", error))
    }
}

impl From<&'static str> for AddressError {
    fn from(msg: &'static str) -> Self {
        AddressError::Message(msg.into())
    }
}

impl From<PublicKeyError> for AddressError {
    fn from(error: PublicKeyError) -> Self {
        AddressError::PublicKeyError(error)
    }
}

impl From<base58::FromBase58Error> for AddressError {
    fn from(error: base58::FromBase58Error) -> Self {
        AddressError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for AddressError {
    fn from(error: bech32::Error) -> Self {
        AddressError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::str::Utf8Error> for AddressError {
    fn from(error: core::str::Utf8Error) -> Self {
        AddressError::Crate("core::str", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for AddressError {
    fn from(error: hex::FromHexError) -> Self {
        AddressError::Crate("hex", format!("{:?}", error))
    }
}

impl From<rand_core::Error> for AddressError {
    fn from(error: rand_core::Error) -> Self {
        AddressError::Crate("rand", format!("{:?}", error))
    }
}
