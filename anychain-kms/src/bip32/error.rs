//! Error type.

use core::fmt::{self, Display};

use hmac::digest::InvalidLength;

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Base58 errors.
    Base58,

    /// BIP39-related errors.
    Bip39,

    /// Child number-related errors.
    ChildNumber,

    /// Cryptographic errors.
    Crypto,

    /// Decoding errors (not related to Base58).
    Decode,

    /// Maximum derivation depth exceeded.
    Depth,

    /// Seed length invalid.
    SeedLength,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Base58 => f.write_str("base58 error"),
            Error::Bip39 => f.write_str("bip39 error"),
            Error::ChildNumber => f.write_str("invalid child number"),
            Error::Crypto => f.write_str("cryptographic error"),
            Error::Decode => f.write_str("decoding error"),
            Error::Depth => f.write_str("maximum derivation depth exceeded"),
            Error::SeedLength => f.write_str("seed length invalid"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bs58::decode::Error> for Error {
    fn from(_: bs58::decode::Error) -> Error {
        Error::Base58
    }
}

impl From<bs58::encode::Error> for Error {
    fn from(_: bs58::encode::Error) -> Error {
        Error::Base58
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Error {
        Error::Decode
    }
}

/*
impl From<digest::InvalidKeyLength> for Error {
    fn from(_: hmac::crypto_mac::InvalidKeyLength) -> Error {
        Error::Crypto
    }

}
 */

impl From<InvalidLength> for Error {
    fn from(_: InvalidLength) -> Error {
        Error::Crypto
    }
}
/*
impl From<k256::elliptic_curve::Error> for Error {
    fn from(_: k256::elliptic_curve::Error) -> Error {
        Error::Crypto
    }
}


impl From<k256::ecdsa::Error> for Error {
    fn from(_: k256::ecdsa::Error) -> Error {
        Error::Crypto
    }
}
*/

impl From<libsecp256k1::Error> for Error {
    fn from(_: libsecp256k1::Error) -> Error {
        Error::Crypto
    }
}
