use {
    crate::{
        AddressError,
        AmountError,
        FormatError,
        PublicKeyError,
        TransactionError,
        no_std::{String, io::Error as IoError, fmt::Error as FmtError, num::ParseIntError as NumParseIntError},
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Runtime Error:{0}")]
    RuntimeError(String),

    #[error("Invalid Address: {0}")]
    InvalidAddress(#[from] AddressError),

    #[error("Invalid Transaction: {0:}")]
    InvalidTransaction(#[from] TransactionError),

    #[error("Invalid Amount: {0:}")]
    InvalidAmount(#[from] AmountError),

    #[error("Invalid PublickKey: {0:}")]
    InvalidPublickKey(#[from] PublicKeyError),

    #[error("Invalid Format: {0:}")]
    InvalidFormat(#[from] FormatError),

    #[error("io error: {0:}")]
    Io(#[from] IoError),

    #[error("fmt error: {0:}")]
    Fmt(#[from] FmtError),

    #[error("fromHex error: {0:}")]
    FromHex(#[from] ::hex::FromHexError),

    #[error("parsing error: {0:}")]
    ParseInt(#[from] NumParseIntError),
}
