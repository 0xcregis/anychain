use {
    crate::{
        address::{Address, AddressError},
        amount::AmountError,
        format::Format,
        no_std::{
            fmt::{Debug, Display},
            hash::Hash,
            String, Vec,
        },
        public_key::PublicKey,
        utilities::crypto::keccak256,
    },
    thiserror::Error,
};

/**
 * 返回合约函数签名，取keccak256 hash值的前4个Bytes
 */
pub fn func_selector(func_signature: &str) -> [u8; 4] {
    let mut func_id = [0u8; 4];
    func_id.clone_from_slice(&keccak256(func_signature.as_bytes())[..4]);
    func_id
}

/// The interface for a generic transaction id.
pub trait TransactionId:
    Clone + Debug + Display + Send + Sync + 'static + Eq + Sized + Hash
{
}

/// The interface for a generic transactions.
pub trait Transaction: Clone + Send + Sync + 'static {
    type Address: Address;
    type Format: Format;
    type PublicKey: PublicKey;
    type TransactionId: TransactionId;
    type TransactionParameters;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError>;

    /// Returns a signed transaction bytes given the (signature,recovery_id)
    fn sign(&mut self, signature: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError>;

    /// Returns a transaction given the transaction bytes.
    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError>;

    /// Returns the transaction in bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError>;

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError>;
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("{0}")]
    AddressError(#[from] AddressError),

    #[error("{0}")]
    AmountError(#[from] AmountError),

    #[error("witnesses have a conflicting anchor")]
    ConflictingWitnessAnchors(),

    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error("Failed note decryption for enc_cyphertext: {0}")]
    FailedNoteDecryption(String),

    #[error("invalid binding signature for the transaction")]
    InvalidBindingSig(),

    #[error("invalid chain id {0}")]
    InvalidChainId(u8),

    #[error("invalid ephemeral key {0}")]
    InvalidEphemeralKey(String),

    #[error("insufficient information to craft transaction. missing: {0}")]
    InvalidInputs(String),

    #[error("invalid output address: {0}")]
    InvalidOutputAddress(String),

    #[error("invalid ouptut description for address: {0}")]
    InvalidOutputDescription(String),

    #[error("invalid transaction RLP length: expected - 9, found - {0}")]
    InvalidRlpLength(usize),

    #[error("invalid script pub key for format: {0}")]
    InvalidScriptPubKey(String),

    #[error("invalid segwit flag: {0}")]
    InvalidSegwitFlag(usize),

    #[error("invalid spend description for address")]
    InvalidSpendDescription,

    #[error("invalid transaction id {0}")]
    InvalidTransactionId(usize),

    #[error(
        "invalid transaction - either both sender and signature should be present, or neither"
    )]
    InvalidTransactionState,

    #[error("invalid variable size integer: {0}")]
    InvalidVariableSizeInteger(usize),

    #[error("{0}")]
    Message(String),

    #[error("missing diversifier, check that the address is a Sapling address")]
    MissingDiversifier,

    #[error("missing outpoint address")]
    MissingOutpointAddress,

    #[error("missing outpoint amount")]
    MissingOutpointAmount,

    #[error("missing outpoint script public key")]
    MissingOutpointScriptPublicKey,

    #[error("missing output parameters")]
    MissingOutputParameters,

    #[error("missing spend description")]
    MissingSpendDescription,

    #[error("missing spend parameters")]
    MissingSpendParameters,

    #[error("missing signature")]
    MissingSignature,

    #[error("Null Error")]
    NullError(()),

    #[error("Joinsplits are not supported")]
    UnsupportedJoinsplits,

    #[error("unsupported preimage operation on address format of {0}")]
    UnsupportedPreimage(String),

    #[error("Reaching end of Ripple SerializedType 'Object'")]
    EndOfObject,

    #[error("Reaching end of Ripple SerializedType 'Array'")]
    EndOfArray,
}

impl From<crate::no_std::io::Error> for TransactionError {
    fn from(error: crate::no_std::io::Error) -> Self {
        TransactionError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<&'static str> for TransactionError {
    fn from(msg: &'static str) -> Self {
        TransactionError::Message(msg.into())
    }
}

impl From<()> for TransactionError {
    fn from(error: ()) -> Self {
        TransactionError::NullError(error)
    }
}

impl From<base58::FromBase58Error> for TransactionError {
    fn from(error: base58::FromBase58Error) -> Self {
        TransactionError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for TransactionError {
    fn from(error: bech32::Error) -> Self {
        TransactionError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::num::ParseIntError> for TransactionError {
    fn from(error: core::num::ParseIntError) -> Self {
        TransactionError::Crate("core::num", format!("{:?}", error))
    }
}

impl From<core::str::ParseBoolError> for TransactionError {
    fn from(error: core::str::ParseBoolError) -> Self {
        TransactionError::Crate("core::str", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for TransactionError {
    fn from(error: hex::FromHexError) -> Self {
        TransactionError::Crate("hex", format!("{:?}", error))
    }
}

// impl From<rlp::DecoderError> for TransactionError {
//     fn from(error: rlp::DecoderError) -> Self {
//         TransactionError::Crate("rlp", format!("{:?}", error))
//     }
// }

// impl From<libsecp256k1::Error> for TransactionError {
//     fn from(error: libsecp256k1::Error) -> Self {
//         TransactionError::Crate("libsecp256k1", format!("{:?}", error))
//     }
// }

impl From<serde_json::error::Error> for TransactionError {
    fn from(error: serde_json::error::Error) -> Self {
        TransactionError::Crate("serde_json", format!("{:?}", error))
    }
}

#[cfg(test)]
mod tests {
    use crate::func_selector;

    #[test]
    fn test_func_selector() {
        let selector = func_selector("transfer(address,uint256)");
        assert_eq!("a9059cbb", hex::encode(selector));
    }
}
