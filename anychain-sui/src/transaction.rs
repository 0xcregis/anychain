use crate::{address::SuiAddress, format::SuiFormat, SuiPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::fmt::Display;

pub struct SuiTransactionParameters {}

#[derive(Debug, Clone)]
pub struct SuiTransaction {}
impl Transaction for SuiTransaction {
    type Address = SuiAddress;
    type Format = SuiFormat;
    type PublicKey = SuiPublicKey;
    type TransactionId = SuiTransactionId;
    type TransactionParameters = SuiTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        todo!()
    }

    fn sign(
        &mut self,
        signature: Vec<u8>,
        recid: u8,
    ) -> Result<Vec<u8>, anychain_core::TransactionError> {
        todo!()
    }

    fn from_bytes(transaction: &[u8]) -> Result<Self, anychain_core::TransactionError> {
        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, anychain_core::TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, anychain_core::TransactionError> {
        todo!()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SuiTransactionId {}
impl TransactionId for SuiTransactionId {}

impl Display for SuiTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
