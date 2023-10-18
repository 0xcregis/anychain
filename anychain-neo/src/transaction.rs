use std::fmt::Display;

use anychain_core::{Transaction, TransactionError, TransactionId};

use crate::{NeoFormat, NeoAddress, NeoPublicKey};

#[derive(Clone)]
pub struct TxIn {
    prev_hash: Vec<u8>,
    index: u16,
}

#[derive(Clone)]
pub struct TxOut {
    asset_id: Vec<u8>,
    address: Vec<u8>,
    value: u64,
}

impl TxIn {
    fn serialize(&self) -> Vec<u8> {
        if self.prev_hash.len() != 32 {
            panic!("Invalid prev_hash length");
        }
        let prevhash = self.prev_hash.clone();
        let index = self.index.to_le_bytes().to_vec();
        [prevhash, index].concat()
    }
}

impl TxOut {
    fn serialize(&self) -> Vec<u8> {
        if self.asset_id.len() != 32 {
            panic!("Invalid prev_hash length");
        }
        if self.asset_id.len() != 20 {
            panic!("Invalid prev_hash length");
        }
        let mut asset_id = self.asset_id.clone();
        asset_id.reverse();
        let value = self.value.to_le_bytes().to_vec();
        let address = self.address.clone();
        [asset_id, value, address].concat()
    }
}

#[derive(Clone)]
pub struct NeoTransactionParameters {
    txins: Vec<TxIn>,
    txouts: Vec<TxOut>,
}

impl NeoTransactionParameters {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![0u8; 0];
        ret.push(0x80); // contract type byte
        ret.push(0x00); // version byte
        for txin in &self.txins {
            ret.extend(txin.serialize());
        }
        for txout in &self.txouts {
            ret.extend(txout.serialize());
        }
        ret
    }
}

#[derive(Clone)]
pub struct NeoTransaction {
    params: NeoTransactionParameters,
    signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct NeoTransactionId {
    txid: Vec<u8>,
}

impl Display for NeoTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl TransactionId for NeoTransactionId {}

impl Transaction for NeoTransaction {
    type TransactionId = NeoTransactionId;
    type Format = NeoFormat;
    type TransactionParameters = NeoTransactionParameters;
    type Address = NeoAddress;
    type PublicKey = NeoPublicKey;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self { params: params.clone(), signature: None })
    }

    fn sign(&mut self, rs: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}
