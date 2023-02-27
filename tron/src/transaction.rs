use std::fmt;
use chainlib_core::Transaction;
use chainlib_core::TransactionError;
use crate::{
    TronAddress,
    TronFormat,
    TronPublicKey,
};
use crate::protocol::Tron::transaction::{
    Raw as TransactionRaw,
    Contract
};
use crate::protocol::Tron::Transaction as TransactionProto;
use chainlib_core::utilities::crypto;
use chainlib_core::TransactionId;
use protobuf::{Message};
use crate::trx;


/// Represents the parameters for a Tron transaction
#[derive(Debug, Clone, PartialEq)]
pub struct TronTransactionParameters {
    pub ref_block_hash: Vec<u8>,
    pub ref_block_bytes: Vec<u8>,
    pub fee_limit: i64,
    pub expiration: i64,
    pub timestamp: i64,
    pub memo: String,
    pub contract: Contract
}

impl TronTransactionParameters {
    pub fn set_ref_block(&mut self, number: i64, hash: &str){

        self.ref_block_bytes = vec![
                ((number & 0xff00) >> 8) as u8,
                (number & 0xff) as u8,
            ];
        self.ref_block_hash = hex::decode(hash).unwrap()[8..16].to_owned();
    }

    pub fn set_contract(&mut self, ct: Contract){
        self.contract = ct;
    }

    pub fn set_timestamp(&mut self, time: i64){
        self.timestamp = time;
    }

    pub fn set_expiration(&mut self, time: i64){
        self.expiration = time;
    }

    pub fn set_fee_limit(&mut self, fee: i64){
        self.fee_limit = fee;
    }
    
    pub fn to_transaction_raw(&self) -> Result<TransactionRaw, TransactionError>{
        let mut raw = TransactionRaw::new();
        let mut timestamp = self.timestamp;
        // if timestamp equals 0, means the tx is new
        if self.timestamp == 0 {
            timestamp = trx::timestamp_millis();
        }
        raw.contract = vec![self.contract.clone()].into();
        if self.memo.len() > 0 {
            raw.data = self.memo.as_bytes().to_owned();
        }
        
        if self.fee_limit != 0{
            raw.fee_limit = self.fee_limit;
        }
        
        raw.timestamp = timestamp;
        raw.expiration = timestamp + self.expiration;
        raw.ref_block_bytes = self.ref_block_bytes.clone();
        raw.ref_block_hash = self.ref_block_hash.clone();

        Ok(raw)
    }
}


impl Default for TronTransactionParameters{
    fn default() -> Self {
        Self { 
            ref_block_hash: Default::default(), 
            ref_block_bytes: Default::default(),
            fee_limit: 0,
            timestamp: 0,
            expiration: 1000 * 60 * 5_i64, 
            memo: "".to_string(), 
            contract: Default::default() }
    }
}


/// Represents an Ethereum transaction signature
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TronTransactionSignature(Vec<u8>);

impl TronTransactionSignature {
    pub fn new(rs: &Vec<u8>, recid: u8) -> Self{
        let mut vec = rs.clone();
        vec.push(recid);
        TronTransactionSignature(vec)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TronTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for TronTransactionId {}

impl fmt::Display for TronTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TronTransaction {
    pub data: TronTransactionParameters,
    pub signature: Option<TronTransactionSignature>
}

impl TronTransaction{

}

impl Transaction for TronTransaction {
    type Address = TronAddress;
    type Format = TronFormat;
    type PublicKey = TronPublicKey;
    type TransactionId = TronTransactionId;
    type TransactionParameters = TronTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self{
            data: parameters.clone(),
            signature: None
        })
    }

    fn sign(&mut self, signature: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        self.signature = Some(TronTransactionSignature::new(&signature, recid));
        self.to_bytes()
    }

    fn from_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        let raw =  TransactionRaw::parse_from_bytes(transaction.as_slice()).map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?;
        let param = TronTransactionParameters{
            timestamp: raw.timestamp,
            expiration: raw.expiration - raw.timestamp,
            ref_block_bytes: raw.ref_block_bytes.clone(),
            ref_block_hash: raw.ref_block_hash.clone(),
            memo: String::from_utf8(raw.data.clone()).map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?,
            fee_limit: raw.fee_limit,
            contract: raw.contract[0].clone()
        };

        Ok(Self{
            data: param,
            signature: None
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let raw = self.data.to_transaction_raw()?;
        match self.signature.clone() {
            Some(sign) => {
                let mut signed_tx = TransactionProto::new();
                signed_tx.raw_data = ::protobuf::MessageField::some(raw.clone());
                signed_tx.signature = vec![sign.to_bytes()];
                signed_tx.write_to_bytes().map_err(|e| TransactionError::Crate("protobuf", e.to_string()))
            },
            None   => {
                raw.write_to_bytes().map_err(|e| TransactionError::Crate("protobuf", e.to_string()))
            }
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let bytes = self.data.to_transaction_raw()?.write_to_bytes().map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?;
        Ok(Self::TransactionId {
            txid: crypto::sha256(&bytes).iter().cloned().collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;
    use chainlib_core::libsecp256k1;

    pub fn build_trx_transaction() -> TronTransaction{
        let addr_from = "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr";
        let addr_to = "TFk5LfscQv8hYM11mZYmi3ZcnRfFc4LLap";
        let amount = 10*1000000;
        let ct =  trx::build_transfer_contract(addr_from, addr_to, amount).unwrap();
        let mut param = TronTransactionParameters::default();
        param.set_timestamp(trx::timestamp_millis());
        param.set_ref_block(26661399, "000000000196d21784deb05dee04c69ed112b8e078e74019f9a0b1df6adc414e");
        param.set_contract(ct);
        let transaction = TronTransaction::new(&param).unwrap();
       
        return transaction;
    }

    pub fn build_trc20_transaction() -> TronTransaction {
        let owner_addr = "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr";
        let contract_addr = "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD";
        let to_addr = "TFk5LfscQv8hYM11mZYmi3ZcnRfFc4LLap";
        let amount = "10000000000000000000";
        let ct = trx::build_trc20_transfer_contract(owner_addr, contract_addr, to_addr, amount).unwrap();
        let mut param = TronTransactionParameters::default();
        param.set_timestamp(trx::timestamp_millis());
        param.set_ref_block(26661399, "000000000196d21784deb05dee04c69ed112b8e078e74019f9a0b1df6adc414e");
        param.set_contract(ct);
        let transaction = TronTransaction::new(&param).unwrap();
        return transaction;
    }

    #[test]
    pub fn test_txid() {
        let transaction = build_trx_transaction();
        println!("{}",transaction.to_transaction_id().unwrap());
        let raw = transaction.data.to_transaction_raw().unwrap();
        let raw_bytes = crypto::sha256(&raw.write_to_bytes().unwrap());
        println!("{}",hex::encode(raw_bytes));
    }

    #[test]
    fn test_build_tx2() {
        let from_addr = "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm";
        let to_addr = "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr";
        let amount = 1*1000000;// 以Sun为单位
        let block_height = 27007120;
        let block_hash = "00000000019c1890f87d110a81d815b9a38a3e62d44a00a7c8fd50a7b322a2df";

        let ct =  trx::build_transfer_contract(from_addr, to_addr, amount).unwrap();
        let mut param = TronTransactionParameters::default();
        param.set_timestamp(trx::timestamp_millis());
        param.set_ref_block(block_height, block_hash);
        param.set_contract(ct);
        let transaction = TronTransaction::new(&param).unwrap();

        let bytes = transaction.to_bytes().unwrap();
        println!("{}",hex::encode(bytes));
        println!("{}",transaction.to_transaction_id().unwrap());
        println!("{:?}",transaction.data);
    }

    #[test]
    pub fn test_from_bytes(){
        let raw = "0a0218902208f87d110a81d815b9409994dbfaac305a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541fa3146ab779ce02392d11209f524ee75d4088a45121541436d74fc1577266b7290b85801145d9c5287e19418c0843d70b9bfd7faac30900180ade204";
        let txid = "519f9d0bdc17d4a083b2676a4e9dce5679045107e7c9a9dad848891ee845235d";
        let transaction = TronTransaction::from_bytes(&hex::decode(raw).unwrap()).unwrap();
        let bytes = transaction.to_bytes().unwrap();
        //println!("{}",transaction.to_transaction_id().unwrap());
        //println!("{:?}",transaction.data);
        assert_eq!(raw, hex::encode(bytes));
        
        assert_eq!(txid, transaction.to_transaction_id().unwrap().to_string());

    }

    #[test]
    pub fn test_raw(){
        let raw = "0a025aa722088cb23bfcb18ea03c40facee394ad305a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541fa3146ab779ce02392d11209f524ee75d4088a45121541436d74fc1577266b7290b85801145d9c5287e19418c0843d709afadf94ad30900180ade204";
        let transaction = TronTransaction::from_bytes(&hex::decode(raw).unwrap()).unwrap();
        println!("{:?}",transaction.data);
    }
}