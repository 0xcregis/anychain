use std::fmt::Display;
use anychain_core::{Transaction, TransactionError, TransactionId, hex};
use crate::{PolkadotAddress, PolkadotNetwork, PolkadotFormat, PolkadotPublicKey};
use parity_scale_codec::Encode;


#[derive(Clone)]
pub struct PolkadotTransactionParameters<N: PolkadotNetwork> {
    version: String,
    from: PolkadotAddress<N>,
    to: PolkadotAddress<N>,
    amount: u64,
    nonce: u64,
    tip: u64,
    block_height: u64,
    block_hash: String,
    genesis_hash: String,
    spec_version: u32,
    tx_version: u32,
    era_height: u64,
}

#[derive(Clone)]
pub struct PolkadotTransaction<N: PolkadotNetwork> {
    pub params: PolkadotTransactionParameters<N>,
    pub signature: Vec<u8>
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PolkadotTransactionId {
    txid: Vec<u8>,
}

impl TransactionId for PolkadotTransactionId {}

impl Display for PolkadotTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

fn get_era(block_height: u64, era_height: u64) -> Vec<u8> {

    todo!()
}

fn encode(val: u64) -> Vec<u8> {
    if val == 0 {
        vec![0]
    } else {
        val.encode()
    }
}

impl<N: PolkadotNetwork> Transaction for PolkadotTransaction<N> {
    type Address = PolkadotAddress<N>;
    type Format = PolkadotFormat;
    type PublicKey = PolkadotPublicKey<N>;
    type TransactionId = PolkadotTransactionId;
    type TransactionParameters = PolkadotTransactionParameters<N>;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        
        todo!()
    }

    fn sign(&mut self, sig: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        
        todo!()
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {

        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let params = &self.params;

        let to = params.to.to_pk_hash()?;
        let amount = encode(params.amount);
        let era = get_era(params.block_height, params.era_height);
        
        let nonce = encode(params.nonce);
        let tip = encode(params.nonce);

        let spec_version = params.spec_version.to_le_bytes().to_vec();
        let tx_version = params.tx_version.to_le_bytes().to_vec();

        let genesis_hash = hex::decode(&params.genesis_hash)?;
        let block_hash = hex::decode(&params.block_hash)?;

        Ok([
            vec![0],
            to,
            amount,
            era,
            nonce,
            tip,
            spec_version,
            tx_version,
            genesis_hash,
            block_hash,
        ].concat())
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use anychain_core::hex;
    use parity_scale_codec::{Encode};

    #[test]
    fn test() {
        let s = 1073741u64;
        let s = s.encode();
        let s = hex::encode(&s);
        println!("s = {}", s);
    }
}