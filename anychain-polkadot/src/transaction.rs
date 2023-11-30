use crate::{PolkadotAddress, PolkadotFormat, PolkadotNetwork, PolkadotPublicKey};
use anychain_core::{
    crypto::{blake2b_256, keccak256, sha256, sha512},
    hex, Transaction, TransactionError, TransactionId,
};
use parity_scale_codec::{Encode, Decode, HasCompact};
use std::fmt::Display;

#[derive(Clone)]
pub struct PolkadotTransactionParameters<N: PolkadotNetwork> {
    pub module_method: String,
    pub version: String,
    pub from: PolkadotAddress<N>,
    pub to: PolkadotAddress<N>,
    pub amount: u64,
    pub nonce: u64,
    pub tip: u64,
    pub block_height: u64,
    pub block_hash: String,
    pub genesis_hash: String,
    pub spec_version: u32,
    pub tx_version: u32,
    pub era_height: u64,
}

struct TxInterim {
    method: Vec<u8>,
    era: Vec<u8>,
    nonce: Vec<u8>,
    tip: Vec<u8>,
    spec_version: Vec<u8>,
    genesis_hash: Vec<u8>,
    block_hash: Vec<u8>,
    tx_version: Vec<u8>,
}

#[derive(Clone)]
pub struct PolkadotTransaction<N: PolkadotNetwork> {
    pub params: PolkadotTransactionParameters<N>,
    pub signature: Option<Vec<u8>>,
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

#[derive(Debug, PartialEq, Encode, Decode)]
struct CompactWrapper<T: HasCompact> {
    #[codec(encoded_as = "<T as HasCompact>::Type")]
    val: T,
}

fn get_era(block_height: u64, mut era_height: u64) -> Vec<u8> {
    if era_height == 0 {
        era_height = 64
    }
    let phase = block_height % era_height;
    let index = 6u64;
    let trailing_zero = index - 1;

    let mut encoded = if trailing_zero > 15 {
        15
    } else if trailing_zero < 1 {
        1
    } else {
        trailing_zero
    };

    encoded += phase / 1 << 4;
    let first = (encoded >> 8) as u8;
    let second = (encoded & 0xff) as u8;

    vec![second, first]
}

fn encode(val: u64) -> Vec<u8> {
    if val == 0 {
        vec![0]
    } else {
        CompactWrapper { val }.encode()
    }
}

impl<N: PolkadotNetwork> Transaction for PolkadotTransaction<N> {
    type Address = PolkadotAddress<N>;
    type Format = PolkadotFormat;
    type PublicKey = PolkadotPublicKey<N>;
    type TransactionId = PolkadotTransactionId;
    type TransactionParameters = PolkadotTransactionParameters<N>;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(PolkadotTransaction {
            params: params.clone(),
            signature: None,
        })
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

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        match &self.signature {
            Some(sig) => {
                let interim = self.to_interim()?;
                let version = hex::decode(&self.params.version)?;
                let from = self.params.from.to_pk_hash()?;

                let stream = [
                    version,
                    vec![0],
                    from,
                    vec![2], // secp256k1 signature scheme = 2
                    sig.clone(),
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.method,
                ]
                .concat();

                let len = stream.len() as u64;
                let len = encode(len);

                Ok([len, stream].concat())
            }
            None => {
                let interim = self.to_interim()?;
                Ok([
                    interim.method,
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.spec_version,
                    interim.tx_version,
                    interim.genesis_hash,
                    interim.block_hash,
                ]
                .concat())
            }
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(PolkadotTransactionId {
            txid: self.digest(1)?,
        })
    }
}

impl<N: PolkadotNetwork> PolkadotTransaction<N> {
    fn to_interim(&self) -> Result<TxInterim, TransactionError> {
        let params = &self.params;

        let method = hex::decode(&params.module_method)?;
        let to = params.to.to_pk_hash()?;
        let amount = encode(params.amount);
        let era = get_era(params.block_height, params.era_height);

        let nonce = encode(params.nonce);
        let tip = encode(params.tip);

        let spec_version = params.spec_version.to_le_bytes().to_vec();
        let tx_version = params.tx_version.to_le_bytes().to_vec();

        let genesis_hash = hex::decode(&params.genesis_hash)?;
        let block_hash = hex::decode(&params.block_hash)?;

        let interim = TxInterim {
            method: [method, vec![0], to, amount].concat(),
            era,
            nonce,
            tip,
            spec_version,
            tx_version,
            genesis_hash,
            block_hash,
        };

        Ok(interim)
    }

    pub fn digest(&self, index: u8) -> Result<Vec<u8>, TransactionError> {
        match index {
            0 => Ok(blake2b_256(&self.to_bytes()?).to_vec()),
            1 => Ok(sha256(&self.to_bytes()?).to_vec()),
            2 => Ok(keccak256(&self.to_bytes()?).to_vec()),
            3 => Ok(sha512(&self.to_bytes()?)[..32].to_vec()),
            _ => Err(TransactionError::Message("invalid digest code".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_tx_gen() {

    }
}
