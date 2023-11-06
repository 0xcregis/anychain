use crate::{NeoAddress, NeoFormat, NeoPublicKey};
use anychain_core::{crypto::sha256, hex, Transaction, TransactionError, TransactionId};
use std::fmt::{Display, Error};

#[derive(Clone)]
pub struct TxIn {
    prev_hash: Vec<u8>,
    index: u16,
}

#[derive(Clone)]
pub struct TxOut {
    asset_id: Vec<u8>,
    address: String,
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
        let mut asset_id = self.asset_id.clone();
        asset_id.reverse();
        let value = self.value.to_le_bytes().to_vec();
        let address = NeoAddress(self.address.clone());
        let address = address.to_script_hash();

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

        ret.push(0u8); // attribute length, which is 0

        ret.push(self.txins.len() as u8);

        for txin in &self.txins {
            ret.extend(txin.serialize());
        }

        ret.push(self.txouts.len() as u8);

        for txout in &self.txouts {
            ret.extend(txout.serialize());
        }

        ret
    }
}

#[derive(Clone)]
pub struct NeoSignature {
    rs: Vec<u8>,
    public_key: Vec<u8>,
}

impl NeoSignature {
    fn serialize(&self) -> Vec<u8> {
        let mut stream = vec![];
        let rs = self.rs.clone();
        let pk = self.public_key.clone();

        let rs_script = [vec![rs.len() as u8], rs].concat();
        let pk_script = [vec![pk.len() as u8], pk, vec![172 /* Opcode::CheckSig */]].concat();

        stream.push(rs_script.len() as u8);
        stream.extend(rs_script);
        stream.push(pk_script.len() as u8);
        stream.extend(pk_script);
        stream
    }
}

#[derive(Clone)]
pub struct NeoTransaction {
    params: NeoTransactionParameters,
    signatures: Option<Vec<NeoSignature>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct NeoTransactionId {
    txid: Vec<u8>,
}

impl Display for NeoTransactionId {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        Ok(Self {
            params: params.clone(),
            signatures: None,
        })
    }

    fn sign(&mut self, rs_pk_s: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs_pk_s.len() % 97 != 0 {
            return Err(TransactionError::Message(format!(
                "Invalid signauture-public-key tuple length {}",
                rs_pk_s.len()
            )));
        }

        let sigs_cnt = rs_pk_s.len() / 97;
        let txins_cnt = self.params.txins.len();

        if sigs_cnt != txins_cnt {
            return Err(TransactionError::Message(format!(
                "Amount of signatures {} differs with that of tx inputs {}",
                sigs_cnt, txins_cnt,
            )));
        }

        let mut sigs = vec![];
        for i in 0..sigs_cnt {
            let start = 97 * i;
            let divide = start + 64;
            let end = divide + 33;
            let sig = NeoSignature {
                rs: rs_pk_s[start..divide].to_vec(),
                public_key: rs_pk_s[divide..end].to_vec(),
            };
            sigs.push(sig);
        }

        self.signatures = Some(sigs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut stream = self.params.serialize();
        if let Some(sigs) = &self.signatures {
            stream.push(sigs.len() as u8);
            for sig in sigs {
                stream.extend(sig.serialize());
            }
        }
        Ok(stream)
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let stream = self.to_bytes()?;
        Ok(NeoTransactionId {
            txid: sha256(&stream).to_vec(),
        })
    }
}

impl Display for NeoTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            &hex::encode(match self.to_bytes() {
                Ok(transaction) => transaction,
                _ => return Err(Error),
            })
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{TxIn, TxOut};

    use super::{NeoFormat, NeoPublicKey, NeoTransaction, NeoTransactionParameters};

    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    use anychain_core::{hex, PublicKey, Transaction};
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

    #[test]
    fn test_tx_gen() {
        let sk = [
            1u8, 1, 1, 23, 1, 1, 1, 59, 1, 1, 1, 16, 87, 1, 1, 1, 1, 99, 1, 1, 1, 1, 79, 1, 1, 1,
            1, 1, 121, 1, 1, 1,
        ];
        let sk = p256::SecretKey::from_slice(&sk).unwrap();
        let pk = NeoPublicKey::from_secret_key(&sk);
        let format = &NeoFormat::Standard;
        let _from = pk.to_address(format).unwrap();

        let sk_to = [
            2u8, 7, 0, 5, 0, 0, 1, 1, 111, 23, 34, 39, 109, 20, 1, 2, 7, 0, 5, 0, 0, 1, 1, 111, 23,
            34, 39, 109, 203, 1, 5, 55,
        ];
        let sk_to = p256::SecretKey::from_slice(&sk_to).unwrap();
        let pk_to = NeoPublicKey::from_secret_key(&sk_to);
        let to = pk_to.to_address(format).unwrap();

        let prev_hash = "b3ad3320f8230a8358a4c056ead57182d787ec8607870f70d70a844dc4d049a3";
        let index = 0;

        let asset_id = "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b";

        let mut prev_hash = hex::decode(prev_hash).unwrap();
        prev_hash.reverse();

        let asset_id = hex::decode(asset_id).unwrap();

        let input = TxIn { prev_hash, index };
        let output = TxOut {
            asset_id,
            address: to.0,
            value: 1000000000,
        };

        let params = NeoTransactionParameters {
            txins: vec![input],
            txouts: vec![output],
        };

        let mut tx = NeoTransaction::new(&params).unwrap();
        let hash = tx.to_transaction_id().unwrap().txid;

        let signing_key = SigningKey::from(sk);

        // the signature differs with bipay signature, possible cause being that
        // bipay use a random r as opposed to a fixed r used by this signer
        let sig: Signature = signing_key.sign(&hash);

        let mut sig = sig.to_bytes().as_slice().to_vec();
        sig.extend(pk.serialize_compressed());

        let tx = tx.sign(sig, 0).unwrap();
        let tx_hex = hex::encode(&tx);
        let tx_64 = STANDARD_NO_PAD.encode(&tx);

        println!("tx hex = {}\ntx 64 = {}", tx_hex, tx_64);
    }
}
