use std::fmt::Display;
use std::str::FromStr;

use crate::hasher::{roinput::ROInput, DomainParameter, Hashable};
use crate::public_key::CompressedPubKey;
use crate::{MinaAddress, MinaFormat, MinaPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use serde_json::{json, Value};

const MEMO_BYTES: usize = 34;
const TAG_BITS: usize = 3;

#[derive(Clone, Debug)]
pub struct MinaTransactionParameters {
    pub fee: u64,
    pub fee_token: u64,
    pub fee_payer_pk: CompressedPubKey,
    pub nonce: u32,
    pub valid_until: u32,
    pub memo: [u8; MEMO_BYTES],
    pub tag: [bool; TAG_BITS],
    pub source_pk: CompressedPubKey,
    pub receiver_pk: CompressedPubKey,
    pub token_id: u64,
    pub amount: u64,
    pub token_locked: bool,
}

/// Mina network (or blockchain) identifier
#[derive(Debug, Clone)]
pub enum NetworkId {
    /// Id for all testnets
    Testnet = 0x00,

    /// Id for mainnet
    Mainnet = 0x01,
}

impl From<NetworkId> for u8 {
    fn from(id: NetworkId) -> u8 {
        id as u8
    }
}

impl DomainParameter for NetworkId {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

impl Hashable for MinaTransactionParameters {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new()
            .append_field(self.fee_payer_pk.x)
            .append_field(self.source_pk.x)
            .append_field(self.receiver_pk.x)
            .append_u64(self.fee)
            .append_u64(self.fee_token)
            .append_bool(self.fee_payer_pk.is_odd)
            .append_u32(self.nonce)
            .append_u32(self.valid_until)
            .append_bytes(&self.memo);

        for tag_bit in self.tag {
            roi = roi.append_bool(tag_bit);
        }

        roi.append_bool(self.source_pk.is_odd)
            .append_bool(self.receiver_pk.is_odd)
            .append_u64(self.token_id)
            .append_u64(self.amount)
            .append_bool(self.token_locked)
    }

    fn domain_string(network_id: NetworkId) -> Option<String> {
        // Domain strings must have length <= 20
        match network_id {
            NetworkId::Mainnet => "MinaSignatureMainnet",
            NetworkId::Testnet => "CodaSignature",
        }
        .to_string()
        .into()
    }
}

impl MinaTransactionParameters {
    fn set_memo(&mut self, memo: &str) -> Result<(), TransactionError> {
        let len = memo.len();
        if len > 32 {
            return Err(TransactionError::Message(
                "Memo length exceeds 32".to_string(),
            ));
        }
        self.memo[0] = 1;
        self.memo[1] = len as u8;
        self.memo[2..2 + len].copy_from_slice(memo.as_bytes());
        Ok(())
    }

    fn get_memo(&self) -> Result<String, TransactionError> {
        let len = self.memo[1] as usize;
        Ok(String::from_utf8(self.memo[2..len + 2].to_vec())?)
    }
}

#[derive(Clone)]
pub struct MinaSignature {
    rx: Vec<u8>,
    s: Vec<u8>,
}

impl MinaSignature {
    fn field(&self) -> String {
        hex::encode(&self.rx)
    }

    fn scalar(&self) -> String {
        hex::encode(&self.s)
    }
}

#[derive(Clone)]
pub struct MinaTransaction {
    pub params: MinaTransactionParameters,
    pub signature: Option<MinaSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MinaTransactionId {
    pub txid: Vec<u8>,
}

impl Display for MinaTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.txid))
    }
}

impl TransactionId for MinaTransactionId {}

impl Transaction for MinaTransaction {
    type PublicKey = MinaPublicKey;
    type Address = MinaAddress;
    type Format = MinaFormat;
    type TransactionId = MinaTransactionId;
    type TransactionParameters = MinaTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            params: parameters.clone(),
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
        self.signature = Some(MinaSignature {
            rx: rs[..32].to_vec(),
            s: rs[32..].to_vec(),
        });
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let params = &self.params;
        match &self.signature {
            Some(sig) => Ok(json!({
                "publicKey": params.fee_payer_pk.to_address(),
                "signature": {
                    "field": sig.field(),
                    "scalar": sig.scalar(),
                },
                "payload": {
                    "to": params.receiver_pk.to_address(),
                    "from": params.source_pk.to_address(),
                    "fee": params.fee.to_string(),
                    "amount": params.amount.to_string(),
                    "nonce": params.nonce.to_string(),
                    "memo": params.get_memo()?,
                    "validUntil": params.valid_until.to_string(),
                }
            })
            .to_string()
            .as_bytes()
            .to_vec()),
            None => Ok(json!({
                "publicKey": params.fee_payer_pk.to_address(),
                "payload": {
                    "to": params.receiver_pk.to_address(),
                    "from": params.source_pk.to_address(),
                    "fee": params.fee.to_string(),
                    "amount": params.amount.to_string(),
                    "nonce": params.nonce,
                    "memo": params.get_memo()?,
                    "validUntil": params.valid_until.to_string(),
                }
            })
            .to_string()
            .as_bytes()
            .to_vec()),
        }
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let tx = String::from_utf8(tx.to_vec())?;
        let tx = serde_json::from_str::<Value>(&tx)?;

        let fee = tx["payload"]["fee"].as_str().unwrap();
        let fee_payer = tx["publicKey"].as_str().unwrap();
        let nonce = tx["payload"]["nonce"].as_str().unwrap();
        let valid_util = tx["payload"]["validUntil"].as_str().unwrap();
        let memo = tx["payload"]["memo"].as_str().unwrap();
        let from = tx["payload"]["from"].as_str().unwrap();
        let to = tx["payload"]["to"].as_str().unwrap();
        let amount = tx["payload"]["amount"].as_str().unwrap();

        let fee = fee.parse::<u64>()?;
        let fee_token = 1;
        let fee_payer_pk = CompressedPubKey::from_address(fee_payer).unwrap();
        let nonce = nonce.parse::<u32>()?;
        let valid_until = valid_util.parse::<u32>()?;
        let tag = [false; TAG_BITS];
        let source_pk = CompressedPubKey::from_address(from).unwrap();
        let receiver_pk = CompressedPubKey::from_address(to).unwrap();
        let token_id = 1;
        let amount = amount.parse::<u64>()?;
        let token_locked = false;

        let mut params = MinaTransactionParameters {
            fee,
            fee_token,
            fee_payer_pk,
            nonce,
            valid_until,
            memo: [0u8; MEMO_BYTES],
            tag,
            source_pk,
            receiver_pk,
            token_id,
            amount,
            token_locked,
        };

        params.set_memo(memo)?;

        let signature = if tx["signature"].is_object() {
            let field = tx["signature"]["field"].as_str().unwrap();
            let scalar = tx["signature"]["scalar"].as_str().unwrap();
            let rx = hex::decode(field)?;
            let s = hex::decode(scalar)?;
            let sig = MinaSignature { rx, s };
            Some(sig)
        } else {
            None
        };

        Ok(MinaTransaction { params, signature })
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Err(TransactionError::Message("Not supported".to_string()))
    }
}

impl std::fmt::Display for MinaTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(self.to_bytes().unwrap()).unwrap()
        )
    }
}

impl FromStr for MinaTransaction {
    type Err = TransactionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::Transaction;
    use super::{MEMO_BYTES, TAG_BITS};
    use crate::{public_key::CompressedPubKey, MinaTransaction, MinaTransactionParameters};
    use std::str::FromStr;

    #[test]
    fn test() {
        let from = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
        let to = "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy";

        let from = CompressedPubKey::from_address(from).unwrap();
        let to = CompressedPubKey::from_address(to).unwrap();

        let mut params = MinaTransactionParameters {
            fee: 0,
            fee_token: 0,
            fee_payer_pk: from.clone(),
            nonce: 0,
            valid_until: 0,
            memo: [0; MEMO_BYTES],
            tag: [false; TAG_BITS],
            source_pk: from,
            receiver_pk: to,
            token_id: 0,
            amount: 0,
            token_locked: false,
        };

        params.set_memo("guai").unwrap();

        let sig = vec![1; 64];

        let mut tx = MinaTransaction::new(&params).unwrap();
        let tx = tx.sign(sig, 0).unwrap();
        let tx = String::from_utf8(tx).unwrap();

        let tx = MinaTransaction::from_str(&tx).unwrap();

        println!("tx = {}", tx);
    }
}
