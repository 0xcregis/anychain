use crate::util::{adapt2, pad_zeros, restore_sender, trim_leading_zeros};
use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey};
use anychain_core::{hex, utilities::crypto::keccak256, Transaction, TransactionError};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethereum_types::U256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use super::EthereumTransactionId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip1559TransactionParameters {
    pub chain_id: u32,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: EthereumAddress,
    pub amount: U256,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessItem>,
}

impl Eip1559TransactionParameters {
    pub fn to_rlp(&self, array_len: usize) -> Result<RlpStream, TransactionError> {
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("{}", e)))?;

        let mut rlp = RlpStream::new();
        rlp.begin_list(array_len);

        rlp.append(&self.chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp.append(&self.gas_limit);
        rlp.append(&to);
        rlp.append(&self.amount);
        rlp.append(&self.data);
        rlp.append_list(&self.access_list);

        Ok(rlp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eip1559TransactionSignature {
    pub y_parity: bool,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessItem {
    pub address: EthereumAddress,
    pub storage_keys: Vec<Vec<u8>>,
}

impl Encodable for AccessItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.address.to_bytes().unwrap());
        s.append_list::<Vec<u8>, Vec<u8>>(&self.storage_keys);
    }
}

impl Decodable for AccessItem {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let address = hex::encode(rlp.val_at::<Vec<u8>>(0)?);
        let address = EthereumAddress::from_str(&address).unwrap();
        let storage_keys = rlp.list_at::<Vec<u8>>(1)?;
        Ok(Self {
            address,
            storage_keys,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip1559Transaction<N: EthereumNetwork> {
    pub sender: Option<EthereumAddress>,
    pub params: Eip1559TransactionParameters,
    pub signature: Option<Eip1559TransactionSignature>,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> Eip1559Transaction<N> {
    pub fn restore_sender(&mut self) -> Result<(), TransactionError> {
        if self.signature.is_none() {
            return Err(TransactionError::Message(
                "Signature is missing".to_string(),
            ));
        }

        let sig = self.signature.clone().unwrap();
        self.signature = None;

        let recid = match sig.y_parity {
            true => 1,
            false => 0,
        } as u8;

        let _sig = [sig.r.clone(), sig.s.clone()].concat();
        let msg = self.to_transaction_id()?.txid;

        let sender = restore_sender(msg, _sig, recid)?;

        self.sender = Some(sender);
        self.signature = Some(sig);

        Ok(())
    }
}

impl<N: EthereumNetwork> Transaction for Eip1559Transaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = Eip1559TransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            sender: None,
            params: params.clone(),
            signature: None,
            _network: PhantomData,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length: {}",
                rs.len()
            )));
        }
        let y_parity = recid == 1;
        let r = rs[..32].to_vec();
        let s = rs[32..].to_vec();
        self.signature = Some(Eip1559TransactionSignature { y_parity, r, s });
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let rlp = match &self.signature {
            Some(sig) => {
                let mut rlp = self.params.to_rlp(12)?;
                let r = trim_leading_zeros(&sig.r);
                let s = trim_leading_zeros(&sig.s);
                rlp.append(&sig.y_parity);
                rlp.append(&r);
                rlp.append(&s);
                rlp.out().to_vec()
            }
            None => self.params.to_rlp(9)?.out().to_vec(),
        };
        Ok([vec![2u8], rlp].concat())
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let rlp = Rlp::new(&tx[1..]);

        let to = adapt2(rlp.val_at::<Vec<u8>>(5))?;
        let to = hex::encode(to);

        let chain_id = adapt2(rlp.val_at::<u32>(0))?;
        let nonce = adapt2(rlp.val_at::<U256>(1))?;
        let max_priority_fee_per_gas = adapt2(rlp.val_at::<U256>(2))?;
        let max_fee_per_gas = adapt2(rlp.val_at::<U256>(3))?;
        let gas_limit = adapt2(rlp.val_at::<U256>(4))?;
        let to = EthereumAddress::from_str(&to)?;
        let amount = adapt2(rlp.val_at::<U256>(6))?;
        let data = adapt2(rlp.val_at::<Vec<u8>>(7))?;
        let access_list = adapt2(rlp.list_at::<AccessItem>(8))?;

        let y_parity = adapt2(rlp.val_at::<bool>(9))?;
        let mut r = adapt2(rlp.val_at::<Vec<u8>>(10))?;
        let mut s = adapt2(rlp.val_at::<Vec<u8>>(11))?;

        let params = Eip1559TransactionParameters {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data,
            access_list,
        };

        let mut tx = Eip1559Transaction::<N>::new(&params)?;

        if !r.is_empty() && !s.is_empty() {
            pad_zeros(&mut r, 32);
            pad_zeros(&mut s, 32);
            let sig = Eip1559TransactionSignature { y_parity, r, s };
            tx.signature = Some(sig);
            tx.restore_sender()?;
        }

        Ok(tx)
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(Self::TransactionId {
            txid: keccak256(&self.to_bytes()?).to_vec(),
        })
    }
}

impl<N: EthereumNetwork> FromStr for Eip1559Transaction<N> {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = match &tx[..2] {
            "0x" => &tx[2..],
            _ => tx,
        };
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl<N: EthereumNetwork> fmt::Display for Eip1559Transaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}",
            &hex::encode(match self.to_bytes() {
                Ok(transaction) => transaction,
                _ => return Err(fmt::Error),
            })
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Eip1559Transaction, Eip1559TransactionParameters, EthereumAddress, EthereumNetwork,
        Sepolia, TransferWithAuthorizationParameters,
    };
    use anychain_core::{hex, Transaction};
    use anychain_kms::secp256k1_sign;
    use core::str::FromStr;
    use ethereum_types::U256;
    use std::time::SystemTime;

    #[test]
    fn test_eip1559_tx() {
        let params = Eip1559TransactionParameters {
            chain_id: Sepolia::CHAIN_ID,
            nonce: U256::from_dec_str("4").unwrap(),
            max_priority_fee_per_gas: U256::from_dec_str("100000000000").unwrap(),
            max_fee_per_gas: U256::from_dec_str("200000000000").unwrap(),
            gas_limit: U256::from_dec_str("21000").unwrap(),
            to: EthereumAddress::from_str("0xf7a63003b8ef116939804b4c2dd49290a39c4d97").unwrap(),
            amount: U256::from_dec_str("10000000000000000").unwrap(),
            data: vec![],
            access_list: vec![],
        };
        let mut tx = Eip1559Transaction::<Sepolia>::new(&params).unwrap();
        let msg = tx.to_transaction_id().unwrap().txid;
        let msg = libsecp256k1::Message::parse_slice(&msg).unwrap();

        let sk = "08d586ed207046d6476f92fd4852be3830a9d651fc148d6fa5a6f15b77ba5df0";
        let sk = hex::decode(sk).unwrap();
        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let (sig, recid) = libsecp256k1::sign(&msg, &sk);
        let sig = sig.serialize().to_vec();
        let recid = recid.serialize();

        let _ = tx.sign(sig, recid);

        println!("{}", tx);
    }

    #[test]
    fn test_eip3009_tx() {
        let sk = "3d98c2d5a7f737693b470114816000645419af49bd21258cc99142f6ef5fd60a".to_string();
        let sk = hex::decode(sk).unwrap();

        let from = "0x7eE4c635d204eBE65fc8987CE6570CFA1651E8Af".to_string();
        let to = "0xf7a63003b8ef116939804b4c2dd49290a39c4d97".to_string();
        let usdc = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".to_string();
        let amount = "100000".to_string();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut transfer = TransferWithAuthorizationParameters::<Sepolia>::new(
            "USDC".to_string(),
            "2".to_string(),
            usdc.clone(),
            from,
            to,
            amount,
            now.to_string(),
            (now + 100).to_string(),
            "0xc16e8459b9c3ecfbbc20c34444c72ce016cdb109fa5a982b0dd223e15e8f96de".to_string(),
        )
        .unwrap();

        let digest = transfer.digest().unwrap();
        let (rs, recid) = secp256k1_sign(&sk, &digest).unwrap();
        let data = transfer
            .sign(recid, rs[..32].to_vec(), rs[32..].to_vec())
            .unwrap();

        let nonce = U256::from(22);
        let max_priority_fee_per_gas = U256::from_dec_str("50000000000").unwrap();
        let max_fee_per_gas = U256::from_dec_str("50000000000").unwrap();
        let gas_limit = U256::from(210000);
        let to = EthereumAddress::from_str(&usdc).unwrap();
        let amount = U256::from(0);

        let params = Eip1559TransactionParameters {
            chain_id: Sepolia::CHAIN_ID,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data,
            access_list: vec![],
        };

        let mut tx = Eip1559Transaction::<Sepolia>::new(&params).unwrap();
        let txid = tx.to_transaction_id().unwrap().txid;
        let (rs, recid) = secp256k1_sign(&sk, &txid).unwrap();
        let tx = tx.sign(rs, recid).unwrap();
        let tx = hex::encode(tx);

        println!("Tx: {}", tx);
    }
}
