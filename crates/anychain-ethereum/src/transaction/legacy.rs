use super::EthereumTransactionId;
use crate::util::{adapt2, pad_zeros, restore_sender, trim_leading_zeros};
use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey};
use anychain_core::{hex, utilities::crypto::keccak256, Transaction, TransactionError};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethereum_types::U256;
use rlp::{Rlp, RlpStream};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionParameters {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: EthereumAddress,
    pub amount: U256,
    pub data: Vec<u8>,
}

impl EthereumTransactionParameters {
    pub fn to_rlp(&self) -> Result<RlpStream, TransactionError> {
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("{}", e)))?;

        let mut rlp = RlpStream::new();
        rlp.begin_list(9);

        rlp.append(&self.nonce);
        rlp.append(&self.gas_price);
        rlp.append(&self.gas_limit);
        rlp.append(&to);
        rlp.append(&self.amount);
        rlp.append(&self.data);

        Ok(rlp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionSignature {
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransaction<N: EthereumNetwork> {
    /// The address of the sender
    pub sender: Option<EthereumAddress>,
    /// The transaction parameters (gas, gas_price, nonce, data)
    pub params: EthereumTransactionParameters,
    /// The transaction signature
    pub signature: Option<EthereumTransactionSignature>,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> EthereumTransaction<N> {
    pub fn restore_sender(&mut self) -> Result<(), TransactionError> {
        if self.signature.is_none() {
            return Err(TransactionError::Message(
                "Signature is missing".to_string(),
            ));
        }

        let sig = self.signature.clone().unwrap();
        self.signature = None;

        let r = sig.r.clone();
        let s = sig.s.clone();

        let recid = (sig.v - 2 * N::CHAIN_ID - 35) as u8;

        let _sig = [r, s].concat();
        let msg = self.to_transaction_id()?.txid;

        let sender = restore_sender(msg, _sig, recid)?;

        self.sender = Some(sender);
        self.signature = Some(sig);

        Ok(())
    }
}

impl<N: EthereumNetwork> Transaction for EthereumTransaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = EthereumTransactionParameters;

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
        let v = 2 * N::CHAIN_ID + 35 + (recid as u32);
        let r = rs[..32].to_vec();
        let s = rs[32..].to_vec();
        self.signature = Some(EthereumTransactionSignature { v, r, s });
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        match &self.signature {
            Some(sig) => {
                let mut rlp = self.params.to_rlp()?;
                let r = trim_leading_zeros(&sig.r);
                let s = trim_leading_zeros(&sig.s);
                rlp.append(&sig.v);
                rlp.append(&r);
                rlp.append(&s);
                Ok(rlp.out().to_vec())
            }
            None => {
                let mut rlp = self.params.to_rlp()?;
                rlp.append(&N::CHAIN_ID);
                rlp.append(&0u8);
                rlp.append(&0u8);
                Ok(rlp.out().to_vec())
            }
        }
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let rlp = Rlp::new(tx);

        let to = adapt2(rlp.val_at::<Vec<u8>>(3))?;
        let to = hex::encode(to);

        let nonce = adapt2(rlp.val_at::<U256>(0))?;
        let gas_price = adapt2(rlp.val_at::<U256>(1))?;
        let gas_limit = adapt2(rlp.val_at::<U256>(2))?;
        let to = EthereumAddress::from_str(&to)?;
        let amount = adapt2(rlp.val_at::<U256>(4))?;
        let data = adapt2(rlp.val_at::<Vec<u8>>(5))?;

        let v = adapt2(rlp.val_at::<u32>(6))?;
        let mut r = adapt2(rlp.val_at::<Vec<u8>>(7))?;
        let mut s = adapt2(rlp.val_at::<Vec<u8>>(8))?;

        let params = EthereumTransactionParameters {
            nonce,
            gas_price,
            gas_limit,
            to,
            amount,
            data,
        };

        let mut tx = EthereumTransaction::<N>::new(&params)?;

        if !r.is_empty() && !s.is_empty() {
            pad_zeros(&mut r, 32);
            pad_zeros(&mut s, 32);
            let sig = EthereumTransactionSignature { v, r, s };
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

impl<N: EthereumNetwork> FromStr for EthereumTransaction<N> {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = match &tx[..2] {
            "0x" => &tx[2..],
            _ => tx,
        };
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl<N: EthereumNetwork> fmt::Display for EthereumTransaction<N> {
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
    use crate::{EthereumAddress, EthereumTransaction, EthereumTransactionParameters, Sepolia};
    use anychain_core::{hex, Transaction};
    use core::str::FromStr;
    use ethereum_types::U256;

    #[test]
    fn test_legacy_tx() {
        let params = EthereumTransactionParameters {
            nonce: U256::from_dec_str("6").unwrap(),
            gas_price: U256::from_dec_str("20000000000").unwrap(),
            gas_limit: U256::from_dec_str("21000").unwrap(),
            to: EthereumAddress::from_str("0xf7a63003b8ef116939804b4c2dd49290a39c4d97").unwrap(),
            amount: U256::from_dec_str("10000000000000000").unwrap(),
            data: vec![],
        };

        let mut tx = EthereumTransaction::<Sepolia>::new(&params).unwrap();
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
}
