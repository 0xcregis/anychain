use crate::util::{adapt2, pad_zeros, restore_sender, trim_leading_zeros};
use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey};
use anychain_core::{
    hex, utilities::crypto::keccak256, Transaction, TransactionError, TransactionId,
};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::{ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_json::{json, Value};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for EthereumTransactionId {}

impl fmt::Display for EthereumTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

pub fn encode_transfer(func_name: &str, address: &EthereumAddress, amount: U256) -> Vec<u8> {
    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![
            Param {
                name: "address".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };

    let tokens = vec![
        Token::Address(H160::from_slice(&address.to_bytes().unwrap())),
        Token::Uint(amount),
    ];

    func.encode_input(&tokens).unwrap()
}

pub fn decode_transfer(data: Vec<u8>) -> Result<Value, TransactionError> {
    if data.len() < 4 {
        return Err(TransactionError::Message("Illegal data".to_string()));
    }

    let selector = &data[..4];

    match selector {
        // function selector for 'transfer(address,uint256)'
        [169, 5, 156, 187] => {
            #[allow(deprecated)]
            let func = Function {
                name: "transfer".to_string(),
                inputs: vec![
                    Param {
                        name: "to".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    },
                    Param {
                        name: "amount".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                constant: None,
                state_mutability: StateMutability::Payable,
            };
            match func.decode_input(&data[4..]) {
                Ok(tokens) => {
                    let to = hex::encode(tokens[0].clone().into_address().unwrap().as_bytes());
                    let amount = tokens[1].clone().into_uint().unwrap();
                    Ok(json!({
                        "function": "transfer",
                        "params": {
                            "to": to,
                            "amount": amount.to_string(),
                        }
                    }))
                }
                Err(e) => Err(TransactionError::Message(e.to_string())),
            }
        }
        _ => Err(TransactionError::Message(
            "Unsupported contract function".to_string(),
        )),
    }
}

// mod tests {
//     use super::*;
//     use crate::Sepolia;

//     #[test]
//     fn test_legacy_tx() {
//         let params = EthereumTransactionParameters {
//             nonce: U256::from_dec_str("6").unwrap(),
//             gas_price: U256::from_dec_str("20000000000").unwrap(),
//             gas_limit: U256::from_dec_str("21000").unwrap(),
//             to: EthereumAddress::from_str("0xf7a63003b8ef116939804b4c2dd49290a39c4d97").unwrap(),
//             amount: U256::from_dec_str("10000000000000000").unwrap(),
//             data: vec![],
//         };
//         let mut tx = EthereumTransaction::<Sepolia>::new(&params).unwrap();
//         let msg = tx.to_transaction_id().unwrap().txid;
//         let msg = libsecp256k1::Message::parse_slice(&msg).unwrap();

//         let sk = "08d586ed207046d6476f92fd4852be3830a9d651fc148d6fa5a6f15b77ba5df0";
//         let sk = hex::decode(sk).unwrap();
//         let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

//         let (sig, recid) = libsecp256k1::sign(&msg, &sk);

//         let sig = sig.serialize().to_vec();
//         let recid = recid.serialize();

//         let _ = tx.sign(sig, recid);

//         println!("{}", tx);
//     }

//     #[test]
//     fn test_eip1559_tx() {
//         let params = Eip1559TransactionParameters {
//             chain_id: Sepolia::CHAIN_ID,
//             nonce: U256::from_dec_str("4").unwrap(),
//             max_priority_fee_per_gas: U256::from_dec_str("100000000000").unwrap(),
//             max_fee_per_gas: U256::from_dec_str("200000000000").unwrap(),
//             gas_limit: U256::from_dec_str("21000").unwrap(),
//             to: EthereumAddress::from_str("0xf7a63003b8ef116939804b4c2dd49290a39c4d97").unwrap(),
//             amount: U256::from_dec_str("10000000000000000").unwrap(),
//             data: vec![],
//             access_list: vec![],
//         };
//         let mut tx = Eip1559Transaction::<Sepolia>::new(&params).unwrap();
//         let msg = tx.to_transaction_id().unwrap().txid;
//         let msg = libsecp256k1::Message::parse_slice(&msg).unwrap();

//         let sk = "08d586ed207046d6476f92fd4852be3830a9d651fc148d6fa5a6f15b77ba5df0";
//         let sk = hex::decode(sk).unwrap();
//         let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

//         let (sig, recid) = libsecp256k1::sign(&msg, &sk);
//         let sig = sig.serialize().to_vec();
//         let recid = recid.serialize();

//         let _ = tx.sign(sig, recid);

//         println!("{}", tx);
//     }

//     #[test]
//     fn test() {
//         let tx = "0x02f87683aa36a70485174876e800852e90edd00082520894f7a63003b8ef116939804b4c2dd49290a39c4d97872386f26fc1000080c001a077233c9ef0d1a3211f844865172aa31ef716b98f4d82e7c86c2cd7050455e243a0678fdd0f3dd4e0bce65642e24368fa22bb34a8b4542c6bcac55e943c051dbb56";
//         let tx = Eip1559Transaction::<Sepolia>::from_str(tx).unwrap();
//         println!("{}", tx);
//     }
// }
