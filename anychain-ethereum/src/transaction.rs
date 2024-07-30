use crate::{EthereumAddress, EthereumAmount, EthereumFormat, EthereumNetwork, EthereumPublicKey};
use anychain_core::{
    hex, utilities::crypto::keccak256, PublicKey, Transaction, TransactionError, TransactionId,
};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::{ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{decode_list, RlpStream};
use serde_json::{json, Value};
use std::{convert::TryInto, vec};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionParameters {
    pub nonce: U256,
    pub gas_price: EthereumAmount,
    pub gas_limit: U256,
    pub to: EthereumAddress,
    pub amount: EthereumAmount,
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
        rlp.append(&self.gas_price.0);
        rlp.append(&self.gas_limit);
        rlp.append(&to);
        rlp.append(&self.amount.0);
        rlp.append(&self.data);

        Ok(rlp)
    }

    pub fn decode_data(&self) -> Result<Value, TransactionError> {
        if self.data.len() < 4 {
            return Err(TransactionError::Message("Illegal data".to_string()));
        }

        let selector = &self.data[..4];

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
                match func.decode_input(&self.data[4..]) {
                    Ok(tokens) => {
                        let to = hex::encode(tokens[0].clone().into_address().unwrap().as_bytes());
                        let amount = tokens[1].clone().into_uint().unwrap().as_u128();
                        Ok(json!({
                            "function": "transfer",
                            "params": {
                                "to": to,
                                "amount": amount
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionSignature {
    pub v: Vec<u8>,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
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

        let v = sig.v.clone();
        let r = sig.r.clone();
        let s = sig.s.clone();

        let v: [u8; 4] = v.try_into().unwrap();
        let v = u32::from_be_bytes(v);
        let recid = (v - N::CHAIN_ID * 2 - 35) as u8;

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
        let v = u32::from(recid) + N::CHAIN_ID * 2 + 35;
        let v = v.to_be_bytes().to_vec();
        let r = rs[..32].to_vec();
        let s = rs[32..].to_vec();
        self.signature = Some(EthereumTransactionSignature { v, r, s });
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        match &self.signature {
            Some(sig) => {
                let mut rlp = self.params.to_rlp()?;
                let v = trim_leading_zeros(&sig.v);
                let r = trim_leading_zeros(&sig.r);
                let s = trim_leading_zeros(&sig.s);
                rlp.append(&v);
                rlp.append(&r);
                rlp.append(&s);
                Ok(rlp.out().to_vec())
            }
            None => {
                let mut rlp = self.params.to_rlp()?;
                let chain_id = N::CHAIN_ID.to_be_bytes().to_vec();
                let chain_id = trim_leading_zeros(&chain_id);
                rlp.append(&chain_id);
                rlp.append(&0u8);
                rlp.append(&0u8);
                Ok(rlp.out().to_vec())
            }
        }
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(tx);

        if list.len() != 9 {
            return Err(TransactionError::InvalidRlpLength(list.len()));
        }

        let nonce = match list[0].is_empty() {
            true => U256::zero(),
            false => U256::from(list[0].as_slice()),
        };

        let gas_price = match list[1].is_empty() {
            true => EthereumAmount::from_u256(U256::zero()),
            false => EthereumAmount::from_u256(U256::from(list[1].as_slice())),
        };

        let gas_limit = match list[2].is_empty() {
            true => U256::zero(),
            false => U256::from(list[2].as_slice()),
        };

        let to = EthereumAddress::from_str(&hex::encode(&list[3]))?;

        let amount = match list[4].is_empty() {
            true => EthereumAmount::from_u256(U256::zero()),
            false => EthereumAmount::from_u256(U256::from(list[4].as_slice())),
        };

        let params = EthereumTransactionParameters {
            nonce,
            gas_price,
            gas_limit,
            to,
            amount,
            data: list[5].clone(),
        };

        let mut tx = EthereumTransaction::<N>::new(&params)?;

        if !list[7].is_empty() && !list[8].is_empty() {
            let mut v = list[6].clone();
            let mut r = list[7].clone();
            let mut s = list[8].clone();
            pad_zeros(&mut v, 4);
            pad_zeros(&mut r, 32);
            pad_zeros(&mut s, 32);
            tx.signature = Some(EthereumTransactionSignature { v, r, s });
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eip1559TransactionSignature {
    pub y_parity: bool,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip1559TransactionParameters {
    pub chain_id: u32,
    pub nonce: U256,
    pub max_priority_fee_per_gas: EthereumAmount,
    pub max_fee_per_gas: EthereumAmount,
    pub gas_limit: U256,
    pub to: EthereumAddress,
    pub amount: EthereumAmount,
    pub data: Vec<u8>,
}

impl Eip1559TransactionParameters {
    pub fn to_rlp(&self, array_len: usize) -> Result<RlpStream, TransactionError> {
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("{}", e)))?;

        let mut rlp = RlpStream::new();
        rlp.begin_list(array_len);

        let chain_id = self.chain_id.to_be_bytes().to_vec();
        let chain_id = trim_leading_zeros(&chain_id);

        let mut access_list = RlpStream::new();
        access_list.begin_list(0);
        let access_list = access_list.out().to_vec();

        rlp.append(&chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas.0);
        rlp.append(&self.max_fee_per_gas.0);
        rlp.append(&self.gas_limit);
        rlp.append(&to);
        rlp.append(&self.amount.0);
        rlp.append(&self.data);
        rlp.append(&access_list);

        Ok(rlp)
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
                let y_parity = match sig.y_parity {
                    true => vec![1u8],
                    false => vec![0u8],
                };
                rlp.append(&y_parity);
                rlp.append(&sig.r);
                rlp.append(&sig.s);
                rlp.out().to_vec()
            }
            None => self.params.to_rlp(9)?.out().to_vec(),
        };
        Ok([vec![2u8], rlp].concat())
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(&tx[1..]);

        let len = list.len();
        if len != 9 && len != 12 {
            return Err(TransactionError::InvalidRlpLength(list.len()));
        }

        let mut chain_id = list[0].clone();
        pad_zeros(&mut chain_id, 4);
        let chain_id: [u8; 4] = chain_id.try_into().unwrap();
        let chain_id = u32::from_be_bytes(chain_id);

        let nonce = match list[1].is_empty() {
            true => U256::zero(),
            false => U256::from(list[1].as_slice()),
        };

        let max_priority_fee_per_gas = match list[2].is_empty() {
            true => EthereumAmount::from_u256(U256::zero()),
            false => EthereumAmount::from_u256(U256::from(list[2].as_slice())),
        };

        let max_fee_per_gas = match list[3].is_empty() {
            true => EthereumAmount::from_u256(U256::zero()),
            false => EthereumAmount::from_u256(U256::from(list[3].as_slice())),
        };

        let gas_limit = match list[4].is_empty() {
            true => U256::zero(),
            false => U256::from(list[4].as_slice()),
        };

        let to = EthereumAddress::from_str(&hex::encode(&list[5]))?;

        let amount = match list[6].is_empty() {
            true => EthereumAmount::from_u256(U256::zero()),
            false => EthereumAmount::from_u256(U256::from(list[6].as_slice())),
        };

        let params = Eip1559TransactionParameters {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data: list[7].clone(),
        };

        let mut tx = Eip1559Transaction::<N>::new(&params)?;

        if len == 12 {
            let y_parity = list[9].clone();
            let y_parity = match y_parity[0] {
                0 => false,
                1 => true,
                _ => return Err(TransactionError::Message("Invalid signature".to_string())),
            };
            let mut r = list[10].clone();
            let mut s = list[11].clone();
            pad_zeros(&mut r, 32);
            pad_zeros(&mut s, 32);
            tx.signature = Some(Eip1559TransactionSignature { y_parity, r, s });
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

/// Trim the leading zeros of a byte stream and return it
fn trim_leading_zeros(v: &Vec<u8>) -> &[u8] {
    let mut cnt: usize = 0;
    for byte in v {
        if *byte != 0 {
            break;
        } else {
            cnt += 1;
        }
    }
    &v[cnt..]
}

/// Prepend a number of zeros to 'v' to make it 'to_len' bytes long
fn pad_zeros(v: &mut Vec<u8>, to_len: usize) {
    if v.len() < to_len {
        let mut temp = v.clone();
        let len = v.len();
        v.clear();
        v.resize(to_len - len, 0);
        v.append(&mut temp);
    }
}

fn restore_sender(
    msg: Vec<u8>,
    sig: Vec<u8>,
    recid: u8,
) -> Result<EthereumAddress, TransactionError> {
    let recid = libsecp256k1::RecoveryId::parse(recid)
        .map_err(|e| TransactionError::Message(format!("{}", e)))?;
    let sig = libsecp256k1::Signature::parse_standard_slice(&sig)
        .map_err(|e| TransactionError::Message(format!("{}", e)))?;
    let msg = libsecp256k1::Message::parse_slice(&msg)
        .map_err(|e| TransactionError::Message(format!("{}", e)))?;
    let pk = libsecp256k1::recover(&msg, &sig, &recid)
        .map_err(|e| TransactionError::Message(format!("{}", e)))?;
    let pk = EthereumPublicKey::from_secp256k1_public_key(pk);
    let sender = pk
        .to_address(&EthereumFormat::Standard)
        .map_err(|e| TransactionError::Message(format!("{}", e)))?;
    Ok(sender)
}
