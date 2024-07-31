use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey, Sepolia};
use anychain_core::{
    hex, utilities::crypto::keccak256, PublicKey, Transaction, TransactionError, TransactionId,
};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::{ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{Decodable, Encodable, RlpStream, DecoderError};
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
    pub v: u32,
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
        todo!()
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
        Ok(Self { address, storage_keys })
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
        todo!()
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
