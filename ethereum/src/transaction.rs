use crate::address::EthereumAddress;
use crate::amount::EthereumAmount;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::public_key::EthereumPublicKey;
use chainlib_core::{PublicKey, Transaction, TransactionId,libsecp256k1,hex, Error, TransactionError};
use core::{fmt, marker::PhantomData, str::FromStr};
use chainlib_core::ethereum_types::U256;
use rlp::{decode_list, RlpStream};
use chainlib_core::utilities::crypto::keccak256;
use ethabi::ethereum_types::H160;
use ethabi::{Function, Param, ParamType, StateMutability, Token};


pub fn to_bytes(value: u32) -> Result<Vec<u8>, TransactionError> {
    match value {
        // bounded by u8::max_value()
        0..=255 => Ok(vec![value as u8]),
        // bounded by u16::max_value()
        256..=65535 => Ok((value as u16).to_le_bytes().to_vec()),
        // bounded by u32::max_value()
        _ => Ok(value.to_le_bytes().to_vec()),
    }
}

pub fn u256_to_bytes(value: &U256) -> Result<Vec<u8>, Error> {
    let mut bytes : Vec<u8> = vec![];
    value.to_big_endian(&mut bytes);
    Ok(bytes)
}

pub fn from_bytes(value: &Vec<u8>) -> Result<u32, TransactionError> {
    match value.len() {
        0 => Ok(0u32),
        1 => Ok(u32::from_le_bytes([value[0], 0, 0, 0])),
        2 => Ok(u32::from_le_bytes([value[0], value[1], 0, 0])),
        3 => Ok(u32::from_le_bytes([value[0], value[1], value[2], 0])),
        4 => Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]])),
        _ => Err(TransactionError::Message(
            "invalid byte length for u32 value".to_string(),
        )),
    }
}

pub fn encode_transfer(func_name: &str, address: &EthereumAddress, amount: U256) -> Vec<u8> {
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![
            Param { name: "address".to_string(), kind: ParamType::Address, internal_type: None },
            Param { name: "amount".to_string(), kind: ParamType::Uint(256), internal_type: None },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    let mut tokens = Vec::<Token>::new();
    tokens.push(Token::Address(H160::from_slice(&address.to_bytes().unwrap())));
    tokens.push(Token::Uint(amount));
    func.encode_input(&tokens).unwrap()
}

/// Represents the parameters for an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionParameters {
    /// The address of the receiver
    pub receiver: EthereumAddress,
    /// The amount (in wei)
    pub amount: EthereumAmount,
    /// The transaction gas limit
    pub gas: U256,
    /// The transaction gas price in wei
    pub gas_price: EthereumAmount,
    /// The nonce of the Ethereum account
    pub nonce: U256,
    /// The transaction data
    pub data: Vec<u8>,
}

/// Represents an Ethereum transaction signature
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EthereumTransactionSignature {
    /// The V field of the signature protected with a chain_id
    v: Vec<u8>,
    /// The R field of the signature
    r: Vec<u8>,
    /// The S field of the signature
    s: Vec<u8>,
}

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for EthereumTransactionId {}

impl fmt::Display for EthereumTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", &hex::encode(&self.txid))
    }
}

/// Represents an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransaction<N: EthereumNetwork> {
    /// The address of the sender
    sender: Option<EthereumAddress>,
    /// The transaction parameters (gas, gas_price, nonce, data)
    parameters: EthereumTransactionParameters,
    /// The transaction signature
    signature: Option<EthereumTransactionSignature>,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> Transaction for EthereumTransaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = EthereumTransactionParameters;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            sender: None,
            parameters: parameters.clone(),
            signature: None,
            _network: PhantomData,
        })
    }

    /// Returns a signed transaction given the {r,s,recid}.
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError>{
        let message = libsecp256k1::Message::parse_slice(&self.to_transaction_id()?.txid)?;
        let recovery_id = libsecp256k1::RecoveryId::parse(recid)?;
        let signature = rs.clone();

        let public_key = EthereumPublicKey::from_secp256k1_public_key(
            libsecp256k1::recover(
                &message,
                &libsecp256k1::Signature::parse_standard_slice(signature.as_slice())?,
                &recovery_id,
            )?
        );
        self.sender = Some(public_key.to_address(&EthereumFormat::Standard)?);
        self.signature = Some(EthereumTransactionSignature {
            v: to_bytes(u32::from(recid) + N::CHAIN_ID * 2 + 35)?, // EIP155
            r: rs[..32].to_vec(),
            s: rs[32..64].to_vec(),
        });
        self.to_bytes()
    }

    /// Returns a transaction given the transaction bytes.
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    fn from_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(&transaction);
        if list.len() != 9 {
            return Err(TransactionError::InvalidRlpLength(list.len()));
        }

        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(&hex::encode(&list[3]))?,
            amount: match list[4].is_empty() {
                true => EthereumAmount::from_u256(U256::zero()),
                false => EthereumAmount::from_u256(U256::from(list[4].as_slice())),
            },
            gas: match list[2].is_empty() {
                true => U256::zero(),
                false => U256::from(list[2].as_slice()),
            },
            gas_price: match list[1].is_empty() {
                true => EthereumAmount::from_u256(U256::zero()),
                false => EthereumAmount::from_u256(U256::from(list[1].as_slice())),
            },
            nonce: match list[0].is_empty() {
                true => U256::zero(),
                false => U256::from(list[0].as_slice()),
            },
            data: list[5].clone(),
        };

        match list[7].is_empty() && list[8].is_empty() {
            true => {
                // Raw transaction
                Ok(Self {
                    sender: None,
                    parameters,
                    signature: None,
                    _network: PhantomData,
                })
            }
            false => {
                // Signed transaction
                let v = from_bytes(&list[6])?;
                let recovery_id = libsecp256k1::RecoveryId::parse((v - N::CHAIN_ID * 2 - 35) as u8)?;
                let mut signature = list[7].clone();
                signature.extend_from_slice(&list[8]);

                let raw_transaction = Self {
                    sender: None,
                    parameters: parameters.clone(),
                    signature: None,
                    _network: PhantomData,
                };
                let message = libsecp256k1::Message::parse_slice(&raw_transaction.to_transaction_id()?.txid)?;
                let public_key = EthereumPublicKey::from_secp256k1_public_key(libsecp256k1::recover(
                    &message,
                    &libsecp256k1::Signature::parse_standard_slice(signature.as_slice())?,
                    &recovery_id,
                )?);

                Ok(Self {
                    sender: Some(public_key.to_address(&EthereumFormat::Standard)?),
                    parameters,
                    signature: Some(EthereumTransactionSignature {
                        v: list[6].clone(),
                        r: list[7].clone(),
                        s: list[8].clone(),
                    }),
                    _network: PhantomData,
                })
            }
        }
    }

    /// Returns the transaction in bytes.
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        // Returns an encoded transaction in Recursive Length Prefix (RLP) format.
        // https://github.com/ethereum/wiki/wiki/RLP
        fn encode_transaction(
            transaction_rlp: &mut RlpStream,
            parameters: &EthereumTransactionParameters,
        ) -> Result<(), TransactionError> {
            transaction_rlp.append(&parameters.nonce);
            transaction_rlp.append(&parameters.gas_price.0);
            transaction_rlp.append(&parameters.gas);
            transaction_rlp.append(&hex::decode(&parameters.receiver.to_string()[2..])?);
            transaction_rlp.append(&parameters.amount.0);
            transaction_rlp.append(&parameters.data);
            Ok(())
        }

        // Returns the raw transaction (in RLP).
        fn raw_transaction<N: EthereumNetwork>(
            parameters: &EthereumTransactionParameters,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            transaction_rlp.append(&to_bytes(N::CHAIN_ID)?);
            transaction_rlp.append(&0u8);
            transaction_rlp.append(&0u8);
            Ok(transaction_rlp)
        }

        // Returns the signed transaction (in RLP).
        fn signed_transaction(
            parameters: &EthereumTransactionParameters,
            signature: &EthereumTransactionSignature,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            transaction_rlp.append(&signature.v);
            transaction_rlp.append(&signature.r);
            transaction_rlp.append(&signature.s);
            Ok(transaction_rlp)
        }

        match &self.signature {
            Some(signature) => Ok(signed_transaction(&self.parameters, signature)?.out().to_vec()),
            None => Ok(raw_transaction::<N>(&self.parameters)?.out().to_vec()),
        }
    }

    /// Returns the hash of the signed transaction, if the signature is present.
    /// Otherwise, returns the hash of the raw transaction.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(Self::TransactionId {
            txid: Vec::<u8>::from(&keccak256(&self.to_bytes()?)[..])
        })
    }
}

impl<N: EthereumNetwork> EthereumTransaction<N> {

    pub fn get_from(&self) -> EthereumAddress {
        self.sender.clone().unwrap()
    }

    pub fn get_to(&self) -> EthereumAddress {
        self.parameters.receiver.clone()
    }

    pub fn get_amount(&self) -> EthereumAmount {
        self.parameters.amount
    }

    pub fn get_fee(&self) -> EthereumAmount {
        self.parameters.gas_price
    }

    pub fn get_gas(&self) -> U256 {
        self.parameters.gas
    }

    pub fn get_nonce(&self) -> U256 {
        self.parameters.nonce
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.parameters.data.clone()
    }
    
    pub fn get_signature(&self) -> Result<Vec<u8>, TransactionError> {
        match self.signature.clone() {
            Some(sig) => {
                let v = from_bytes(&sig.v)?;
                let recid = (v - N::CHAIN_ID * 2 - 35) as u8;
                let mut ret = sig.r;
                ret.append(&mut sig.s.clone());
                ret.push(recid);
                Ok(ret)
            },
            None => Err(TransactionError::MissingSignature),
        }
    }
}

impl<N: EthereumNetwork> FromStr for EthereumTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&hex::decode(transaction)?)
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
