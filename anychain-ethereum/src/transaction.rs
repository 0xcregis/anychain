use crate::address::EthereumAddress;
use crate::amount::EthereumAmount;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::public_key::EthereumPublicKey;
use anychain_core::utilities::crypto::keccak256;
use anychain_core::{hex, PublicKey, Transaction, TransactionError, TransactionId};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::ethereum_types::H160;
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{decode_list, RlpStream};
use std::convert::TryInto;

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
pub struct EthereumTransactionSignature {
    /// The V field of the signature protected with a chain_id
    pub v: Vec<u8>,
    /// The R field of the signature
    pub r: Vec<u8>,
    /// The S field of the signature
    pub s: Vec<u8>,
}

/// Represents an Ethereum transaction id
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

/// Represents an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransaction<N: EthereumNetwork> {
    /// The address of the sender
    pub sender: Option<EthereumAddress>,
    /// The transaction parameters (gas, gas_price, nonce, data)
    pub parameters: EthereumTransactionParameters,
    /// The transaction signature
    pub signature: Option<EthereumTransactionSignature>,
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
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        let message = libsecp256k1::Message::parse_slice(&self.to_transaction_id()?.txid)
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?;
        let recovery_id = libsecp256k1::RecoveryId::parse(recid)
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?;

        let public_key = EthereumPublicKey::from_secp256k1_public_key(
            libsecp256k1::recover(
                &message,
                &libsecp256k1::Signature::parse_standard_slice(rs.as_slice()).map_err(|error| {
                    TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                })?,
                &recovery_id,
            )
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?,
        );
        self.sender = Some(public_key.to_address(&EthereumFormat::Standard)?);
        self.signature = Some(EthereumTransactionSignature {
            v: (u32::from(recid) + N::CHAIN_ID * 2 + 35)
                .to_be_bytes()
                .to_vec(), // EIP155
            r: rs[..32].to_vec(),
            s: rs[32..64].to_vec(),
        });
        self.to_bytes()
    }

    /// Returns a transaction given the transaction bytes.
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md>
    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(transaction);
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
                let mut v = list[6].clone();
                pad_zeros(&mut v, 4);
                let v: [u8; 4] = v.try_into().unwrap();
                let v = u32::from_be_bytes(v);
                let recovery_id = libsecp256k1::RecoveryId::parse((v - N::CHAIN_ID * 2 - 35) as u8)
                    .map_err(|error| {
                        TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                    })?;
                let mut r = list[7].clone();
                pad_zeros(&mut r, 32);
                let mut s = list[8].clone();
                pad_zeros(&mut s, 32);
                let signature = [r.clone(), s.clone()].concat();
                let raw_transaction = Self {
                    sender: None,
                    parameters: parameters.clone(),
                    signature: None,
                    _network: PhantomData,
                };
                let message =
                    libsecp256k1::Message::parse_slice(&raw_transaction.to_transaction_id()?.txid)
                        .map_err(|error| {
                            TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                        })?;
                let public_key = EthereumPublicKey::from_secp256k1_public_key(
                    libsecp256k1::recover(
                        &message,
                        &libsecp256k1::Signature::parse_standard_slice(signature.as_slice())
                            .map_err(|error| {
                                TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                            })?,
                        &recovery_id,
                    )
                    .map_err(|error| {
                        TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                    })?,
                );

                Ok(Self {
                    sender: Some(public_key.to_address(&EthereumFormat::Standard)?),
                    parameters,
                    signature: Some(EthereumTransactionSignature {
                        v: v.to_be_bytes().to_vec(),
                        r,
                        s,
                    }),
                    _network: PhantomData,
                })
            }
        }
    }

    /// Returns the transaction in bytes.
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md>
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
            let chain_id = N::CHAIN_ID.to_be_bytes().to_vec();
            let chain_id = trim_leading_zeros(&chain_id);
            transaction_rlp.append(&chain_id);
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
            // trim the leading zeros of v
            let v = trim_leading_zeros(&signature.v);
            transaction_rlp.append(&v);
            // trim the leading zeros of r
            let r = trim_leading_zeros(&signature.r);
            transaction_rlp.append(&r);
            // trim the leading zeros of s
            let s = trim_leading_zeros(&signature.s);
            transaction_rlp.append(&s);
            Ok(transaction_rlp)
        }

        match &self.signature {
            Some(signature) => Ok(signed_transaction(&self.parameters, signature)?
                .out()
                .to_vec()),
            None => Ok(raw_transaction::<N>(&self.parameters)?.out().to_vec()),
        }
    }

    /// Returns the hash of the signed transaction, if the signature is present.
    /// Otherwise, returns the hash of the raw transaction.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(Self::TransactionId {
            txid: Vec::<u8>::from(&keccak256(&self.to_bytes()?)[..]),
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
