use crate::{
    BitcoinAddress, BitcoinAmount, BitcoinFormat, BitcoinNetwork, BitcoinPublicKey, WitnessProgram,
    BASE32_DECODE_TABLE,
};
use anychain_core::{
    crypto::checksum as double_sha2, Transaction, TransactionError, TransactionId,
};
use anychain_core::{
    hex,
    no_std::{io::Read, *},
    PublicKey,
};
use libsecp256k1::Signature;

use base58::FromBase58;
use bech32::{u5, FromBase32};
use core::{fmt, str::FromStr};
use serde::Serialize;
pub use sha2::{Digest, Sha256};

/// Returns the variable length integer of the given value.
/// `<https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>`
pub fn variable_length_integer(value: u64) -> Result<Vec<u8>, TransactionError> {
    match value {
        // bounded by u8::max_value()
        0..=252 => Ok(vec![value as u8]),
        // bounded by u16::max_value()
        253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
        // bounded by u32::max_value()
        65536..=4294967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
        // bounded by u64::max_value()
        _ => Ok([vec![0xff], value.to_le_bytes().to_vec()].concat()),
    }
}

/// Decode the value of a variable length integer.
/// `<https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>`
pub fn read_variable_length_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {
    let mut flag = [0u8; 1];
    let _ = reader.read(&mut flag)?;

    match flag[0] {
        0..=252 => Ok(flag[0] as usize),
        0xfd => {
            let mut size = [0u8; 2];
            let _ = reader.read(&mut size)?;
            match u16::from_le_bytes(size) {
                s if s < 253 => Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        0xfe => {
            let mut size = [0u8; 4];
            let _ = reader.read(&mut size)?;
            match u32::from_le_bytes(size) {
                s if s < 65536 => Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        _ => {
            let mut size = [0u8; 8];
            let _ = reader.read(&mut size)?;
            match u64::from_le_bytes(size) {
                s if s < 4294967296 => {
                    Err(TransactionError::InvalidVariableSizeInteger(s as usize))
                }
                s => Ok(s as usize),
            }
        }
    }
}

pub struct BitcoinVector;

impl BitcoinVector {
    /// Read and output a vector with a variable length integer
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> Result<Vec<E>, TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }

    /// Read and output a vector with a variable length integer and the integer itself
    pub fn read_witness<R: Read, E, F>(
        mut reader: R,
        func: F,
    ) -> Result<(usize, Result<Vec<E>, TransactionError>), TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        Ok((count, Self::read(reader, func)))
    }
}

/// Generate the script_pub_key of a corresponding address
pub fn create_script_pub_key<N: BitcoinNetwork>(
    address: &BitcoinAddress<N>,
) -> Result<Vec<u8>, TransactionError> {
    match address.format() {
        BitcoinFormat::P2PKH => {
            let bytes = &address.to_string().from_base58()?;

            // Trim the prefix (1st byte) and the checksum (last 4 bytes)
            let pub_key_hash = bytes[1..(bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_DUP as u8);
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(Opcode::OP_EQUALVERIFY as u8);
            script.push(Opcode::OP_CHECKSIG as u8);
            Ok(script)
        }
        BitcoinFormat::P2SH_P2WPKH => {
            let script_bytes = &address.to_string().from_base58()?;
            let script_hash = script_bytes[1..(script_bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(script_hash.len() as u64)?);
            script.extend(script_hash);
            script.push(Opcode::OP_EQUAL as u8);
            Ok(script)
        }
        BitcoinFormat::P2WSH => {
            let (_, data, _) = bech32::decode(&address.to_string())?;
            let (v, script) = data.split_at(1);
            let script = Vec::from_base32(script)?;
            let mut script_bytes = vec![v[0].to_u8(), script.len() as u8];
            script_bytes.extend(script);
            Ok(script_bytes)
        }
        BitcoinFormat::Bech32 => {
            let (_, data, _) = bech32::decode(&address.to_string())?;
            let (v, program) = data.split_at(1);
            let program = Vec::from_base32(program)?;
            let mut program_bytes = vec![v[0].to_u8(), program.len() as u8];
            program_bytes.extend(program);
            Ok(WitnessProgram::new(&program_bytes)?.to_scriptpubkey())
        }
        BitcoinFormat::CashAddr => {
            let address = address.to_string();
            let prefix = N::to_address_prefix(BitcoinFormat::CashAddr)?.prefix();

            let start = if address.starts_with(&prefix) {
                prefix.len() + 1
            } else {
                0
            };

            // trim the prefix and the checksum
            let bytes_u8 = address.as_bytes()[start..address.len() - 8].to_vec();

            let bytes_u5: Vec<u5> = bytes_u8
                .iter()
                .map(|byte| u5::try_from_u8(BASE32_DECODE_TABLE[*byte as usize] as u8).unwrap())
                .collect();
            let payload = Vec::<u8>::from_base32(&bytes_u5)?;
            // trim the version byte, left the public key hash
            let hash = payload[1..].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_DUP as u8);
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(hash.len() as u64)?);
            script.extend(hash);
            script.push(Opcode::OP_EQUALVERIFY as u8);
            script.push(Opcode::OP_CHECKSIG as u8);

            Ok(script)
        }
    }
}

/// Construct and return the OP_RETURN script for the data
/// output of a tx that spends 'amount' basic units of omni
/// layer asset as indicated by 'property_id'.
pub fn create_script_op_return(property_id: u32, amount: i64) -> Result<Vec<u8>, TransactionError> {
    let mut script = vec![];

    let msg_type: u16 = 0;
    let msg_version: u16 = 0;

    script.push(Opcode::OP_RETURN as u8);
    script.push(Opcode::OP_PUSHBYTES_20 as u8);
    script.push(b'o');
    script.push(b'm');
    script.push(b'n');
    script.push(b'i');
    script.append(&mut msg_version.to_be_bytes().to_vec());
    script.append(&mut msg_type.to_be_bytes().to_vec());
    script.append(&mut property_id.to_be_bytes().to_vec());
    script.append(&mut amount.to_be_bytes().to_vec());

    Ok(script)
}

/// Represents a Bitcoin signature hash
/// `<https://en.bitcoin.it/wiki/OP_CHECKSIG>`
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// Signs all inputs and outputs.
    SIGHASH_ALL = 0x01,

    /// Signs all inputs and none of the outputs.
    /// (e.g. "blank check" transaction, where any address can redeem the output)
    SIGHASH_NONE = 0x02,

    /// Signs all inputs and one corresponding output per input.
    /// (e.g. signing vin 0 will result in signing vout 0)
    SIGHASH_SINGLE = 0x03,

    SIGHASH_ALL_SIGHASH_FORKID = 0x41,
    SIGHASH_NONE_SIGHASH_FORKID = 0x42,
    SIGHASH_SINGLE_SIGHASH_FORKID = 0x43,

    /// Signs only one input and all outputs.
    /// Allows anyone to add or remove other inputs, forbids changing any outputs.
    /// (e.g. "crowdfunding" transaction, where the output is the "goal" address)
    SIGHASH_ALL_SIGHASH_ANYONECANPAY = 0x81,

    /// Signs only one input and none of the outputs.
    /// Allows anyone to add or remove other inputs or any outputs.
    /// (e.g. "dust collector" transaction, where "dust" can be aggregated and spent together)
    SIGHASH_NONE_SIGHASH_ANYONECANPAY = 0x82,

    /// Signs only one input and one corresponding output per input.
    /// Allows anyone to add or remove other inputs.
    SIGHASH_SINGLE_SIGHASH_ANYONECANPAY = 0x83,

    SIGHASH_ALL_SIGHASH_FORKID_SIGHASH_ANYONECANPAY = 0xc1,
    SIGHASH_NONE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY = 0xc2,
    SIGHASH_SINGLE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY = 0xc3,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureHash::SIGHASH_ALL => write!(f, "SIGHASH_ALL"),
            SignatureHash::SIGHASH_NONE => write!(f, "SIGHASH_NONE"),
            SignatureHash::SIGHASH_SINGLE => write!(f, "SIGHASH_SINGLE"),
            SignatureHash::SIGHASH_ALL_SIGHASH_FORKID => {
                write!(f, "SIGHASH_ALL | SIGHASH_FORKID")
            }
            SignatureHash::SIGHASH_NONE_SIGHASH_FORKID => {
                write!(f, "SIGHASH_NONE | SIGHASH_FORKID")
            }
            SignatureHash::SIGHASH_SINGLE_SIGHASH_FORKID => {
                write!(f, "SIGHASH_SINGLE | SIGHASH_FORKID")
            }
            SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_ALL | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_NONE | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_SINGLE | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_ALL_SIGHASH_FORKID_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_NONE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_SINGLE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY")
            }
        }
    }
}

impl SignatureHash {
    pub fn from_byte(byte: &u8) -> Self {
        match byte {
            0x02 => SignatureHash::SIGHASH_NONE,
            0x03 => SignatureHash::SIGHASH_SINGLE,
            0x41 => SignatureHash::SIGHASH_ALL_SIGHASH_FORKID,
            0x42 => SignatureHash::SIGHASH_NONE_SIGHASH_FORKID,
            0x43 => SignatureHash::SIGHASH_SINGLE_SIGHASH_FORKID,
            0x81 => SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY,
            0x82 => SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY,
            0x83 => SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY,
            0xc1 => SignatureHash::SIGHASH_ALL_SIGHASH_FORKID_SIGHASH_ANYONECANPAY,
            0xc2 => SignatureHash::SIGHASH_NONE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY,
            0xc3 => SignatureHash::SIGHASH_SINGLE_SIGHASH_FORKID_SIGHASH_ANYONECANPAY,
            _ => SignatureHash::SIGHASH_ALL,
        }
    }
}

/// Represents the commonly used script opcodes
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RETURN = 0x6a,
    OP_PUSHBYTES_20 = 0x14,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Opcode::OP_DUP => write!(f, "OP_DUP"),
            Opcode::OP_HASH160 => write!(f, "OP_HASH160"),
            Opcode::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            Opcode::OP_EQUAL => write!(f, "OP_EQUAL"),
            Opcode::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
            Opcode::OP_RETURN => write!(f, "OP_RETURN"),
            Opcode::OP_PUSHBYTES_20 => write!(f, "OP_PUSHBYTES_20"),
        }
    }
}

/// Represents a Bitcoin transaction outpoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outpoint {
    /// Hash of the previous transaction (32 bytes) (uses reversed hash order from Bitcoin RPC)
    pub reverse_transaction_id: Vec<u8>,
    /// The index of certain utxo in the previous transaction (4 bytes)
    pub index: u32,
}

impl Outpoint {
    /// Returns a new Bitcoin transaction outpoint
    pub fn new(reverse_transaction_id: Vec<u8>, index: u32) -> Self {
        Self {
            reverse_transaction_id,
            index,
        }
    }
}

/// Represents a Bitcoin transaction input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinTransactionInput<N: BitcoinNetwork> {
    /// The outpoint (36 bytes)
    pub outpoint: Outpoint,
    /// The balance of the utxo pointed by this input (used for SegWit transaction signatures)
    pub balance: Option<BitcoinAmount>,
    /// The address of the utxo pointed by this input
    pub address: Option<BitcoinAddress<N>>,
    /// The address format of the utxo pointed by this input
    pub format: Option<BitcoinFormat>,
    /// The 'scriptPubkey' of the utxo pointed by this input
    pub script_pub_key: Option<Vec<u8>>,
    /// An optional redeem script in case of an SegWit utxo
    pub redeem_script: Option<Vec<u8>>,
    /// The transaction input script (variable size)
    pub script_sig: Vec<u8>,
    /// The sequence number (4 bytes) (0xFFFFFFFF unless lock > 0)
    /// Also used in replace-by-fee (BIP 125)
    pub sequence: Vec<u8>,
    /// The signature hash (4 bytes) (used in signing raw transaction only)
    pub sighash_code: SignatureHash,
    /// The witnesses in a SegWit transaction
    pub witnesses: Vec<Vec<u8>>,
    /// If true, the input has been signed
    pub is_signed: bool,
    /// Provide more flexibility for multiple signatures (for P2WSH)
    pub additional_witness: Option<(Vec<u8>, bool)>,
    /// Option for additional witness stack script args
    pub witness_script_data: Option<Vec<u8>>,
}

impl<N: BitcoinNetwork> BitcoinTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xf2, 0xff, 0xff, 0xff];

    /// Returns a new Bitcoin transaction input.
    pub fn new(
        transaction_id: Vec<u8>,
        index: u32,
        public_key: Option<BitcoinPublicKey<N>>,
        format: Option<BitcoinFormat>,
        address: Option<BitcoinAddress<N>>,
        balance: Option<BitcoinAmount>,
        sighash: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Byte-wise reverse of computed SHA-256 hash values
        // https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let format = match format {
            Some(f) => Some(f),
            None => Some(BitcoinFormat::P2PKH),
        };

        let (address, script_pub_key, redeem_script) = match public_key {
            Some(pk) => {
                let addr = pk.to_address(&format.clone().unwrap())?;
                if let Some(v) = address {
                    if v != addr {
                        return Err(TransactionError::Message(format!(
                            "Provided address {} does not match the provided public key {}",
                            addr, pk,
                        )));
                    }
                }
                let script_pub_key = create_script_pub_key(&addr)?;
                let redeem_script = match format {
                    Some(BitcoinFormat::P2SH_P2WPKH) => {
                        Some(BitcoinAddress::<N>::create_redeem_script(&pk).to_vec())
                    }
                    _ => None,
                };
                (Some(addr), Some(script_pub_key), redeem_script)
            }
            None => match address {
                Some(addr) => {
                    let script_pub_key = create_script_pub_key(&addr)?;
                    (Some(addr), Some(script_pub_key), None)
                }
                None => (None, None, None),
            },
        };

        Ok(Self {
            outpoint: Outpoint::new(reverse_transaction_id, index),
            balance,
            address,
            format,
            script_pub_key,
            redeem_script,
            script_sig: vec![],
            sequence: BitcoinTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec(),
            sighash_code: sighash,
            witnesses: vec![],
            is_signed: false,
            additional_witness: None,
            witness_script_data: None,
        })
    }

    pub fn set_public_key(
        &mut self,
        public_key: BitcoinPublicKey<N>,
        format: BitcoinFormat,
    ) -> Result<(), TransactionError> {
        let address = public_key.to_address(&format)?;
        self.format = Some(format.clone());
        self.script_pub_key = Some(create_script_pub_key(&address)?);
        self.address = Some(address);
        self.redeem_script = match format {
            BitcoinFormat::P2SH_P2WPKH => {
                Some(BitcoinAddress::<N>::create_redeem_script(&public_key).to_vec())
            }
            _ => None,
        };
        Ok(())
    }

    pub fn set_redeem_script(&mut self, redeem_script: Vec<u8>) -> Result<(), TransactionError> {
        self.redeem_script = Some(redeem_script);
        Ok(())
    }

    pub fn set_format(&mut self, format: BitcoinFormat) -> Result<(), TransactionError> {
        self.format = Some(format);
        Ok(())
    }

    pub fn set_balance(&mut self, balance: i64) -> Result<(), TransactionError> {
        self.balance = Some(BitcoinAmount(balance));
        Ok(())
    }

    pub fn set_sequence(&mut self, sequence: u32) -> Result<(), TransactionError> {
        self.sequence = u32::to_le_bytes(sequence).to_vec();
        Ok(())
    }

    pub fn set_sighash(&mut self, sighash: SignatureHash) -> Result<(), TransactionError> {
        self.sighash_code = sighash;
        Ok(())
    }

    pub fn get_address(&self) -> Option<BitcoinAddress<N>> {
        self.address.clone()
    }

    pub fn get_format(&self) -> Option<BitcoinFormat> {
        self.format.clone()
    }

    pub fn get_balance(&self) -> Option<BitcoinAmount> {
        self.balance
    }

    pub fn get_sequence(&self) -> u32 {
        let sequence: [u8; 4] = self.sequence.clone().try_into().unwrap();
        u32::from_le_bytes(sequence)
    }

    pub fn get_sighash(&self) -> SignatureHash {
        self.sighash_code
    }

    /// Read and output a Bitcoin transaction input
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut transaction_hash = [0u8; 32];
        let mut vin = [0u8; 4];
        let mut sequence = [0u8; 4];

        let _ = reader.read(&mut transaction_hash)?;
        let _ = reader.read(&mut vin)?;

        let outpoint = Outpoint::new(transaction_hash.to_vec(), u32::from_le_bytes(vin));

        let script_sig: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            let _ = s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        let _ = reader.read(&mut sequence)?;

        let script_sig_len = read_variable_length_integer(&script_sig[..])?;

        let sighash_code = SignatureHash::from_byte(&match script_sig_len {
            0 => 0x01,
            length => script_sig[length],
        });

        Ok(Self {
            outpoint,
            balance: None,
            address: None,
            format: None,
            script_pub_key: None,
            redeem_script: None,
            script_sig: script_sig.to_vec(),
            sequence: sequence.to_vec(),
            sighash_code,
            witnesses: vec![],
            is_signed: !script_sig.is_empty(),
            additional_witness: None,
            witness_script_data: None,
        })
    }

    /// Returns the serialized transaction input.
    pub fn serialize(&self, raw: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.outpoint.reverse_transaction_id);
        input.extend(&self.outpoint.index.to_le_bytes());
        match raw {
            true => input.extend(vec![0x00]),
            false => match self.script_sig.len() {
                0 => match &self.address {
                    Some(address) => match address.format() {
                        BitcoinFormat::P2PKH => {
                            let script_pub_key = match &self.script_pub_key {
                                Some(script) => script,
                                None => {
                                    return Err(TransactionError::MissingOutpointScriptPublicKey)
                                }
                            };
                            input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                            input.extend(script_pub_key);
                        }
                        _ => input.extend(vec![0x00]),
                    },
                    None => input.extend(vec![0x00]),
                },
                _ => {
                    input.extend(variable_length_integer(self.script_sig.len() as u64)?);
                    input.extend(&self.script_sig);
                }
            },
        };

        input.extend(&self.sequence);

        Ok(input)
    }

    /// Insert 'signature' and 'public_key' into this input to make it signed
    pub fn sign(
        &mut self,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), TransactionError> {
        let mut signature = Signature::parse_standard_slice(&signature)
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?
            .serialize_der()
            .as_ref()
            .to_vec();
        signature.push(self.sighash_code as u8);

        let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();
        let public_key = [
            variable_length_integer(public_key.len() as u64)?,
            public_key,
        ]
        .concat();

        match self.get_format().unwrap() {
            BitcoinFormat::P2PKH | BitcoinFormat::CashAddr => {
                self.script_sig = [signature, public_key].concat()
            }
            BitcoinFormat::P2SH_P2WPKH => {
                let input_script = match &self.redeem_script {
                    Some(script) => script.clone(),
                    None => {
                        return Err(TransactionError::Message(
                            "Missing redeem script".to_string(),
                        ))
                    }
                };
                self.script_sig = [
                    variable_length_integer(input_script.len() as u64)?,
                    input_script,
                ]
                .concat();
                self.witnesses.append(&mut vec![signature, public_key]);
            }
            BitcoinFormat::Bech32 => self.witnesses.append(&mut vec![signature, public_key]),
            BitcoinFormat::P2WSH => {
                return Err(TransactionError::Message(
                    "P2WSH signing not supported".to_string(),
                ))
            }
        }

        self.is_signed = true;

        Ok(())
    }
}

/// Represents a Bitcoin transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionOutput {
    /// The amount (in Satoshi)
    pub amount: BitcoinAmount,
    /// The public key script
    pub script_pub_key: Vec<u8>,
}

impl BitcoinTransactionOutput {
    /// Returns a Bitcoin transaction output.
    pub fn new<N: BitcoinNetwork>(
        address: BitcoinAddress<N>,
        amount: BitcoinAmount,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            script_pub_key: create_script_pub_key::<N>(&address)?,
        })
    }

    /// Returns the data output for a tx that spends 'amount' basic
    /// units of omni-layer asset as indicated by 'property_id'.
    pub fn omni_data_output(
        property_id: u32,
        amount: BitcoinAmount,
    ) -> Result<Self, TransactionError> {
        let data_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(0),
            script_pub_key: create_script_op_return(property_id, amount.0)?,
        };

        Ok(data_output)
    }

    /// Read and output a Bitcoin transaction output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut amount = [0u8; 8];
        let _ = reader.read(&mut amount)?;

        let script_pub_key: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            let _ = s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        Ok(Self {
            amount: BitcoinAmount::from_satoshi(u64::from_le_bytes(amount) as i64)?,
            script_pub_key,
        })
    }

    /// Returns the serialized transaction output.
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut output = vec![];
        output.extend(&self.amount.0.to_le_bytes());
        output.extend(variable_length_integer(self.script_pub_key.len() as u64)?);
        output.extend(&self.script_pub_key);
        Ok(output)
    }
}

/// Represents an Bitcoin transaction id and witness transaction id
/// `<https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-id>`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionId {
    txid: Vec<u8>,
    wtxid: Vec<u8>,
}

impl TransactionId for BitcoinTransactionId {}

impl fmt::Display for BitcoinTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

/// Represents the Bitcoin transaction parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinTransactionParameters<N: BitcoinNetwork> {
    /// The version number (4 bytes)
    pub version: u32,
    /// The transaction inputs
    pub inputs: Vec<BitcoinTransactionInput<N>>,
    /// The transaction outputs
    pub outputs: Vec<BitcoinTransactionOutput>,
    /// The lock time (4 bytes)
    pub lock_time: u32,
    /// An optional 2 bytes to indicate SegWit transactions
    pub segwit_flag: bool,
}

impl<N: BitcoinNetwork> BitcoinTransactionParameters<N> {
    /// Returns a BitcoinTransactionParameters given the inputs and outputs
    pub fn new(
        inputs: Vec<BitcoinTransactionInput<N>>,
        outputs: Vec<BitcoinTransactionOutput>,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
            segwit_flag: false,
        })
    }

    /// Read and output the Bitcoin transaction parameters
    pub fn read<R: Read>(mut reader: R) -> Result<Self, TransactionError> {
        let mut version = [0u8; 4];
        let _ = reader.read(&mut version)?;

        let mut inputs = BitcoinVector::read(&mut reader, BitcoinTransactionInput::<N>::read)?;

        let segwit_flag = match inputs.is_empty() {
            true => {
                let mut flag = [0u8; 1];
                let _ = reader.read(&mut flag)?;
                match flag[0] {
                    1 => {
                        inputs =
                            BitcoinVector::read(&mut reader, BitcoinTransactionInput::<N>::read)?;
                        true
                    }
                    _ => return Err(TransactionError::InvalidSegwitFlag(flag[0] as usize)),
                }
            }
            false => false,
        };

        let outputs = BitcoinVector::read(&mut reader, BitcoinTransactionOutput::read)?;

        if segwit_flag {
            for input in &mut inputs {
                let witnesses: Vec<Vec<u8>> = BitcoinVector::read(&mut reader, |s| {
                    let (size, witness) = BitcoinVector::read_witness(s, |sr| {
                        let mut byte = [0u8; 1];
                        let _ = sr.read(&mut byte)?;
                        Ok(byte[0])
                    })?;
                    Ok([variable_length_integer(size as u64)?, witness?].concat())
                })?;

                if !witnesses.is_empty() {
                    input.sighash_code =
                        SignatureHash::from_byte(&witnesses[0][&witnesses[0].len() - 1]);
                    input.is_signed = true;
                }

                input.witnesses = witnesses;
            }
        }

        let mut lock_time = [0u8; 4];
        let _ = reader.read(&mut lock_time)?;

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: u32::from_le_bytes(version),
            inputs,
            outputs,
            lock_time: u32::from_le_bytes(lock_time),
            segwit_flag,
        };

        Ok(transaction_parameters)
    }
}

/// Represents a Bitcoin transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinTransaction<N: BitcoinNetwork> {
    /// The transaction parameters (version, inputs, outputs, lock_time, segwit_flag)
    pub parameters: BitcoinTransactionParameters<N>,
}

impl<N: BitcoinNetwork> fmt::Display for BitcoinTransaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl<N: BitcoinNetwork> Transaction for BitcoinTransaction<N> {
    type Address = BitcoinAddress<N>;
    type Format = BitcoinFormat;
    type PublicKey = BitcoinPublicKey<N>;
    type TransactionId = BitcoinTransactionId;
    type TransactionParameters = BitcoinTransactionParameters<N>;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: parameters.clone(),
        })
    }

    /// Returns a transaction given the transaction bytes.
    /// Note:: Raw transaction hex does not include enough
    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: Self::TransactionParameters::read(transaction)?,
        })
    }

    /// Returns the transaction in bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        if self.parameters.segwit_flag {
            transaction.extend(vec![0x00, 0x01]);
        }

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        let mut has_witness = false;
        for input in &self.parameters.inputs {
            if !has_witness {
                has_witness = !input.witnesses.is_empty();
            }
            transaction.extend(input.serialize(!input.is_signed)?);
        }

        transaction.extend(variable_length_integer(
            self.parameters.outputs.len() as u64
        )?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        if has_witness {
            for input in &self.parameters.inputs {
                match input.witnesses.len() {
                    0 => transaction.extend(vec![0x00]),
                    _ => {
                        transaction.extend(variable_length_integer(input.witnesses.len() as u64)?);
                        for witness in &input.witnesses {
                            transaction.extend(witness);
                        }
                    }
                };
            }
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut txid = double_sha2(&self.to_transaction_bytes_without_witness()?).to_vec();
        let mut wtxid = double_sha2(&self.to_bytes()?).to_vec();

        txid.reverse();
        wtxid.reverse();

        Ok(Self::TransactionId { txid, wtxid })
    }

    fn sign(&mut self, _signature: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        panic!(
            "trait method sign() deprecated for bitcoin, use custom methods for signature\
             insertion in its own impl block instead."
        );
    }
}

impl<N: BitcoinNetwork> BitcoinTransaction<N> {
    /// Return the P2PKH hash preimage of the raw transaction.
    pub fn p2pkh_hash_preimage(
        &self,
        vin: usize,
        sighash: SignatureHash,
    ) -> Result<Vec<u8>, TransactionError> {
        let mut preimage = self.parameters.version.to_le_bytes().to_vec();
        preimage.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for (index, input) in self.parameters.inputs.iter().enumerate() {
            preimage.extend(input.serialize(index != vin)?);
        }
        preimage.extend(variable_length_integer(
            self.parameters.outputs.len() as u64
        )?);
        for output in &self.parameters.outputs {
            preimage.extend(output.serialize()?);
        }
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());
        Ok(preimage)
    }

    /// Return the SegWit hash preimage of the raw transaction
    /// `<https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification>`
    pub fn segwit_hash_preimage(
        &self,
        vin: usize,
        sighash: SignatureHash,
    ) -> Result<Vec<u8>, TransactionError> {
        let mut prev_outputs = vec![];
        let mut prev_sequences = vec![];
        let mut outputs = vec![];

        for input in &self.parameters.inputs {
            prev_outputs.extend(&input.outpoint.reverse_transaction_id);
            prev_outputs.extend(&input.outpoint.index.to_le_bytes());
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.parameters.outputs {
            outputs.extend(&output.serialize()?);
        }

        let input = &self.parameters.inputs[vin];
        let format = match &input.address {
            Some(address) => address.format(),
            None => return Err(TransactionError::MissingOutpointAddress),
        };

        let script = match format {
            BitcoinFormat::Bech32 => match &input.script_pub_key {
                Some(script) => script[1..].to_vec(),
                None => return Err(TransactionError::MissingOutpointScriptPublicKey),
            },
            BitcoinFormat::CashAddr => match &input.script_pub_key {
                Some(script) => script.to_vec(),
                None => return Err(TransactionError::MissingOutpointScriptPublicKey),
            },
            BitcoinFormat::P2WSH => match &input.redeem_script {
                Some(redeem_script) => redeem_script.to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
            },
            BitcoinFormat::P2SH_P2WPKH => match &input.redeem_script {
                Some(redeem_script) => redeem_script[1..].to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
            },
            _ => return Err(TransactionError::UnsupportedPreimage("P2PKH".into())),
        };

        let mut script_code = vec![];
        if format == BitcoinFormat::P2WSH || format == BitcoinFormat::CashAddr {
            script_code.extend(script);
        } else {
            script_code.push(Opcode::OP_DUP as u8);
            script_code.push(Opcode::OP_HASH160 as u8);
            script_code.extend(script);
            script_code.push(Opcode::OP_EQUALVERIFY as u8);
            script_code.push(Opcode::OP_CHECKSIG as u8);
        }
        let script_code = [
            variable_length_integer(script_code.len() as u64)?,
            script_code,
        ]
        .concat();
        let hash_prev_outputs = double_sha2(&prev_outputs);
        let hash_sequence = double_sha2(&prev_sequences);
        let hash_outputs = double_sha2(&outputs);
        let balance = match &input.balance {
            Some(balance) => balance.0.to_le_bytes(),
            None => return Err(TransactionError::MissingOutpointAmount),
        };

        let mut preimage = vec![];
        preimage.extend(&self.parameters.version.to_le_bytes());
        preimage.extend(hash_prev_outputs);
        preimage.extend(hash_sequence);
        preimage.extend(&input.outpoint.reverse_transaction_id);
        preimage.extend(&input.outpoint.index.to_le_bytes());
        preimage.extend(&script_code);
        preimage.extend(&balance);
        preimage.extend(&input.sequence);
        preimage.extend(hash_outputs);
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());

        Ok(preimage)
    }

    /// Returns the transaction with the traditional serialization (no witness).
    pub fn to_transaction_bytes_without_witness(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for input in &self.parameters.inputs {
            transaction.extend(input.serialize(false)?);
        }

        transaction.extend(variable_length_integer(
            self.parameters.outputs.len() as u64
        )?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }

    pub fn input(
        &mut self,
        index: u32,
    ) -> Result<&mut BitcoinTransactionInput<N>, TransactionError> {
        if index as usize >= self.parameters.inputs.len() {
            return Err(TransactionError::Message(format!(
                "you are referring to input {}, which is out of bound",
                index
            )));
        }
        Ok(&mut self.parameters.inputs[index as usize])
    }

    pub fn digest(&mut self, index: u32) -> Result<Vec<u8>, TransactionError> {
        let input = self.input(index)?;
        let sighash = input.sighash_code;
        match input.get_address() {
            Some(addr) => {
                let preimage = match addr.format() {
                    BitcoinFormat::P2PKH => self.p2pkh_hash_preimage(index as usize, sighash)?,
                    _ => self.segwit_hash_preimage(index as usize, sighash)?,
                };
                Ok(double_sha2(&preimage).to_vec())
            }
            None => Err(TransactionError::MissingOutpointAddress),
        }
    }

    pub fn set_segwit(&mut self) -> Result<(), TransactionError> {
        for input in self.parameters.inputs.clone() {
            if self.parameters.segwit_flag {
                break;
            }
            if input.is_signed {
                match input.get_format() {
                    Some(BitcoinFormat::P2SH_P2WPKH) | Some(BitcoinFormat::Bech32) => {
                        self.parameters.segwit_flag = true
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&hex::decode(transaction)?)
    }
}
