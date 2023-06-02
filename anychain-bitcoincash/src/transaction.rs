use crate::{
    BitcoincashAddress, BitcoincashAmount, BitcoincashFormat, BitcoincashNetwork,
    BitcoincashPublicKey, BASE32_DECODE_TABLE,
};
use anychain_bitcoin::transaction::{
    read_variable_length_integer, variable_length_integer, BitcoinVector, Opcode, SignatureHash,
};
use anychain_core::{
    crypto::checksum as double_sha2, hex, Transaction, TransactionError, TransactionId,
};
use base58::FromBase58;
use bech32::{u5, FromBase32};
use std::{fmt, io::Read, str::FromStr, vec};

/// Generate the script_pub_key of a Bitcoincash address
pub fn create_script_pub_key<N: BitcoincashNetwork>(
    address: BitcoincashAddress<N>,
) -> Result<Vec<u8>, TransactionError> {
    let hash = match address.format() {
        BitcoincashFormat::CashAddr => {
            let address = address.to_string();
            // trim the prefix and the checksum
            let bytes_u8 = address.as_bytes()[N::prefix().len() + 1..address.len() - 8].to_vec();
            let bytes_u5: Vec<u5> = bytes_u8
                .iter()
                .map(|byte| u5::try_from_u8(BASE32_DECODE_TABLE[*byte as usize] as u8).unwrap())
                .collect();
            let payload = Vec::<u8>::from_base32(&bytes_u5)?;
            // trim the version byte, left the public key hash
            payload[1..].to_vec()
        }
        BitcoincashFormat::Legacy => {
            let address = address.to_string();
            let bytes = address.from_base58()?;
            // trim the version byte and the checksum
            bytes[1..21].to_vec()
        }
    };

    let mut script = vec![];
    script.push(Opcode::OP_DUP as u8);
    script.push(Opcode::OP_HASH160 as u8);
    script.extend(variable_length_integer(hash.len() as u64)?);
    script.extend(hash);
    script.push(Opcode::OP_EQUALVERIFY as u8);
    script.push(Opcode::OP_CHECKSIG as u8);

    Ok(script)
}

/// Represents a Bitcoin cash transaction outpoint
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outpoint<N: BitcoincashNetwork> {
    /// The previous transaction hash (32 bytes) (uses reversed hash order from Bitcoinbash RPC)
    pub reverse_transaction_id: Vec<u8>,
    /// The index of the transaction input (4 bytes)
    pub index: u32,
    /// The amount associated with this input (used for SegWit transaction signatures)
    pub amount: Option<BitcoincashAmount>,
    /// The address of the outpoint
    pub address: Option<BitcoincashAddress<N>>,
    /// The script public key associated with spending this input
    pub script_pub_key: Option<Vec<u8>>,
}

/// Represents a Bitcoin transaction input
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashTransactionInput<N: BitcoincashNetwork> {
    /// The outpoint (36 bytes)
    pub outpoint: Outpoint<N>,
    /// The transaction input script (variable size)
    pub script_sig: Option<Vec<u8>>,
    /// The sequence number (4 bytes) (0xFFFFFFFF unless lock > 0)
    /// Also used in replace-by-fee (BIP 125)
    pub sequence: Vec<u8>,
    /// The signature hash (4 bytes) (used in signing raw transaction only)
    pub sighash_code: SignatureHash,
}

impl<N: BitcoincashNetwork> BitcoincashTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// Returns a new Bitcoin cash transaction input.
    pub fn new(
        transaction_id: Vec<u8>,
        index: u32,
        sighash: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        let mut transaction_id = transaction_id;
        transaction_id.reverse();

        let outpoint = Outpoint::<N> {
            reverse_transaction_id: transaction_id,
            index,
            amount: None,
            script_pub_key: None,
            address: None,
        };

        Ok(Self {
            outpoint,
            script_sig: None,
            sequence: BitcoincashTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec(),
            sighash_code: sighash,
        })
    }

    pub fn set_address(&mut self, address: BitcoincashAddress<N>) {
        self.outpoint.script_pub_key = Some(create_script_pub_key(address.clone()).unwrap());
        self.outpoint.address = Some(address);
    }

    pub fn set_amount(&mut self, amount: BitcoincashAmount) {
        self.outpoint.amount = Some(amount);
    }

    pub fn set_script_sig(&mut self, script_sig: Vec<u8>) {
        self.script_sig = Some(script_sig);
    }

    /// Read and generate a Bitcoin cash transaction input
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut transaction_hash = [0u8; 32];
        let mut vin = [0u8; 4];
        let mut sequence = [0u8; 4];

        reader.read(&mut transaction_hash)?;
        reader.read(&mut vin)?;

        let outpoint = Outpoint::<N> {
            reverse_transaction_id: transaction_hash.to_vec(),
            index: u32::from_le_bytes(vin),
            amount: None,
            address: None,
            script_pub_key: None,
        };

        let script_sig: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        reader.read(&mut sequence)?;

        let script_sig_len = read_variable_length_integer(&script_sig[..])?;

        let sighash_code = SignatureHash::from_byte(&match script_sig_len {
            0 => 0x01,
            length => script_sig[length],
        });

        Ok(Self {
            outpoint,
            script_sig: Some(script_sig.to_vec()),
            sequence: sequence.to_vec(),
            sighash_code,
        })
    }

    /// Returns the serialized transaction input.
    pub fn serialize(&self, raw: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.outpoint.reverse_transaction_id);
        input.extend(&self.outpoint.index.to_le_bytes());

        match raw {
            true => input.extend(vec![0x00]),
            false => match &self.script_sig {
                Some(script_sig) => {
                    input.extend(variable_length_integer(script_sig.len() as u64)?);
                    input.extend(script_sig);
                }
                None => match &self.outpoint.script_pub_key {
                    Some(script_pub_key) => {
                        input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                        input.extend(script_pub_key);
                    }
                    None => return Err(TransactionError::MissingOutpointScriptPublicKey),
                },
            },
        };

        input.extend(&self.sequence);
        Ok(input)
    }
}

/// Represents a Bitcoin cash transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashTransactionOutput {
    /// The amount (in Satoshi)
    pub amount: BitcoincashAmount,
    /// The public key script
    pub script_pub_key: Vec<u8>,
}

impl BitcoincashTransactionOutput {
    /// Returns a Bitcoin cash transaction output.
    pub fn new<N: BitcoincashNetwork>(
        address: BitcoincashAddress<N>,
        amount: BitcoincashAmount,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            script_pub_key: create_script_pub_key::<N>(address)?,
        })
    }

    /// Read and output a Bitcoin transaction output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut amount = [0u8; 8];
        reader.read(&mut amount)?;

        let script_pub_key: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        Ok(Self {
            amount: BitcoincashAmount::from_satoshi(u64::from_le_bytes(amount) as i64)?,
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

/// The Bitcoin cash transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashTransactionParameters<N: BitcoincashNetwork> {
    /// The version number (4 bytes)
    pub version: u32,
    /// The transaction inputs
    pub inputs: Vec<BitcoincashTransactionInput<N>>,
    /// The transaction outputs
    pub outputs: Vec<BitcoincashTransactionOutput>,
    /// The lock time (4 bytes)
    pub lock_time: u32,
}

impl<N: BitcoincashNetwork> BitcoincashTransactionParameters<N> {
    /// Returns a BitcoinTransactionParameters given the inputs and outputs
    pub fn new(
        inputs: Vec<BitcoincashTransactionInput<N>>,
        outputs: Vec<BitcoincashTransactionOutput>,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
        })
    }

    /// Read and output the Bitcoin transaction parameters
    pub fn read<R: Read>(mut reader: R) -> Result<Self, TransactionError> {
        let mut version = [0u8; 4];
        reader.read(&mut version)?;

        let inputs = BitcoinVector::read(&mut reader, BitcoincashTransactionInput::<N>::read)?;
        let outputs = BitcoinVector::read(&mut reader, BitcoincashTransactionOutput::read)?;

        let mut lock_time = [0u8; 4];
        reader.read(&mut lock_time)?;

        let tx = BitcoincashTransactionParameters::<N> {
            version: u32::from_le_bytes(version),
            inputs,
            outputs,
            lock_time: u32::from_le_bytes(lock_time),
        };

        Ok(tx)
    }
}

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for BitcoincashTransactionId {}

impl fmt::Display for BitcoincashTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

/// Represents a Bitcoin transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashTransaction<N: BitcoincashNetwork> {
    /// The transaction parameters (version, inputs, outputs, lock_time, segwit_flag)
    pub parameters: BitcoincashTransactionParameters<N>,
}

impl<N: BitcoincashNetwork> fmt::Display for BitcoincashTransaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl<N: BitcoincashNetwork> Transaction for BitcoincashTransaction<N> {
    type Address = BitcoincashAddress<N>;
    type Format = BitcoincashFormat;
    type PublicKey = BitcoincashPublicKey<N>;
    type TransactionId = BitcoincashTransactionId;
    type TransactionParameters = BitcoincashTransactionParameters<N>;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: parameters.clone(),
        })
    }

    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: Self::TransactionParameters::read(transaction)?,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut tx = self.parameters.version.to_le_bytes().to_vec();
        tx.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for input in &self.parameters.inputs {
            tx.extend(input.serialize(!input.script_sig.is_some())?);
        }
        tx.extend(variable_length_integer(
            self.parameters.outputs.len() as u64
        )?);
        for output in &self.parameters.outputs {
            tx.extend(output.serialize()?);
        }
        tx.extend(&self.parameters.lock_time.to_le_bytes());
        Ok(tx)
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut txid = double_sha2(&self.to_bytes()?).to_vec();
        txid.reverse();
        Ok(Self::TransactionId { txid })
    }

    fn sign(&mut self, _signature: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        panic!(
            "trait method sign() deprecated for bitcoin cash, use custom methods for signature\
             insertion in its own impl block instead."
        );
    }
}

impl<N: BitcoincashNetwork> BitcoincashTransaction<N> {
    /// Return the P2PKH hash preimage of the raw transaction.
    pub fn p2pkh_hash_preimage(
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

        let script_code = input.outpoint.script_pub_key.clone().unwrap();

        let script_code = [
            variable_length_integer(script_code.len() as u64)?,
            script_code,
        ]
        .concat();

        let hash_prev_outputs = double_sha2(&prev_outputs);
        let hash_sequence = double_sha2(&prev_sequences);
        let hash_outputs = double_sha2(&outputs);
        let outpoint_amount = match &input.outpoint.amount {
            Some(amount) => amount.0.to_le_bytes(),
            None => return Err(TransactionError::MissingOutpointAmount),
        };

        let mut preimage = vec![];
        preimage.extend(&self.parameters.version.to_le_bytes());
        preimage.extend(hash_prev_outputs);
        preimage.extend(hash_sequence);
        preimage.extend(&input.outpoint.reverse_transaction_id);
        preimage.extend(&input.outpoint.index.to_le_bytes());
        preimage.extend(&script_code);
        preimage.extend(&outpoint_amount);
        preimage.extend(&input.sequence);
        preimage.extend(hash_outputs);
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());

        Ok(preimage)
    }

    /// Insert an 'address' into the input at 'index'
    pub fn insert_address(
        &mut self,
        address: BitcoincashAddress<N>,
        index: u32,
    ) -> Result<(), TransactionError> {
        self.parameters.inputs[index as usize].set_address(address);
        Ok(())
    }

    /// Insert 'signature' and 'public_key' into the 'script_sig' field of the input at
    /// 'index' to make this input signed, and returns the signed transaction stream
    pub fn sign_p2pkh(
        &mut self,
        mut signature: Vec<u8>,
        public_key: Vec<u8>,
        index: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        let input = &mut self.parameters.inputs[index as usize];

        signature.push((input.sighash_code as u32).to_le_bytes()[0]);

        let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();
        let public_key = [vec![public_key.len() as u8], public_key].concat();

        input.set_script_sig([signature, public_key].concat());

        self.to_bytes()
    }

    pub fn txid_p2pkh(&self, index: u32) -> Result<Vec<u8>, TransactionError> {
        let sighash = self.parameters.inputs[index as usize].sighash_code;
        let preimage = self.p2pkh_hash_preimage(index as usize, sighash)?;
        Ok(double_sha2(&preimage).to_vec())
    }

    pub fn get_version(&self) -> Result<u32, TransactionError> {
        Ok(self.parameters.version)
    }

    pub fn get_inputs(&self) -> Result<Vec<String>, TransactionError> {
        let mut inputs: Vec<String> = vec![];
        for input in self.parameters.inputs.iter() {
            let mut sequence: u32 = 0;
            let p: *mut u32 = &mut sequence;
            let mut p = p as *mut u8;
            unsafe {
                for i in 0..4 {
                    *p = input.sequence[i];
                    p = p.add(1);
                }
            }
            let outpoint = &input.outpoint;
            let mut txid = outpoint.reverse_transaction_id.clone();
            txid.reverse();
            let txid = hex::encode(&txid);
            let signature = match &input.script_sig {
                Some(sig) => hex::encode(sig),
                None => "".to_string(),
            };
            let input = format!(
                "sequence: {}, txid: {}, index: {}, signature: {}, sighash: {}",
                sequence, txid, outpoint.index, signature, input.sighash_code
            );
            inputs.push(input);
        }
        Ok(inputs)
    }

    pub fn get_outputs(&self) -> Result<Vec<String>, TransactionError> {
        let mut outputs: Vec<String> = vec![];
        for output in self.parameters.outputs.iter() {
            // p2pkh script = [OP_DUP] [OP_HASH160] [pkhash_len(20)] pkhash ...
            // 'OP_DUP', 'OP_HASH160', 'pkhash_len' all occupy one byte memory
            let pkhash = &output.script_pub_key[3..23];
            let address =
                BitcoincashAddress::<N>::from_hash160(pkhash, &BitcoincashFormat::CashAddr)?;
            let output = format!("to: {}, amount: {}", address, output.amount);
            outputs.push(output);
        }
        Ok(outputs)
    }
}

impl<N: BitcoincashNetwork> FromStr for BitcoincashTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&hex::decode(transaction)?)
    }
}

#[cfg(test)]
mod tests {
    use super::create_script_pub_key;
    use crate::{
        BitcoincashAddress, BitcoincashAmount, BitcoincashTransaction, BitcoincashTransactionInput,
        BitcoincashTransactionOutput, BitcoincashTransactionParameters, Mainnet, Testnet,
    };
    use anychain_bitcoin::transaction::SignatureHash;
    use anychain_core::{
        hex,
        libsecp256k1::{self, Message, SecretKey},
        Transaction,
    };
    use std::str::FromStr;

    #[test]
    fn test_script_gen() {
        let addr = "bitcoincash:qqpcmun00mm0q6zezvtfhn2xg2zx2ufpvs7dpdxx0n";
        let addr = BitcoincashAddress::<Mainnet>::from_str(addr).unwrap();
        let v = create_script_pub_key(addr).unwrap();
        println!("v = {:?}", v);
    }

    #[test]
    fn test_tx_gen() {
        let txid = hex::decode("f2ed030e9cc2bc6ae590f9a9bd70d718c4ebdc68561aedc4e130a4ffe79787cd")
            .unwrap();

        let from = "bchtest:qqpcmun00mm0q6zezvtfhn2xg2zx2ufpvs6l92y3g0";
        let to = "bchtest:qpumqqygwcnt999fz3gp5nxjy66ckg6esvmzshj478";

        let from = BitcoincashAddress::<Testnet>::from_str(from).unwrap();
        let to = BitcoincashAddress::<Testnet>::from_str(to).unwrap();

        let sk = [
            56, 127, 139, 242, 234, 208, 96, 112, 134, 251, 100, 45, 230, 217, 251, 107, 58, 234,
            218, 188, 213, 253, 10, 92, 251, 17, 190, 150, 100, 177, 1, 22,
        ] as [u8; 32];

        let sk = SecretKey::parse(&sk).unwrap();

        let mut input = BitcoincashTransactionInput::<Testnet>::new(
            txid,
            1,
            SignatureHash::SIGHASH_ALL_SIGHASH_FORKID,
        )
        .unwrap();

        input.set_address(from.clone());
        input.set_amount(BitcoincashAmount(5000000));

        let output1 = BitcoincashTransactionOutput::new(to, BitcoincashAmount(2500000)).unwrap();

        let output2 = BitcoincashTransactionOutput::new(from, BitcoincashAmount(2300000)).unwrap();

        let params =
            BitcoincashTransactionParameters::new(vec![input], vec![output1, output2]).unwrap();

        let mut tx = BitcoincashTransaction::new(&params).unwrap();

        let hash = tx.txid_p2pkh(0).unwrap();
        let msg = Message::parse_slice(&hash).unwrap();
        let sig = libsecp256k1::sign(&msg, &sk).0;

        let sig = sig.serialize_der().as_ref().to_vec();
        let pubkey = libsecp256k1::PublicKey::from_secret_key(&sk)
            .serialize_compressed()
            .to_vec();

        let _ = tx.sign_p2pkh(sig, pubkey, 0).unwrap();

        println!("tx = {}", tx);

        let tx = "0200000001cd8797e7ffa430e1c4ed1a5668dcebc418d770bda9f990e56abcc29c0e03edf2010000006a47304402204e6e88e2feb5011e25533edabe37efde89ea8775d9dc50fe6e25508357bc9b2e022058a563ccb0b154d2d97503165f33cc15da02144901bba542007009bb03f4ebbe412102fc1cee6dbbf3a07d58794b1543c02679c5aae5a7d463162eb9a86ff29dbe3e90ffffffff02a0252600000000001976a91479b000887626b294a914501a4cd226b58b23598388ac60182300000000001976a914038df26f7ef6f0685913169bcd4642846571216488ac00000000";

        let tx = BitcoincashTransaction::<Testnet>::from_str(tx).unwrap();

        println!("\ntx = {}", tx);
    }
}
