use crate::util::{adapt2, pad_zeros, restore_sender, trim_leading_zeros};
use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey, Sepolia};
use anychain_core::{hex, utilities::crypto::keccak256, PublicKey, Transaction, TransactionError};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::{encode, ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_json::{json, Value};

use crate::{eip1559::AccessItem, encode_transfer, EthereumTransactionId};
use anychain_kms::bip32::{DerivationPath, Prefix, XprvSecp256k1};
use anychain_kms::bip39::{Language, Mnemonic, Seed};
use anychain_kms::secp256k1_sign;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authorization {
    pub chain_id: u32,
    pub address: EthereumAddress,
    pub nonce: U256,
    pub y_parity: bool,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl Authorization {
    pub fn digest(&self) -> Vec<u8> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(3);
        rlp.append(&self.chain_id);
        rlp.append(&self.address.to_bytes().unwrap());
        rlp.append(&self.nonce);

        let stream = [vec![5u8], rlp.out().as_ref().to_vec()].concat();
        keccak256(&stream).to_vec()
    }

    pub fn sign(&mut self, sig: (Vec<u8>, u8)) {
        self.y_parity = sig.1 == 1;
        self.r = sig.0[..32].to_vec();
        self.s = sig.0[32..].to_vec();
    }
}

impl Encodable for Authorization {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6);
        s.append(&self.chain_id);
        s.append(&self.address.to_bytes().unwrap());
        s.append(&self.nonce);
        s.append(&self.y_parity);
        s.append(&trim_leading_zeros(&self.r));
        s.append(&trim_leading_zeros(&self.s));
    }
}

impl Decodable for Authorization {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let chain_id = rlp.val_at::<u32>(0)?;
        let address = rlp.val_at::<Vec<u8>>(1)?;
        let address = hex::encode(address);
        let address = EthereumAddress::from_str(&address).unwrap();
        let nonce = rlp.val_at::<U256>(2)?;
        let y_parity = rlp.val_at(3)?;
        let mut r = rlp.val_at(4)?;
        let mut s = rlp.val_at(5)?;
        pad_zeros(&mut r, 32);
        pad_zeros(&mut s, 32);
        Ok(Self {
            chain_id,
            address,
            nonce,
            y_parity,
            r,
            s,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip7702TransactionParameters {
    pub chain_id: u32,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: EthereumAddress,
    pub amount: U256,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessItem>,
    pub authorizations: Vec<Authorization>,
}

impl Eip7702TransactionParameters {
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
        rlp.append_list(&self.authorizations);

        Ok(rlp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eip7702TransactionSignature {
    pub y_parity: bool,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip7702Transaction<N: EthereumNetwork> {
    pub sender: Option<EthereumAddress>,
    pub params: Eip7702TransactionParameters,
    pub signature: Option<Eip7702TransactionSignature>,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> Eip7702Transaction<N> {
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

impl<N: EthereumNetwork> Transaction for Eip7702Transaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = Eip7702TransactionParameters;

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
        self.signature = Some(Eip7702TransactionSignature { y_parity, r, s });
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let rlp = match &self.signature {
            Some(sig) => {
                let mut rlp = self.params.to_rlp(13)?;
                let r = trim_leading_zeros(&sig.r);
                let s = trim_leading_zeros(&sig.s);
                rlp.append(&sig.y_parity);
                rlp.append(&r);
                rlp.append(&s);
                rlp.out().to_vec()
            }
            None => self.params.to_rlp(10)?.out().to_vec(),
        };
        Ok([vec![4u8], rlp].concat())
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        if tx.is_empty() || tx[0] != 4u8 {
            return Err(TransactionError::Message(
                "Invalid transaction type for EIP-7702".to_string(),
            ));
        }
        let rlp = Rlp::new(&tx[1..]);

        let item_count = adapt2(rlp.item_count())?;
        if item_count != 10 && item_count != 13 {
            return Err(TransactionError::Message(format!(
                "Invalid RLP item count for EIP-7702: {}",
                item_count
            )));
        }

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
        let authorizations = adapt2(rlp.list_at::<Authorization>(9))?;

        let params = Eip7702TransactionParameters {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data,
            access_list,
            authorizations,
        };

        let mut tx = Eip7702Transaction::<N>::new(&params)?;

        if item_count == 13 {
            let y_parity = adapt2(rlp.val_at::<bool>(10))?;
            let mut r = adapt2(rlp.val_at::<Vec<u8>>(11))?;
            let mut s = adapt2(rlp.val_at::<Vec<u8>>(12))?;

            pad_zeros(&mut r, 32);
            pad_zeros(&mut s, 32);
            let sig = Eip7702TransactionSignature { y_parity, r, s };
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

impl<N: EthereumNetwork> FromStr for Eip7702Transaction<N> {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = match &tx[..2] {
            "0x" => &tx[2..],
            _ => tx,
        };
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl<N: EthereumNetwork> fmt::Display for Eip7702Transaction<N> {
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

pub fn parse_mnemonic(phrase: String) -> Value {
    if let Some(lang) = Language::from_phrase(&phrase) {
        Mnemonic::validate(&phrase, lang).unwrap();
        let phrase = Mnemonic::from_phrase(&phrase, lang).unwrap();
        let seed = Seed::new(&phrase, "");
        let seed = seed.as_bytes();
        let xprv = XprvSecp256k1::new(seed).unwrap();
        let xpub = xprv.public_key().to_string(Prefix::XPUB);
        let xprv = xprv.to_string(Prefix::XPRV).to_string();
        let data = json!({
            "xprv": xprv,
            "xpub": xpub,
        });
        data
    } else {
        Value::Null
    }
}

pub fn create_sk(xprv: String, path: String) -> libsecp256k1::SecretKey {
    let xprv = XprvSecp256k1::from_str(&xprv).unwrap();
    let derive_path = DerivationPath::from_str(&path).unwrap();
    let xprv = xprv.derive_from_path(&derive_path).unwrap();
    let sk = xprv.private_key();
    *sk
}

pub fn create_address(xprv: String, path: String) -> EthereumAddress {
    let xprv = XprvSecp256k1::from_str(&xprv).unwrap();
    let derive_path = DerivationPath::from_str(&path).unwrap();
    let xprv = xprv.derive_from_path(&derive_path).unwrap();
    let xpub = xprv.public_key();
    let pk = *xpub.public_key();

    EthereumPublicKey::from_secp256k1_public_key(pk)
        .to_address(&EthereumFormat::Standard)
        .unwrap()
}

pub struct Many2ManyTransfer {
    pub xprv: String,
    pub path: String,     // fee payer
    pub nonce: u64,       // fee payer nonce
    pub contract: String, // caller contract address
    pub transfers: Vec<One2ManyTransfer>,
}

impl Many2ManyTransfer {
    pub fn new(
        xprv: String,
        path: String,
        nonce: u64,
        contract: String,
        transfers: Vec<One2ManyTransfer>,
    ) -> Self {
        Self {
            xprv,
            path,
            nonce,
            contract,
            transfers,
        }
    }

    pub fn to_tx(&self) -> Result<Vec<u8>, TransactionError> {
        let params = Eip7702TransactionParameters {
            chain_id: Sepolia::CHAIN_ID,
            nonce: U256::from(self.nonce),
            max_priority_fee_per_gas: U256::from_dec_str("1000000000").unwrap(),
            max_fee_per_gas: U256::from_dec_str("1000000000").unwrap(),
            gas_limit: U256::from(2100000),
            to: EthereumAddress::from_str(&self.contract).unwrap(),
            amount: U256::zero(),
            data: self.data()?,
            access_list: vec![],
            authorizations: self.authorizations()?,
        };

        let mut tx = Eip7702Transaction::<Sepolia>::new(&params)?;
        let msg = tx.to_transaction_id()?.txid;

        let sk = create_sk(self.xprv.clone(), self.path.clone());
        let (rs, recid) =
            secp256k1_sign(&sk, &msg).map_err(|e| TransactionError::Message(format!("{}", e)))?;

        tx.sign(rs, recid)
    }

    pub fn authorizations(&self) -> Result<Vec<Authorization>, TransactionError> {
        self.transfers
            .iter()
            .map(|transfer| transfer.authorization())
            .collect::<Result<Vec<Authorization>, TransactionError>>()
            .map_err(|e| TransactionError::Message(format!("{}", e)))
    }

    pub fn data(&self) -> Result<Vec<u8>, TransactionError> {
        encode_many_2_many_transfers("schedule", &self.transfers)
    }
}

pub struct One2ManyTransfer {
    pub xprv: String,
    pub path: String,        // from address path
    pub nonce: u64,          // from address nonce
    pub contract: String,    // batch transfer contract
    pub transfers: Vec<One2OneTransfer>,
}

impl One2ManyTransfer {
    pub fn new(
        xprv: String,
        path: String,
        nonce: u64,
        contract: String,
        transfers: Vec<One2OneTransfer>,
    ) -> Self {
        Self {
            xprv,
            path,
            nonce,
            contract,
            transfers,
        }
    }

    pub fn authorization(&self) -> Result<Authorization, TransactionError> {
        let sk = create_sk(self.xprv.clone(), self.path.clone());

        let address = EthereumAddress::from_str(&self.contract)?;
        let nonce = U256::from(self.nonce);
        let chain_id = Sepolia::CHAIN_ID;

        let mut auth = Authorization {
            chain_id,
            address,
            nonce,
            y_parity: false,
            r: vec![],
            s: vec![],
        };

        let msg = auth.digest();
        let (rs, recid) =
            secp256k1_sign(&sk, &msg).map_err(|e| TransactionError::Message(format!("{}", e)))?;

        auth.sign((rs, recid));
        Ok(auth)
    }

    pub fn data(&self) -> Result<Vec<u8>, TransactionError> {
        let sk = create_sk(self.xprv.clone(), self.path.clone());
        encode_one_2_many_transfers(
            "execute_batch_transfer",
            &self.transfers,
            &sk,
        )
    }

    pub fn to_token(&self) -> Token {
        let address = create_address(self.xprv.clone(), self.path.clone());
        let to = Token::Address(H160::from_slice(&address.to_bytes().unwrap()));
        let amount = Token::Uint(U256::zero());
        let data = Token::Bytes(self.data().unwrap());
        Token::Tuple(vec![to, amount, data])
    }
}

pub struct One2OneTransfer {
    pub token: Option<EthereumAddress>,
    pub to: EthereumAddress,
    pub amount: U256,
}

impl One2OneTransfer {
    pub fn new(token: Option<String>, to: String, amount: &str) -> Self {
        Self {
            token: token.map(|t| EthereumAddress::from_str(&t).unwrap()),
            to: EthereumAddress::from_str(&to).unwrap(),
            amount: U256::from_dec_str(amount).unwrap(),
        }
    }

    pub fn to_token(&self) -> Token {
        match &self.token {
            Some(token) => {
                let to = Token::Address(H160::from_slice(&token.to_bytes().unwrap()));
                let amount = Token::Uint(U256::from(0));
                let data = Token::Bytes(encode_transfer("transfer", &self.to, self.amount));
                Token::Tuple(vec![to, amount, data])
            }
            None => {
                let to = Token::Address(H160::from_slice(&self.to.to_bytes().unwrap()));
                let amount = Token::Uint(self.amount);
                let data = Token::Bytes(vec![]);
                Token::Tuple(vec![to, amount, data])
            }
        }
    }
}

pub fn encode_one_2_many_transfers(
    func_name: &str,
    transfers: &[One2OneTransfer],
    sk: &libsecp256k1::SecretKey,
) -> Result<Vec<u8>, TransactionError> {
    let param_calls = Param {
        name: "calls".to_string(),
        kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Bytes,
        ]))),
        internal_type: None,
    };
    let param_v = Param {
        name: "v".to_string(),
        kind: ParamType::Uint(8),
        internal_type: None,
    };
    let param_r = Param {
        name: "r".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };
    let param_s = Param {
        name: "s".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };

    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![param_calls, param_v, param_r, param_s],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };

    let calls = Token::Array(
        transfers
            .iter()
            .map(|t| t.to_token())
            .collect::<Vec<Token>>(),
    );

    let stream = encode(&[calls.clone()]);
    let hash = keccak256(&stream).to_vec();
    let (rs, recid) = secp256k1_sign(sk, &hash).unwrap();
    let v = recid + 27;
    let r = rs[..32].to_vec();
    let s = rs[32..].to_vec();

    let v = Token::Uint(U256::from(v));
    let r = Token::FixedBytes(r);
    let s = Token::FixedBytes(s);

    let tokens = vec![calls, v, r, s];

    func.encode_input(&tokens)
        .map_err(|e| TransactionError::Message(format!("Failed to encode transfers: {}", e)))
}

pub fn encode_many_2_many_transfers(
    func_name: &str,
    transfers: &[One2ManyTransfer],
) -> Result<Vec<u8>, TransactionError> {
    let param_calls = Param {
        name: "calls".to_string(),
        kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Bytes,
        ]))),
        internal_type: None,
    };

    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![param_calls],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };

    let calls = Token::Array(
        transfers
            .iter()
            .map(|t| t.to_token())
            .collect::<Vec<Token>>(),
    );

    let tokens = vec![calls];

    func.encode_input(&tokens)
        .map_err(|e| TransactionError::Message(format!("Failed to encode transfers: {}", e)))
}

#[cfg(test)]
mod tests {
    use anychain_core::{hex, Transaction};
    use anychain_kms::{bip32::PrivateKey, secp256k1_sign};
    use core::str::FromStr;
    use ethereum_types::U256;

    use crate::{
        create_address, create_sk, parse_mnemonic, Authorization, Eip1559Transaction, Eip1559TransactionParameters, Eip7702Transaction, Eip7702TransactionParameters, EthereumAddress, EthereumNetwork, Many2ManyTransfer, One2ManyTransfer, One2OneTransfer, Sepolia
    };

    #[test]
    fn test() {
        let phrase = "armor moon bonus rhythm add raccoon truly noodle admit lesson filter bitter lend exotic long".to_string();
        let wallet = parse_mnemonic(phrase);

        let xprv = wallet["xprv"].as_str().unwrap().to_string();
        println!("xprv: {}", xprv);

        let delegate = "m/44/60/0/3".to_string();
        let from1 = "m/44/60/0/2".to_string();
        let from2 = "m/44/60/0/1".to_string();
        let to1 = "m/44/60/0/0".to_string();
        let to2 = "m/44/60/0/4".to_string();
        let to3 = "m/44/60/0/5".to_string();
        let to4 = "m/44/60/0/6".to_string();

        let sk_from1 = create_sk(xprv.clone(), from1.clone()).to_bytes();
        let sk_from2 = create_sk(xprv.clone(), from2.clone()).to_bytes();

        let sk_from1 = hex::encode(sk_from1);
        let sk_from2 = hex::encode(sk_from2);

        println!("sk from1: {}\nsk from2: {}", sk_from1, sk_from2);

        let _delegate = create_address(xprv.clone(), delegate.clone()).to_string();
        let _from1 = create_address(xprv.clone(), from1.clone()).to_string();
        let _from2 = create_address(xprv.clone(), from2.clone()).to_string();
        let _to1 = create_address(xprv.clone(), to1.clone()).to_string();
        let _to2 = create_address(xprv.clone(), to2.clone()).to_string();
        let _to3 = create_address(xprv.clone(), to3.clone()).to_string();
        let _to4 = create_address(xprv.clone(), to4.clone()).to_string();

        println!("Delegate: {}", _delegate);
        println!("From1: {}", _from1);
        println!("From2: {}", _from2);
        println!("To1: {}", _to1);
        println!("To2: {}", _to2);
        println!("To3: {}", _to3);
        println!("To4: {}", _to4);

        // Delegate: 0x7eE4c635d204eBE65fc8987CE6570CFA1651E8Af
        // From1: 0x424Ef693c6F2648983aEc92f35a1143ba9Dd076C
        // From2: 0x6f5ce2e6F2C8D2a6f91FbDeAc835074363c24a6E
        // To1: 0xBed74Ed65aE59eEa3339Daa215ea1d3B162F4E8B
        // To2: 0xf04e36C86e94093C2cb79FaD024962382568EFec
        // To3: 0x4a4763eFA2e89b88B3Aeef1282d150aC84188F06
        // To4: 0xE87C78EA9Faa78A6924E228eAe24b59AB53e1c9e

        let batch_contract = "0x2e266E955208dB2B5db982a84d324Ff3E4fF0130".to_string();
        let scheduler_contract = "0x4B8e5032238B6FAc4E329717aA0A0460e2698560".to_string();
        let usdc_contract = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".to_string();

        let transfer1 = One2OneTransfer::new(Some(usdc_contract.clone()), _to1, "20000");
        // let transfer2 = One2OneTransfer::new(Some(usdc_contract.clone()), _to2, "100000");
        // let transfer3 = One2OneTransfer::new(Some(usdc_contract.clone()), _to3, "100000");
        // let transfer4 = One2OneTransfer::new(Some(usdc_contract.clone()), _to4, "100000");

        let one2many1 = One2ManyTransfer::new(
            xprv.clone(),
            delegate.clone(),
            38,
            batch_contract.clone(),
            vec![transfer1/* , transfer2*/],
        );

        // let one2many2 = One2ManyTransfer::new(
        //     xprv.clone(),
        //     from2,
        //     53,
        //     0,
        //     batch_contract.clone(),
        //     vec![transfer3, transfer4],
        // );

        let many2many = Many2ManyTransfer::new(
            xprv,
            delegate,
            37,
            scheduler_contract,
            vec![one2many1/* , one2many2*/],
        );

        let tx = many2many.to_tx().unwrap();
        let tx = hex::encode(tx);

        println!("Transaction: {}", tx);
    }

    #[test]
    fn test_tx() {
        let xprv = "xprv9s21ZrQH143K4AQzoQF6p3riRHUPG7VMQpYdCkcc548CYYT76Ay2nTFDXAfrMq7MT6NMePhuYP2uTGhTXjZZ1AZrGPZ4MyysX8ffTx9VwXU".to_string();

        let delegate = "m/44/60/0/3".to_string();
        let sk_delegate = create_sk(xprv.clone(), delegate.clone());

        let chain_id = Sepolia::CHAIN_ID;
        let nonce = U256::from(61);
        let max_priority_fee_per_gas = U256::from("200000000");
        let max_fee_per_gas = U256::from("200000000");
        let gas_limit = U256::from("21000");
        let to = EthereumAddress::from_str("0x424Ef693c6F2648983aEc92f35a1143ba9Dd076C").unwrap();
        let amount = U256::from_dec_str("100000000000000000").unwrap();

        let params = Eip1559TransactionParameters {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data: vec![],
            access_list: vec![],
        };

        let mut tx = Eip1559Transaction::<Sepolia>::new(&params).unwrap();
        let msg = tx.to_transaction_id().unwrap().txid;
        let (rs, recid) = secp256k1_sign(&sk_delegate, &msg).unwrap();
        let tx = tx.sign(rs, recid).unwrap();
        let tx = hex::encode(tx);

        println!("Tx: {}", tx);
    }

    #[test]
    fn test_decouple() {
        let xprv = "xprv9s21ZrQH143K4AQzoQF6p3riRHUPG7VMQpYdCkcc548CYYT76Ay2nTFDXAfrMq7MT6NMePhuYP2uTGhTXjZZ1AZrGPZ4MyysX8ffTx9VwXU".to_string();

        // let from1 = "m/44/60/0/2".to_string();
        // let sk_from1 = create_sk(xprv.clone(), from1.clone());

        let sk = "3d98c2d5a7f737693b470114816000645419af49bd21258cc99142f6ef5fd60a".to_string();
        let sk = hex::decode(sk).unwrap();
        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let batch = "0x0000000000000000000000000000000000000000";
        let batch = EthereumAddress::from_str(batch).unwrap();

        let mut auth = Authorization {
            chain_id: Sepolia::CHAIN_ID,
            address: batch,
            nonce: U256::from(66),
            y_parity: false,
            r: vec![],
            s: vec![],
        };

        let digest = auth.digest();
        let (rs, recid) = secp256k1_sign(&sk, &digest).unwrap();
        auth.sign((rs, recid));

        let params = Eip7702TransactionParameters {
            chain_id: Sepolia::CHAIN_ID,
            nonce: U256::from(65),
            max_priority_fee_per_gas: U256::from_dec_str("1000000000").unwrap(),
            max_fee_per_gas: U256::from_dec_str("1000000000").unwrap(),
            gas_limit: U256::from(2100000),
            to: EthereumAddress::from_str("0x7eE4c635d204eBE65fc8987CE6570CFA1651E8Af").unwrap(),
            amount: U256::zero(),
            data: vec![],
            access_list: vec![],
            authorizations: vec![auth],
        };

        let mut tx = Eip7702Transaction::<Sepolia>::new(&params).unwrap();
        let txid = tx.to_transaction_id().unwrap().txid;
        let (rs, recid) = secp256k1_sign(&sk, &txid).unwrap();
        let tx = tx.sign(rs, recid).unwrap();

        let tx = hex::encode(tx);

        println!("Tx: {}", tx);
    }
}

// Delegate: 0x7eE4c635d204eBE65fc8987CE6570CFA1651E8Af
// From1: 0x424Ef693c6F2648983aEc92f35a1143ba9Dd076C
// From2: 0x6f5ce2e6F2C8D2a6f91FbDeAc835074363c24a6E
// To1: 0xBed74Ed65aE59eEa3339Daa215ea1d3B162F4E8B
// To2: 0xf04e36C86e94093C2cb79FaD024962382568EFec
// To3: 0x4a4763eFA2e89b88B3Aeef1282d150aC84188F06
// To4: 0xE87C78EA9Faa78A6924E228eAe24b59AB53e1c9e
