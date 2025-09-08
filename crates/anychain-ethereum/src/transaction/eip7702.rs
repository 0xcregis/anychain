use crate::contract::{erc20_transfer_func, execute_batch_transfer_func, schedule_func};
use crate::util::{adapt2, pad_zeros, restore_sender, trim_leading_zeros};
use crate::{erc20_transfer, AccessItem, EthereumTransactionId};
use crate::{EthereumAddress, EthereumFormat, EthereumNetwork, EthereumPublicKey};

use anychain_core::{hex, utilities::crypto::keccak256, Transaction, TransactionError};
use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::{encode, ethereum_types::H160, Token};
use ethereum_types::U256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authorization {
    pub chain_id: u32,
    pub contract: EthereumAddress,
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
        rlp.append(&self.contract.to_bytes().unwrap());
        rlp.append(&self.nonce);

        let stream = [vec![5u8], rlp.out().as_ref().to_vec()].concat();
        keccak256(&stream).to_vec()
    }

    pub fn sign(&mut self, rs: Vec<u8>, recid: u8) {
        self.y_parity = recid == 1;
        self.r = rs[..32].to_vec();
        self.s = rs[32..].to_vec();
    }
}

impl Encodable for Authorization {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6);
        s.append(&self.chain_id);
        s.append(&self.contract.to_bytes().unwrap());
        s.append(&self.nonce);
        s.append(&self.y_parity);
        s.append(&trim_leading_zeros(&self.r));
        s.append(&trim_leading_zeros(&self.s));
    }
}

impl Decodable for Authorization {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let chain_id = rlp.val_at::<u32>(0)?;
        let contract = rlp.val_at::<Vec<u8>>(1)?;
        let contract = hex::encode(contract);
        let contract = EthereumAddress::from_str(&contract).unwrap();
        let nonce = rlp.val_at::<U256>(2)?;
        let y_parity = rlp.val_at(3)?;
        let mut r = rlp.val_at(4)?;
        let mut s = rlp.val_at(5)?;
        pad_zeros(&mut r, 32);
        pad_zeros(&mut s, 32);
        Ok(Self {
            chain_id,
            contract,
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

pub struct Many2ManyTransfer<N: EthereumNetwork> {
    pub transfers: Vec<One2ManyTransfer<N>>,
}

impl<N: EthereumNetwork> Many2ManyTransfer<N> {
    pub fn new(transfers: Vec<One2ManyTransfer<N>>) -> Self {
        Self { transfers }
    }

    pub fn authorizations(&self) -> Result<Vec<Authorization>, TransactionError> {
        self.transfers
            .iter()
            .map(|transfer| transfer.authorization())
            .collect::<Result<Vec<Authorization>, TransactionError>>()
            .map_err(|e| TransactionError::Message(format!("{}", e)))
    }

    pub fn data(&self) -> Result<Vec<u8>, TransactionError> {
        let func = schedule_func();
        let calls = Token::Array(
            self.transfers
                .iter()
                .map(|t| t.to_token())
                .collect::<Vec<Token>>(),
        );

        let tokens = vec![calls];

        func.encode_input(&tokens)
            .map_err(|e| TransactionError::Message(format!("Failed to encode transfers: {}", e)))
    }
}

pub struct One2ManyTransfer<N: EthereumNetwork> {
    // address which initiates transfers
    pub from: String,

    // nonce of from address
    pub nonce: u64,

    // nonce of the transfer contract (for replay protection)
    pub nonce_contract: u64,

    // contract authorized to from by 7702
    pub contract: String,

    // transfer batch
    pub transfers: Vec<Transfer>,

    // from's signature for contract authorization
    pub sig_auth: Option<Vec<u8>>,

    // froms's signature for transfers
    pub sig_transfer: Option<Vec<u8>>,

    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> One2ManyTransfer<N> {
    pub fn new(
        from: String,
        nonce: u64,
        nonce_contract: u64,
        contract: String,
        transfers: Vec<Transfer>,
    ) -> Self {
        Self {
            from,
            nonce,
            nonce_contract,
            contract,
            transfers,
            sig_auth: None,
            sig_transfer: None,
            _network: PhantomData,
        }
    }

    pub fn digest(&self, typ: u8) -> Result<Vec<u8>, TransactionError> {
        match typ {
            // returns the auth digest
            0 => {
                let auth = self.authorization()?;
                Ok(auth.digest())
            }
            // returns the transfer digest
            1 => {
                let chain_id = U256::from(N::CHAIN_ID);
                let chain_id = Token::Uint(chain_id);
                let nonce = Token::Uint(U256::from(self.nonce_contract));
                let calls = Token::Array(
                    self.transfers
                        .iter()
                        .map(|t| t.to_token())
                        .collect::<Vec<Token>>(),
                );

                let stream = encode(&[chain_id, nonce, calls]);
                Ok(keccak256(&stream).to_vec())
            }
            _ => Err(TransactionError::Message("invalid digest type".to_string())),
        }
    }

    pub fn sign(&mut self, rs: Vec<u8>, recid: u8, typ: u8) -> Result<(), TransactionError> {
        let sig = [rs, vec![recid]].concat();
        match typ {
            // insert the auth signature
            0 => {
                self.sig_auth = Some(sig);
                Ok(())
            }
            // insert the transfer signature
            1 => {
                self.sig_transfer = Some(sig);
                Ok(())
            }
            _ => Err(TransactionError::Message(
                "invalid signature type".to_string(),
            )),
        }
    }

    pub fn authorization(&self) -> Result<Authorization, TransactionError> {
        let chain_id = N::CHAIN_ID;
        let contract = EthereumAddress::from_str(&self.contract)?;
        let nonce = U256::from(self.nonce);

        let mut auth = Authorization {
            chain_id,
            contract,
            nonce,
            y_parity: false,
            r: vec![],
            s: vec![],
        };

        match &self.sig_auth {
            Some(sig_auth) => {
                auth.sign(sig_auth[..64].to_vec(), sig_auth[64]);
                Ok(auth)
            }
            None => Ok(auth),
        }
    }

    pub fn data(&self) -> Result<Vec<u8>, TransactionError> {
        if self.sig_transfer.is_none() {
            return Err(TransactionError::Message(
                "transfers not signed yet".to_string(),
            ));
        }

        let func = execute_batch_transfer_func();

        let calls = Token::Array(
            self.transfers
                .iter()
                .map(|t| t.to_token())
                .collect::<Vec<Token>>(),
        );

        let sig = self.sig_transfer.clone().unwrap();

        let v = sig[64] + 27;
        let r = sig[..32].to_vec();
        let s = sig[32..64].to_vec();

        let v = Token::Uint(U256::from(v));
        let r = Token::FixedBytes(r);
        let s = Token::FixedBytes(s);

        let tokens = vec![calls, v, r, s];

        func.encode_input(&tokens)
            .map_err(|e| TransactionError::Message(format!("Failed to encode transfers: {}", e)))
    }

    pub fn to_token(&self) -> Token {
        let from = EthereumAddress::from_str(&self.from).unwrap();
        let to = Token::Address(H160::from_slice(&from.to_bytes().unwrap()));
        let amount = Token::Uint(U256::zero());
        let data = Token::Bytes(self.data().unwrap());
        Token::Tuple(vec![to, amount, data])
    }
}

pub struct Transfer {
    pub token: Option<EthereumAddress>,
    pub to: EthereumAddress,
    pub amount: U256,
}

impl Transfer {
    pub fn new(token: Option<String>, to: String, amount: String) -> Self {
        Self {
            token: token.map(|t| EthereumAddress::from_str(&t).unwrap()),
            to: EthereumAddress::from_str(&to).unwrap(),
            amount: U256::from_dec_str(&amount).unwrap(),
        }
    }

    pub fn to_token(&self) -> Token {
        match &self.token {
            Some(token) => {
                let to = Token::Address(H160::from_slice(&token.to_bytes().unwrap()));
                let amount = Token::Uint(U256::from(0));
                let data = Token::Bytes(erc20_transfer(&self.to, self.amount));
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

    pub fn from_token(token: Token) -> Result<Self, TransactionError> {
        let call = token.into_tuple().unwrap();
        let to = call[0].clone().into_address().unwrap();
        let to = EthereumAddress::from_str(&hex::encode(to)).unwrap();
        let amount = call[1].clone().clone().into_uint().unwrap();
        let data = call[2].clone().into_bytes().unwrap();

        if data.is_empty() {
            Ok(Self {
                token: None,
                to,
                amount,
            })
        } else {
            let func = erc20_transfer_func();
            let transfer = func
                .decode_input(&data[4..])
                .map_err(|e| TransactionError::Message(format!("Failed to decode data: {}", e)))?;
            if transfer.len() != 2 {
                return Err(TransactionError::Message(
                    "Invalid ERC20 transfer data length".to_string(),
                ));
            }
            let token = Some(to);
            let to = transfer[0].clone().into_address().unwrap();
            let to = EthereumAddress::from_str(&hex::encode(to)).unwrap();
            let amount = transfer[1].clone().into_uint().unwrap();

            Ok(Self { token, to, amount })
        }
    }

    pub fn to_json(&self) -> Value {
        let to = self.to.to_string();
        let amount = self.amount.to_string();

        match &self.token {
            Some(token) => {
                let token = token.to_string();
                json!({
                    "token": token,
                    "to": to,
                    "amount": amount,
                })
            }
            None => json!({
                "to": to,
                "amount": amount,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use anychain_core::{hex, PublicKey, Transaction};
    use anychain_kms::{
        bip32::{DerivationPath, Prefix, XprvSecp256k1},
        bip39::{Language, Mnemonic, Seed},
        secp256k1_sign,
    };
    use core::str::FromStr;
    use ethereum_types::U256;
    use serde_json::{json, Value};

    use crate::{
        Authorization, Eip1559Transaction, Eip1559TransactionParameters, Eip7702Transaction,
        Eip7702TransactionParameters, EthereumAddress, EthereumFormat, EthereumNetwork,
        EthereumPublicKey, Sepolia,
    };

    pub fn _parse_mnemonic(phrase: String) -> Value {
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

    pub fn _create_address(xprv: String, path: String) -> EthereumAddress {
        let xprv = XprvSecp256k1::from_str(&xprv).unwrap();
        let derive_path = DerivationPath::from_str(&path).unwrap();
        let xprv = xprv.derive_from_path(&derive_path).unwrap();
        let xpub = xprv.public_key();
        let pk = *xpub.public_key();

        EthereumPublicKey::from_secp256k1_public_key(pk)
            .to_address(&EthereumFormat::Standard)
            .unwrap()
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
        let sk = "3d98c2d5a7f737693b470114816000645419af49bd21258cc99142f6ef5fd60a".to_string();
        let sk = hex::decode(sk).unwrap();
        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let batch = "0x0000000000000000000000000000000000000000";
        let batch = EthereumAddress::from_str(batch).unwrap();

        let mut auth = Authorization {
            chain_id: Sepolia::CHAIN_ID,
            contract: batch,
            nonce: U256::from(66),
            y_parity: false,
            r: vec![],
            s: vec![],
        };

        let digest = auth.digest();
        let (rs, recid) = secp256k1_sign(&sk, &digest).unwrap();
        auth.sign(rs, recid);

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
