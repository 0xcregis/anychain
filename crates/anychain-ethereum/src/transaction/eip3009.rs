use core::marker::PhantomData;
use core::str::FromStr;

use crate::Ethereum;
use crate::EthereumAddress;
use crate::EthereumNetwork;
use anychain_core::{crypto::keccak256, hex, TransactionError};
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use ethereum_types::{H160, U256};

trait EIP712TypedData {
    fn type_hash(&self) -> Result<Vec<u8>, TransactionError>;
    fn encode(&self) -> Result<Vec<u8>, TransactionError>;
    fn hash_struct(&self) -> Result<Vec<u8>, TransactionError> {
        let hash = self.type_hash()?;
        let data = self.encode()?;
        let stream = [hash, data].concat();
        Ok(keccak256(stream.as_ref()).to_vec())
    }
}

pub struct EIP712Domain<N: EthereumNetwork> {
    name: String,
    version: String,
    verifying_contract: EthereumAddress,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> EIP712TypedData for EIP712Domain<N> {
    fn type_hash(&self) -> Result<Vec<u8>, TransactionError> {
        let stream =
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .as_bytes();
        Ok(keccak256(stream).to_vec())
    }

    fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        let name = keccak256(self.name.as_bytes()).to_vec();
        let version = keccak256(self.version.as_bytes()).to_vec();

        let chain_id: [u8; 4] = N::CHAIN_ID.to_be_bytes();
        let chain_id = chain_id.to_vec();
        
        let address = self
            .verifying_contract
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        Ok([name, version, chain_id, address].concat())
    }
}

impl<N: EthereumNetwork> EIP712Domain<N> {
    fn new(
        name: String,
        version: String,
        contract: String,
    ) -> Result<Self, TransactionError> {
        let verifying_contract = EthereumAddress::from_str(&contract)?;

        Ok(Self {
            name,
            version,
            verifying_contract,
            _network: PhantomData
        })
    }
}

pub struct TransferWithAuthorizationParameters<N: EthereumNetwork> {
    domain: Option<EIP712Domain<N>>,
    from: EthereumAddress,
    to: EthereumAddress,
    amount: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: Vec<u8>, // hex encoded 32 bytes
    v: u8,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl<N: EthereumNetwork> EIP712TypedData for TransferWithAuthorizationParameters<N> {
    fn type_hash(&self) -> Result<Vec<u8>, TransactionError> {
        let stream = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)".as_bytes();
        Ok(keccak256(stream).to_vec())
    }

    fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        let from = self
            .from
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let mut amount = [0u8; 32];
        let mut valid_after = [0u8; 32];
        let mut valid_before = [0u8; 32];

        self.amount.to_big_endian(amount.as_mut_slice());
        self.valid_after.to_big_endian(valid_after.as_mut_slice());
        self.valid_before.to_big_endian(valid_before.as_mut_slice());

        let amount = amount.to_vec();
        let valid_after = valid_after.to_vec();
        let valid_before = valid_before.to_vec();

        let nonce = self.nonce.clone();

        Ok([from, to, amount, valid_after, valid_before, nonce].concat())
    }
}

impl<N: EthereumNetwork> TransferWithAuthorizationParameters<N> {
    pub fn new(
        name: String,
        version: String,
        contract: String,
        from: String,
        to: String,
        amount: String,
        valid_after: String,
        valid_before: String,
        nonce: String,
    ) -> Result<Self, TransactionError> {
        let domain = Some(EIP712Domain::<N>::new(name, version, contract)?);
        let from = EthereumAddress::from_str(&from)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let to =
            EthereumAddress::from_str(&to).map_err(|e| TransactionError::Message(e.to_string()))?;
        let amount =
            U256::from_dec_str(&amount).map_err(|e| TransactionError::Message(e.to_string()))?;
        let valid_after = U256::from_dec_str(&valid_after)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let valid_before = U256::from_dec_str(&valid_before)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let nonce = if nonce.starts_with("0x") {
            &nonce[2..]
        } else {
            &nonce
        };
        let nonce = hex::decode(nonce)?;

        Ok(Self {
            domain,
            from,
            to,
            amount,
            valid_after,
            valid_before,
            nonce,
            v: 0,
            r: vec![],
            s: vec![],
        })
    }

    pub fn sign(&mut self, recid: u8, r: Vec<u8>, s: Vec<u8>) -> Result<Vec<u8>, TransactionError> {
        self.v = recid + 27;
        self.r = r;
        self.s = s;
        self.to_data()
    }

    pub fn digest(&self) -> Result<Vec<u8>, TransactionError> {
        if let Some(domain) = &self.domain {
            let domain_separator = domain.hash_struct()?;
            let hash_params = self.hash_struct()?;
            let stream = [
                vec![25],
                /* 0x19 */ vec![1],
                /* 0x01 */ domain_separator,
                hash_params,
            ]
            .concat();
            Ok(keccak256(stream.as_ref()).to_vec())
        } else {
            Err(TransactionError::Message("domain not provided".to_string()))
        }
    }

    fn to_data(&self) -> Result<Vec<u8>, TransactionError> {
        let func_name = "transferWithAuthorization".to_string();

        #[allow(deprecated)]
        let func = Function {
            name: func_name,
            inputs: vec![
                Param {
                    name: "from".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "to".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "value".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "validAfter".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "validBefore".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "nonce".to_string(),
                    kind: ParamType::FixedBytes(32),
                    internal_type: None,
                },
                Param {
                    name: "v".to_string(),
                    kind: ParamType::Uint(8),
                    internal_type: None,
                },
                Param {
                    name: "r".to_string(),
                    kind: ParamType::FixedBytes(32),
                    internal_type: None,
                },
                Param {
                    name: "s".to_string(),
                    kind: ParamType::FixedBytes(32),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        };

        let from = self
            .from
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let amount = self.amount;
        let valid_after = self.valid_after;
        let valid_before = self.valid_before;
        let nonce = self.nonce.clone();
        let v = U256::from(self.v);
        let r = self.r.clone();
        let s = self.s.clone();

        let tokens = vec![
            Token::Address(H160::from_slice(&from)),
            Token::Address(H160::from_slice(&to)),
            Token::Uint(amount),
            Token::Uint(valid_after),
            Token::Uint(valid_before),
            Token::FixedBytes(nonce),
            Token::Uint(v),
            Token::FixedBytes(r),
            Token::FixedBytes(s),
        ];

        func.encode_input(&tokens)
            .map_err(|e| TransactionError::Message(e.to_string()))
    }
}

#[test]
fn test() {
    let name = "USDC".to_string();
    let contract = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".to_string();
    let version = "2".to_string();

    let from = "0xCFfe787aBF02d047D32c7a4f7B321EbE6050F0af".to_string();
    let to = "0xcebb21825b6401efe118f1325e42c54597658c2c".to_string();
    let amount = "9931591".to_string();
    let valid_after = "1754464386".to_string();
    let valid_before = "1754472244".to_string();
    let nonce = "0xc16e8459b9c3ecfbbc20c34444c72ce016cdb109fa5a982b0dd223e15e8f96de".to_string();

    let mut params = TransferWithAuthorizationParameters::<Ethereum>::new(
        name,
        version,
        contract,
        from,
        to,
        amount,
        valid_after,
        valid_before,
        nonce,
    )
    .unwrap();

    let digest = params.digest().unwrap();
    let digest = hex::encode(digest);

    let data = params.sign(0, vec![0], vec![0]).unwrap();
    let data = hex::encode(data);

    println!("Digest: {}\nData: {}", digest, data);
}
