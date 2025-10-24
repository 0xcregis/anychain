use core::marker::PhantomData;
use core::str::FromStr;

use crate::contract::eip3009_transfer_func;
use crate::{EthereumAddress, EthereumNetwork};
use anychain_core::{crypto::keccak256, hex, TransactionError};
use ethabi::{encode, Token};
use ethereum_types::{H160, U256};

trait EIP712TypedData {
    fn type_hash(&self) -> Result<Vec<u8>, TransactionError>;
    fn encode(&self) -> Result<Vec<u8>, TransactionError>;
    fn hash_struct(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(keccak256(&self.encode()?).to_vec())
    }
}

struct EIP712Domain<N: EthereumNetwork> {
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
        let type_hash = self.type_hash()?;
        let name = keccak256(self.name.as_bytes()).to_vec();
        let version = keccak256(self.version.as_bytes()).to_vec();
        let chain_id = U256::from(N::CHAIN_ID);
        let contract = self
            .verifying_contract
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let contract = H160::from_slice(&contract);

        let type_hash = Token::FixedBytes(type_hash);
        let name = Token::FixedBytes(name);
        let version = Token::FixedBytes(version);
        let chain_id = Token::Uint(chain_id);
        let contract = Token::Address(contract);

        Ok(encode(&[type_hash, name, version, chain_id, contract]))
    }
}

impl<N: EthereumNetwork> EIP712Domain<N> {
    fn new(name: String, version: String, contract: String) -> Result<Self, TransactionError> {
        let verifying_contract = EthereumAddress::from_str(&contract)?;

        Ok(Self {
            name,
            version,
            verifying_contract,
            _network: PhantomData,
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
    nonce: Vec<u8>, // 32-byte hash
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
        let type_hash = self.type_hash()?;

        let from = self
            .from
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let to = self
            .to
            .to_bytes()
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let from = H160::from_slice(&from);
        let to = H160::from_slice(&to);

        let type_hash = Token::FixedBytes(type_hash);

        let from = Token::Address(from);
        let to = Token::Address(to);
        let amount = Token::Uint(self.amount);

        let valid_after = Token::Uint(self.valid_after);
        let valid_before = Token::Uint(self.valid_before);
        let nonce = Token::FixedBytes(self.nonce.clone());

        Ok(encode(&[
            type_hash,
            from,
            to,
            amount,
            valid_after,
            valid_before,
            nonce,
        ]))
    }
}

impl<N: EthereumNetwork> TransferWithAuthorizationParameters<N> {
    #[allow(clippy::too_many_arguments)]
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

        let nonce = match nonce.strip_prefix("0x") {
            Some(nonce) => nonce,
            None => &nonce,
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
                vec![25], /* 0x19 */
                vec![1],  /* 0x01 */
                domain_separator,
                hash_params,
            ]
            .concat();
            Ok(keccak256(stream.as_ref()).to_vec())
        } else {
            Err(TransactionError::Message("domain not provided".to_string()))
        }
    }

    fn to_data(&self) -> Result<Vec<u8>, TransactionError> {
        let func = eip3009_transfer_func();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eip3009::TransferWithAuthorizationParameters, Eip1559Transaction,
        Eip1559TransactionParameters, Sepolia,
    };
    use anychain_core::Transaction;
    use anychain_kms::secp256k1_sign;
    use std::time::SystemTime;

    #[test]
    fn test_eip3009_tx() {
        let sk = "3d98c2d5a7f737693b470114816000645419af49bd21258cc99142f6ef5fd60a".to_string();
        let sk = hex::decode(sk).unwrap();

        let from = "0x7eE4c635d204eBE65fc8987CE6570CFA1651E8Af".to_string();
        let to = "0xf7a63003b8ef116939804b4c2dd49290a39c4d97".to_string();
        let usdc = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".to_string();
        let amount = "100000".to_string();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        use rand::RngCore;

        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);

        let mut transfer = TransferWithAuthorizationParameters::<Sepolia>::new(
            "USDC".to_string(),
            "2".to_string(),
            usdc.clone(),
            from,
            to,
            amount,
            now.to_string(),
            (now + 100).to_string(),
            nonce,
        )
        .unwrap();

        let digest = transfer.digest().unwrap();
        let (rs, recid) = secp256k1_sign(&sk, &digest).unwrap();
        let data = transfer
            .sign(recid, rs[..32].to_vec(), rs[32..].to_vec())
            .unwrap();

        println!("Data: 0x{}", hex::encode(&data));

        let nonce = U256::from(67);
        let max_priority_fee_per_gas = U256::from_dec_str("1000000000").unwrap();
        let max_fee_per_gas = U256::from_dec_str("1000000000").unwrap();
        let gas_limit = U256::from(210000);
        let to = EthereumAddress::from_str(&usdc).unwrap();
        let amount = U256::from(0);

        let params = Eip1559TransactionParameters {
            chain_id: Sepolia::CHAIN_ID,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            amount,
            data,
            access_list: vec![],
        };

        let mut tx = Eip1559Transaction::<Sepolia>::new(&params).unwrap();
        let txid = tx.to_transaction_id().unwrap().txid;
        let (rs, recid) = secp256k1_sign(&sk, &txid).unwrap();
        let tx = tx.sign(rs, recid).unwrap();
        let tx = hex::encode(tx);

        println!("Tx: {}", tx);
    }
}
