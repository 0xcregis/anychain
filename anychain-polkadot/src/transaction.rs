use crate::utilities::crypto::blake2b_256;
use crate::{PolkadotAddress, PolkadotFormat, PolkadotNetwork, PolkadotPublicKey};
use anychain_core::{hex, Transaction, TransactionError, TransactionId};
use parity_scale_codec::{Decode, Encode, HasCompact};
use std::fmt::Display;

#[derive(Clone)]
pub struct PolkadotTransactionParameters<N: PolkadotNetwork> {
    pub from: PolkadotAddress<N>,
    pub to: PolkadotAddress<N>,
    pub amount: u64,
    pub nonce: u64,
    pub tip: u64,
    pub block_hash: String,
    pub genesis_hash: String,
    pub spec_version: u32,
    pub tx_version: u32,
}

struct TxInterim {
    method: Vec<u8>,
    era: Vec<u8>,
    nonce: Vec<u8>,
    tip: Vec<u8>,
    spec_version: Vec<u8>,
    genesis_hash: Vec<u8>,
    block_hash: Vec<u8>,
    tx_version: Vec<u8>,
}

#[derive(Clone)]
pub struct PolkadotTransaction<N: PolkadotNetwork> {
    pub params: PolkadotTransactionParameters<N>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PolkadotTransactionId {
    txid: Vec<u8>,
}

impl TransactionId for PolkadotTransactionId {}

impl Display for PolkadotTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct CompactWrapper<T: HasCompact> {
    #[codec(encoded_as = "<T as HasCompact>::Type")]
    val: T,
}

fn encode(val: u64) -> Vec<u8> {
    if val == 0 {
        vec![0]
    } else {
        CompactWrapper { val }.encode()
    }
}

impl<N: PolkadotNetwork> Transaction for PolkadotTransaction<N> {
    type Address = PolkadotAddress<N>;
    type Format = PolkadotFormat;
    type PublicKey = PolkadotPublicKey<N>;
    type TransactionId = PolkadotTransactionId;
    type TransactionParameters = PolkadotTransactionParameters<N>;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(PolkadotTransaction {
            params: params.clone(),
            signature: None,
        })
    }

    // Only used for secp256k1 signing scheme
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some([rs, vec![recid]].concat());
        self.to_bytes()
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    // Only used for secp256k1 signing scheme
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        match &self.signature {
            Some(sig) => {
                let interim = self.to_interim()?;
                let from = self.params.from.to_payload()?;

                let stream = [
                    vec![0x84], // version = 0x84
                    vec![0],
                    from,
                    vec![2], // ed25519 = 0, sr25519 = 1, secp256k1 = 2
                    sig.clone(),
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.method,
                ]
                .concat();

                let len = stream.len() as u64;
                let len = encode(len);

                Ok([len, stream].concat())
            }
            None => {
                let interim = self.to_interim()?;
                Ok([
                    interim.method,
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.spec_version,
                    interim.tx_version,
                    interim.genesis_hash,
                    interim.block_hash,
                ]
                .concat())
            }
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(PolkadotTransactionId {
            txid: blake2b_256(&self.to_bytes()?).to_vec(),
        })
    }
}

impl<N: PolkadotNetwork> PolkadotTransaction<N> {
    fn to_interim(&self) -> Result<TxInterim, TransactionError> {
        let params = &self.params;

        let to = params.to.to_payload()?;
        let amount = encode(params.amount);
        let era = vec![0];

        let nonce = encode(params.nonce);
        let tip = encode(params.tip);

        let spec_version = params.spec_version.to_le_bytes().to_vec();
        let tx_version = params.tx_version.to_le_bytes().to_vec();

        let genesis_hash = hex::decode(&params.genesis_hash)?;
        let block_hash = hex::decode(&params.block_hash)?;

        let interim = TxInterim {
            method: [
                vec![N::PALLET_ASSET, N::TRANSFER_ALLOW_DEATH],
                vec![0],
                to,
                amount,
            ]
            .concat(),
            era,
            nonce,
            tip,
            spec_version,
            tx_version,
            genesis_hash,
            block_hash,
        };

        Ok(interim)
    }

    // Alternative to to_bytes() when using ed25519 signing scheme
    fn to_bytes_ed25519(&self) -> Result<Vec<u8>, TransactionError> {
        match &self.signature {
            Some(sig) => {
                let interim = self.to_interim()?;
                let from = self.params.from.to_payload()?;

                let stream = [
                    vec![0x84], // version = 0x84
                    vec![0],
                    from,
                    vec![0], // ed25519 = 0, sr25519 = 1, secp256k1 = 2
                    sig.clone(),
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.method,
                ]
                .concat();

                let len = stream.len() as u64;
                let len = encode(len);

                Ok([len, stream].concat())
            }
            None => {
                let interim = self.to_interim()?;
                Ok([
                    interim.method,
                    interim.era,
                    interim.nonce,
                    interim.tip,
                    interim.spec_version,
                    interim.tx_version,
                    interim.genesis_hash,
                    interim.block_hash,
                ]
                .concat())
            }
        }
    }

    // Alternative to sign() when using ed25519 signing scheme
    pub fn sign_ed25519(&mut self, rs: Vec<u8>) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes_ed25519()
    }
}

impl<N: PolkadotNetwork> Display for PolkadotTransaction<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        PolkadotAddress, PolkadotFormat, PolkadotNetwork, PolkadotSecretKey, PolkadotTransaction,
        PolkadotTransactionParameters, Westend,
    };
    use anychain_core::Address;
    use anychain_core::{hex, Transaction};
    use ed25519_dalek::{SecretKey, Signature, Signer};
    use serde_json::Value;
    use std::str::FromStr;

    fn tx_from_str<N: PolkadotNetwork>(json: &str) -> PolkadotTransaction<N> {
        let json = serde_json::from_str::<Value>(json).unwrap();

        let from = PolkadotAddress::<N>::from_str(json["from"].as_str().unwrap()).unwrap();

        let to = PolkadotAddress::<N>::from_str(json["to"].as_str().unwrap()).unwrap();

        let amount = json["amount"].as_u64().unwrap();
        let nonce = json["nonce"].as_u64().unwrap();
        let tip = json["tip"].as_u64().unwrap();
        let block_hash = json["block_hash"].as_str().unwrap().to_string();
        let genesis_hash = json["genesis_hash"].as_str().unwrap().to_string();
        let spec_version = json["spec_version"].as_u64().unwrap() as u32;
        let tx_version = json["tx_version"].as_u64().unwrap() as u32;

        let params = PolkadotTransactionParameters::<N> {
            from,
            to,
            amount,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            tx_version,
        };

        PolkadotTransaction::<N>::new(&params).unwrap()
    }

    #[test]
    fn test_address_gen() {
        let format = &PolkadotFormat::Standard;

        let sk_from = [
            228u8, 121, 108, 167, 244, 6, 57, 61, 104, 68, 229, 88, 23, 16, 212, 157, 110, 171, 36,
            26, 232, 171, 144, 41, 109, 182, 148, 243, 20, 23, 29, 61,
        ];

        let sk_to = [
            3, 1, 2, 5, 8, 1, 118, 203, 0, 1, 2, 1, 1, 2, 1, 1, 1, 103, 0, 0, 2, 2, 2, 2, 2, 2, 3,
            5, 8, 13, 17, 29,
        ];

        let sk_from = libsecp256k1::SecretKey::parse_slice(&sk_from).unwrap();
        let sk_to = libsecp256k1::SecretKey::parse_slice(&sk_to).unwrap();

        let sk_from = PolkadotSecretKey::Secp256k1(sk_from);
        let sk_to = PolkadotSecretKey::Secp256k1(sk_to);

        let from = PolkadotAddress::<Westend>::from_secret_key(&sk_from, format).unwrap();
        let to = PolkadotAddress::<Westend>::from_secret_key(&sk_to, format).unwrap();

        assert_eq!(
            "5FnS6tYbCTAtK3QCfNnddwVR61ypLLM7APRrs98paFs7yMSY",
            from.to_string()
        );
        assert_eq!(
            "5DoW9HHuqSfpf55Ux5pLdJbHFWvbngeg8Ynhub9DrdtxmZeV",
            to.to_string()
        );
    }

    #[test]
    fn test_address_gen_2() {
        let format = &PolkadotFormat::Standard;

        let sk_from = [
            228u8, 121, 108, 167, 244, 6, 57, 61, 104, 68, 229, 88, 23, 16, 212, 157, 110, 171, 36,
            26, 232, 171, 144, 41, 109, 182, 148, 243, 20, 23, 29, 61,
        ];

        let sk_to = [
            3, 1, 2, 5, 8, 1, 118, 203, 0, 1, 2, 1, 1, 2, 1, 1, 1, 103, 0, 0, 2, 2, 2, 2, 2, 2, 3,
            5, 8, 13, 17, 29,
        ];

        let sk_from: SecretKey = sk_from[..ed25519_dalek::SECRET_KEY_LENGTH]
            .try_into()
            .unwrap();
        let sk_to: SecretKey = sk_to[..ed25519_dalek::SECRET_KEY_LENGTH]
            .try_into()
            .unwrap();

        let sk_from = PolkadotSecretKey::Ed25519(sk_from);
        let sk_to = PolkadotSecretKey::Ed25519(sk_to);

        let from = PolkadotAddress::<Westend>::from_secret_key(&sk_from, format).unwrap();
        let to = PolkadotAddress::<Westend>::from_secret_key(&sk_to, format).unwrap();

        assert_eq!(
            "5DPaKszR7KpCbvNNtGCGTfrGdeDTUNRt1UdxwXp9G6iWvdk7",
            from.to_string()
        );
        assert_eq!(
            "5D1NKGqfc2Q8hw53icrX74YQryjb3MMySWwFBhM71afKbdad",
            to.to_string()
        );
    }

    #[test]
    fn test_tx_gen() {
        let tx = r#"{
            "from": "5FnS6tYbCTAtK3QCfNnddwVR61ypLLM7APRrs98paFs7yMSY",
            "to": "5DoW9HHuqSfpf55Ux5pLdJbHFWvbngeg8Ynhub9DrdtxmZeV",
            "amount": 1000000000000,
            "nonce": 3,
            "tip": 0,
            "block_hash": "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            "genesis_hash": "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            "spec_version": 1005000,
            "tx_version": 24
        }"#;

        let mut tx = tx_from_str::<Westend>(tx);
        let hash = tx.to_transaction_id().unwrap().txid;
        let msg = libsecp256k1::Message::parse_slice(&hash).unwrap();

        let sk = [
            228u8, 121, 108, 167, 244, 6, 57, 61, 104, 68, 229, 88, 23, 16, 212, 157, 110, 171, 36,
            26, 232, 171, 144, 41, 109, 182, 148, 243, 20, 23, 29, 61,
        ];

        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();
        let (sig, rec) = libsecp256k1::sign(&msg, &sk);
        let sig = sig.serialize().to_vec();
        let rec = rec.serialize();

        let signed_tx = tx.sign(sig, rec).unwrap();
        let signed_tx = hex::encode(signed_tx);

        assert_eq!(
            "41028400a487f8cf0c11fd48eae13f819dbb06e5cb97b7103d2434897bd7cb3ea80963e502ba136449919abc037e45cb36fbeae2b1d5dde212f7cd6f9eef604833811a6ac07eba271bdbb4bfb940f6f0ab810e0afea3d0bcdce0b2a51270a2235d42d3816300000c000400004ce05abd387b560855a3d486eba6237b9a08c6e9dfe351302a5ceda90be801fe070010a5d4e8",
            signed_tx
        );
    }

    #[test]
    fn test_tx_gen_2() {
        let tx = r#"{
            "from": "5DPaKszR7KpCbvNNtGCGTfrGdeDTUNRt1UdxwXp9G6iWvdk7",
            "to": "5D1NKGqfc2Q8hw53icrX74YQryjb3MMySWwFBhM71afKbdad",
            "amount": 1000000000000,
            "nonce": 5,
            "tip": 0,
            "block_hash": "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            "genesis_hash": "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            "spec_version": 1005000,
            "tx_version": 24
        }"#;

        let mut tx = tx_from_str::<Westend>(tx);
        let msg = tx.to_bytes_ed25519().unwrap();

        let sk = [
            228u8, 121, 108, 167, 244, 6, 57, 61, 104, 68, 229, 88, 23, 16, 212, 157, 110, 171, 36,
            26, 232, 171, 144, 41, 109, 182, 148, 243, 20, 23, 29, 61,
        ];

        let signing_key: &SecretKey = &sk[..ed25519_dalek::SECRET_KEY_LENGTH].try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(signing_key);
        let sig: Signature = signing_key.sign(&msg);

        let signed_tx = tx.sign_ed25519(sig.to_vec()).unwrap();
        let signed_tx = hex::encode(signed_tx);

        assert_eq!(
            "3d0284003aa08b895131d34e7c1364ca80067f282fc6b2417b4eefcf7e2ecf7c19d7f81900aff4f335398d8584150fae80adc6dcaea686b2a5a2c9cb28a82a5a59314b7fd3ceaac142b91c949e482aec06f16202c9ea8dcd1c82a4b250cc72dfae03a6360400140004000029b0b723f2e8b89f1bcdc0cf2b3d0e624454a0cb898a46b5b59368964c5544f5070010a5d4e8",
            signed_tx
        );
    }
}
