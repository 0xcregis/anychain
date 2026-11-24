use {
    crate::{
        address::{
            encode_hip32_alias_bytes, parse_hedera_account, HederaAddress, ParsedHederaAccount,
        },
        format::HederaFormat,
        protobuf::{
            transaction_body::Data, SignedTransaction, Transaction as TransactionWrapper,
            TransactionBody, TransactionList,
        },
        public_key::HederaPublicKey,
    },
    anychain_core::{Transaction, TransactionError, TransactionId},
    hiero_sdk::{
        AccountId, AnyTransaction, Hbar, PublicKey, TokenId, TransactionId as HieroTxId,
        TransferTransaction,
    },
    prost::Message,
    std::fmt::{self, Display, Formatter},
    time::OffsetDateTime,
};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct HederaTransactionId {
    pub txid: String,
}

impl TransactionId for HederaTransactionId {}

impl Display for HederaTransactionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.txid)
    }
}

fn parse_numeric_account_id(s: &str) -> Result<AccountId, TransactionError> {
    match parse_hedera_account(s).map_err(|e| TransactionError::Message(e.to_string()))? {
        ParsedHederaAccount::Numeric { shard, realm, num } => Ok(AccountId::new(shard, realm, num)),
        ParsedHederaAccount::Hip32Alias { .. } => Err(TransactionError::Message(format!(
            "expected numeric account id <shard>.<realm>.<num>, got alias: {s}"
        ))),
    }
}

fn parse_recipient_account_id(s: &str) -> Result<AccountId, TransactionError> {
    let parsed = parse_hedera_account(s).map_err(|e| TransactionError::Message(e.to_string()))?;
    Ok(parsed.to_hiero_account_id())
}

fn parse_token_id(s: &str) -> Result<TokenId, TransactionError> {
    match parse_hedera_account(s).map_err(|e| TransactionError::Message(e.to_string()))? {
        ParsedHederaAccount::Numeric { shard, realm, num } => Ok(TokenId::new(shard, realm, num)),
        ParsedHederaAccount::Hip32Alias { .. } => {
            Err(TransactionError::Message(format!("invalid token id: {s}")))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HederaTransactionParameters {
    pub token: Option<String>,
    pub from: String,
    pub to: String,
    pub amount: i64,
    pub fee: u64,
    pub now: i64,
    pub memo: String,
    pub public_key: Vec<u8>,
    pub node: String,
}

impl HederaTransactionParameters {
    fn to_anytx(&self) -> Result<AnyTransaction, TransactionError> {
        let from = parse_numeric_account_id(&self.from)?;
        let to = parse_recipient_account_id(&self.to)?;
        let neg_amount = self
            .amount
            .checked_neg()
            .ok_or_else(|| TransactionError::Message("Invalid transfer amount".to_string()))?;
        let fee_tinybars = i64::try_from(self.fee)
            .map_err(|_| TransactionError::Message("Fee exceeds i64::MAX".to_string()))?;
        let spend = Hbar::from_tinybars(neg_amount);
        let receive = Hbar::from_tinybars(self.amount);
        let fee = Hbar::from_tinybars(fee_tinybars);
        let node = parse_numeric_account_id(&self.node)?;

        let now = OffsetDateTime::from_unix_timestamp(self.now)
            .map_err(|e| TransactionError::Message(format!("Invalid timestamp: {}", e)))?
            .replace_nanosecond(0)
            .map_err(|e| TransactionError::Message(format!("Invalid nanosecond: {}", e)))?;

        let txid = HieroTxId {
            account_id: from,
            valid_start: now,
            nonce: None,
            scheduled: false,
        };

        let mut tx = TransferTransaction::new();
        match &self.token {
            Some(token) => {
                let token = parse_token_id(token)?;
                tx.token_transfer(token, from, neg_amount);
                tx.token_transfer(token, to, self.amount);
            }
            None => {
                tx.hbar_transfer(from, spend);
                tx.hbar_transfer(to, receive);
            }
        }

        tx.max_transaction_fee(fee);
        tx.transaction_id(txid);
        tx.node_account_ids(vec![node]);

        if !self.memo.is_empty() {
            tx.transaction_memo(&self.memo);
        }

        tx.freeze()
            .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;

        Ok(tx.into())
    }
}

#[derive(Clone, Debug)]
pub struct HederaTransaction {
    pub params: HederaTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl HederaTransaction {
    fn to_anytx(&self) -> Result<AnyTransaction, TransactionError> {
        let mut anytx = self.params.to_anytx()?;
        if let Some(sig) = &self.signature {
            let pk = self.params.public_key.clone();
            let pk = PublicKey::from_bytes_ed25519(&pk)
                .map_err(|e| TransactionError::Message(format!("Invalid public key: {}", e)))?;
            anytx.add_signature(pk, sig.clone());
        };
        Ok(anytx)
    }

    fn to_tx_wrapper(&self) -> Result<TransactionWrapper, TransactionError> {
        let anytx = self.to_anytx()?;
        Self::get_tx_wrapper(&anytx)
    }

    fn get_tx_wrapper(anytx: &AnyTransaction) -> Result<TransactionWrapper, TransactionError> {
        let bytes = anytx
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("to_bytes failed: {}", e)))?;

        let tx_list = TransactionList::decode(&*bytes).map_err(|e| {
            TransactionError::Message(format!("decode TransactionList failed: {}", e))
        })?;

        let tx = tx_list.transaction_list.first().ok_or_else(|| {
            TransactionError::Message("No transaction in transaction list".to_string())
        })?;

        Ok(tx.clone())
    }
}

impl Transaction for HederaTransaction {
    type Address = HederaAddress;
    type Format = HederaFormat;
    type PublicKey = HederaPublicKey;
    type TransactionId = HederaTransactionId;
    type TransactionParameters = HederaTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            params: parameters.clone(),
            signature: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length: {}",
                rs.len()
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let tx = self.to_tx_wrapper()?;
        match &self.signature {
            Some(_) => {
                let payload = tx.encode_to_vec();

                // gRPC prefix
                let len = payload.len() as u32;
                let len = len.to_be_bytes();

                let mut full_bytes = Vec::with_capacity(5 + payload.len());
                full_bytes.push(0u8);
                full_bytes.extend_from_slice(&len);

                full_bytes.extend_from_slice(&payload);

                Ok(full_bytes)
            }
            None => {
                let signed_tx =
                    SignedTransaction::decode(&*tx.signed_transaction_bytes).map_err(|e| {
                        TransactionError::Message(format!("decode SignedTransaction failed: {}", e))
                    })?;
                Ok(signed_tx.body_bytes)
            }
        }
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        if tx.len() < 5 {
            return Err(TransactionError::Message(
                "Invalid transaction bytes: missing gRPC prefix".to_string(),
            ));
        }

        let tx = TransactionWrapper::decode(&tx[5..])
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let tx = SignedTransaction::decode(&*tx.signed_transaction_bytes)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let tx = TransactionBody::decode(&*tx.body_bytes)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let txid = tx
            .transaction_id
            .ok_or_else(|| TransactionError::Message("missing transaction_id".to_string()))?;
        let data = tx
            .data
            .ok_or_else(|| TransactionError::Message("missing transaction data".to_string()))?;

        let from = txid
            .account_id
            .ok_or_else(|| TransactionError::Message("missing payer account_id".to_string()))?
            .to_string()?;
        let fee = tx.transaction_fee;
        let memo = tx.memo;
        let now = txid
            .transaction_valid_start
            .ok_or_else(|| {
                TransactionError::Message("missing transaction_valid_start".to_string())
            })?
            .seconds;
        let node = tx
            .node_account_id
            .ok_or_else(|| TransactionError::Message("missing node_account_id".to_string()))?
            .to_string()?;

        let (token, to, amount) = match data {
            Data::CryptoCreateAccount(body) => {
                let key = body
                    .key
                    .ok_or_else(|| TransactionError::Message("missing account key".to_string()))?;
                let alias = encode_hip32_alias_bytes(&key.encode_to_vec())
                    .map_err(|e| TransactionError::Message(e.to_string()))?;
                let to = format!("0.0.{}", alias);
                let amount = i64::try_from(body.initial_balance).map_err(|_| {
                    TransactionError::Message("initial_balance exceeds i64::MAX".to_string())
                })?;
                (None, to, amount)
            }
            Data::CryptoTransfer(body) => {
                if let Some(transfers) = body.transfers {
                    let transfer = transfers.account_amounts.get(1).ok_or_else(|| {
                        TransactionError::Message("missing transfer recipient".to_string())
                    })?;
                    let to = transfer
                        .account_id
                        .as_ref()
                        .ok_or_else(|| {
                            TransactionError::Message("missing recipient account_id".to_string())
                        })?
                        .to_string()?;
                    let amount = transfer.amount;
                    (None, to, amount)
                } else {
                    let list = body.token_transfers.first().ok_or_else(|| {
                        TransactionError::Message("empty token transfers".to_string())
                    })?;
                    let token = list
                        .token
                        .as_ref()
                        .ok_or_else(|| TransactionError::Message("missing token id".to_string()))?
                        .to_string()?;
                    let transfer = list.transfers.get(1).ok_or_else(|| {
                        TransactionError::Message("missing token transfer recipient".to_string())
                    })?;
                    let to = transfer
                        .account_id
                        .as_ref()
                        .ok_or_else(|| {
                            TransactionError::Message("missing recipient account_id".to_string())
                        })?
                        .to_string()?;
                    let amount = transfer.amount;
                    (Some(token), to, amount)
                }
            }
        };

        HederaTransaction::new(&HederaTransactionParameters {
            token,
            from,
            to,
            amount,
            fee,
            now,
            memo,
            public_key: vec![],
            node,
        })
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let id = self
            .params
            .to_anytx()?
            .get_transaction_id()
            .ok_or_else(|| TransactionError::Message("Missing transaction ID".to_string()))?;
        let txid = format!(
            "{}@{}.{}",
            id.account_id,
            id.valid_start.unix_timestamp(),
            id.valid_start.nanosecond()
        );
        Ok(HederaTransactionId { txid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::{self, account_id::Account};
    use anychain_core::Address;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::{Signer, SigningKey};
    use hiero_sdk::{AccountCreateTransaction, Client, PrivateKey};
    use std::collections::HashMap;
    use std::str::FromStr;

    // const END_POINT: &str = "http://0.testnet.hedera.com:50211/proto.CryptoService/cryptoTransfer";
    const USDC: &str = "0.0.429274";

    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "be16996c9f6731347d11eb59c498d8908d7ff2b0d0bef860552c6ee1da66fd3a";
    const PRIVATE_HEX_CARO: &str =
        "a66be16996c98d8908d7ff2b0d0bef86f6731347d11eb59c490552c6ee1dfd3a";

    fn sign_and_encode(params: &HederaTransactionParameters, sk_hex: &str) -> Vec<u8> {
        let sk = PrivateKey::from_str_ed25519(sk_hex).unwrap();
        let mut hedera_tx = HederaTransaction::new(params).unwrap();
        let body_bytes = hedera_tx.to_bytes().unwrap();

        let private_arr: [u8; 32] = sk.to_bytes().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        hedera_tx.sign(signature.to_bytes().to_vec(), 0).unwrap()
    }

    fn decode_body(raw_grpc_tx: &[u8]) -> TransactionBody {
        let wrapper = TransactionWrapper::decode(&raw_grpc_tx[5..]).unwrap();
        let signed = SignedTransaction::decode(&*wrapper.signed_transaction_bytes).unwrap();
        TransactionBody::decode(&*signed.body_bytes).unwrap()
    }

    #[ignore]
    #[tokio::test]
    async fn test_transfer_alice_to_bob() {
        // 1. Setup client with ECDSA operator (Alice's funded account 0.0.8007608) to pay for the initial account creation
        let mut custom_nodes = HashMap::new();
        custom_nodes.insert(
            "35.237.119.55:50211".to_string(),
            AccountId::from_str("0.0.4").unwrap(),
        );
        let client = Client::for_network(custom_nodes).unwrap();
        let id_alice = AccountId::from_str("0.0.8007608").unwrap();
        let sk_alice = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        client.set_operator(id_alice, sk_alice);
        client.set_default_max_transaction_fee(hiero_sdk::Hbar::from_tinybars(1_000_000)); // Limit default max fee to 0.01 HBAR!

        let id_bob = AccountId::from_str("0.0.9549757").unwrap();

        let create_response = hiero_sdk::TransferTransaction::new()
            .hbar_transfer(id_alice, hiero_sdk::Hbar::from_tinybars(-100_000_000)) // Fund Bob with 0.05 HBAR
            .hbar_transfer(id_bob, hiero_sdk::Hbar::from_tinybars(100_000_000))
            .max_transaction_fee(hiero_sdk::Hbar::from_tinybars(78_000_000)) // 0.78 HBAR maximum fee to exactly cover actual creation fees within Alice's 84M balance limit
            .execute(&client)
            .await
            .unwrap();

        let _create_receipt = create_response.get_receipt(&client).await.unwrap();
        let info = hiero_sdk::AccountInfoQuery::new()
            .account_id(id_bob)
            .execute(&client)
            .await
            .unwrap();
        let id_bob = info.account_id;
        println!(
            "Successfully transferred {} HBARs to account: {}",
            1, id_bob
        );
    }

    #[tokio::test]
    async fn test_transfer_bob_to_alice() {
        let id_bob = "0.0.9549757".to_string();
        let id_alice = "0.0.8007608".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: None,
            from: id_bob.clone(),
            to: id_alice.clone(),
            amount: 100_000_000,
            fee: 2_000_000,
            now,
            memo: "transfer".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let tx = sign_and_encode(&params, PRIVATE_HEX_BOB);
        let decoded = HederaTransaction::from_bytes(&tx).unwrap();
        assert_eq!(decoded.params.token, None);
        assert_eq!(decoded.params.from, id_bob);
        assert_eq!(decoded.params.to, id_alice);
        assert_eq!(decoded.params.amount, 100_000_000);
        assert_eq!(decoded.params.fee, 2_000_000);
        assert_eq!(decoded.params.now, now);
        assert_eq!(decoded.params.memo, "transfer");
        assert_eq!(decoded.params.node, "0.0.3");
    }

    #[tokio::test]
    async fn test_transfer_bob_to_caro_hip32_ed25519() {
        let id_bob = "0.0.9549757".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let caro_sk_bytes: [u8; 32] = hex::decode(PRIVATE_HEX_CARO).unwrap().try_into().unwrap();
        let caro_signing_key = SigningKey::from_bytes(&caro_sk_bytes);
        let caro_hip32 = HederaAddress::from_secret_key(&caro_signing_key, &HederaFormat::Standard)
            .unwrap()
            .to_string();
        assert!(caro_hip32.starts_with("0.0.CIQ"));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: None,
            from: id_bob.clone(),
            to: caro_hip32.clone(),
            amount: 100_000_000,
            fee: 200_000_000,
            now,
            memo: "hip32 transfer to caro".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let tx = sign_and_encode(&params, PRIVATE_HEX_BOB);

        // Verify raw protobuf uses CryptoTransfer with Account::Alias(0x12 0x20 <32-byte pk>)
        let body = decode_body(&tx);
        let expected_alias = protobuf::Key {
            key: Some(protobuf::key::Key::Ed25519(
                caro_signing_key.verifying_key().to_bytes().to_vec(),
            )),
        }
        .encode_to_vec();
        assert_eq!(expected_alias[0], 0x12);
        assert_eq!(expected_alias[1], 0x20);
        assert_eq!(expected_alias.len(), 34);

        match body.data.unwrap() {
            Data::CryptoTransfer(transfer) => {
                let amounts = transfer.transfers.unwrap().account_amounts;
                assert_eq!(amounts.len(), 2);
                assert_eq!(amounts[0].amount, -100_000_000);
                assert_eq!(amounts[1].amount, 100_000_000);
                let recipient = amounts[1].account_id.as_ref().unwrap();
                assert_eq!(recipient.shard_num, 0);
                assert_eq!(recipient.realm_num, 0);
                assert_eq!(recipient.account, Some(Account::Alias(expected_alias)));
            }
            other => panic!("expected CryptoTransfer, got {:?}", other),
        }

        let decoded = HederaTransaction::from_bytes(&tx).unwrap();
        assert_eq!(decoded.params.token, None);
        assert_eq!(decoded.params.from, id_bob);
        assert_eq!(decoded.params.to, caro_hip32);
        assert_eq!(decoded.params.amount, 100_000_000);
        assert_eq!(decoded.params.fee, 200_000_000);
        assert_eq!(decoded.params.now, now);
        assert_eq!(decoded.params.memo, "hip32 transfer to caro");
        assert_eq!(decoded.params.node, "0.0.3");
    }

    #[tokio::test]
    async fn test_transfer_bob_to_ecdsa_hip32_alias() {
        let id_bob = "0.0.9549757".to_string();
        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let sk_ecdsa = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        let expected_alias = protobuf::Key {
            key: Some(protobuf::key::Key::EcdsaSecp256k1(
                sk_ecdsa.public_key().to_bytes_raw(),
            )),
        }
        .encode_to_vec();
        assert_eq!(expected_alias[0], 0x3a);
        assert_eq!(expected_alias[1], 0x21);
        assert_eq!(expected_alias.len(), 35);

        let ecdsa_hip32 = format!("0.0.{}", BASE32_NOPAD.encode(&expected_alias));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: None,
            from: id_bob.clone(),
            to: ecdsa_hip32.clone(),
            amount: 50_000_000,
            fee: 200_000_000,
            now,
            memo: "hip32 ecdsa".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let tx = sign_and_encode(&params, PRIVATE_HEX_BOB);
        let body = decode_body(&tx);
        match body.data.unwrap() {
            Data::CryptoTransfer(transfer) => {
                let recipient = transfer.transfers.unwrap().account_amounts[1]
                    .account_id
                    .clone()
                    .unwrap();
                assert_eq!(recipient.account, Some(Account::Alias(expected_alias)));
            }
            other => panic!("expected CryptoTransfer, got {:?}", other),
        }

        let decoded = HederaTransaction::from_bytes(&tx).unwrap();
        assert_eq!(decoded.params.to, ecdsa_hip32);
        assert_eq!(decoded.params.amount, 50_000_000);
    }

    #[tokio::test]
    async fn test_transfer_bob_to_caro_usdc() {
        let id_bob = "0.0.9549757".to_string();
        let id_caro = "0.0.10248559".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: Some(USDC.to_string()),
            from: id_bob.clone(),
            to: id_caro.clone(),
            amount: 10_000_000,
            fee: 200_000_000,
            now,
            memo: "to Caro USDC".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let tx = sign_and_encode(&params, PRIVATE_HEX_BOB);
        let decoded = HederaTransaction::from_bytes(&tx).unwrap();
        assert_eq!(decoded.params.token, Some(USDC.to_string()));
        assert_eq!(decoded.params.from, id_bob);
        assert_eq!(decoded.params.to, id_caro);
        assert_eq!(decoded.params.amount, 10_000_000);
    }

    #[tokio::test]
    async fn test_transfer_usdc_to_hip32_alias() {
        let id_bob = "0.0.9549757".to_string();
        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let caro_sk_bytes: [u8; 32] = hex::decode(PRIVATE_HEX_CARO).unwrap().try_into().unwrap();
        let caro_hip32 = HederaAddress::from_secret_key(
            &SigningKey::from_bytes(&caro_sk_bytes),
            &HederaFormat::Standard,
        )
        .unwrap()
        .to_string();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: Some(USDC.to_string()),
            from: id_bob.clone(),
            to: caro_hip32.clone(),
            amount: 10_000_000,
            fee: 200_000_000,
            now,
            memo: "to Caro HIP-32 USDC".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let tx = sign_and_encode(&params, PRIVATE_HEX_BOB);
        let decoded = HederaTransaction::from_bytes(&tx).unwrap();
        assert_eq!(decoded.params.token, Some(USDC.to_string()));
        assert_eq!(decoded.params.from, id_bob);
        assert_eq!(decoded.params.to, caro_hip32);
        assert_eq!(decoded.params.amount, 10_000_000);
    }

    #[test]
    fn test_reject_raw_hex_pubkey_recipient() {
        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let sk_caro = PrivateKey::from_str_ed25519(PRIVATE_HEX_CARO).unwrap();
        let pk_caro_hex = hex::encode(sk_caro.public_key().to_bytes());

        let params = HederaTransactionParameters {
            token: None,
            from: "0.0.9549757".to_string(),
            to: pk_caro_hex,
            amount: 100_000_000,
            fee: 200_000_000,
            now: 1770364044,
            memo: "legacy hex".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let hedera_tx = HederaTransaction::new(&params).unwrap();
        assert!(hedera_tx.to_bytes().is_err());
    }

    #[test]
    fn test_reject_alias_as_payer_or_node() {
        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();
        let caro_sk_bytes: [u8; 32] = hex::decode(PRIVATE_HEX_CARO).unwrap().try_into().unwrap();
        let caro_hip32 = HederaAddress::from_secret_key(
            &SigningKey::from_bytes(&caro_sk_bytes),
            &HederaFormat::Standard,
        )
        .unwrap()
        .to_string();

        let bad_from = HederaTransactionParameters {
            token: None,
            from: caro_hip32.clone(),
            to: "0.0.8007608".to_string(),
            amount: 100_000_000,
            fee: 2_000_000,
            now: 1770364044,
            memo: String::new(),
            public_key: pk_bob.clone(),
            node: "0.0.3".to_string(),
        };
        assert!(HederaTransaction::new(&bad_from)
            .unwrap()
            .to_bytes()
            .is_err());

        let bad_node = HederaTransactionParameters {
            token: None,
            from: "0.0.9549757".to_string(),
            to: "0.0.8007608".to_string(),
            amount: 100_000_000,
            fee: 2_000_000,
            now: 1770364044,
            memo: String::new(),
            public_key: pk_bob,
            node: caro_hip32,
        };
        assert!(HederaTransaction::new(&bad_node)
            .unwrap()
            .to_bytes()
            .is_err());
    }

    #[test]
    fn test_decode_legacy_crypto_create_account_as_hip32() {
        let sk_caro = PrivateKey::from_str_ed25519(PRIVATE_HEX_CARO).unwrap();
        let caro_sk_bytes: [u8; 32] = hex::decode(PRIVATE_HEX_CARO).unwrap().try_into().unwrap();
        let expected_hip32 = HederaAddress::from_secret_key(
            &SigningKey::from_bytes(&caro_sk_bytes),
            &HederaFormat::Standard,
        )
        .unwrap()
        .to_string();

        let mut tx = AccountCreateTransaction::new();
        tx.max_automatic_token_associations(-1)
            .set_key_without_alias(sk_caro.public_key())
            .initial_balance(Hbar::from_tinybars(100_000_000))
            .max_transaction_fee(Hbar::from_tinybars(200_000_000))
            .transaction_id(HieroTxId {
                account_id: AccountId::new(0, 0, 9549757),
                valid_start: OffsetDateTime::from_unix_timestamp(1770364044).unwrap(),
                nonce: None,
                scheduled: false,
            })
            .node_account_ids(vec![AccountId::new(0, 0, 3)])
            .freeze()
            .unwrap();

        let anytx: AnyTransaction = tx.into();
        let wrapper = HederaTransaction::get_tx_wrapper(&anytx).unwrap();
        let payload = wrapper.encode_to_vec();
        let mut grpc_bytes = Vec::with_capacity(5 + payload.len());
        grpc_bytes.push(0u8);
        grpc_bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        grpc_bytes.extend_from_slice(&payload);

        let decoded = HederaTransaction::from_bytes(&grpc_bytes).unwrap();
        assert_eq!(decoded.params.to, expected_hip32);
        assert_eq!(decoded.params.from, "0.0.9549757");
        assert_eq!(decoded.params.amount, 100_000_000);
    }
}
