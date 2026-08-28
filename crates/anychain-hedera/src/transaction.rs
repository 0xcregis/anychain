use {
    crate::{
        address::HederaAddress,
        format::HederaFormat,
        protobuf::{
            key::Key, transaction_body::Data, SignedTransaction, Transaction as TransactionWrapper,
            TransactionBody, TransactionList,
        },
        public_key::HederaPublicKey,
    },
    anychain_core::{Transaction, TransactionError, TransactionId},
    hiero_sdk::{
        AccountCreateTransaction, AccountId, AnyTransaction, Hbar, PublicKey, TokenId,
        TransactionId as HieroTxId, TransferTransaction,
    },
    prost::Message,
    std::{
        fmt::{self, Display, Formatter},
        str::FromStr,
    },
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

fn get_account_id(s: &str) -> Result<AccountId, TransactionError> {
    AccountId::from_str(s).map_err(|e| TransactionError::Message(e.to_string()))
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
        let from = get_account_id(&self.from)?;
        let spend = Hbar::from_tinybars(-self.amount);
        let receive = Hbar::from_tinybars(self.amount);
        let fee = Hbar::from_tinybars(self.fee as i64);
        let node = get_account_id(&self.node)?;

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

        let tx: AnyTransaction = if self.to.contains(".") {
            let mut tx = TransferTransaction::new();
            let to = get_account_id(&self.to)?;

            match &self.token {
                Some(token) => {
                    let token = TokenId::from_str(token)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                    tx.token_transfer(token, from, -self.amount);
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
            tx.into()
        } else {
            if self.token.is_some() {
                return Err(TransactionError::Message(
                    "cannot transfer token to non-existing account".to_string(),
                ));
            }

            let mut tx = AccountCreateTransaction::new();

            let pk = hex::decode(self.to.clone())?;
            let pk = PublicKey::from_bytes_ed25519(&pk)
                .map_err(|e| TransactionError::Message(format!("Invalid public key: {}", e)))?;

            tx.max_automatic_token_associations(-1);
            tx.set_key_without_alias(pk);
            tx.initial_balance(receive);

            tx.max_transaction_fee(fee);
            tx.transaction_id(txid);
            tx.node_account_ids(vec![node]);

            if !self.memo.is_empty() {
                tx.transaction_memo(&self.memo);
            }

            tx.freeze()
                .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;
            tx.into()
        };

        Ok(tx)
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
        let tx = TransactionWrapper::decode(&tx[5..])
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let tx = SignedTransaction::decode(&*tx.signed_transaction_bytes)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let tx = TransactionBody::decode(&*tx.body_bytes)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let txid = tx.transaction_id.unwrap();
        let data = tx.data.unwrap();

        let from = txid.account_id.unwrap().to_string()?;
        let fee = tx.transaction_fee;
        let memo = tx.memo;
        let now = txid.transaction_valid_start.unwrap().seconds;
        let node = tx.node_account_id.unwrap().to_string()?;

        let (token, to, amount) = match data {
            Data::CryptoCreateAccount(body) => {
                let to = if let Key::Ed25519(pk) = body.key.unwrap().key.unwrap() {
                    hex::encode(pk)
                } else {
                    return Err(TransactionError::Message("invalid public key".to_string()));
                };
                let amount = body.initial_balance as i64;
                (None, to, amount)
            }
            Data::CryptoTransfer(body) => {
                if body.transfers.is_some() {
                    let transfers = match body.transfers {
                        Some(transfers) => transfers,
                        None => {
                            return Err(TransactionError::Message("empty transfers".to_string()))
                        }
                    };
                    let transfers = transfers.account_amounts;
                    let transfer = transfers[1].clone();
                    let to = transfer.account_id.unwrap().to_string()?;
                    let amount = transfer.amount;
                    (None, to, amount)
                } else {
                    let list = body.token_transfers[0].clone();
                    let token = list.token.unwrap().to_string()?;
                    let transfer = list.transfers[1].clone();
                    let to = transfer.account_id.unwrap().to_string()?;
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
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use hiero_sdk::{Client, PrivateKey};
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
        // 0ab4012ab101
        let id_bob = "0.0.9549757".to_string();
        let id_alice = "0.0.8007608".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: None,
            from: id_bob,
            to: id_alice,
            amount: 100_000_000,
            fee: 2_000_000,
            now,
            memo: "transfer".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let body_bytes = hedera_tx.to_bytes().unwrap();

        let private_arr: [u8; 32] = sk_bob.to_bytes().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();

        let tx = hedera_tx.sign(signature_bytes, 0).unwrap();

        let _tx = HederaTransaction::from_bytes(&tx).unwrap();
        println!("{:?}", _tx);

        // let tx = hex::encode(tx);

        // Assemble the curl command to send the transaction to the Hedera network
        // let curl_command = format!(
        //     "echo \"{}\" | xxd -r -p | curl --verbose --proxytunnel --noproxy \"*\" --http2-prior-knowledge -H \"Content-Type: application/grpc\" -H \"TE: trailers\" --data-binary @- --output - {}",
        //     tx, END_POINT
        // );

        // println!("{}", curl_command);
    }

    #[tokio::test]
    async fn test_transfer_bob_to_caro() {
        // 0af2012aef01
        let id_bob = "0.0.9549757".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let sk_caro = PrivateKey::from_str_ed25519(PRIVATE_HEX_CARO).unwrap();
        let pk_caro = sk_caro.public_key().to_bytes();
        let pk_caro = hex::encode(pk_caro);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: None,
            from: id_bob,
            to: pk_caro,
            amount: 100_000_000,
            fee: 200_000_000,
            now,
            memo: "create caro account".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let body_bytes = hedera_tx.to_bytes().unwrap();

        let private_arr: [u8; 32] = sk_bob.to_bytes().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();

        let tx = hedera_tx.sign(signature_bytes, 0).unwrap();

        let _tx = HederaTransaction::from_bytes(&tx).unwrap();
        println!("{:?}", _tx);

        // let tx = hex::encode(tx);

        // Assemble the curl command to send the transaction to the Hedera network
        // let curl_command = format!(
        //     "echo \"{}\" | xxd -r -p | curl --verbose --proxytunnel --noproxy \"*\" --http2-prior-knowledge -H \"Content-Type: application/grpc\" -H \"TE: trailers\" --data-binary @- --output - {}",
        //     tx, END_POINT
        // );

        // println!("{}", curl_command);
    }

    #[tokio::test]
    async fn test_transfer_bob_to_caro_usdc() {
        // 0abf012abc01
        let id_bob = "0.0.9549757".to_string();
        let id_caro = "0.0.10248559".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let params = HederaTransactionParameters {
            token: Some(USDC.to_string()),
            from: id_bob,
            to: id_caro,
            amount: 10_000_000,
            fee: 200_000_000,
            now,
            memo: "to Caro USDC".to_string(),
            public_key: pk_bob,
            node: "0.0.3".to_string(),
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let body_bytes = hedera_tx.to_bytes().unwrap();

        let private_arr: [u8; 32] = sk_bob.to_bytes().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();

        let tx = hedera_tx.sign(signature_bytes, 0).unwrap();

        let _tx = HederaTransaction::from_bytes(&tx).unwrap();
        println!("{:?}", _tx);

        // let tx = hex::encode(tx);

        // Assemble the curl command to send the transaction to the Hedera network
        // let curl_command = format!(
        //     "echo \"{}\" | xxd -r -p | curl --verbose --proxytunnel --noproxy \"*\" --http2-prior-knowledge -H \"Content-Type: application/grpc\" -H \"TE: trailers\" --data-binary @- --output - {}",
        //     tx, END_POINT
        // );

        // println!("{}", curl_command);
    }
}
