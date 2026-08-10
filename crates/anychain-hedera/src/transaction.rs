use {
    crate::protobuf::{
        account_id::Account, key::Key, signature_pair::Signature, transaction_body::Data,
        SignedTransaction, TransactionBody, TransactionList,
    },
    crate::{address::HederaAddress, format::HederaFormat, public_key::HederaPublicKey},
    anychain_core::{Transaction, TransactionError, TransactionId},
    hiero_sdk::{AccountId, AnyTransaction, Hbar, TransactionId as HieroTxId, TransferTransaction},
    prost::Message,
    std::fmt::{self, Display, Formatter},
    std::str::FromStr,
    time::OffsetDateTime,
};

fn parse_account_id(s: &str) -> Result<AccountId, TransactionError> {
    if s.starts_with("0x") {
        let clean_hex = s.strip_prefix("0x").unwrap();
        let alias_str = format!("0.0.{}", clean_hex);
        AccountId::from_str(&alias_str)
            .map_err(|e| TransactionError::Message(format!("Invalid public key alias: {}", e)))
    } else {
        AccountId::from_str(s)
            .map_err(|e| TransactionError::Message(format!("Invalid account ID: {}", e)))
    }
}

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

#[derive(Clone, Debug, PartialEq)]
pub enum HederaTransactionData {
    Transfer {
        receiver_account_id: String,
        amount: i64, // amount in tinybars
    },
    CreateAccount {
        new_account_public_key: Vec<u8>,
        initial_balance: u64, // in tinybars
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct HederaTransactionParameters {
    pub payer_account_id: String,
    pub node_account_ids: Vec<String>,
    pub valid_start_seconds: i64,
    pub valid_start_nanos: i32,
    pub max_transaction_fee: u64, // in tinybars
    pub memo: String,
    pub public_key: Vec<u8>, // the public key of the signer
    pub data: HederaTransactionData,
}

#[derive(Clone, Debug)]
pub struct HederaTransaction {
    pub params: HederaTransactionParameters,
    pub tx: AnyTransaction,
    pub signature: Option<Vec<u8>>,
}

impl Transaction for HederaTransaction {
    type Address = HederaAddress;
    type Format = HederaFormat;
    type PublicKey = HederaPublicKey;
    type TransactionId = HederaTransactionId;
    type TransactionParameters = HederaTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        let payer = parse_account_id(&parameters.payer_account_id)?;

        let valid_start = OffsetDateTime::from_unix_timestamp(parameters.valid_start_seconds)
            .map_err(|e| TransactionError::Message(format!("Invalid timestamp: {}", e)))?
            .replace_nanosecond(parameters.valid_start_nanos as u32)
            .map_err(|e| TransactionError::Message(format!("Invalid nanosecond: {}", e)))?;

        let tx_id = HieroTxId {
            account_id: payer,
            valid_start,
            nonce: None,
            scheduled: false,
        };

        let any_tx: AnyTransaction = match &parameters.data {
            HederaTransactionData::Transfer {
                receiver_account_id,
                amount,
            } => {
                let receiver = parse_account_id(receiver_account_id)?;
                let mut tx = TransferTransaction::new();
                tx.hbar_transfer(payer, Hbar::from_tinybars(-amount));
                tx.hbar_transfer(receiver, Hbar::from_tinybars(*amount));
                tx.transaction_id(tx_id);
                if !parameters.node_account_ids.is_empty() {
                    let mut nodes = Vec::new();
                    for node_str in &parameters.node_account_ids {
                        let node = AccountId::from_str(node_str).map_err(|e| {
                            TransactionError::Message(format!("Invalid node account ID: {}", e))
                        })?;
                        nodes.push(node);
                    }
                    tx.node_account_ids(nodes);
                }
                if parameters.max_transaction_fee > 0 {
                    tx.max_transaction_fee(Hbar::from_tinybars(
                        parameters.max_transaction_fee as i64,
                    ));
                }
                if !parameters.memo.is_empty() {
                    tx.transaction_memo(&parameters.memo);
                }
                tx.freeze()
                    .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;
                tx.into()
            }
            HederaTransactionData::CreateAccount {
                new_account_public_key,
                initial_balance,
            } => {
                use hiero_sdk::AccountCreateTransaction;
                let mut tx = AccountCreateTransaction::new();
                let pk = hiero_sdk::PublicKey::from_bytes_ed25519(new_account_public_key)
                    .map_err(|e| TransactionError::Message(format!("Invalid public key: {}", e)))?;
                tx.set_key_without_alias(pk);
                if *initial_balance > 0 {
                    tx.initial_balance(Hbar::from_tinybars(*initial_balance as i64));
                }
                tx.transaction_id(tx_id);
                if !parameters.node_account_ids.is_empty() {
                    let mut nodes = Vec::new();
                    for node_str in &parameters.node_account_ids {
                        let node = AccountId::from_str(node_str).map_err(|e| {
                            TransactionError::Message(format!("Invalid node account ID: {}", e))
                        })?;
                        nodes.push(node);
                    }
                    tx.node_account_ids(nodes);
                }
                if parameters.max_transaction_fee > 0 {
                    tx.max_transaction_fee(Hbar::from_tinybars(
                        parameters.max_transaction_fee as i64,
                    ));
                }
                if !parameters.memo.is_empty() {
                    tx.transaction_memo(&parameters.memo);
                }
                tx.freeze()
                    .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;
                tx.into()
            }
        };

        Ok(Self {
            params: parameters.clone(),
            tx: any_tx,
            signature: None,
        })
    }

    fn sign(&mut self, signature: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        let mut pk_bytes = self.params.public_key.clone();
        if pk_bytes.starts_with(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]) {
            pk_bytes = pk_bytes[12..].to_vec();
        }
        let hiero_pk = hiero_sdk::PublicKey::from_bytes_ed25519(&pk_bytes)
            .map_err(|e| TransactionError::Message(format!("Invalid public key: {}", e)))?;

        self.tx.add_signature(hiero_pk, signature.clone());
        self.signature = Some(signature);

        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        let any_tx = AnyTransaction::from_bytes(bytes)
            .map_err(|e| TransactionError::Message(format!("from_bytes failed: {}", e)))?;

        // Reconstruct parameters
        let payer_account_id = any_tx
            .get_transaction_id()
            .map(|id| id.account_id.to_string())
            .unwrap_or_default();

        let valid_start_seconds = any_tx
            .get_transaction_id()
            .map(|id| id.valid_start.unix_timestamp())
            .unwrap_or_default();

        let valid_start_nanos = any_tx
            .get_transaction_id()
            .map(|id| id.valid_start.nanosecond() as i32)
            .unwrap_or_default();

        let memo = any_tx.get_transaction_memo().to_string();

        let max_transaction_fee = any_tx
            .get_max_transaction_fee()
            .map(|fee| fee.to_tinybars() as u64)
            .unwrap_or_default();

        let node_account_ids = any_tx
            .get_node_account_ids()
            .map(|nodes| nodes.iter().map(|n| n.to_string()).collect())
            .unwrap_or_default();

        // Decode the transfer/creation details from body_bytes if available
        let tx_bytes = any_tx.to_bytes().unwrap_or_default();
        let mut tx_data = None;

        if let Ok(tx_list) = TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) =
                    SignedTransaction::decode(&*proto_tx.signed_transaction_bytes)
                {
                    if let Ok(body) = TransactionBody::decode(&*signed_tx.body_bytes) {
                        if let Some(data) = body.data {
                            match data {
                                Data::CryptoTransfer(transfer_body) => {
                                    let mut receiver_account_id = String::new();
                                    let mut amount = 0i64;
                                    if let Some(transfers) = transfer_body.transfers {
                                        for aa in transfers.account_amounts {
                                            if let Some(acc) = aa.account_id {
                                                let acc_str = match &acc.account {
                                                    Some(Account::AccountNum(num)) => {
                                                        format!(
                                                            "{}.{}.{}",
                                                            acc.shard_num, acc.realm_num, num
                                                        )
                                                    }
                                                    Some(Account::Alias(alias)) => {
                                                        if alias.len() == 20 {
                                                            format!("0x{}", hex::encode(alias))
                                                        } else {
                                                            format!(
                                                                "{}.{}.{}",
                                                                acc.shard_num,
                                                                acc.realm_num,
                                                                hex::encode(alias)
                                                            )
                                                        }
                                                    }
                                                    None => format!(
                                                        "{}.{}.0",
                                                        acc.shard_num, acc.realm_num
                                                    ),
                                                };
                                                if aa.amount < 0 {
                                                    // Payer (debit)
                                                } else if aa.amount > 0 {
                                                    // Receiver (credit)
                                                    receiver_account_id = acc_str;
                                                    amount = aa.amount;
                                                }
                                            }
                                        }
                                    }
                                    tx_data = Some(HederaTransactionData::Transfer {
                                        receiver_account_id,
                                        amount,
                                    });
                                }
                                Data::CryptoCreateAccount(create_body) => {
                                    let mut new_account_public_key = Vec::new();
                                    if let Some(key) = create_body.key {
                                        if let Some(Key::Ed25519(pk_bytes)) = key.key {
                                            new_account_public_key = pk_bytes;
                                        }
                                    }
                                    tx_data = Some(HederaTransactionData::CreateAccount {
                                        new_account_public_key,
                                        initial_balance: create_body.initial_balance,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut signature = None;
        if let Ok(tx_list) = TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) =
                    SignedTransaction::decode(&*proto_tx.signed_transaction_bytes)
                {
                    if let Some(sig_map) = signed_tx.sig_map {
                        if let Some(sig_pair) = sig_map.sig_pair.first() {
                            if let Some(Signature::Ed25519(sig)) = &sig_pair.signature {
                                signature = Some(sig.clone());
                            }
                        }
                    }
                }
            }
        }

        let data = tx_data.unwrap_or(HederaTransactionData::Transfer {
            receiver_account_id: String::new(),
            amount: 0,
        });

        let params = HederaTransactionParameters {
            payer_account_id,
            node_account_ids,
            valid_start_seconds,
            valid_start_nanos,
            max_transaction_fee,
            memo,
            public_key: Vec::new(),
            data,
        };

        Ok(Self {
            params,
            tx: any_tx,
            signature,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let tx_bytes = self
            .tx
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("to_bytes failed: {}", e)))?;

        let mut tx_list = TransactionList::decode(&*tx_bytes).map_err(|e| {
            TransactionError::Message(format!("decode TransactionList failed: {}", e))
        })?;

        let tx = tx_list.transaction_list.first_mut().ok_or_else(|| {
            TransactionError::Message("No transaction in transaction list".to_string())
        })?;

        match &self.signature {
            Some(_) => Ok(tx.encode_to_vec()),
            None => {
                let signed_tx =
                    SignedTransaction::decode(&*tx.signed_transaction_bytes).map_err(|e| {
                        TransactionError::Message(format!("decode SignedTransaction failed: {}", e))
                    })?;
                Ok(signed_tx.body_bytes)
            }
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let id = self
            .tx
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

    const END_POINT: &str = "http://35.237.119.55:50211/proto.CryptoService/cryptoTransfer";
    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "be16996c9f6731347d11eb59c498d8908d7ff2b0d0bef860552c6ee1da66fd3a";

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
        let unique_nanos = ("alice"
            .as_bytes()
            .iter()
            .fold(0u32, |acc, &b| acc + b as u32)
            * 1000
            + "bob".as_bytes().iter().fold(0u32, |acc, &b| acc + b as u32))
            as i32;

        let id_bob = "0.0.9549757".to_string();
        let id_alice = "0.0.8007608".to_string();

        let sk_bob = PrivateKey::from_str_ed25519(PRIVATE_HEX_BOB).unwrap();
        let pk_bob = sk_bob.public_key().to_bytes();

        let params = HederaTransactionParameters {
            payer_account_id: id_bob.clone(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: time::OffsetDateTime::now_utc().unix_timestamp() - 10,
            valid_start_nanos: unique_nanos,
            max_transaction_fee: 2_000_000,
            memo: format!("onchain-{}-to-{}", id_bob, id_alice),
            public_key: pk_bob,
            data: HederaTransactionData::Transfer {
                receiver_account_id: id_alice,
                amount: 10_000_000,
            },
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let body_bytes = hedera_tx.to_bytes().unwrap();

        let private_arr: [u8; 32] = sk_bob.to_bytes().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();

        let tx = hedera_tx.sign(signature_bytes, 0).unwrap();

        fn generate_grpc_curl_cmd(payload: &[u8], url: &str) -> String {
            // 1. 获取 payload 长度并转换为 4 字节的大端序数组
            let len = payload.len() as u32;
            let len_bytes = len.to_be_bytes();

            // 2. 构造 5 字节的 gRPC 前缀：1 字节压缩标志(0) + 4 字节大端序长度
            let mut full_bytes = Vec::with_capacity(5 + payload.len());
            full_bytes.push(0u8);
            full_bytes.extend_from_slice(&len_bytes);

            // 3. 拼入原始数据
            full_bytes.extend_from_slice(payload);

            // 4. 将全套字节整体转换为 Hex 字符串
            let full_hex = hex::encode(full_bytes);

            // 5. 组装成最终可在终端运行的 curl 命令行字符串
            format!(
                "echo \"{}\" | xxd -r -p | curl --verbose --proxytunnel --http2-prior-knowledge -H \"Content-Type: application/grpc\" -H \"TE: trailers\" --data-binary @-  {}",
                full_hex, url
            )
        }

        let curl_command = generate_grpc_curl_cmd(&tx, END_POINT);

        println!("{}", curl_command);
    }
}
