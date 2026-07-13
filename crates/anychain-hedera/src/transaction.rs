use {
    crate::protobuf::sdk::TransactionList,
    crate::protobuf::services::{
        account_id::Account, key::Key, signature_pair::Signature, transaction_body::Data,
        SignedTransaction, TransactionBody,
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
        let proto_tx = tx_list.transaction_list.first_mut().ok_or_else(|| {
            TransactionError::Message("No transaction in transaction list".to_string())
        })?;

        let mut signed_tx = SignedTransaction::decode(&*proto_tx.signed_transaction_bytes)
            .map_err(|e| {
                TransactionError::Message(format!("decode SignedTransaction failed: {}", e))
            })?;

        let body = TransactionBody::decode(&*signed_tx.body_bytes).map_err(|e| {
            TransactionError::Message(format!("decode TransactionBody failed: {}", e))
        })?;

        signed_tx.body_bytes = prost::Message::encode_to_vec(&body);
        proto_tx.signed_transaction_bytes = prost::Message::encode_to_vec(&signed_tx);

        if self.signature.is_none() {
            Ok(signed_tx.body_bytes)
        } else {
            Ok(proto_tx.encode_to_vec())
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        if self.signature.is_none() {
            let bytes = self.to_bytes()?;
            Ok(HederaTransactionId {
                txid: hex::encode(bytes),
            })
        } else {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    #[test]
    fn test_hedera_public_key_alias_parsing() {
        let private_alice = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let private_alice_arr: [u8; 32] = private_alice.try_into().unwrap();
        let sk_alice = SigningKey::from_bytes(&private_alice_arr);
        let pk_alice_hex = hex::encode(sk_alice.verifying_key().to_bytes());

        let private_bob = hex::decode(PRIVATE_HEX_BOB).unwrap();
        let private_bob_arr: [u8; 32] = private_bob.try_into().unwrap();
        let sk_bob = SigningKey::from_bytes(&private_bob_arr);
        let pk_bob_hex = hex::encode(sk_bob.verifying_key().to_bytes());

        let alias_payer = format!("0.0.{}", pk_alice_hex);
        let alias_receiver = format!("0.0.{}", pk_bob_hex);

        let params = HederaTransactionParameters {
            payer_account_id: alias_payer.to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "alias parsing test".to_string(),
            public_key: sk_alice.verifying_key().to_bytes().to_vec(),
            data: HederaTransactionData::Transfer {
                receiver_account_id: alias_receiver.to_string(),
                amount: 250,
            },
        };

        let tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.payer_account_id, alias_payer);
    }

    #[test]
    fn test_print_b_pubkey() {
        let pk = hiero_sdk::PrivateKey::from_str_ed25519(
            "10676410088a00b2debc0e00d7e686789d514d369d0d864f3bd943f954b0dd65",
        )
        .unwrap();
        println!(
            "DERIVED B PUBLIC KEY: {}",
            hex::encode(pk.public_key().to_bytes_raw())
        );
    }

    #[test]
    fn test_hedera_transaction_signing_roundtrip() {
        use ed25519_dalek::Signer;

        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();

        let params = HederaTransactionParameters {
            payer_account_id: "0.0.8007608".to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "roundtrip test".to_string(),
            public_key: public_key_bytes.clone(),
            data: HederaTransactionData::Transfer {
                receiver_account_id: "0.0.8007609".to_string(),
                amount: 100,
            },
        };

        // 1. Create transaction
        let mut tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.memo, "roundtrip test");
        assert_eq!(tx.params.payer_account_id, "0.0.8007608");
        match &tx.params.data {
            HederaTransactionData::Transfer {
                receiver_account_id,
                amount,
            } => {
                assert_eq!(receiver_account_id, "0.0.8007609");
                assert_eq!(*amount, 100);
            }
            _ => panic!("expected Transfer transaction data"),
        }

        // 2. Generate body bytes to sign
        let tx_id = tx.to_transaction_id().unwrap();
        let body_bytes = hex::decode(tx_id.txid).unwrap();

        let expected_body = tx.to_bytes().unwrap();
        assert_eq!(body_bytes, expected_body);

        // 3. Sign the body_bytes
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();
        assert_eq!(signature_bytes.len(), 64);

        // 4. Insert signature
        let signed_tx_bytes = tx.sign(signature_bytes.clone(), 0).unwrap();

        // 5. Parse back from bytes
        let parsed_tx = HederaTransaction::from_bytes(&signed_tx_bytes).unwrap();
        assert_eq!(parsed_tx.params.payer_account_id, "0.0.8007608");
        assert_eq!(parsed_tx.params.memo, "roundtrip test");
        match &parsed_tx.params.data {
            HederaTransactionData::Transfer {
                receiver_account_id,
                amount,
            } => {
                assert_eq!(receiver_account_id, "0.0.8007609");
                assert_eq!(*amount, 100);
            }
            _ => panic!("expected Transfer transaction data"),
        }
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    #[test]
    fn test_hedera_account_create_signing_roundtrip() {
        use ed25519_dalek::Signer;

        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();

        let mut new_key_bytes = [0u8; 32];
        new_key_bytes[..4].copy_from_slice(b"test");
        let new_account_signing_key = SigningKey::from_bytes(&new_key_bytes);
        let new_account_pk_bytes = new_account_signing_key.verifying_key().to_bytes().to_vec();

        let params = HederaTransactionParameters {
            payer_account_id: "0.0.8007608".to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "account create test".to_string(),
            public_key: public_key_bytes.clone(),
            data: HederaTransactionData::CreateAccount {
                new_account_public_key: new_account_pk_bytes.clone(),
                initial_balance: 500_000_000, // 5 HBAR
            },
        };

        // 1. Create transaction
        let mut tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.memo, "account create test");
        assert_eq!(tx.params.payer_account_id, "0.0.8007608");
        match &tx.params.data {
            HederaTransactionData::CreateAccount {
                new_account_public_key,
                initial_balance,
            } => {
                assert_eq!(new_account_public_key, &new_account_pk_bytes);
                assert_eq!(*initial_balance, 500_000_000);
            }
            _ => panic!("expected CreateAccount transaction data"),
        }

        // 2. Generate bytes to sign
        let tx_id = tx.to_transaction_id().unwrap();
        let body_bytes = hex::decode(tx_id.txid).unwrap();

        // 3. Sign the body_bytes
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();
        assert_eq!(signature_bytes.len(), 64);

        // 4. Insert signature
        let signed_tx_bytes = tx.sign(signature_bytes.clone(), 0).unwrap();

        // 5. Parse back from bytes
        let parsed_tx = HederaTransaction::from_bytes(&signed_tx_bytes).unwrap();
        assert_eq!(parsed_tx.params.payer_account_id, "0.0.8007608");
        assert_eq!(parsed_tx.params.memo, "account create test");
        match &parsed_tx.params.data {
            HederaTransactionData::CreateAccount {
                new_account_public_key,
                initial_balance,
            } => {
                assert_eq!(new_account_public_key, &new_account_pk_bytes);
                assert_eq!(*initial_balance, 500_000_000);
            }
            _ => panic!("expected CreateAccount transaction data"),
        }
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    async fn run_onchain_transfer_test(payer_type: &str, receiver_type: &str) {
        use ed25519_dalek::Signer;
        use hiero_sdk::{Client, PrivateKey, TransactionReceiptQuery};
        use std::collections::HashMap;
        use std::str::FromStr;

        // 1. Setup client with ECDSA operator (Alice's funded account 0.0.8007608) to pay for the initial account creation
        let mut custom_nodes = HashMap::new();
        custom_nodes.insert(
            "35.237.119.55:50211".to_string(),
            AccountId::from_str("0.0.4").unwrap(),
        );
        let client = Client::for_network(custom_nodes).unwrap();
        let initial_operator_id = AccountId::from_str("0.0.8007608").unwrap();
        let initial_operator_key = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        client.set_operator(initial_operator_id, initial_operator_key);
        client.set_default_max_transaction_fee(hiero_sdk::Hbar::from_tinybars(1_000_000)); // Limit default max fee to 0.01 HBAR!

        let channel = tonic::transport::Channel::from_static("http://35.237.119.55:50211")
            .timeout(std::time::Duration::from_secs(10)) // Set a 10-second network-level timeout to prevent hangs
            .connect()
            .await;

        let channel = match channel {
            Ok(c) => c,
            Err(e) => {
                println!("Skipping live test because consensus node is unreachable (DNS/Network error): {:?}", e);
                return;
            }
        };
        let mut grpc_client = tonic::client::Grpc::new(channel.clone());

        // 2. Dynamically create a funded Ed25519 operator to act as the payer for our test via Transfer (Auto-Creation)
        let ed_operator_key = hiero_sdk::PrivateKey::generate_ed25519();
        let mut ed_operator_pk_bytes = ed_operator_key.public_key().to_bytes_raw();

        // Strip 12-byte DER prefix from Bob's public key if present to get the raw 32-byte Ed25519 key
        if ed_operator_pk_bytes.starts_with(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]) {
            ed_operator_pk_bytes = ed_operator_pk_bytes[12..].to_vec();
        }
        let ed_operator_sk_bytes = ed_operator_key.to_bytes_raw();

        let ed_operator_alias_str = format!("0.0.{}", hex::encode(&ed_operator_pk_bytes));
        let ed_operator_alias = AccountId::from_str(&ed_operator_alias_str).unwrap();

        println!("Dynamically auto-creating a funded Ed25519 operator on testnet...");
        let create_response = hiero_sdk::TransferTransaction::new()
            .hbar_transfer(
                initial_operator_id,
                hiero_sdk::Hbar::from_tinybars(-5_000_000),
            ) // Fund Bob with 0.05 HBAR
            .hbar_transfer(ed_operator_alias, hiero_sdk::Hbar::from_tinybars(5_000_000))
            .max_transaction_fee(hiero_sdk::Hbar::from_tinybars(78_000_000)) // 0.78 HBAR maximum fee to exactly cover actual creation fees within Alice's 84M balance limit
            .execute(&client)
            .await
            .unwrap();

        let _create_receipt = create_response.get_receipt(&client).await.unwrap();
        let ed_operator_id = ed_operator_alias.clone();
        println!(
            "Successfully auto-created Ed25519 operator alias: {}",
            ed_operator_id
        );

        // 3. Generate Ed25519 keypair for Alice (Receiver)
        let alice_key = PrivateKey::generate_ed25519();
        let alice_pk_bytes = alice_key.public_key().to_bytes_raw();
        let _alice_sk_bytes = alice_key.to_bytes_raw();

        // Reuse the funded Alice account 0.0.8007608 as the recipient to prevent new account creation fees
        let alice_seq = if receiver_type == "sequential" {
            "0.0.8007608".to_string()
        } else {
            "".to_string()
        };

        // Update the client operator to our new Ed25519 account
        client.set_operator(ed_operator_id, ed_operator_key.clone());

        let bob_seq = ed_operator_id.to_string();
        let bob_pk = ed_operator_pk_bytes;
        let bob_sk = ed_operator_sk_bytes;

        // Strip 12-byte DER prefix from Alice's public key if present
        let mut alice_pk = alice_pk_bytes;
        if alice_pk.starts_with(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]) {
            alice_pk = alice_pk[12..].to_vec();
        }

        // Format the aliases with the correct DER-prefixed public key format required by Hedera nodes
        let alice_alias = format!("0.0.302a300506032b6570032100{}", hex::encode(&alice_pk));
        let _bob_alias = format!("0.0.302a300506032b6570032100{}", hex::encode(&bob_pk));

        let (payer_id, receiver_id, payer_pk, payer_sk) = match receiver_type {
            "alias" => (
                bob_seq.clone(),
                alice_alias.clone(),
                bob_pk.clone(),
                bob_sk.clone(),
            ),
            "sequential" => (
                bob_seq.clone(),
                alice_seq.clone(),
                bob_pk.clone(),
                bob_sk.clone(),
            ),
            _ => panic!("invalid receiver type"),
        };

        println!(
            "Running onchain transfer from Payer ({}) to Receiver ({})",
            payer_id, receiver_id
        );

        let unique_nanos = (payer_type
            .as_bytes()
            .iter()
            .fold(0u32, |acc, &b| acc + b as u32)
            * 1000
            + receiver_type
                .as_bytes()
                .iter()
                .fold(0u32, |acc, &b| acc + b as u32)) as i32;

        let params = HederaTransactionParameters {
            payer_account_id: payer_id,
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: time::OffsetDateTime::now_utc().unix_timestamp() - 10,
            valid_start_nanos: unique_nanos,
            max_transaction_fee: 2_000_000,
            memo: format!("onchain-{}-to-{}", payer_type, receiver_type),
            public_key: payer_pk,
            data: HederaTransactionData::Transfer {
                receiver_account_id: receiver_id,
                amount: 500_000,
            },
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let tx_id = hedera_tx.to_transaction_id().unwrap();
        let body_bytes = hex::decode(tx_id.txid).unwrap();
        let private_arr: [u8; 32] = payer_sk.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let signature = signing_key.sign(&body_bytes);
        let signature_bytes = signature.to_bytes().to_vec();

        let signed_tx_bytes = hedera_tx.sign(signature_bytes, 0).unwrap();

        let path = http::uri::PathAndQuery::from_static("/proto.CryptoService/cryptoTransfer");
        let req = tonic::Request::new(signed_tx_bytes.clone());

        grpc_client.ready().await.unwrap();

        let grpc_response = grpc_client
            .unary(req, path, RawCodec)
            .await
            .unwrap()
            .into_inner();

        assert_eq!(grpc_response.node_transaction_precheck_code, 0);

        let sdk_tx = AnyTransaction::from_bytes(&signed_tx_bytes).unwrap();
        let sdk_tx_id = sdk_tx.get_transaction_id().unwrap();

        let transfer_receipt = TransactionReceiptQuery::new()
            .transaction_id(sdk_tx_id)
            .execute(&client)
            .await
            .unwrap();

        println!(
            "Transfer consensus receipt status: {:?}",
            transfer_receipt.status
        );
        assert_eq!(transfer_receipt.status, hiero_sdk::Status::Success);
    }

    #[tokio::test]
    #[ignore]
    async fn test_onchain_transfer_sequential_to_alias() {
        run_onchain_transfer_test("sequential", "alias").await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_onchain_transfer_sequential_to_sequential() {
        run_onchain_transfer_test("sequential", "sequential").await;
    }

    struct RawCodec;

    impl tonic::codec::Codec for RawCodec {
        type Encode = Vec<u8>;
        type Decode = crate::protobuf::services::TransactionResponse;
        type Encoder = RawEncoder;
        type Decoder = RawDecoder;

        fn encoder(&mut self) -> Self::Encoder {
            RawEncoder
        }

        fn decoder(&mut self) -> Self::Decoder {
            RawDecoder
        }
    }

    struct RawEncoder;

    impl tonic::codec::Encoder for RawEncoder {
        type Item = Vec<u8>;
        type Error = tonic::Status;

        fn encode(
            &mut self,
            item: Self::Item,
            dst: &mut tonic::codec::EncodeBuf<'_>,
        ) -> Result<(), Self::Error> {
            use prost::bytes::BufMut;
            dst.put_slice(&item);
            Ok(())
        }
    }

    struct RawDecoder;

    impl tonic::codec::Decoder for RawDecoder {
        type Item = crate::protobuf::services::TransactionResponse;
        type Error = tonic::Status;

        fn decode(
            &mut self,
            src: &mut tonic::codec::DecodeBuf<'_>,
        ) -> Result<Option<Self::Item>, Self::Error> {
            use prost::Message;
            let res = crate::protobuf::services::TransactionResponse::decode(src)
                .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?;
            Ok(Some(res))
        }
    }
}
