use {
    crate::{address::HederaAddress, format::HederaFormat, public_key::HederaPublicKey},
    anychain_core::{crypto::keccak256, Transaction, TransactionError, TransactionId},
    hiero_sdk::{AccountId, AnyTransaction, Hbar, TransactionId as HieroTxId, TransferTransaction, EvmAddress},
    prost::Message,
    std::fmt::{self, Display, Formatter},
    std::str::FromStr,
    time::OffsetDateTime,
};

fn parse_account_id(s: &str) -> Result<AccountId, TransactionError> {
    if s.starts_with("0x") {
        let clean_hex = s.strip_prefix("0x").unwrap();
        if clean_hex.len() == 40 {
            let is_long_zero = clean_hex.chars().take(24).all(|c| c == '0' || c == '0');
            if is_long_zero {
                AccountId::from_solidity_address(clean_hex)
                    .map_err(|e| TransactionError::Message(format!("Invalid solidity address: {}", e)))
            } else {
                let evm_addr = EvmAddress::from_str(s)
                    .map_err(|e| TransactionError::Message(format!("Invalid EVM address: {}", e)))?;
                Ok(AccountId::from_evm_address(&evm_addr, 0, 0))
            }
        } else if clean_hex.len() == 64 || clean_hex.len() == 66 {
            let alias_str = format!("0.0.{}", clean_hex);
            AccountId::from_str(&alias_str)
                .map_err(|e| TransactionError::Message(format!("Invalid public key alias: {}", e)))
        } else {
            AccountId::from_str(s)
                .map_err(|e| TransactionError::Message(format!("Invalid account ID: {}", e)))
        }
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
            HederaTransactionData::Transfer { receiver_account_id, amount } => {
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
                    tx.max_transaction_fee(Hbar::from_tinybars(parameters.max_transaction_fee as i64));
                }
                if !parameters.memo.is_empty() {
                    tx.transaction_memo(&parameters.memo);
                }
                tx.freeze()
                    .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;
                tx.into()
            }
            HederaTransactionData::CreateAccount { new_account_public_key, initial_balance } => {
                use hiero_sdk::AccountCreateTransaction;
                let mut tx = AccountCreateTransaction::new();
                let pk = hiero_sdk::PublicKey::from_bytes_ecdsa(new_account_public_key)
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
                    tx.max_transaction_fee(Hbar::from_tinybars(parameters.max_transaction_fee as i64));
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
        let hiero_pk = hiero_sdk::PublicKey::from_bytes_ecdsa(&self.params.public_key)
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

        // Let's decode the transfer/creation details from body_bytes if available
        let tx_bytes = any_tx.to_bytes().unwrap_or_default();
        let mut tx_data = None;

        if let Ok(tx_list) = crate::protobuf::sdk::TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) = crate::protobuf::services::SignedTransaction::decode(
                    &*proto_tx.signed_transaction_bytes,
                ) {
                    if let Ok(body) =
                        crate::protobuf::services::TransactionBody::decode(&*signed_tx.body_bytes)
                    {
                        if let Some(data) = body.data {
                            match data {
                                crate::protobuf::services::transaction_body::Data::CryptoTransfer(
                                    transfer_body,
                                ) => {
                                    let mut receiver_account_id = String::new();
                                    let mut amount = 0i64;
                                    if let Some(transfers) = transfer_body.transfers {
                                        for aa in transfers.account_amounts {
                                            if let Some(acc) = aa.account_id {
                                                let acc_str = match &acc.account {
                                                    Some(crate::protobuf::services::account_id::Account::AccountNum(num)) => {
                                                        format!("{}.{}.{}", acc.shard_num, acc.realm_num, num)
                                                    }
                                                    Some(crate::protobuf::services::account_id::Account::Alias(alias)) => {
                                                        if alias.len() == 20 {
                                                            format!("0x{}", hex::encode(alias))
                                                        } else {
                                                            format!("{}.{}.{}", acc.shard_num, acc.realm_num, hex::encode(alias))
                                                        }
                                                    }
                                                    None => format!("{}.{}.0", acc.shard_num, acc.realm_num),
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
                                crate::protobuf::services::transaction_body::Data::CryptoCreateAccount(
                                    create_body,
                                ) => {
                                    let mut new_account_public_key = Vec::new();
                                    if let Some(key) = create_body.key {
                                        if let Some(crate::protobuf::services::key::Key::EcdsaSecp256k1(pk_bytes)) = key.key {
                                            new_account_public_key = pk_bytes;
                                        }
                                    }
                                    tx_data = Some(HederaTransactionData::CreateAccount {
                                        new_account_public_key,
                                        initial_balance: create_body.initial_balance,
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        let mut signature = None;
        if let Ok(tx_list) = crate::protobuf::sdk::TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) = crate::protobuf::services::SignedTransaction::decode(
                    &*proto_tx.signed_transaction_bytes,
                ) {
                    if let Some(sig_map) = signed_tx.sig_map {
                        if let Some(sig_pair) = sig_map.sig_pair.first() {
                            if let Some(
                                crate::protobuf::services::signature_pair::Signature::EcdsaSecp256k1(
                                    sig,
                                ),
                            ) = &sig_pair.signature
                            {
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
        let tx_bytes = self.tx
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("to_bytes failed: {}", e)))?;
        let mut tx_list = crate::protobuf::sdk::TransactionList::decode(&*tx_bytes).map_err(|e| {
            TransactionError::Message(format!("decode TransactionList failed: {}", e))
        })?;
        let proto_tx = tx_list.transaction_list.first_mut().ok_or_else(|| {
            TransactionError::Message("No transaction in transaction list".to_string())
        })?;

        let mut signed_tx = crate::protobuf::services::SignedTransaction::decode(
            &*proto_tx.signed_transaction_bytes,
        )
        .map_err(|e| {
            TransactionError::Message(format!("decode SignedTransaction failed: {}", e))
        })?;

        let mut body = crate::protobuf::services::TransactionBody::decode(&*signed_tx.body_bytes)
            .map_err(|e| {
                TransactionError::Message(format!("decode TransactionBody failed: {}", e))
            })?;

        // Manually patch any EVM Address aliases that were serialized as 0.0.0 by the SDK
        if let Some(crate::protobuf::services::transaction_body::Data::CryptoTransfer(
            ref mut transfer_body,
        )) = body.data {
            if let Some(ref mut transfers) = transfer_body.transfers {
                for aa in &mut transfers.account_amounts {
                    if let Some(ref mut acc) = aa.account_id {
                        let is_zero = match &acc.account {
                            Some(crate::protobuf::services::account_id::Account::AccountNum(num)) => *num == 0,
                            _ => false,
                        };
                        if is_zero {
                            if aa.amount < 0 {
                                // Payer
                                if self.params.payer_account_id.starts_with("0x") {
                                    let clean_hex = self.params.payer_account_id.strip_prefix("0x").unwrap();
                                    if clean_hex.len() == 40 {
                                        let is_long_zero = clean_hex.chars().take(24).all(|c| c == '0');
                                        if !is_long_zero {
                                            let evm_bytes = hex::decode(clean_hex).unwrap();
                                            acc.account = Some(crate::protobuf::services::account_id::Account::Alias(evm_bytes));
                                        }
                                    }
                                }
                            } else if aa.amount > 0 {
                                // Recipient
                                if let HederaTransactionData::Transfer { receiver_account_id, .. } = &self.params.data {
                                    if receiver_account_id.starts_with("0x") {
                                        let clean_hex = receiver_account_id.strip_prefix("0x").unwrap();
                                        if clean_hex.len() == 40 {
                                            let is_long_zero = clean_hex.chars().take(24).all(|c| c == '0');
                                            if !is_long_zero {
                                                let evm_bytes = hex::decode(clean_hex).unwrap();
                                                acc.account = Some(crate::protobuf::services::account_id::Account::Alias(evm_bytes));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

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
            let digest_bytes = keccak256(&bytes);
            Ok(HederaTransactionId {
                txid: hex::encode(digest_bytes),
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
    use hiero_sdk::PrivateKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_hedera_public_key_alias_parsing() {
        let public_key_bytes = hex::decode(RAW_HEX_ALICE).unwrap();

        // Build parameters with public key alias
        let alias_payer = "0.0.0242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768";
        let alias_receiver = "0.0.03de71d0528d931b6622f08d30bbb6ebed68ad867348c7ea31fe9e1857fcc5fad6";

        let params = HederaTransactionParameters {
            payer_account_id: alias_payer.to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "alias parsing test".to_string(),
            public_key: public_key_bytes.clone(),
            data: HederaTransactionData::Transfer {
                receiver_account_id: alias_receiver.to_string(),
                amount: 250,
            },
        };

        // Create transaction
        let tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.payer_account_id, alias_payer);
    }

    #[test]
    fn test_print_b_pubkey() {
        let pk = hiero_sdk::PrivateKey::from_str_ecdsa("10676410088a00b2debc0e00d7e686789d514d369d0d864f3bd943f954b0dd65").unwrap();
        println!("DERIVED B PUBLIC KEY: {}", hex::encode(pk.public_key().to_bytes_raw()));
    }

    const RAW_HEX_ALICE: &str =
        "0242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768";
    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const RAW_HEX_BOB: &str =
        "03d638f8acfffc03fb05c1958afaf5431bd79bb2fe569121217478cfdc850ad089";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    #[test]
    fn test_hedera_transaction_signing_roundtrip() {
        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
        let public_key_bytes = hex::decode(RAW_HEX_ALICE).unwrap();

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
            HederaTransactionData::Transfer { receiver_account_id, amount } => {
                assert_eq!(receiver_account_id, "0.0.8007609");
                assert_eq!(*amount, 100);
            }
            _ => panic!("expected Transfer transaction data"),
        }

        // 2. Generate digest to sign
        let tx_id = tx.to_transaction_id().unwrap();
        let digest = hex::decode(tx_id.txid).unwrap();
        assert_eq!(digest.len(), 32);

        // Verify digest is indeed Keccak256 hash of body bytes
        let body_bytes = tx.to_bytes().unwrap();
        let expected_digest = anychain_core::crypto::keccak256(&body_bytes).to_vec();
        assert_eq!(digest, expected_digest);

        // 3. Sign the digest
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_vec();
        assert_eq!(signature_bytes.len(), 64);

        // 4. Insert signature
        let signed_tx_bytes = tx.sign(signature_bytes.clone(), 0).unwrap();

        // 5. Parse back from bytes
        let parsed_tx = HederaTransaction::from_bytes(&signed_tx_bytes).unwrap();
        assert_eq!(parsed_tx.params.payer_account_id, "0.0.8007608");
        assert_eq!(parsed_tx.params.memo, "roundtrip test");
        match &parsed_tx.params.data {
            HederaTransactionData::Transfer { receiver_account_id, amount } => {
                assert_eq!(receiver_account_id, "0.0.8007609");
                assert_eq!(*amount, 100);
            }
            _ => panic!("expected Transfer transaction data"),
        }
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    #[test]
    fn test_hedera_account_create_signing_roundtrip() {
        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
        let public_key_bytes = hex::decode(RAW_HEX_ALICE).unwrap();

        let new_account_key = PrivateKey::generate_ecdsa();
        let new_account_pk = new_account_key.public_key();

        let params = HederaTransactionParameters {
            payer_account_id: "0.0.8007608".to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "account create test".to_string(),
            public_key: public_key_bytes.clone(),
            data: HederaTransactionData::CreateAccount {
                new_account_public_key: new_account_pk.to_bytes_raw(),
                initial_balance: 500_000_000, // 5 HBAR
            },
        };

        // 1. Create transaction
        let mut tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.memo, "account create test");
        assert_eq!(tx.params.payer_account_id, "0.0.8007608");
        match &tx.params.data {
            HederaTransactionData::CreateAccount { new_account_public_key, initial_balance } => {
                assert_eq!(new_account_public_key, &new_account_pk.to_bytes_raw());
                assert_eq!(*initial_balance, 500_000_000);
            }
            _ => panic!("expected CreateAccount transaction data"),
        }

        // 2. Generate digest to sign
        let tx_id = tx.to_transaction_id().unwrap();
        let digest = hex::decode(tx_id.txid).unwrap();
        assert_eq!(digest.len(), 32);

        // Verify digest is indeed Keccak256 hash of body bytes
        let body_bytes = tx.to_bytes().unwrap();
        let expected_digest = anychain_core::crypto::keccak256(&body_bytes).to_vec();
        assert_eq!(digest, expected_digest);

        // 3. Sign the digest
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_vec();
        assert_eq!(signature_bytes.len(), 64);

        // 4. Insert signature
        let signed_tx_bytes = tx.sign(signature_bytes.clone(), 0).unwrap();

        // 5. Parse back from bytes
        let parsed_tx = HederaTransaction::from_bytes(&signed_tx_bytes).unwrap();
        assert_eq!(parsed_tx.params.payer_account_id, "0.0.8007608");
        assert_eq!(parsed_tx.params.memo, "account create test");
        match &parsed_tx.params.data {
            HederaTransactionData::CreateAccount { new_account_public_key, initial_balance } => {
                assert_eq!(new_account_public_key, &new_account_pk.to_bytes_raw());
                assert_eq!(*initial_balance, 500_000_000);
            }
            _ => panic!("expected CreateAccount transaction data"),
        }
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    #[test]
    fn test_hedera_evm_address_signing_roundtrip() {
        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
        let public_key_bytes = hex::decode(RAW_HEX_ALICE).unwrap();

        // 1. Build parameters with real public-key-hash EVM address
        let evm_payer = "0xa41e9278435263c4b6d7e9d30521ea3c24b09a5a";
        let evm_receiver = "0x1234567890123456789012345678901234567890";

        let params = HederaTransactionParameters {
            payer_account_id: evm_payer.to_string(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "evm roundtrip test".to_string(),
            public_key: public_key_bytes.clone(),
            data: HederaTransactionData::Transfer {
                receiver_account_id: evm_receiver.to_string(),
                amount: 250,
            },
        };

        // 2. Create transaction
        let mut tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.memo, "evm roundtrip test");

        // 3. Generate digest
        let tx_id = tx.to_transaction_id().unwrap();
        let digest = hex::decode(tx_id.txid).unwrap();
        assert_eq!(digest.len(), 32);

        // 4. Sign and finalize bytes
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_vec();
        let signed_tx_bytes = tx.sign(signature_bytes.clone(), 0).unwrap();

        // 5. Parse back from bytes and verify EVM address mapping is perfectly preserved!
        let parsed_tx = HederaTransaction::from_bytes(&signed_tx_bytes).unwrap();
        assert_eq!(parsed_tx.params.memo, "evm roundtrip test");
        match &parsed_tx.params.data {
            HederaTransactionData::Transfer { receiver_account_id, amount } => {
                assert_eq!(receiver_account_id, evm_receiver);
                assert_eq!(*amount, 250);
            }
            _ => panic!("expected Transfer transaction data"),
        }
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    async fn run_onchain_transfer_test(payer_type: &str, receiver_type: &str) {
        use hiero_sdk::{Client, PrivateKey, TransactionReceiptQuery};
        use std::str::FromStr;
        use std::collections::HashMap;

        // 1. Setup client and operator (as faucet/funding source)
        let mut custom_nodes = HashMap::new();
        custom_nodes.insert("35.237.119.55:50211".to_string(), AccountId::from_str("0.0.4").unwrap());
        let client = Client::for_network(custom_nodes).unwrap();
        let operator_id = AccountId::from_str("0.0.8007619").unwrap();
        let operator_key = PrivateKey::from_str_ecdsa(PRIVATE_HEX_BOB).unwrap();
        client.set_operator(operator_id, operator_key.clone());

        // Connect to consensus node 0.0.4 using Tonic (via static IP)
        let channel = tonic::transport::Channel::from_static("http://35.237.119.55:50211")
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

        // Bob's key, ID and address representations (Payer)
        let bob_seq = "0.0.8007619".to_string();
        let _bob_pkh = "0.0.03d638f8acfffc03fb05c1958afaf5431bd79bb2fe569121217478cfdc850ad089".to_string();
        let bob_lz = format!("0x00000000000000000000000000000000{:08x}", 8007619);
        let bob_pk = operator_key.public_key().to_bytes_raw();
        let bob_sk = operator_key.to_bytes_raw();

        // Alice's key, ID and address representations (Receiver)
        let alice_key = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        let alice_seq = "0.0.8007608".to_string();
        let alice_pkh = format!("0x{}", hex::encode(alice_key.public_key().to_bytes_raw()));
        let alice_lz = format!("0x00000000000000000000000000000000{:08x}", 8007608);

        // Map payer and receiver addresses based on test types.
        // For the fee payer ID, we use bob_seq or bob_lz (both are fully supported as payers on-chain).
        // For the recipient ID, we use alice_pkh, alice_lz, or alice_seq.
        let (payer_id, receiver_id, payer_pk, payer_sk) = match (payer_type, receiver_type) {
            ("pkh", "pkh") => (bob_seq.clone(), alice_pkh.clone(), bob_pk.clone(), bob_sk.clone()),
            ("pkh", "long-zero") => (bob_seq.clone(), alice_lz.clone(), bob_pk.clone(), bob_sk.clone()),
            ("long-zero", "pkh") => (bob_lz.clone(), alice_pkh.clone(), bob_pk.clone(), bob_sk.clone()),
            ("long-zero", "long-zero") => (bob_lz.clone(), alice_lz.clone(), bob_pk.clone(), bob_sk.clone()),
            ("pkh", "sequential") => (bob_seq.clone(), alice_seq.clone(), bob_pk.clone(), bob_sk.clone()),
            ("sequential", "pkh") => (bob_seq.clone(), alice_pkh.clone(), bob_pk.clone(), bob_sk.clone()),
            ("long-zero", "sequential") => (bob_lz.clone(), alice_seq.clone(), bob_pk.clone(), bob_sk.clone()),
            ("sequential", "long-zero") => (bob_seq.clone(), alice_lz.clone(), bob_pk.clone(), bob_sk.clone()),
            ("sequential", "sequential") => (bob_seq.clone(), alice_seq.clone(), bob_pk.clone(), bob_sk.clone()),
            _ => panic!("invalid payer or receiver type"),
        };

        println!("Running onchain transfer from Payer ({}) to Receiver ({})", payer_id, receiver_id);

        let unique_nanos = (payer_type.as_bytes().iter().fold(0u32, |acc, &b| acc + b as u32) * 1000 
            + receiver_type.as_bytes().iter().fold(0u32, |acc, &b| acc + b as u32)) as i32;

        let params = HederaTransactionParameters {
            payer_account_id: payer_id,
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: time::OffsetDateTime::now_utc().unix_timestamp() - 10,
            valid_start_nanos: unique_nanos,
            max_transaction_fee: 5_000_000, // 0.05 HBAR max fee
            memo: format!("onchain-{}-to-{}", payer_type, receiver_type),
            public_key: payer_pk,
            data: HederaTransactionData::Transfer {
                receiver_account_id: receiver_id,
                amount: 1_000_000, // 0.01 HBAR (in tinybars)
            },
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();
        let tx_id = hedera_tx.to_transaction_id().unwrap();
        let digest = hex::decode(tx_id.txid).unwrap();
        let signing_key = SigningKey::from_slice(&payer_sk).unwrap();
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_vec();

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

        println!("Transfer consensus receipt status: {:?}", transfer_receipt.status);
        assert_eq!(transfer_receipt.status, hiero_sdk::Status::Success);
    }

    #[tokio::test]
    async fn test_onchain_transfer_pkh_to_pkh() {
        run_onchain_transfer_test("pkh", "pkh").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_pkh_to_long_zero() {
        run_onchain_transfer_test("pkh", "long-zero").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_long_zero_to_pkh() {
        run_onchain_transfer_test("long-zero", "pkh").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_long_zero_to_long_zero() {
        run_onchain_transfer_test("long-zero", "long-zero").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_pkh_to_sequential() {
        run_onchain_transfer_test("pkh", "sequential").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_sequential_to_pkh() {
        run_onchain_transfer_test("sequential", "pkh").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_long_zero_to_sequential() {
        run_onchain_transfer_test("long-zero", "sequential").await;
    }

    #[tokio::test]
    async fn test_onchain_transfer_sequential_to_long_zero() {
        run_onchain_transfer_test("sequential", "long-zero").await;
    }

    #[tokio::test]
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

        fn encode(&mut self, item: Self::Item, dst: &mut tonic::codec::EncodeBuf<'_>) -> Result<(), Self::Error> {
            use prost::bytes::BufMut;
            dst.put_slice(&item);
            Ok(())
        }
    }

    struct RawDecoder;

    impl tonic::codec::Decoder for RawDecoder {
        type Item = crate::protobuf::services::TransactionResponse;
        type Error = tonic::Status;

        fn decode(&mut self, src: &mut tonic::codec::DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
            use prost::Message;
            let res = crate::protobuf::services::TransactionResponse::decode(src)
                .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?;
            Ok(Some(res))
        }
    }
}
