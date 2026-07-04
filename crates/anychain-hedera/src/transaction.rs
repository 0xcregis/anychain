use {
    crate::{address::HederaAddress, format::HederaFormat, public_key::HederaPublicKey},
    anychain_core::{crypto::keccak256, Transaction, TransactionError, TransactionId},
    hiero_sdk::{AccountId, AnyTransaction, Hbar, TransactionId as HieroTxId, TransferTransaction},
    prost::Message,
    std::fmt::{self, Display, Formatter},
    std::str::FromStr,
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

#[derive(Clone, Debug, PartialEq)]
pub struct HederaTransactionParameters {
    pub payer_account_id: String,
    pub receiver_account_id: String,
    pub amount: i64, // amount in tinybars
    pub node_account_ids: Vec<String>,
    pub valid_start_seconds: i64,
    pub valid_start_nanos: i32,
    pub max_transaction_fee: u64, // in tinybars
    pub memo: String,
    pub public_key: Vec<u8>, // the public key of the signer
}

#[derive(Clone, Debug)]
pub struct HederaTransaction {
    pub params: HederaTransactionParameters,
    pub tx: AnyTransaction,
    pub signature: Option<Vec<u8>>,
}

impl HederaTransaction {
    /// Returns the raw transaction body bytes that need to be signed.
    pub fn body_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let tx_bytes = self.to_bytes()?;
        let tx_list = hiero_sdk_proto::sdk::TransactionList::decode(&*tx_bytes).map_err(|e| {
            TransactionError::Message(format!("decode TransactionList failed: {}", e))
        })?;
        let proto_tx = tx_list.transaction_list.first().ok_or_else(|| {
            TransactionError::Message("No transaction in transaction list".to_string())
        })?;
        let signed_tx = hiero_sdk_proto::services::SignedTransaction::decode(
            &*proto_tx.signed_transaction_bytes,
        )
        .map_err(|e| {
            TransactionError::Message(format!("decode SignedTransaction failed: {}", e))
        })?;
        Ok(signed_tx.body_bytes)
    }

    /// Returns the digest to be signed (Keccak256 hash of the transaction body bytes).
    pub fn digest(&self) -> Result<Vec<u8>, TransactionError> {
        let body = self.body_bytes()?;
        Ok(keccak256(&body).to_vec())
    }
}

impl Transaction for HederaTransaction {
    type Address = HederaAddress;
    type Format = HederaFormat;
    type PublicKey = HederaPublicKey;
    type TransactionId = HederaTransactionId;
    type TransactionParameters = HederaTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        let payer = AccountId::from_str(&parameters.payer_account_id)
            .map_err(|e| TransactionError::Message(format!("Invalid payer account ID: {}", e)))?;
        let receiver = AccountId::from_str(&parameters.receiver_account_id).map_err(|e| {
            TransactionError::Message(format!("Invalid receiver account ID: {}", e))
        })?;

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

        let mut tx = TransferTransaction::new();
        // Negative amount for debit from payer
        tx.hbar_transfer(payer, Hbar::from_tinybars(-parameters.amount));
        // Positive amount for credit to receiver
        tx.hbar_transfer(receiver, Hbar::from_tinybars(parameters.amount));

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

        // Freeze the transaction so it's ready to be signed or serialized
        tx.freeze()
            .map_err(|e| TransactionError::Message(format!("Freeze failed: {}", e)))?;

        let any_tx: AnyTransaction = tx.into();

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

        // Let's decode the transfer details from body_bytes if available
        let tx_bytes = any_tx.to_bytes().unwrap_or_default();
        let mut receiver_account_id = String::new();
        let mut amount = 0i64;

        if let Ok(tx_list) = hiero_sdk_proto::sdk::TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) = hiero_sdk_proto::services::SignedTransaction::decode(
                    &*proto_tx.signed_transaction_bytes,
                ) {
                    if let Ok(body) =
                        hiero_sdk_proto::services::TransactionBody::decode(&*signed_tx.body_bytes)
                    {
                        if let Some(
                            hiero_sdk_proto::services::transaction_body::Data::CryptoTransfer(
                                transfer_body,
                            ),
                        ) = body.data
                        {
                            if let Some(transfers) = transfer_body.transfers {
                                for aa in transfers.account_amounts {
                                    if let Some(acc) = aa.account_id {
                                        let acc_num = match acc.account {
                                            Some(hiero_sdk_proto::services::account_id::Account::AccountNum(num)) => num,
                                            _ => 0,
                                        };
                                        let acc_str = format!(
                                            "{}.{}.{}",
                                            acc.shard_num, acc.realm_num, acc_num
                                        );
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
                        }
                    }
                }
            }
        }

        let mut signature = None;
        if let Ok(tx_list) = hiero_sdk_proto::sdk::TransactionList::decode(&*tx_bytes) {
            if let Some(proto_tx) = tx_list.transaction_list.first() {
                if let Ok(signed_tx) = hiero_sdk_proto::services::SignedTransaction::decode(
                    &*proto_tx.signed_transaction_bytes,
                ) {
                    if let Some(sig_map) = signed_tx.sig_map {
                        if let Some(sig_pair) = sig_map.sig_pair.first() {
                            if let Some(
                                hiero_sdk_proto::services::signature_pair::Signature::EcdsaSecp256k1(
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

        let params = HederaTransactionParameters {
            payer_account_id,
            receiver_account_id,
            amount,
            node_account_ids,
            valid_start_seconds,
            valid_start_nanos,
            max_transaction_fee,
            memo,
            public_key: Vec::new(),
        };

        Ok(Self {
            params,
            tx: any_tx,
            signature,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        self.tx
            .to_bytes()
            .map_err(|e| TransactionError::Message(format!("to_bytes failed: {}", e)))
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
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    const RAW_HEX_ALICE: &str =
        "0242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768";
    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";

    #[test]
    fn test_hedera_transaction_signing_roundtrip() {
        let private_key_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
        let public_key_bytes = hex::decode(RAW_HEX_ALICE).unwrap();

        let params = HederaTransactionParameters {
            payer_account_id: "0.0.8007608".to_string(),
            receiver_account_id: "0.0.8007609".to_string(),
            amount: 100,
            node_account_ids: vec!["0.0.3".to_string()],
            valid_start_seconds: 1717171717,
            valid_start_nanos: 123456789,
            max_transaction_fee: 1000000,
            memo: "roundtrip test".to_string(),
            public_key: public_key_bytes.clone(),
        };

        // 1. Create transaction
        let mut tx = HederaTransaction::new(&params).unwrap();
        assert_eq!(tx.params.amount, 100);
        assert_eq!(tx.params.memo, "roundtrip test");
        assert_eq!(tx.params.payer_account_id, "0.0.8007608");

        // 2. Generate digest to sign
        let digest = tx.digest().unwrap();
        assert_eq!(digest.len(), 32);

        // Verify digest is indeed Keccak256 hash of body bytes
        let body_bytes = tx.body_bytes().unwrap();
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
        assert_eq!(parsed_tx.params.receiver_account_id, "0.0.8007609");
        assert_eq!(parsed_tx.params.amount, 100);
        assert_eq!(parsed_tx.params.memo, "roundtrip test");
        assert_eq!(parsed_tx.signature.unwrap(), signature_bytes);
    }

    #[tokio::test]
    async fn test_live_hedera_testnet_transfer() {
        use hiero_sdk::{AccountCreateTransaction, Client, Hbar, PrivateKey};
        use std::str::FromStr;

        // 1. Setup client and operator (as faucet/funding source)
        let client = Client::for_testnet();
        let operator_id = AccountId::from_str("0.0.8007608").unwrap();
        let operator_key = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        client.set_operator(operator_id, operator_key);

        // 2. Generate new key pair
        let new_key = PrivateKey::generate_ecdsa();
        let new_pk = new_key.public_key();

        // 3. Register address and fund it from faucet (operator initial balance)
        let mut create_tx = AccountCreateTransaction::new();
        create_tx
            .set_key_without_alias(new_pk)
            .initial_balance(Hbar::new(5)) // fund with 5 HBAR
            .freeze_with(Some(&client))
            .unwrap();

        let response = create_tx.execute(&client).await.unwrap();
        let receipt = response.get_receipt(&client).await.unwrap();
        let new_account_id = receipt.account_id.unwrap();
        println!("Registered new account: {}", new_account_id);

        // 4. Build transfer transaction from new account back to operator
        let params = HederaTransactionParameters {
            payer_account_id: new_account_id.to_string(),
            receiver_account_id: "0.0.8007608".to_string(),
            amount: 100_000_000, // 1 HBAR (in tinybars)
            node_account_ids: vec!["0.0.3".to_string()],
            valid_start_seconds: time::OffsetDateTime::now_utc().unix_timestamp() - 10, // slightly in past to avoid clock drift issues
            valid_start_nanos: 0,
            max_transaction_fee: 100_000_000, // 1 HBAR max fee
            memo: "anychain hedera live test".to_string(),
            public_key: new_pk.to_bytes_raw(),
        };

        let mut hedera_tx = HederaTransaction::new(&params).unwrap();

        // 5. Generate digest and sign it
        let digest = hedera_tx.digest().unwrap();
        let signing_key = SigningKey::from_slice(&new_key.to_bytes_raw()).unwrap();
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_vec();

        // 6. Sign and insert signature
        let signed_tx_bytes = hedera_tx.sign(signature_bytes, 0).unwrap();

        // 7. Execute the signed transaction on the network
        let mut exec_tx = AnyTransaction::from_bytes(&signed_tx_bytes).unwrap();
        let transfer_response = exec_tx.execute(&client).await.unwrap();
        let transfer_receipt = transfer_response.get_receipt(&client).await.unwrap();

        println!("Transfer receipt status: {:?}", transfer_receipt.status);
        assert_eq!(transfer_receipt.status, hiero_sdk::Status::Success);
    }
}
