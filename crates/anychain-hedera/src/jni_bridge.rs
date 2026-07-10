use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jlong, jint, jstring, jbyteArray};
use std::str::FromStr;
use crate::transaction::{HederaTransaction, HederaTransactionParameters, HederaTransactionData};
use hiero_sdk::{AccountId, Client, PrivateKey, AnyTransaction, TransactionReceiptQuery};
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use anychain_core::Transaction;

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_createAndFundAccount(
    mut env: JNIEnv,
    _class: JClass,
    operator_id_str: JString,
    operator_priv_hex_str: JString,
) -> jstring {
    let operator_id_str: String = env.get_string(&operator_id_str).unwrap().into();
    let operator_priv_hex_str: String = env.get_string(&operator_priv_hex_str).unwrap().into();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let res = runtime.block_on(async {
        let client = Client::for_testnet();
        let operator_id = AccountId::from_str(&operator_id_str).unwrap();
        let operator_key = PrivateKey::from_str_ecdsa(&operator_priv_hex_str).unwrap();
        client.set_operator(operator_id, operator_key.clone());

        let new_key = PrivateKey::generate_ecdsa();
        let new_pk = new_key.public_key();

        let create_params = HederaTransactionParameters {
            payer_account_id: operator_id_str.clone(),
            node_account_ids: vec!["0.0.4".to_string()],
            valid_start_seconds: time::OffsetDateTime::now_utc().unix_timestamp() - 10,
            valid_start_nanos: 0,
            max_transaction_fee: 100_000_000,
            memo: "anychain hedera live account create test via JNI".to_string(),
            public_key: operator_key.public_key().to_bytes_raw(),
            data: HederaTransactionData::CreateAccount {
                new_account_public_key: new_pk.to_bytes_raw(),
                initial_balance: 500_000_000, // 5 HBAR
            },
        };

        let mut create_tx = HederaTransaction::new(&create_params).unwrap();
        let create_digest = hex::decode(create_tx.to_transaction_id().unwrap().txid).unwrap();
        let operator_signing_key = SigningKey::from_slice(&operator_key.to_bytes_raw()).unwrap();
        let (create_sig, _) = operator_signing_key.sign_prehash(&create_digest).unwrap();
        let signed_create_bytes = create_tx.sign(create_sig.to_vec(), 0).unwrap();

        let mut sdk_tx = AnyTransaction::from_bytes(&signed_create_bytes).unwrap();
        let response = sdk_tx.execute(&client).await;
        match response {
            Ok(resp) => {
                let receipt = resp.get_receipt(&client).await.unwrap();
                let new_account_id = receipt.account_id.unwrap();
                format!(
                    "{},{},{}",
                    new_account_id,
                    hex::encode(new_key.to_bytes_raw()),
                    hex::encode(new_pk.to_bytes_raw())
                )
            }
            Err(hiero_sdk::Error::TransactionPreCheckStatus { status: hiero_sdk::Status::InsufficientPayerBalance, .. }) => {
                "INSUFFICIENT_PAYER_BALANCE,,".to_string()
            }
            Err(e) => {
                panic!("create account failed: {:?}", e);
            }
        }
    });

    env.new_string(res).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_createTransaction(
    mut env: JNIEnv,
    _class: JClass,
    payer_str: JString,
    receiver_str: JString,
    amount: jlong,
    node_str: JString,
    valid_start_seconds: jlong,
    valid_start_nanos: jint,
    max_fee: jlong,
    memo_str: JString,
    public_key_arr: JByteArray,
) -> jlong {
    let payer: String = env.get_string(&payer_str).unwrap().into();
    let receiver: String = env.get_string(&receiver_str).unwrap().into();
    let node_str: String = env.get_string(&node_str).unwrap().into();
    let memo: String = env.get_string(&memo_str).unwrap().into();
    let public_key: Vec<u8> = env.convert_byte_array(&public_key_arr).unwrap();

    let node_account_ids = if node_str.is_empty() {
        vec![]
    } else {
        vec![node_str]
    };

    let params = HederaTransactionParameters {
        payer_account_id: payer,
        node_account_ids,
        valid_start_seconds,
        valid_start_nanos,
        max_transaction_fee: max_fee as u64,
        memo,
        public_key,
        data: HederaTransactionData::Transfer {
            receiver_account_id: receiver,
            amount,
        },
    };

    let tx = HederaTransaction::new(&params).unwrap();
    let boxed_tx = Box::new(tx);
    Box::into_raw(boxed_tx) as jlong
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_getDigest(
    env: JNIEnv,
    _class: JClass,
    tx_ptr: jlong,
) -> jbyteArray {
    let tx = unsafe { &*(tx_ptr as *const HederaTransaction) };
    let tx_id = tx.to_transaction_id().unwrap();
    let digest = hex::decode(tx_id.txid).unwrap();
    let j_array = env.byte_array_from_slice(&digest).unwrap();
    j_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_sign(
    env: JNIEnv,
    _class: JClass,
    tx_ptr: jlong,
    signature_arr: JByteArray,
) -> jbyteArray {
    let tx = unsafe { &mut *(tx_ptr as *mut HederaTransaction) };
    let signature: Vec<u8> = env.convert_byte_array(&signature_arr).unwrap();
    let signed_tx_bytes = tx.sign(signature, 0).unwrap();
    let j_array = env.byte_array_from_slice(&signed_tx_bytes).unwrap();
    j_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_freeTransaction(
    _env: JNIEnv,
    _class: JClass,
    tx_ptr: jlong,
) {
    if tx_ptr != 0 {
        let _ = unsafe { Box::from_raw(tx_ptr as *mut HederaTransaction) };
    }
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_signDigest(
    env: JNIEnv,
    _class: JClass,
    digest_arr: JByteArray,
    private_key_arr: JByteArray,
) -> jbyteArray {
    let digest: Vec<u8> = env.convert_byte_array(&digest_arr).unwrap();
    let private_key_bytes: Vec<u8> = env.convert_byte_array(&private_key_arr).unwrap();

    let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
    let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
    let signature_bytes = signature.to_vec();

    let j_array = env.byte_array_from_slice(&signature_bytes).unwrap();
    j_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_queryReceipt(
    mut env: JNIEnv,
    _class: JClass,
    operator_id_str: JString,
    operator_priv_hex_str: JString,
    signed_tx_bytes_arr: JByteArray,
) -> jstring {
    let operator_id_str: String = env.get_string(&operator_id_str).unwrap().into();
    let operator_priv_hex_str: String = env.get_string(&operator_priv_hex_str).unwrap().into();
    let signed_tx_bytes: Vec<u8> = env.convert_byte_array(&signed_tx_bytes_arr).unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let status_str = runtime.block_on(async {
        let client = Client::for_testnet();
        let operator_id = AccountId::from_str(&operator_id_str).unwrap();
        let operator_key = PrivateKey::from_str_ecdsa(&operator_priv_hex_str).unwrap();
        client.set_operator(operator_id, operator_key);

        let sdk_tx = AnyTransaction::from_bytes(&signed_tx_bytes).unwrap();
        let sdk_tx_id = sdk_tx.get_transaction_id().unwrap();

        let transfer_receipt = TransactionReceiptQuery::new()
            .transaction_id(sdk_tx_id)
            .execute(&client)
            .await
            .unwrap();

        match transfer_receipt.account_id {
            Some(acc_id) => format!("Success,{}", acc_id),
            None => format!("{:?}", transfer_receipt.status),
        }
    });

    env.new_string(status_str).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_createAccountTransaction(
    mut env: JNIEnv,
    _class: JClass,
    payer_str: JString,
    node_str: JString,
    valid_start_seconds: jlong,
    valid_start_nanos: jint,
    max_fee: jlong,
    memo_str: JString,
    payer_public_key_arr: JByteArray,
    new_account_public_key_arr: JByteArray,
    initial_balance: jlong,
) -> jlong {
    let payer: String = env.get_string(&payer_str).unwrap().into();
    let node_str: String = env.get_string(&node_str).unwrap().into();
    let memo: String = env.get_string(&memo_str).unwrap().into();
    let payer_public_key: Vec<u8> = env.convert_byte_array(&payer_public_key_arr).unwrap();
    let new_account_public_key: Vec<u8> = env.convert_byte_array(&new_account_public_key_arr).unwrap();

    let node_account_ids = if node_str.is_empty() {
        vec![]
    } else {
        vec![node_str]
    };

    let params = HederaTransactionParameters {
        payer_account_id: payer,
        node_account_ids,
        valid_start_seconds,
        valid_start_nanos,
        max_transaction_fee: max_fee as u64,
        memo,
        public_key: payer_public_key,
        data: HederaTransactionData::CreateAccount {
            new_account_public_key,
            initial_balance: initial_balance as u64,
        },
    };

    let tx = HederaTransaction::new(&params).unwrap();
    let boxed_tx = Box::new(tx);
    Box::into_raw(boxed_tx) as jlong
}

#[no_mangle]
pub extern "system" fn Java_HederaTransactionTest_getEvmAddress(
    env: JNIEnv,
    _class: JClass,
    public_key_arr: JByteArray,
) -> jstring {
    let public_key: Vec<u8> = env.convert_byte_array(&public_key_arr).unwrap();
    
    let k256_pk = k256::PublicKey::from_sec1_bytes(&public_key).unwrap();
    let encoded_point = k256_pk.to_encoded_point(false);
    let raw_bytes = encoded_point.as_bytes();
    
    let evm_addr = if raw_bytes.len() == 65 && raw_bytes[0] == 4 {
        let digest_bytes = anychain_core::crypto::keccak256(&raw_bytes[1..]);
        let evm_addr_bytes = &digest_bytes[12..];
        format!("0x{}", hex::encode(evm_addr_bytes))
    } else {
        panic!("Failed to decompress public key");
    };

    env.new_string(evm_addr).unwrap().into_raw()
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