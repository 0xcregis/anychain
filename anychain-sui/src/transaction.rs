use crate::{address::SuiAddress, format::SuiFormat, public_key::SuiKeyPair, SuiPublicKey};
use anychain_core::{AddressError, Transaction, TransactionError, TransactionId};
use fastcrypto::encoding::{Base58, Encoding};
use shared_crypto::intent::{Intent, IntentMessage};
use std::fmt::Display;
use sui_types::{
    base_types::{ObjectRef, SuiAddress as RawSuiAddress},
    crypto::{default_hash, Signature as RawSignature},
    transaction::TransactionData as RawSuiTransaction,
};

#[derive(Debug)]
pub struct SuiTransactionParameters {
    pub keypair: SuiKeyPair,
    pub recipient: SuiAddress,
    pub mist: u64,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub gas_payment: ObjectRef,
}

impl SuiTransactionParameters {
    pub fn new(
        keypair: SuiKeyPair,
        recipient: SuiAddress,
        mist: u64,
        gas_budget: u64,
        gas_price: u64,
        gas_payment: ObjectRef,
    ) -> Self {
        Self {
            keypair,
            recipient,
            mist,
            gas_budget,
            gas_price,
            gas_payment,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuiTransaction {
    keypair: Option<SuiKeyPair>,
    tx_data: RawSuiTransaction,
    signature: Vec<u8>,
}

impl Transaction for SuiTransaction {
    type Address = SuiAddress;
    type Format = SuiFormat;
    type PublicKey = SuiPublicKey;
    type TransactionId = SuiTransactionId;
    type TransactionParameters = SuiTransactionParameters;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        let sender = RawSuiAddress::from(&parameters.keypair.0.public());
        let recipient =
            RawSuiAddress::from_bytes(parameters.recipient.as_ref()).map_err(|err| {
                TransactionError::AddressError(AddressError::InvalidAddress(format!(
                    "Parse sui address failed: {}",
                    err
                )))
            })?;

        let tx_data = RawSuiTransaction::new_transfer_sui(
            recipient,
            sender,
            Some(parameters.mist),
            parameters.gas_payment,
            parameters.gas_budget,
            parameters.gas_price,
        );

        Ok(Self {
            keypair: Some(parameters.keypair.clone()),
            tx_data,
            signature: vec![],
        })
    }

    fn sign(&mut self, _signature: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        let signature = RawSignature::new_secure(
            &IntentMessage::new(Intent::sui_transaction(), &self.tx_data),
            &self
                .keypair
                .as_ref()
                .expect("Keypair is missing for signing transaction")
                .0,
        )
        .as_ref()
        .to_vec();

        self.signature.clone_from(&signature);
        Ok(signature)
    }

    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        Ok(Self {
            keypair: None,
            tx_data: bcs::from_bytes(transaction).map_err(|err| {
                TransactionError::Message(format!("Deserialize transaction failed: {}", err))
            })?,
            signature: vec![],
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        bcs::to_bytes(&self.tx_data).map_err(|err| {
            TransactionError::Message(format!("Serialize transaction failed: {}", err))
        })
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, anychain_core::TransactionError> {
        Ok(SuiTransactionId(default_hash(&self.tx_data)))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SuiTransactionId([u8; 32]);

impl TransactionId for SuiTransactionId {}

impl Display for SuiTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base58::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::SuiTransactionParameters;
    use anychain_core::Address;
    use fastcrypto::{ed25519::Ed25519KeyPair, traits::ToFromBytes};
    use std::str::FromStr;
    use sui_types::{crypto::SuiKeyPair as RawSuiKeyPair, object::Object};

    use super::*;
    use crate::SuiAddress;

    #[test]
    fn test_tx_generation_one_sui_transfer() {
        // Sender's keypair
        let keypair_bytes = [
            51, 95, 147, 235, 93, 221, 105, 227, 208, 198, 105, 132, 164, 28, 174, 83, 68, 231, 82,
            133, 50, 67, 181, 184, 126, 93, 85, 244, 135, 108, 205, 101,
        ];
        let raw_alice_keypair =
            RawSuiKeyPair::Ed25519(Ed25519KeyPair::from_bytes(&keypair_bytes).unwrap());
        let alice_keypair = SuiKeyPair::from_raw(raw_alice_keypair);
        let address_alice =
            SuiAddress::from_public_key(&alice_keypair.pubkey(), &SuiFormat::Hex).unwrap();

        // Recipient's address
        let address_bob = SuiAddress::from_str(
            "af306e86c74e937552df132b41a6cb3af58559f5342c6e82a98f7d1f7a4a9f30",
        )
        .unwrap();

        // Transfer value, gas_budget, gas_price.
        let sui_transfered = 1_000_000_000u64; // 1 SUI
        let gas_budget = 3_000_000u64; // 0.003 SUI
        let gas_price = 750u64; // 0.00000075 SUI

        // Sender's balance object.
        let gas_object = Object::with_owner_for_testing(address_alice.to_raw()); // 300_000 SUI

        // Construct transaction parameters
        let params = SuiTransactionParameters::new(
            alice_keypair,
            address_bob,
            sui_transfered,
            gas_budget,
            gas_price,
            gas_object.compute_object_reference(),
        );

        // Construct transaction by parameters
        let mut transaction = SuiTransaction::new(&params).unwrap();
        println!(
            "transaction id: {}",
            transaction.to_transaction_id().unwrap()
        );

        // Sign the transaction
        let res = transaction.sign(vec![], 0);
        assert!(res.is_ok());

        // Serialize transaction
        let tx_data = transaction.to_bytes().unwrap();

        // Deserializ transaction
        let deserialized_tx = SuiTransaction::from_bytes(&tx_data);
        assert!(deserialized_tx.is_ok());
        assert_eq!(transaction.tx_data, deserialized_tx.unwrap().tx_data);
    }
}
