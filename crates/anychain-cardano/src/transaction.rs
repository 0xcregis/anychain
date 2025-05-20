use crate::{CardanoAddress, CardanoFormat, CardanoPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};
use cml_chain::{
    utils::NetworkId,
    transaction::{TransactionInput, TransactionOutput, TransactionWitnessSet, Transaction as SignedTransaction},
    assets::Value,
    crypto::{Vkey, Vkeywitness},
    builders::{
        input_builder::SingleInputBuilder,
        output_builder::TransactionOutputBuilder,
        tx_builder::{
            ChangeSelectionAlgo,
            choose_change_selection_algo
        },
    },
};
use cml_crypto::{TransactionHash, Ed25519Signature, blake2b256};
use cml_core::serialization::{Serialize, Deserialize, RawBytesEncoding};
use crate::util::create_default_tx_builder;

#[derive(Debug, Clone)]
pub struct Input {
    pub txid: String,
    pub index: u64,
    pub address: CardanoAddress,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub address: CardanoAddress,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct CardanoTransactionParameters {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub slot: u64,
    pub network: u8,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CardanoTransaction {
    pub params: CardanoTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl FromStr for CardanoTransaction {
    type Err = TransactionError;
    fn from_str(_: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CardanoTransactionId(pub [u8; 32]);

impl fmt::Display for CardanoTransactionId {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
        todo!()
    }
}

impl TransactionId for CardanoTransactionId {}

impl Transaction for CardanoTransaction {
    type Address = CardanoAddress;
    type Format = CardanoFormat;
    type PublicKey = CardanoPublicKey;
    type TransactionId = CardanoTransactionId;
    type TransactionParameters = CardanoTransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(CardanoTransaction {
            params: params.clone(),
            signature: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut builder = create_default_tx_builder();
        let change_address = &self.params.inputs[0].address.0;

        for input in &self.params.inputs {
            let txid = TransactionHash::from_hex(&input.txid)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
            let address = input.address.0.clone();
            let amount = Value::from(input.index);

            let input = TransactionInput::new(txid, input.index);

            let output = TransactionOutput::new(
                address,
                amount,
                None,
                None,
            );

            let input = SingleInputBuilder::new(input, output).payment_key()
               .map_err(|e| TransactionError::Message(e.to_string()))?;

            builder.add_input(input)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
        }

        for output in &self.params.outputs {
            let output = TransactionOutputBuilder::new()
                .with_address(output.address.0.clone())
                .next()
                .map_err(|e| TransactionError::Message(e.to_string()))?
                .with_value(output.amount)
                .build()
                .map_err(|e| TransactionError::Message(e.to_string()))?;

            builder.add_output(output)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
        }

        builder.set_ttl(self.params.slot + 200);

        let check = choose_change_selection_algo(ChangeSelectionAlgo::Default)(
            &mut builder,
            change_address,
            false,
        ).map_err(|e| TransactionError::Message(e.to_string()))?;

        if !check {
            return Err(TransactionError::Message("failed to add change".to_string()));
        }

        let input_amount = builder
            .get_explicit_input()
            .map_err(|e| TransactionError::Message(e.to_string()))?
            .checked_add(&builder.get_implicit_input().unwrap())
            .map_err(|e| TransactionError::Message(e.to_string()))?;
            
        let output_amount = builder
            .get_explicit_output()
            .map_err(|e| TransactionError::Message(e.to_string()))?
            .checked_add(&Value::from(builder.get_fee_if_set().unwrap()))
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        if input_amount != output_amount {
            return Err(TransactionError::Message("Input and output amounts do not match".to_string()));
        }

        let network = NetworkId::from(self.params.network as u64);
        builder.set_network_id(network);

        let tx = builder.build(ChangeSelectionAlgo::Default, change_address)
            .map_err(|e| TransactionError::Message(e.to_string()))?
            .body();

        match &self.signature {
            Some(sig) => {
                let pk = &self.params.public_key;
                let pk = Vkey::from_raw_bytes(pk)
                    .map_err(|e| TransactionError::Message(e.to_string()))?;
                let sig = Ed25519Signature::from_raw_bytes(sig)
                    .map_err(|e| TransactionError::Message(e.to_string()))?;
                let witness = Vkeywitness::new(pk, sig);

                let mut witness_set = TransactionWitnessSet::new();
                witness_set.vkeywitnesses = Some(vec![witness].into());

                let signed_tx = SignedTransaction::new(
                    tx,
                    witness_set,
                    true,
                    None,
                );

                Ok(signed_tx.to_cbor_bytes())
            }
            None =>  Ok(tx.to_cbor_bytes())
        }
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let hash = blake2b256(&self.to_bytes()?);
        Ok(CardanoTransactionId(hash))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {

    }
}
