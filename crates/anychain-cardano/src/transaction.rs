use crate::util::create_default_tx_builder;
use crate::{CardanoAddress, CardanoFormat, CardanoPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use cml_chain::Deserialize;
use cml_chain::{
    assets::Value,
    builders::{
        input_builder::SingleInputBuilder, output_builder::TransactionOutputBuilder,
        tx_builder::ChangeSelectionAlgo,
    },
    crypto::{Vkey, Vkeywitness},
    transaction::{
        Transaction as SignedTransaction, TransactionInput, TransactionOutput,
        TransactionWitnessSet,
    },
    utils::NetworkId,
};
use cml_core::serialization::{RawBytesEncoding, Serialize};
use cml_crypto::{blake2b256, Ed25519Signature, TransactionHash};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone)]
pub struct Input {
    pub txid: String,
    pub index: u64,
    pub address: Option<CardanoAddress>,
    pub amount: Option<u64>,
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
}

#[derive(Debug, Clone)]
pub struct CardanoSignature {
    pub public_key: Vec<u8>,
    pub rs: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CardanoTransaction {
    pub params: CardanoTransactionParameters,
    pub signatures: Option<Vec<CardanoSignature>>,
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

impl CardanoTransaction {
    pub fn sign(&mut self, sigs: Vec<CardanoSignature>) -> Result<Vec<u8>, TransactionError> {
        self.signatures = Some(sigs);
        self.to_bytes()
    }
}

impl Transaction for CardanoTransaction {
    type Address = CardanoAddress;
    type Format = CardanoFormat;
    type PublicKey = CardanoPublicKey;
    type TransactionId = CardanoTransactionId;
    type TransactionParameters = CardanoTransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(CardanoTransaction {
            params: params.clone(),
            signatures: None,
        })
    }

    fn sign(&mut self, _: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut builder = create_default_tx_builder();
        let change_address = self.params.inputs[0].address.clone();
        let change_address = &change_address.unwrap().0;

        for input in &self.params.inputs {
            let txid = TransactionHash::from_hex(&input.txid)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
            let address = input.address.clone().unwrap().0.clone();
            let amount = Value::from(input.amount.unwrap());

            let input = TransactionInput::new(txid, input.index);

            let output = TransactionOutput::new(address, amount, None, None);

            let input = SingleInputBuilder::new(input, output)
                .payment_key()
                .map_err(|e| TransactionError::Message(e.to_string()))?;

            builder
                .add_input(input)
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

            builder
                .add_output(output)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
        }

        let input_amount = builder
            .get_explicit_input()
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let output_amount = builder
            .get_explicit_output()
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let fee = input_amount.coin - output_amount.coin;
        builder.set_fee(fee);

        let network = NetworkId::from(self.params.network as u64);
        builder.set_network_id(network);

        builder.set_ttl(self.params.slot + 200);

        let tx = builder
            .build(ChangeSelectionAlgo::Default, change_address)
            .map_err(|e| TransactionError::Message(e.to_string()))?
            .body();

        match &self.signatures {
            Some(sigs) => {
                let mut witnesses = vec![];

                for sig in sigs {
                    let pk = sig.public_key.as_slice();
                    let rs = sig.rs.as_slice();

                    let pk = Vkey::from_raw_bytes(pk)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                    let rs = Ed25519Signature::from_raw_bytes(rs)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;

                    let witness = Vkeywitness::new(pk, rs);

                    witnesses.push(witness);
                }

                let mut witness_set = TransactionWitnessSet::new();
                witness_set.vkeywitnesses = Some(witnesses.into());

                let signed_tx = SignedTransaction::new(tx, witness_set, true, None);

                Ok(signed_tx.to_cbor_bytes())
            }
            None => Ok(tx.to_cbor_bytes()),
        }
    }

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        let signed_tx = SignedTransaction::from_cbor_bytes(stream)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let tx = signed_tx.body;

        let mut inputs = vec![];
        let mut outputs = vec![];

        for input in tx.inputs {
            let txid = input.transaction_id.to_hex();
            let index = input.index;

            inputs.push(Input {
                txid,
                index,
                address: None,
                amount: None,
            });
        }

        for output in tx.outputs {
            let address = CardanoAddress(output.address().clone());
            let amount = output.amount().coin;

            outputs.push(Output { address, amount });
        }

        let network_id = tx.network_id.unwrap().network as u8;

        Self::new(&CardanoTransactionParameters {
            inputs,
            outputs,
            slot: 0,
            network: network_id,
        })
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let hash = blake2b256(&self.to_bytes()?);
        Ok(CardanoTransactionId(hash))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::{CardanoTransaction, CardanoTransactionParameters, Input, Output};
//     use crate::{CardanoAddress, CardanoPublicKey, CardanoSignature};
//     use anychain_core::{PublicKey, Transaction};
//     use anychain_kms::ed25519_sign;
//     use blockfrost::{BlockFrostSettings, BlockfrostAPI, Pagination};
//     use curve25519_dalek::Scalar;
//     use std::str::FromStr;
//     use tokio::runtime::Runtime;

//     #[test]
//     fn test() {
//         let api = BlockfrostAPI::new(
//             "preprodwYU86nDDxOQKRAkTvp660AQu2pxLfh9l",
//             BlockFrostSettings::new(),
//         );

//         let sk1 = [
//             104u8, 78, 102, 228, 174, 250, 35, 99, 180, 223, 45, 40, 124, 22, 12, 130, 70, 82, 183,
//             48, 195, 95, 207, 80, 47, 5, 201, 222, 157, 148, 168, 13,
//         ];

//         let sk2 = [
//             105u8, 78, 102, 228, 174, 250, 35, 98, 181, 23, 45, 40, 124, 22, 127, 130, 70, 82, 183,
//             48, 5, 95, 207, 180, 47, 15, 201, 12, 157, 148, 168, 13,
//         ];

//         let sk1 = Scalar::from_bytes_mod_order(sk1);
//         let pk1 = CardanoPublicKey::from_secret_key(&sk1).0;
//         let pk1 = pk1.to_bytes().to_vec();

//         let sk2 = Scalar::from_bytes_mod_order(sk2);
//         let pk2 = CardanoPublicKey::from_secret_key(&sk2).0;
//         let pk2 = pk2.to_bytes().to_vec();

//         let from1 = "addr_test1vrxhpfe4dxarnwpdhckjqu2ncc9q90ne8ewszgaree9secczx006l";
//         let from2 = "addr_test1vrlum7eyq5t0s8z96fyr83v6q0vust6ygexax29z4xtahcc4egk9j";

//         let mut inputs = vec![];

//         let utxos = Runtime::new()
//             .unwrap()
//             .block_on(async { api.addresses_utxos(from1, Pagination::all()).await.unwrap() });

//         for utxo in utxos {
//             let txid = utxo.tx_hash;
//             let index = utxo.output_index as u64;
//             let address = CardanoAddress::from_str(&utxo.address).unwrap();
//             let amount: u64 = utxo
//                 .amount
//                 .iter()
//                 .find(|u| u.unit == "lovelace")
//                 .unwrap()
//                 .quantity
//                 .parse()
//                 .unwrap();

//             inputs.push(Input {
//                 txid,
//                 index,
//                 address: Some(address),
//                 amount: Some(amount),
//             });
//         }

//         let utxos = Runtime::new()
//             .unwrap()
//             .block_on(async { api.addresses_utxos(from2, Pagination::all()).await.unwrap() });

//         for utxo in utxos {
//             let txid = utxo.tx_hash;
//             let index = utxo.output_index as u64;
//             let address = CardanoAddress::from_str(&utxo.address).unwrap();
//             let amount: u64 = utxo
//                 .amount
//                 .iter()
//                 .find(|u| u.unit == "lovelace")
//                 .unwrap()
//                 .quantity
//                 .parse()
//                 .unwrap();

//             inputs.push(Input {
//                 txid,
//                 index,
//                 address: Some(address),
//                 amount: Some(amount),
//             });
//         }

//         let to = "addr_test1vz9v4d75kzw7t8nnfnn7ua9c85khelnq2y7fp3p6646szucc5xk6n";
//         let to = CardanoAddress::from_str(to).unwrap();
//         let amount = 100000000u64;

//         let to1 = Output {
//             address: to,
//             amount,
//         };

//         let to = "addr_test1vrxhpfe4dxarnwpdhckjqu2ncc9q90ne8ewszgaree9secczx006l";
//         let to = CardanoAddress::from_str(to).unwrap();
//         let amount = 9800000000u64;

//         let to2 = Output {
//             address: to,
//             amount,
//         };

//         let outputs = vec![to1, to2];

//         let slot = Runtime::new()
//             .unwrap()
//             .block_on(async { api.blocks_latest().await.unwrap().slot.unwrap() as u64 });

//         let network = 0u8; // 0 indicates testnet, 1 indicates mainnet

//         let params = CardanoTransactionParameters {
//             inputs,
//             outputs,
//             slot,
//             network,
//         };

//         let mut tx = CardanoTransaction::new(&params).unwrap();
//         let msg = tx.to_transaction_id().unwrap().0.to_vec();

//         let rs1 = ed25519_sign(&sk1, &msg).unwrap();
//         let rs2 = ed25519_sign(&sk2, &msg).unwrap();

//         let sig1 = CardanoSignature {
//             public_key: pk1,
//             rs: rs1,
//         };

//         let sig2 = CardanoSignature {
//             public_key: pk2,
//             rs: rs2,
//         };

//         let tx = tx.sign(vec![sig1, sig2]).unwrap();

//         let tx = CardanoTransaction::from_bytes(&tx).unwrap();

//         println!("{:?}", tx);

//         // let res = Runtime::new()
//         //     .unwrap()
//         //     .block_on(async { api.transactions_submit(tx).await.unwrap() });

//         // println!("res: {}", res);
//     }
// }
