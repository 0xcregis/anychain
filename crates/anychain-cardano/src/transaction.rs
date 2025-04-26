// use crate::{CardanoAddress, CardanoFormat, CardanoPublicKey};
// use anychain_core::{Transaction, TransactionError, TransactionId};
// use std::{fmt, str::FromStr};
//
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct CardanoTransactionParameters {
//     pub token: Option<CardanoAddress>,
//     pub has_token_account: Option<bool>,
//     pub decimals: Option<u8>,
//     pub from: CardanoAddress,
//     pub to: CardanoAddress,
//     pub amount: u64,
//     pub blockhash: String,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct CardanoTransaction {
//     pub params: CardanoTransactionParameters,
//     pub signature: Option<Vec<u8>>,
// }
//
// impl FromStr for CardanoTransaction {
//     type Err = TransactionError;
//     fn from_str(tx: &str) -> Result<Self, Self::Err> {
//         let tx = bs58::decode(tx)
//             .into_vec()
//             .map_err(|e| TransactionError::Message(format!("{}", e)))?;
//         CardanoTransaction::from_bytes(&tx)
//     }
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct CardanoTransactionId(pub [u8; 64]);
//
// impl fmt::Display for CardanoTransactionId {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", bs58::encode(&self.0.to_vec()).into_string())
//     }
// }
//
// impl TransactionId for CardanoTransactionId {}
//
// impl Transaction for CardanoTransaction {
//     type Address = CardanoAddress;
//     type Format = CardanoFormat;
//     type PublicKey = CardanoPublicKey;
//     type TransactionId = CardanoTransactionId;
//     type TransactionParameters = CardanoTransactionParameters;
//
//     fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
//         Ok(CardanoTransaction {
//             params: params.clone(),
//             signature: None,
//         })
//     }
//
//     fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
//         if rs.len() != 64 {
//             return Err(TransactionError::Message(format!(
//                 "Invalid signature length {}",
//                 rs.len(),
//             )));
//         }
//         self.signature = Some(rs);
//         self.to_bytes()
//     }
//
//     fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
//         todo!()
//     }
//
//     fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
//         todo!()
//     }
//
//     fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
//         todo!()
//     }
// }
//
// #[cfg(test)]
// mod tests {}
