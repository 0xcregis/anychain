use crate::address::StellarAddress;
use crate::format::StellarFormat;
use crate::StellarPublicKey;
use anychain_core::{
    crypto::sha256,
    transaction::{Transaction, TransactionError, TransactionId},
};
use core::fmt;
use std::str::FromStr;
use stellar_xdr::{
    AccountId, Asset, BytesM, CreateAccountOp, DecoratedSignature, Hash, Limits, Memo,
    MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber,
    Signature, SignatureHint, Transaction as Tx, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StellarTransactionParameters {
    pub from: StellarAddress,
    pub to: StellarAddress,
    pub has_account: bool,
    pub amount: i64,
    pub fee: u32,
    pub nonce: i64,
    pub network_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StellarTransaction {
    pub params: StellarTransactionParameters,
    pub signatures: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StellarTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for StellarTransactionId {}

impl fmt::Display for StellarTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

impl Transaction for StellarTransaction {
    type Address = StellarAddress;
    type Format = StellarFormat;
    type PublicKey = StellarPublicKey;
    type TransactionId = StellarTransactionId;
    type TransactionParameters = StellarTransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, anychain_core::TransactionError> {
        Ok(Self {
            params: params.clone(),
            signatures: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, anychain_core::TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length: {}",
                rs.len()
            )));
        }
        self.signatures = Some(vec![rs]);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let from = StellarPublicKey::from_str(&self.params.from.to_string())
            .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?
            .0
            .to_bytes();
        let to = StellarPublicKey::from_str(&self.params.to.to_string())
            .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?
            .0
            .to_bytes();

        let source_account = MuxedAccount::Ed25519(Uint256(from));
        let destination = MuxedAccount::Ed25519(Uint256(to));
        let amount = self.params.amount;

        let fee = self.params.fee;
        let seq_num = SequenceNumber(self.params.nonce + 1);

        let op_body = match self.params.has_account {
            true => OperationBody::Payment(PaymentOp {
                destination: destination.clone(),
                asset: Asset::Native,
                amount,
            }),
            false => {
                let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(to)));
                OperationBody::CreateAccount(CreateAccountOp {
                    destination,
                    starting_balance: amount,
                })
            }
        };

        let tx = Tx {
            source_account,
            fee,
            seq_num,
            cond: Preconditions::None,
            memo: Memo::None,
            ext: TransactionExt::V0,
            operations: [Operation {
                source_account: None,
                body: op_body,
            }]
            .try_into()
            .unwrap(),
        };

        match &self.signatures {
            Some(sigs) => {
                let mut hint = [0u8; 4];
                hint.copy_from_slice(&self.params.public_key[28..]);
                let hint = SignatureHint(hint);

                let sig = sigs[0].clone();
                let sig = BytesM::try_from(sig)
                    .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?;
                let signature = Signature(sig);
                let sig = DecoratedSignature { hint, signature };

                let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
                    tx,
                    signatures: VecM::try_from(vec![sig])
                        .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?,
                });

                let stream = envelope
                    .to_xdr(Limits::none())
                    .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?;

                Ok(stream)
            }
            None => {
                let tagged_transaction = TransactionSignaturePayloadTaggedTransaction::Tx(tx);
                let network_id = Hash(sha256(self.params.network_id.as_bytes()));

                let tx = TransactionSignaturePayload {
                    network_id,
                    tagged_transaction,
                };

                let stream = tx
                    .to_xdr(Limits::none())
                    .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?;

                Ok(stream)
            }
        }
    }

    fn from_bytes(_transaction: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let stream = self.to_bytes()?;
        let txid = sha256(&stream).to_vec();
        Ok(StellarTransactionId { txid })
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_tx_gen() {}
}
