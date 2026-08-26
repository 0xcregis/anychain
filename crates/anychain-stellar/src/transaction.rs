use crate::address::StellarAddress;
use crate::format::StellarFormat;
use crate::StellarPublicKey;
use anychain_core::{
    crypto::sha256,
    transaction::{Transaction, TransactionError, TransactionId},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use core::fmt;
use std::str::FromStr;
use stellar_xdr::{
    AlphaNum12, AlphaNum4, Asset, AssetCode12, AssetCode4, BytesM, ChangeTrustAsset, ChangeTrustOp,
    ContractId, CreateAccountOp, DecoratedSignature, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, Operation, OperationBody, PaymentOp, Preconditions,
    ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, Transaction as Tx, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, VecM, WriteXdr,
};

const MAINNET_NETWORK_ID: &str = "Public Global Stellar Network ; September 2015";
const TESTNET_NETWORK_ID: &str = "Test SDF Network ; September 2015";

struct HelperTuple {
    trust_line: Option<StellarTrustLine>,
    token: Option<StellarToken>,
    to: StellarAddress,
    amount: i64,
    has_account: bool,
}

fn asset_code_4(asset_code: &str, issuer: &StellarAddress) -> Result<AlphaNum4, TransactionError> {
    let code =
        AssetCode4::from_str(asset_code).map_err(|e| TransactionError::Message(e.to_string()))?;
    let issuer = issuer.to_account_id()?;
    Ok(AlphaNum4 {
        asset_code: code,
        issuer,
    })
}

fn asset_code_12(
    asset_code: &str,
    issuer: &StellarAddress,
) -> Result<AlphaNum12, TransactionError> {
    let code =
        AssetCode12::from_str(asset_code).map_err(|e| TransactionError::Message(e.to_string()))?;
    let issuer = issuer.to_account_id()?;
    Ok(AlphaNum12 {
        asset_code: code,
        issuer,
    })
}

fn build_asset(asset_code: &str, issuer: &StellarAddress) -> Result<Asset, TransactionError> {
    match asset_code.len() {
        1..=4 => Ok(Asset::CreditAlphanum4(asset_code_4(asset_code, issuer)?)),
        5..=12 => Ok(Asset::CreditAlphanum12(asset_code_12(asset_code, issuer)?)),
        _ => Err(TransactionError::Message(format!(
            "Invalid asset code length: {}",
            asset_code.len()
        ))),
    }
}

fn build_trust_line(
    asset_code: &str,
    issuer: &StellarAddress,
) -> Result<ChangeTrustAsset, TransactionError> {
    match asset_code.len() {
        1..=4 => Ok(ChangeTrustAsset::CreditAlphanum4(asset_code_4(
            asset_code, issuer,
        )?)),
        5..=12 => Ok(ChangeTrustAsset::CreditAlphanum12(asset_code_12(
            asset_code, issuer,
        )?)),
        _ => Err(TransactionError::Message(format!(
            "Invalid asset code length: {}",
            asset_code.len()
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StellarMemo {
    None,
    Text(String),
    Id(u64),
}

impl StellarMemo {
    pub fn to_memo(&self) -> Result<Memo, TransactionError> {
        match self {
            StellarMemo::None => Ok(Memo::None),
            StellarMemo::Text(text) => {
                let memo = StringM::from_str(text)
                    .map_err(|e| TransactionError::Message(e.to_string()))?;
                Ok(Memo::Text(memo))
            }
            StellarMemo::Id(id) => Ok(Memo::Id(*id)),
        }
    }

    pub fn from_memo(memo: &Memo) -> Result<Self, TransactionError> {
        match memo {
            Memo::None => Ok(StellarMemo::None),
            Memo::Text(text) => Ok(StellarMemo::Text(text.to_string())),
            Memo::Id(id) => Ok(StellarMemo::Id(*id)),
            _ => Err(TransactionError::Message(
                "Unsupported memo type".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StellarToken {
    Classic {
        asset_code: String,
        issuer: StellarAddress,
    },
    Soroban {
        contract: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StellarTrustLine {
    pub asset_code: String,
    pub issuer: StellarAddress,
    pub limit: i64,
}

impl StellarTrustLine {
    pub fn to_operation_body(&self) -> Result<OperationBody, TransactionError> {
        let trust_line = build_trust_line(&self.asset_code, &self.issuer)?;
        let trust_line = ChangeTrustOp {
            line: trust_line,
            limit: self.limit,
        };
        Ok(OperationBody::ChangeTrust(trust_line))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StellarTransactionParameters {
    pub trust_line: Option<StellarTrustLine>,
    pub token: Option<StellarToken>,
    pub from: StellarAddress,
    pub to: StellarAddress,
    pub has_account: bool,
    pub amount: i64,
    pub fee: u32,
    pub nonce: i64,
    pub memo: StellarMemo,
    pub network_id: u8,
}

impl StellarTransactionParameters {
    fn to_operation_body(&self) -> Result<OperationBody, TransactionError> {
        if let Some(trustline) = &self.trust_line {
            return trustline.to_operation_body();
        }

        match &self.token {
            Some(token) => match token {
                StellarToken::Classic { asset_code, issuer } => {
                    Ok(OperationBody::Payment(PaymentOp {
                        destination: self.to.to_muxed_account()?,
                        asset: build_asset(asset_code, issuer)?,
                        amount: self.amount,
                    }))
                }
                StellarToken::Soroban { contract } => {
                    let contract = ContractId::from_str(contract)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                    let contract = ScAddress::Contract(contract);

                    let function = StringM::try_from("transfer")
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                    let function = ScSymbol(function);

                    let from = ScVal::Address(ScAddress::Account(self.from.to_account_id()?));
                    let to = ScVal::Address(ScAddress::Account(self.to.to_account_id()?));
                    let amount = ScVal::I64(self.amount);

                    let args: VecM<ScVal> = vec![from, to, amount].try_into().map_err(|_| {
                        TransactionError::Message("VecM transfer error".to_string())
                    })?;

                    let args = InvokeContractArgs {
                        contract_address: contract,
                        function_name: function,
                        args,
                    };

                    let host_function = HostFunction::InvokeContract(args.clone());

                    let credentials = SorobanCredentials::SourceAccount;
                    let root_invocation = SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(args),
                        sub_invocations: vec![].try_into().map_err(|_| {
                            TransactionError::Message("VecM transfer error".to_string())
                        })?,
                    };
                    let auth = SorobanAuthorizationEntry {
                        credentials,
                        root_invocation,
                    };

                    let op = InvokeHostFunctionOp {
                        host_function,
                        auth: vec![auth].try_into().map_err(|_| {
                            TransactionError::Message("VecM transfer error".to_string())
                        })?,
                    };

                    Ok(OperationBody::InvokeHostFunction(op))
                }
            },
            None => match self.has_account {
                true => Ok(OperationBody::Payment(PaymentOp {
                    destination: self.to.to_muxed_account()?,
                    asset: Asset::Native,
                    amount: self.amount,
                })),
                false => Ok(OperationBody::CreateAccount(CreateAccountOp {
                    destination: self.to.to_account_id()?,
                    starting_balance: self.amount,
                })),
            },
        }
    }

    fn from_operation_body(body: &OperationBody) -> Result<HelperTuple, TransactionError> {
        match body {
            OperationBody::Payment(PaymentOp {
                destination,
                amount,
                asset,
            }) => {
                let to = StellarAddress::from_muxed_account(destination)?;
                let token = match asset {
                    Asset::Native => None,
                    Asset::CreditAlphanum4(AlphaNum4 { asset_code, issuer }) => {
                        let asset_code = asset_code.to_string();
                        let issuer = StellarAddress::from_account_id(issuer)?;
                        let token = StellarToken::Classic { asset_code, issuer };
                        Some(token)
                    }
                    Asset::CreditAlphanum12(AlphaNum12 { asset_code, issuer }) => {
                        let asset_code = asset_code.to_string();
                        let issuer = StellarAddress::from_account_id(issuer)?;
                        let token = StellarToken::Classic { asset_code, issuer };
                        Some(token)
                    }
                };
                Ok(HelperTuple {
                    trust_line: None,
                    token,
                    to,
                    amount: *amount,
                    has_account: true,
                })
            }
            OperationBody::CreateAccount(CreateAccountOp {
                destination,
                starting_balance,
                ..
            }) => {
                let to = StellarAddress::from_account_id(destination)?;
                Ok(HelperTuple {
                    trust_line: None,
                    token: None,
                    to,
                    amount: *starting_balance,
                    has_account: false,
                })
            }
            OperationBody::InvokeHostFunction(op) => {
                if let HostFunction::InvokeContract(args) = op.host_function.clone() {
                    let contract = args.contract_address;
                    let args = args.args;
                    let contract = Self::scaddress_to_contract(&contract)?;
                    match (args.get(1), args.get(2)) {
                        (Some(to), Some(amount)) => {
                            let to = Self::scval_to_address(to)?;
                            let amount = Self::scval_to_amount(amount)?;
                            let token = StellarToken::Soroban { contract };
                            Ok(HelperTuple {
                                trust_line: None,
                                token: Some(token),
                                to,
                                amount,
                                has_account: true,
                            })
                        }
                        _ => Err(TransactionError::Message(
                            "invalid contract call".to_string(),
                        )),
                    }
                } else {
                    Err(TransactionError::Message(
                        "invalid contract call".to_string(),
                    ))
                }
            }
            OperationBody::ChangeTrust(trust_line) => match &trust_line.line {
                ChangeTrustAsset::CreditAlphanum4(AlphaNum4 { asset_code, issuer }) => {
                    let asset_code = asset_code.to_string();
                    let issuer = StellarAddress::from_account_id(issuer)?;
                    let line = StellarTrustLine {
                        asset_code,
                        issuer: issuer.clone(),
                        limit: trust_line.limit,
                    };
                    Ok(HelperTuple {
                        trust_line: Some(line),
                        token: None,
                        to: issuer,
                        amount: 0,
                        has_account: true,
                    })
                }
                ChangeTrustAsset::CreditAlphanum12(AlphaNum12 { asset_code, issuer }) => {
                    let asset_code = asset_code.to_string();
                    let issuer = StellarAddress::from_account_id(issuer)?;
                    let line = StellarTrustLine {
                        asset_code,
                        issuer: issuer.clone(),
                        limit: trust_line.limit,
                    };
                    Ok(HelperTuple {
                        trust_line: Some(line),
                        token: None,
                        to: issuer,
                        amount: 0,
                        has_account: true,
                    })
                }
                _ => Err(TransactionError::Message(
                    "Unsupported trust asset type".to_string(),
                )),
            },
            _ => Err(TransactionError::Message(
                "Unsupported operation type".to_string(),
            )),
        }
    }

    pub fn scaddress_to_contract(addr: &ScAddress) -> Result<String, TransactionError> {
        if let ScAddress::Contract(contract) = addr {
            return Ok(contract.to_string());
        }
        Err(TransactionError::Message(
            "scval cannot convert to contract address".to_string(),
        ))
    }

    pub fn scval_to_address(val: &ScVal) -> Result<StellarAddress, TransactionError> {
        if let ScVal::Address(ScAddress::Account(account)) = val {
            return Ok(StellarAddress::from_account_id(account)?);
        }
        Err(TransactionError::Message(
            "scval cannot convert to stellar address".to_string(),
        ))
    }

    pub fn scval_to_amount(val: &ScVal) -> Result<i64, TransactionError> {
        if let ScVal::I64(amount) = val {
            return Ok(*amount);
        }
        Err(TransactionError::Message(
            "scval cannot convert to amount".to_string(),
        ))
    }
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
        let from = self.params.from.clone();
        let memo = self.params.memo.clone();
        let fee = self.params.fee;
        let seq_num = SequenceNumber(self.params.nonce + 1);
        let network_id = match self.params.network_id {
            0 => MAINNET_NETWORK_ID,
            1 => TESTNET_NETWORK_ID,
            _ => {
                return Err(TransactionError::Message(format!(
                    "Invalid network ID: {}",
                    self.params.network_id
                )))
            }
        };

        let tx = Tx {
            source_account: from.to_muxed_account()?,
            fee,
            seq_num,
            cond: Preconditions::None,
            memo: memo.to_memo()?,
            ext: TransactionExt::V0,
            operations: [Operation {
                source_account: None,
                body: self.params.to_operation_body()?,
            }]
            .try_into()
            .unwrap(),
        };

        match &self.signatures {
            Some(sigs) => {
                let mut hint = [0u8; 4];
                let pk = from.to_array()?;
                hint.copy_from_slice(&pk[28..]);
                let hint = SignatureHint(hint);

                let sig = sigs[0].clone();
                let sig = BytesM::try_from(sig)
                    .map_err(|e| TransactionError::Crate("to_bytes", format!("{e:?}")))?;
                let sig = Signature(sig);
                let sig = DecoratedSignature {
                    hint,
                    signature: sig,
                };

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
                let network_id = Hash(sha256(network_id.as_bytes()));

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

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let envelope = TransactionEnvelope::from_xdr(tx, Limits::none())
            .map_err(|e| TransactionError::Crate("from_bytes", format!("{e:?}")))?;

        match envelope {
            TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) => {
                let from = StellarAddress::from_muxed_account(&tx.source_account)?;
                let tuple =
                    StellarTransactionParameters::from_operation_body(&tx.operations[0].body)?;
                let fee = tx.fee;
                let nonce = tx.seq_num.0 - 1;
                let memo = StellarMemo::from_memo(&tx.memo)?;

                Ok(Self {
                    params: StellarTransactionParameters {
                        trust_line: tuple.trust_line,
                        token: tuple.token,
                        from,
                        to: tuple.to,
                        has_account: tuple.has_account,
                        amount: tuple.amount,
                        fee,
                        nonce,
                        memo,
                        network_id: 0, // Network ID is not included in the envelope
                    },
                    signatures: None, // Signatures are not included in the envelope
                })
            }
            _ => Err(TransactionError::Message(
                "Unsupported transaction envelope type".to_string(),
            )),
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let stream = self.to_bytes()?;
        let txid = sha256(&stream).to_vec();
        Ok(StellarTransactionId { txid })
    }
}

impl FromStr for StellarTransaction {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = STANDARD
            .decode(tx)
            .map_err(|e| TransactionError::Message(e.to_string()))
            .unwrap();
        StellarTransaction::from_bytes(&tx)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_tx_gen() {}
}
