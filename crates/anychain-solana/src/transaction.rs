use crate::{SolanaAddress, SolanaFormat, SolanaPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use solana_sdk::{
    hash::Hash, message::Message, pubkey::Pubkey, signature::Signature,
    transaction::Transaction as Tx,
};
use solana_system_interface::instruction::{transfer as sol_transfer, SystemInstruction};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::instruction::{transfer_checked as token_transfer, TokenInstruction};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SolanaTransactionParameters {
    pub token: Option<SolanaAddress>,
    pub program_id: Option<SolanaAddress>,
    pub has_token_account: Option<bool>,
    pub decimals: Option<u8>,
    pub fee_payer: Option<SolanaAddress>,
    pub from: SolanaAddress,
    pub to: SolanaAddress,
    pub amount: u64,
    pub blockhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SolanaTransaction {
    pub params: SolanaTransactionParameters,
    pub sig_fee_payer: Option<Vec<u8>>,
    pub sig_from: Option<Vec<u8>>,
}

impl FromStr for SolanaTransaction {
    type Err = TransactionError;
    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = bs58::decode(tx)
            .into_vec()
            .map_err(|e| TransactionError::Message(format!("{e}")))?;
        SolanaTransaction::from_bytes(&tx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SolanaTransactionId(pub [u8; 64]);

impl fmt::Display for SolanaTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0.to_vec()).into_string())
    }
}

impl TransactionId for SolanaTransactionId {}

fn address_unwrap(address: &SolanaAddress) -> Result<Pubkey, TransactionError> {
    Pubkey::from_str(&address.0)
        .map_err(|e| TransactionError::Message(format!("Invalid address: {e}")))
}

fn get_sig(sig: &Vec<u8>) -> Result<Signature, TransactionError> {
    if sig.len() != 64 {
        return Err(TransactionError::Message(format!(
            "Invalid signature length {}",
            sig.len(),
        )));
    }
    let mut _sig = [0u8; 64];
    _sig.copy_from_slice(sig.as_slice());
    Ok(Signature::from(_sig))
}

impl SolanaTransaction {
    pub fn sign_fee_payer(&mut self, sig: Vec<u8>) -> Result<(), TransactionError> {
        if sig.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                sig.len(),
            )));
        }
        self.sig_fee_payer = Some(sig);
        Ok(())
    }
}

impl Transaction for SolanaTransaction {
    type Address = SolanaAddress;
    type Format = SolanaFormat;
    type PublicKey = SolanaPublicKey;
    type TransactionParameters = SolanaTransactionParameters;
    type TransactionId = SolanaTransactionId;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(SolanaTransaction {
            params: params.clone(),
            sig_from: None,
            sig_fee_payer: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.sig_from = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let from = address_unwrap(&self.params.from)?;
        let to = address_unwrap(&self.params.to)?;
        let amount = self.params.amount;
        let blockhash = Hash::from_str(&self.params.blockhash)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let token = match &self.params.token {
            Some(token) => Some(address_unwrap(token)?),
            None => None,
        };
        let program_id = match &self.params.program_id {
            Some(pid) => Some(address_unwrap(pid)?),
            None => None,
        };
        let has_token_account = self.params.has_token_account;
        let decimals = self.params.decimals;

        let fee_payer = match &self.params.fee_payer {
            Some(fee_payer) => address_unwrap(fee_payer)?,
            None => address_unwrap(&self.params.from)?,
        };

        let msg = match (token, program_id, has_token_account, decimals) {
            (Some(token), Some(program_id), Some(has_token_account), Some(decimals)) => {
                let src = get_associated_token_address_with_program_id(&from, &token, &program_id);
                let dest = get_associated_token_address_with_program_id(&to, &token, &program_id);
                let ixs = match has_token_account {
                    true => {
                        let ix_transfer = token_transfer(
                            &program_id,
                            &src,
                            &token,
                            &dest,
                            &from,
                            &[],
                            amount,
                            decimals,
                        )
                        .unwrap();
                        vec![ix_transfer]
                    }
                    false => {
                        let ix_create_account =
                            create_associated_token_account(&fee_payer, &to, &token, &program_id);
                        let ix_transfer = token_transfer(
                            &program_id,
                            &src,
                            &token,
                            &dest,
                            &from,
                            &[],
                            amount,
                            decimals,
                        )
                        .unwrap();
                        vec![ix_create_account, ix_transfer]
                    }
                };
                Message::new_with_blockhash(&ixs, Some(&fee_payer), &blockhash)
            }
            _ => {
                let ix = sol_transfer(&from, &to, amount);
                Message::new_with_blockhash(&[ix], Some(&fee_payer), &blockhash)
            }
        };

        match &self.sig_from {
            Some(sig_from) => {
                let sig_from = get_sig(sig_from)?;

                let sigs = match &self.sig_fee_payer {
                    Some(sig_fee_payer) => {
                        let sig_fee_payer = get_sig(sig_fee_payer)?;
                        vec![sig_fee_payer, sig_from]
                    }
                    None => vec![sig_from],
                };

                let mut tx = Tx::new_unsigned(msg);
                tx.signatures = sigs;
                Ok(bincode::serialize(&tx).unwrap())
            }
            None => Ok(msg.serialize()),
        }
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let tx = bincode::deserialize::<Tx>(tx)
            .map_err(|e| TransactionError::Message(format!("{e}")))?;

        let (sig_payer, sig_from) = match tx.signatures.len() {
            0 => (None, None),
            1 => {
                let sig = tx.signatures[0];
                let mut sig_from = [0u8; 64];
                sig_from.copy_from_slice(sig.as_ref());
                (None, Some(sig_from.to_vec()))
            }
            2 => {
                let sig_fee_payer = tx.signatures[0];
                let sig_from = tx.signatures[1];
                let mut _sig_fee_payer = [0u8; 64];
                let mut _sig_from = [0u8; 64];
                _sig_fee_payer.copy_from_slice(sig_fee_payer.as_ref());
                _sig_from.copy_from_slice(sig_from.as_ref());
                (Some(_sig_fee_payer.to_vec()), Some(_sig_from.to_vec()))
            }
            _ => {
                return Err(TransactionError::Message(format!(
                    "Unsupported signature amount: {}",
                    tx.signatures.len()
                )));
            }
        };

        let keys = tx.message.account_keys;
        let fee_payer = sig_payer
            .as_ref()
            .map(|_| SolanaAddress(keys[0].to_string()));

        let ixs = tx.message.instructions;
        let blockhash = tx.message.recent_blockhash;

        match ixs.len() {
            1 => {
                let program = keys[ixs[0].program_id_index as usize];
                let account = &ixs[0].accounts;
                let data = &ixs[0].data;
                match format!("{program}").as_str() {
                    "11111111111111111111111111111111" => {
                        let from = keys[account[0] as usize];
                        let to = keys[account[1] as usize];

                        let ix = bincode::deserialize::<SystemInstruction>(data)
                            .map_err(|e| TransactionError::Message(format!("{e}")))?;

                        match ix {
                            SystemInstruction::Transfer { lamports } => {
                                let params = SolanaTransactionParameters {
                                    token: None,
                                    program_id: None,
                                    has_token_account: None,
                                    decimals: None,
                                    fee_payer,
                                    from: SolanaAddress(from.to_string()),
                                    to: SolanaAddress(to.to_string()),
                                    amount: lamports,
                                    blockhash: blockhash.to_string(),
                                };
                                let mut tx = SolanaTransaction::new(&params)?;
                                tx.sig_from = sig_from;
                                tx.sig_fee_payer = sig_payer;
                                Ok(tx)
                            }
                            _ => Err(TransactionError::Message(format!(
                                "Unsupported system instruction: {ix:?}"
                            ))),
                        }
                    }
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                    | "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => {
                        let token = keys[account[1] as usize];
                        let dest = keys[account[2] as usize];
                        let from = keys[account[3] as usize];

                        let ix = TokenInstruction::unpack(data)
                            .map_err(|e| TransactionError::Message(format!("{e}")))?;

                        match ix {
                            TokenInstruction::TransferChecked { amount, decimals } => {
                                let params = SolanaTransactionParameters {
                                    token: Some(SolanaAddress(token.to_string())),
                                    program_id: Some(SolanaAddress(format!("{program}"))),
                                    has_token_account: Some(true),
                                    decimals: Some(decimals),
                                    fee_payer,
                                    from: SolanaAddress(from.to_string()),
                                    to: SolanaAddress(dest.to_string()),
                                    amount,
                                    blockhash: blockhash.to_string(),
                                };
                                let mut tx = SolanaTransaction::new(&params)?;
                                tx.sig_from = sig_from;
                                tx.sig_fee_payer = sig_payer;
                                Ok(tx)
                            }
                            _ => Err(TransactionError::Message(format!(
                                "Unsupported token instruction: {ix:?}"
                            ))),
                        }
                    }
                    _ => Err(TransactionError::Message(format!(
                        "Unsupported program {program}"
                    ))),
                }
            }
            2 => {
                let program1 = keys[ixs[0].program_id_index as usize];
                let program2 = keys[ixs[1].program_id_index as usize];

                if format!("{program1}").as_str() != "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
                {
                    return Err(TransactionError::Message(format!(
                        "Unsupported first program {program1}"
                    )));
                }

                if format!("{program2}").as_str() != "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                    && format!("{program2}").as_str()
                        != "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
                {
                    return Err(TransactionError::Message(format!(
                        "Unsupported second program {program2}"
                    )));
                }

                let account = &ixs[0].accounts;
                let data = &ixs[1].data;

                let from = keys[ixs[1].accounts[3] as usize];
                let to = keys[account[2] as usize];
                let token = keys[account[3] as usize];

                let ix = TokenInstruction::unpack(data)
                    .map_err(|e| TransactionError::Message(format!("{e}")))?;

                match ix {
                    TokenInstruction::TransferChecked { amount, decimals } => {
                        let params = SolanaTransactionParameters {
                            token: Some(SolanaAddress(token.to_string())),
                            program_id: Some(SolanaAddress(format!("{program2}"))),
                            has_token_account: Some(false),
                            decimals: Some(decimals),
                            fee_payer,
                            from: SolanaAddress(from.to_string()),
                            to: SolanaAddress(to.to_string()),
                            amount,
                            blockhash: blockhash.to_string(),
                        };
                        let mut tx = SolanaTransaction::new(&params)?;
                        tx.sig_from = sig_from;
                        tx.sig_fee_payer = sig_payer;
                        Ok(tx)
                    }
                    _ => Err(TransactionError::Message(format!(
                        "Unsupported token instruction: {ix:?}"
                    ))),
                }
            }
            _ => Err(TransactionError::Message(format!(
                "Unsupported instruction amount: {}",
                ixs.len()
            ))),
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        match (&self.sig_fee_payer, &self.sig_from) {
            (Some(sig_fee_payer), _) => {
                let mut txid = [0u8; 64];
                txid.copy_from_slice(sig_fee_payer);
                Ok(SolanaTransactionId(txid))
            }
            (None, Some(sig_from)) => {
                let mut txid = [0u8; 64];
                txid.copy_from_slice(sig_from);
                Ok(SolanaTransactionId(txid))
            }
            _ => Err(TransactionError::Message(
                "Transaction is not signed".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_gen() {
        let token = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
        let program_id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let from = "HQ2SDwyaRtbpV57dL5q21fWWKzYn53EnDeG2y2EgzHkS";
        let to = "A9wA1dAog9XNeS33QJxHwtWQGCMokdXKa5aGyCy1nPDD";
        let fee_payer = "6PJHXT7pQvrXBTDUTmR9gN4ZrXLHoQ4uDNLBwNB7YYN9";

        let params = SolanaTransactionParameters {
            token: Some(SolanaAddress(token.to_string())),
            program_id: Some(SolanaAddress(program_id.to_string())),
            has_token_account: Some(false),
            decimals: Some(6),
            fee_payer: Some(SolanaAddress(fee_payer.to_string())),
            from: SolanaAddress(from.to_string()),
            to: SolanaAddress(to.to_string()),
            amount: 1000000000,
            blockhash: "6ZYbfeFjSiZBpEA9A17gThKXFWJkbgWTwJcqPMpBLEsL".to_string(),
        };

        let mut tx = SolanaTransaction::new(&params).unwrap();
        let sig_from = vec![2u8; 64];
        let sig_fee_payer = vec![1u8; 64];

        tx.sig_from = Some(sig_from);
        tx.sig_fee_payer = Some(sig_fee_payer);

        let tx = tx.to_bytes().unwrap();

        let tx = SolanaTransaction::from_bytes(&tx).unwrap();

        println!("Tx: {:?}", tx);
    }

    #[test]
    fn test() {
        let tx = "BU8oN58NjvzGdbuQ8zGKF9cJ7N25iWRRgnLodf42gEVDnzcQ3g5y7eygBviCRQHH4sC335gt575JA2NfjpX3P7m1vZ5WYWxHem7wW3Pc4S6YYi4ftivYiGqTMr6eKtUVCbBZabwyMuZ7iGjUtTB6L7LnfQj6wGduNUqwpGPy2xD8aFps6zRfgwNAXe9tpoa3tQvTnyU8WgkpiZjkBFdfXFw8abhsUZLZsxaYra2CHmqrXwG6VFUfhTdYANPTXcBcZ2a75RmqC19d5rYJPexmpGJV529A4WXgE4Pm5Gk5AUB7LcNmAxfkKxJk3ikGohb9n3B7vJ3T9zJZg4i6xEGapobavsLwMuYkCjnRBQ69rouMCJEtz33XNuwx1ZN84cGimZV1KSbwQgcPDFzgdZR2ZisViDWAJUXkadfCfADNEME1jxmHDy7oX9gTYJvkeZAnoFjxVhKrVZft8FaADcRgNcdZJPdt9rMMSpCJXBFgBVsGaqo6iteJqg79qQrEoScRviUh6scB7iwCh";
        let tx = SolanaTransaction::from_str(tx).unwrap();
        println!("{:?}", tx);
    }
}
