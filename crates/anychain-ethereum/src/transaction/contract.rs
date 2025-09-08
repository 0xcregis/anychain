use core::str::FromStr;

use crate::{EthereumAddress, Transfer};
use anychain_core::{hex, TransactionError};
use ethabi::{ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use serde_json::{json, Value};

pub fn erc20_transfer_func() -> Function {
    let param_to = Param {
        name: "to".to_string(),
        kind: ParamType::Address,
        internal_type: None,
    };
    let param_amount = Param {
        name: "amount".to_string(),
        kind: ParamType::Uint(256),
        internal_type: None,
    };

    #[allow(deprecated)]
    Function {
        name: "transfer".to_string(),
        inputs: vec![param_to, param_amount],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    }
}

pub fn eip3009_transfer_func() -> Function {
    let param_from = Param {
        name: "from".to_string(),
        kind: ParamType::Address,
        internal_type: None,
    };
    let param_to = Param {
        name: "to".to_string(),
        kind: ParamType::Address,
        internal_type: None,
    };
    let param_value = Param {
        name: "value".to_string(),
        kind: ParamType::Uint(256),
        internal_type: None,
    };
    let param_valid_after = Param {
        name: "validAfter".to_string(),
        kind: ParamType::Uint(256),
        internal_type: None,
    };
    let param_valid_before = Param {
        name: "validBefore".to_string(),
        kind: ParamType::Uint(256),
        internal_type: None,
    };
    let param_nonce = Param {
        name: "nonce".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };
    let param_v = Param {
        name: "v".to_string(),
        kind: ParamType::Uint(8),
        internal_type: None,
    };
    let param_r = Param {
        name: "r".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };
    let param_s = Param {
        name: "s".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };

    #[allow(deprecated)]
    Function {
        name: "transferWithAuthorization".to_string(),
        inputs: vec![
            param_from,
            param_to,
            param_value,
            param_valid_after,
            param_valid_before,
            param_nonce,
            param_v,
            param_r,
            param_s,
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    }
}

pub fn schedule_func() -> Function {
    let param_calls = Param {
        name: "calls".to_string(),
        kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Bytes,
        ]))),
        internal_type: None,
    };

    #[allow(deprecated)]
    Function {
        name: "schedule".to_string(),
        inputs: vec![param_calls],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    }
}

pub fn execute_batch_transfer_func() -> Function {
    let param_calls = Param {
        name: "calls".to_string(),
        kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Bytes,
        ]))),
        internal_type: None,
    };
    let param_v = Param {
        name: "v".to_string(),
        kind: ParamType::Uint(8),
        internal_type: None,
    };
    let param_r = Param {
        name: "r".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };
    let param_s = Param {
        name: "s".to_string(),
        kind: ParamType::FixedBytes(32),
        internal_type: None,
    };

    #[allow(deprecated)]
    Function {
        name: "execute_batch_transfer".to_string(),
        inputs: vec![param_calls, param_v, param_r, param_s],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    }
}

pub fn erc20_transfer(address: &EthereumAddress, amount: U256) -> Vec<u8> {
    let func = erc20_transfer_func();
    let tokens = vec![
        Token::Address(H160::from_slice(&address.to_bytes().unwrap())),
        Token::Uint(amount),
    ];

    func.encode_input(&tokens).unwrap()
}

pub fn decode(data: Vec<u8>) -> Result<Value, TransactionError> {
    if data.len() < 4 {
        return Err(TransactionError::Message("Illegal data".to_string()));
    }

    let selector = hex::encode(&data[..4]);

    match selector.as_str() {
        // we're dealing with an erc20 transfer
        "a9059cbb" => {
            let func = erc20_transfer_func();
            match func.decode_input(&data[4..]) {
                Ok(tokens) => {
                    let to = tokens[0].clone();
                    let amount = tokens[1].clone();

                    let to = hex::encode(to.into_address().unwrap().as_bytes());
                    let amount = amount.into_uint().unwrap().to_string();

                    Ok(json!({
                        "type": "erc20_transfer",
                        "params": {
                            "to": to,
                            "amount": amount,
                        }
                    }))
                }
                Err(e) => Err(TransactionError::Message(e.to_string())),
            }
        }
        // we're dealing with an eip3009 transfer
        "e3ee160e" => {
            let func = eip3009_transfer_func();

            match func.decode_input(&data[4..]) {
                Ok(tokens) => {
                    let from = tokens[0].clone();
                    let to = tokens[1].clone();
                    let value = tokens[2].clone();
                    let valid_after = tokens[3].clone();
                    let valid_before = tokens[4].clone();
                    let nonce = tokens[5].clone();

                    Ok(json!({
                        "type": "eip3009_transfer",
                        "params": {
                            "from": hex::encode(from.into_address().unwrap().as_bytes()),
                            "to": hex::encode(to.into_address().unwrap().as_bytes()),
                            "value": value.into_uint().unwrap().to_string(),
                            "valid_after": valid_after.into_uint().unwrap().to_string(),
                            "valid_before": valid_before.into_uint().unwrap().to_string(),
                            "nonce": hex::encode(nonce.into_fixed_bytes().unwrap()),
                        }
                    }))
                }
                Err(e) => Err(TransactionError::Message(e.to_string())),
            }
        }
        // we're dealing with a batch transfer
        "5a67d813" => {
            let func = schedule_func();

            match func.decode_input(&data[4..]) {
                Ok(tokens) => {
                    let mut batch_transfers = json!([]);
                    let calls = tokens[0].clone();
                    let calls = calls.into_array().unwrap();

                    for call in calls {
                        let mut batch_transfer = json!({});
                        let call = call.into_tuple().unwrap();

                        let from = call[0].clone();
                        let from = hex::encode(from.into_address().unwrap().as_bytes());
                        let from = EthereumAddress::from_str(&from).unwrap();

                        batch_transfer
                            .as_object_mut()
                            .unwrap()
                            .insert("from".to_string(), json!(from.to_string()));

                        let data = call[2].clone();
                        let data = data.into_bytes().unwrap();

                        if data.len() < 4 {
                            return Err(TransactionError::Message("Illegal data".to_string()));
                        }

                        let func = execute_batch_transfer_func();

                        let mut transfers = json!([]);

                        match func.decode_input(&data[4..]) {
                            Ok(tokens) => {
                                let calls = tokens[0].clone();
                                let calls = calls.into_array().unwrap();

                                for call in calls {
                                    let transfer = Transfer::from_token(call)?;
                                    transfers.as_array_mut().unwrap().push(transfer.to_json());
                                }
                            }
                            Err(e) => return Err(TransactionError::Message(e.to_string())),
                        }
                        batch_transfer
                            .as_object_mut()
                            .unwrap()
                            .insert("transfers".to_string(), transfers);
                        batch_transfers.as_array_mut().unwrap().push(batch_transfer);
                    }

                    Ok(json!({
                        "type": "batch_transfer",
                        "batchTransfers": batch_transfers,
                    }))
                }
                Err(e) => Err(TransactionError::Message(e.to_string())),
            }
        }
        _ => Err(TransactionError::Message(
            "Unsupported contract function".to_string(),
        )),
    }
}
