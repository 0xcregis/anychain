use crate::EthereumAddress;
use anychain_core::{hex, TransactionError};
use ethabi::{ethereum_types::H160, Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use serde_json::{json, Value};

pub fn encode_transfer(func_name: &str, address: &EthereumAddress, amount: U256) -> Vec<u8> {
    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![
            Param {
                name: "address".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };

    let tokens = vec![
        Token::Address(H160::from_slice(&address.to_bytes().unwrap())),
        Token::Uint(amount),
    ];

    func.encode_input(&tokens).unwrap()
}

pub fn decode_transfer(data: Vec<u8>) -> Result<Value, TransactionError> {
    if data.len() < 4 {
        return Err(TransactionError::Message("Illegal data".to_string()));
    }

    let selector = &data[..4];

    match selector {
        // function selector for 'transfer(address,uint256)'
        [169, 5, 156, 187] => {
            #[allow(deprecated)]
            let func = Function {
                name: "transfer".to_string(),
                inputs: vec![
                    Param {
                        name: "to".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    },
                    Param {
                        name: "amount".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                constant: None,
                state_mutability: StateMutability::Payable,
            };
            match func.decode_input(&data[4..]) {
                Ok(tokens) => {
                    let to = hex::encode(tokens[0].clone().into_address().unwrap().as_bytes());
                    let amount = tokens[1].clone().into_uint().unwrap();
                    Ok(json!({
                        "function": "transfer",
                        "params": {
                            "to": to,
                            "amount": amount.to_string(),
                        }
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
