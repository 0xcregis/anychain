use crate::TronAddress;
use anychain_core::utilities::crypto::keccak256;
use ethabi::{encode, Token};
use ethereum_types::U256;
use std::str::FromStr;

/// Represents a parameter that's fed to a
/// function of an on-chain contract
pub struct Param {
    pub type_: String,
    pub value: Token,
}

impl From<&TronAddress> for Param {
    fn from(address: &TronAddress) -> Self {
        Param {
            type_: "address".to_string(),
            value: address.to_token(),
        }
    }
}

impl From<U256> for Param {
    fn from(amount: U256) -> Self {
        Param {
            type_: "uint256".to_string(),
            value: Token::Uint(amount),
        }
    }
}

pub fn contract_function_call(function_name: &str, params: &[Param]) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    let param_types = params
        .iter()
        .map(|param| param.type_.as_str())
        .collect::<Vec<&str>>()
        .join(",");

    let function_selector = format!("{}({})", function_name, param_types);

    data.extend_from_slice(&keccak256(function_selector.as_bytes())[..4]);

    let tokens = params
        .iter()
        .map(|param| param.value.clone())
        .collect::<Vec<Token>>();

    data.extend_from_slice(&encode(&tokens));

    data
}

pub fn trc20_transfer(address: &str, amount: &str) -> Vec<u8> {
    let address = TronAddress::from_str(address).unwrap();
    let amount = U256::from_dec_str(amount).unwrap();

    contract_function_call("transfer", &[Param::from(&address), Param::from(amount)])
}

pub fn trc20_approve(address: &str, amount: &str) -> Vec<u8> {
    let address = TronAddress::from_str(address).unwrap();
    let amount = U256::from_dec_str(amount).unwrap();

    contract_function_call("approve", &[Param::from(&address), Param::from(amount)])
}

#[cfg(test)]
mod test_mod {
    use std::str::FromStr;

    use super::{contract_function_call, Param};
    use crate::TronAddress;
    use ethabi::ethereum_types::U256;

    #[test]
    fn test_contract_function_call() {
        let address = TronAddress::from_str("TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr").unwrap();
        let amount = U256::from_dec_str("20000000000000000000").unwrap();

        let call_data =
            contract_function_call("transfer", &[Param::from(&address), Param::from(amount)]);

        assert_eq!(
            "a9059cbb000000000000000000000041436d74fc1577266b7\
             290b85801145d9c5287e19400000000000000000000000000\
             0000000000000000000001158e460913d00000",
            hex::encode(call_data)
        )
    }
}
