use ethabi::{Token, encode};
use chainlib_core::{utilities::crypto::keccak256, ethereum_types::U256};

use crate::TronAddress;

pub struct InputParam {
    pub param_type: String,
    pub param_value: Token
}

impl From<&TronAddress> for InputParam {
    fn from(address: &TronAddress) -> Self {
        InputParam{param_type: "address".to_string(), param_value: address.to_token()}
    }
} 

impl From<U256> for InputParam {
    fn from(amount: U256) -> Self {
        InputParam{param_type: "uint256".to_string(), param_value: Token::Uint(amount)}
    }
} 


pub fn encode_fn(name: &str, inputs: &[InputParam]) -> Vec<u8> {
    let mut data = Vec::<u8>::new();
    let param_types = inputs.iter().map(|input|{
        input.param_type.as_str()
    }).collect::<Vec<&str>>().join(",");
    let function_selector = format!("{}({})", name, param_types);
    data.extend_from_slice( &keccak256(function_selector.as_bytes())[..4]);
    let tokens = inputs.iter().map(|input | input.param_value.clone()).collect::<Vec<Token>>();
    data.extend_from_slice(&encode(&tokens));
    data
}

pub fn encode_transfer(func_name: &str, address: &TronAddress, amount: U256) -> Vec<u8>{
    let inputs = vec![InputParam::from(address),InputParam::from(amount)];
    encode_fn(func_name, &inputs)
}

#[cfg(test)]
mod test_mod{
    use super::encode_fn;
    use super::InputParam;
    use ethabi::ethereum_types::U256;
    use crate::TronAddress;
    use hex;

    #[test]
    fn test_encode_fn(){
        let address: TronAddress = "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr".parse().unwrap();
        let inputs = vec![InputParam::from(&address),InputParam::from(U256::from_dec_str("20000000000000000000").unwrap())];
        let bytes = encode_fn("transfer", &inputs);
        assert_eq!("a9059cbb000000000000000000000041436d74fc1577266b7290b85801145d9c5287e194000000000000000000000000000000000000000000000001158e460913d00000",hex::encode(bytes))
    }
}