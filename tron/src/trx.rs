use protobuf::EnumOrUnknown;
use protobuf::Message;
use protobuf::well_known_types::any::Any;
use crate::protocol::Tron::AccountType;
use crate::protocol::account_contract::AccountCreateContract;
use crate::protocol::balance_contract::TransferContract;
use crate::protocol::smart_contract::TriggerSmartContract;
use chrono::Utc;
use crate::protocol::Tron::transaction::{
    Contract,
    contract::ContractType,
};
use chainlib_core::Error;
use crate::TronAddress;
use std::str::FromStr;
use ethabi::ethereum_types::U256;
use crate::abi;

pub fn timestamp_millis() -> i64 {
    Utc::now().timestamp_millis()
}


pub fn build_transfer_contract(owner: &str, recipient: &str, amount: i64) -> Result<Contract,Error> {
    let sender : TronAddress = owner.parse()?;
    let recipient : TronAddress = recipient.parse()?;

    let mut transfer_contract = TransferContract::new();
    transfer_contract.owner_address =  sender.as_bytes().to_owned();
    transfer_contract.to_address = recipient.as_bytes().to_owned();
    transfer_contract.amount =  amount;
    
    build_contract(&transfer_contract)
}

pub fn build_trc20_func_contract(owner: &str , contract: &str,func_name: &str, recipient: &str, amount :&str) -> Result<Contract,Error> {
    let address = TronAddress::from_str(recipient)?;
    let amount = U256::from_dec_str(amount).map_err(|e| Error::RuntimeError(e.to_string()))?;
    let data = abi::encode_transfer(func_name, &address, amount);
    build_trigger_contract(owner,contract, data)
}

pub fn build_trc20_transfer_contract(owner: &str , contract: &str, recipient: &str, amount :&str) -> Result<Contract,Error> {
    build_trc20_func_contract(owner, contract, "transfer", recipient, amount)
}

pub fn build_trigger_contract(owner: &str, contract: &str, data: Vec<u8>) -> Result<Contract,Error>{
    let mut ts_contract = TriggerSmartContract::new();
    ts_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ts_contract.contract_address = TronAddress::from_str(contract)?.as_bytes().to_vec();
    ts_contract.data = data;
    build_contract(&ts_contract)
}

pub fn build_account_create(owner_addr: &str , create_addr: &str) -> Result<Contract,Error>{
    let mut account_create = AccountCreateContract::new();
    account_create.owner_address = TronAddress::from_str(owner_addr)?.as_bytes().to_vec();
    account_create.account_address = TronAddress::from_str(create_addr)?.as_bytes().to_vec();
    account_create.type_ = EnumOrUnknown::<AccountType>::new(AccountType::Normal);
    build_contract(&account_create)
}

pub fn build_contract(ct: &impl ContractPbExt) -> Result<Contract,Error> {
    let mut contract = Contract::new();
    contract.type_ = ::protobuf::EnumOrUnknown::new(ct.contract_type());
    contract.parameter = ::protobuf::MessageField::some(ct.as_google_any().map_err(|e| Error::RuntimeError(e.to_string()))?);
    Ok(contract)
}



pub trait ContractPbExt: Message {
    fn contract_type(&self) -> ContractType;

    /// Convert Pb to protobuf::well_known_types::Any
    fn as_google_any(&self) -> Result<Any, protobuf::Error> {
        Ok(Any {
            type_url: format!("type.googleapis.com/protocol.{:?}", self.contract_type()),
            value: self.write_to_bytes()?,
            ..Default::default()
        })
    }
}

macro_rules! impl_contract_pb_ext_for {
    ($contract_ty:ident) => {
        impl ContractPbExt for $contract_ty {
            fn contract_type(&self) -> ContractType {
                ContractType::$contract_ty
            }
        }
    };
}

impl_contract_pb_ext_for!(TransferContract);
impl_contract_pb_ext_for!(TriggerSmartContract);
impl_contract_pb_ext_for!(AccountCreateContract);