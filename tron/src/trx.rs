use core::panic;
use std::str::FromStr;
use chrono::Utc;
use chainlib_core::Error;
use ethabi::ethereum_types::U256;
use protobuf::EnumOrUnknown;
use protobuf::Message;
use protobuf::well_known_types::any::Any;
use crate::{
    abi, TronAddress,
    protocol::{
        balance_contract::{
            TransferContract,
            FreezeBalanceContract,
            UnfreezeBalanceContract,
        },
        Tron::transaction::{
            Contract,
            contract::ContractType,
        },
        common::ResourceCode,
        Tron::AccountType,
        account_contract::AccountCreateContract,
        smart_contract::TriggerSmartContract,
    },
};


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
impl_contract_pb_ext_for!(FreezeBalanceContract);
impl_contract_pb_ext_for!(UnfreezeBalanceContract);

fn to_resource_code(r: u8) -> ResourceCode {
    match r {
        0 => ResourceCode::BANDWIDTH,
        1 => ResourceCode::ENERGY,
        _ => panic!("Undefined resource"),
    }
}

pub fn timestamp_millis() -> i64 {
    Utc::now().timestamp_millis()
}

pub fn build_contract(ct: &impl ContractPbExt) -> Result<Contract, Error> {
    let mut contract = Contract::new();
    
    contract.type_ = ::protobuf::EnumOrUnknown::new(ct.contract_type());
    contract.parameter = ::protobuf::MessageField::some(
        ct.as_google_any().map_err(
            |e| Error::RuntimeError(e.to_string())
        )?
    );
    
    Ok(contract)
}

pub fn build_trigger_contract(
    owner: &str,
    contract: &str,
    data: Vec<u8>
) -> Result<Contract, Error> {
    let mut ts_contract = TriggerSmartContract::new();
    
    ts_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ts_contract.contract_address = TronAddress::from_str(contract)?.as_bytes().to_vec();
    ts_contract.data = data;
    
    build_contract(&ts_contract)
}

pub fn build_trc20_func_contract(
    owner: &str,
    contract: &str,
    func_name: &str,
    recipient: &str,
    amount: &str
) -> Result<Contract, Error> {
    let address = TronAddress::from_str(recipient)?;
    let amount = U256::from_dec_str(amount)
        .map_err(
            |e| Error::RuntimeError(e.to_string())
        )?;
    let data = abi::encode_transfer(func_name, &address, amount);
    
    build_trigger_contract(owner, contract, data)
}

pub fn build_trc20_transfer_contract(
    owner: &str,
    contract: &str,
    recipient: &str,
    amount: &str
) -> Result<Contract, Error> {
    build_trc20_func_contract(
        owner,
        contract,
        "transfer",
        recipient,
        amount,
    )
}

pub fn build_transfer_contract(
    owner: &str,
    recipient: &str,
    amount: &str,
) -> Result<Contract, Error> {
    let sender: TronAddress = owner.parse()?;
    let recipient: TronAddress = recipient.parse()?;

    let mut transfer_contract = TransferContract::new();
    
    transfer_contract.owner_address = sender.as_bytes().to_owned();
    transfer_contract.to_address = recipient.as_bytes().to_owned();
    transfer_contract.amount = amount.parse::<i64>()?;
    
    build_contract(&transfer_contract)
}

pub fn build_account_create(
    owner_addr: &str,
    create_addr: &str
) -> Result<Contract, Error> {
    let mut ac_contract = AccountCreateContract::new();
    
    ac_contract.owner_address = TronAddress::from_str(owner_addr)?.as_bytes().to_vec();
    ac_contract.account_address = TronAddress::from_str(create_addr)?.as_bytes().to_vec();
    ac_contract.type_ = EnumOrUnknown::<AccountType>::new(AccountType::Normal);
    
    build_contract(&ac_contract)
}

pub fn build_freeze_balance_contract(
    owner: &str,
    freeze_balance: &str,
    freeze_duration: &str,
    resource: u8,
    recipient: &str
) -> Result<Contract, Error> {
    let mut fb_contract = FreezeBalanceContract::new();

    fb_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    fb_contract.frozen_balance = freeze_balance.parse::<i64>()?;
    fb_contract.frozen_duration = freeze_duration.parse::<i64>()?;
    fb_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));
    fb_contract.receiver_address = TronAddress::from_str(recipient)?.as_bytes().to_vec();

    build_contract(&fb_contract)
}

pub fn build_unfreeze_balance_contract(
    owner: &str,
    resource: u8,
    recipient: &str,
) -> Result<Contract, Error> {
    let mut ub_contract = UnfreezeBalanceContract::new();

    ub_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ub_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));
    ub_contract.receiver_address = TronAddress::from_str(recipient)?.as_bytes().to_vec();

    build_contract(&ub_contract)
}
