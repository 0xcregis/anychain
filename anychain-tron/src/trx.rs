use crate::{
    abi,
    protocol::{
        account_contract::AccountCreateContract,
        balance_contract::{
            DelegateResourceContract, FreezeBalanceV2Contract, TransferContract,
            UnDelegateResourceContract, UnfreezeBalanceV2Contract,
        },
        common::ResourceCode,
        smart_contract::TriggerSmartContract,
        Tron::transaction::{contract::ContractType, Contract},
        Tron::AccountType,
    },
    TronAddress,
};
use anychain_core::Error;
use chrono::Utc;
use core::panic;
use protobuf::{well_known_types::any::Any, EnumOrUnknown, Message};
use std::str::FromStr;

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
impl_contract_pb_ext_for!(FreezeBalanceV2Contract);
impl_contract_pb_ext_for!(UnfreezeBalanceV2Contract);
impl_contract_pb_ext_for!(DelegateResourceContract);
impl_contract_pb_ext_for!(UnDelegateResourceContract);

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
        ct.as_google_any()
            .map_err(|e| Error::RuntimeError(e.to_string()))?,
    );

    Ok(contract)
}

pub fn build_trigger_contract(
    owner: &str,
    contract: &str,
    data: Vec<u8>,
) -> Result<Contract, Error> {
    let mut ts_contract = TriggerSmartContract::new();

    ts_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ts_contract.contract_address = TronAddress::from_str(contract)?.as_bytes().to_vec();
    ts_contract.data = data;

    build_contract(&ts_contract)
}

pub fn build_trc20_transfer_contract(
    owner: &str,
    contract: &str,
    recipient: &str,
    amount: &str,
) -> Result<Contract, Error> {
    build_trigger_contract(owner, contract, abi::trc20_transfer(recipient, amount))
}

pub fn build_trc20_approve_contract(
    owner: &str,
    contract: &str,
    recipient: &str,
    amount: &str,
) -> Result<Contract, Error> {
    build_trigger_contract(owner, contract, abi::trc20_approve(recipient, amount))
}

pub fn build_transfer_contract(
    owner: &str,
    recipient: &str,
    amount: &str,
) -> Result<Contract, Error> {
    let sender: TronAddress = owner.parse()?;
    let recipient: TronAddress = recipient.parse()?;

    let mut transfer_contract = TransferContract::new();

    sender
        .as_bytes()
        .clone_into(&mut transfer_contract.owner_address);
    recipient
        .as_bytes()
        .clone_into(&mut transfer_contract.to_address);
    transfer_contract.amount = amount.parse::<i64>()?;

    build_contract(&transfer_contract)
}

pub fn build_account_create(owner_addr: &str, create_addr: &str) -> Result<Contract, Error> {
    let mut ac_contract = AccountCreateContract::new();

    ac_contract.owner_address = TronAddress::from_str(owner_addr)?.as_bytes().to_vec();
    ac_contract.account_address = TronAddress::from_str(create_addr)?.as_bytes().to_vec();
    ac_contract.type_ = EnumOrUnknown::<AccountType>::new(AccountType::Normal);

    build_contract(&ac_contract)
}

pub fn build_freeze_balance_v2_contract(
    owner: &str,
    freeze_balance: &str,
    resource: u8,
) -> Result<Contract, Error> {
    let mut fb_v2_contract = FreezeBalanceV2Contract::new();

    fb_v2_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    fb_v2_contract.frozen_balance = freeze_balance.parse::<i64>()?;
    fb_v2_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));

    build_contract(&fb_v2_contract)
}

pub fn build_unfreeze_balance_v2_contract(
    owner: &str,
    unfreeze_balance: &str,
    resource: u8,
) -> Result<Contract, Error> {
    let mut ub_v2_contract = UnfreezeBalanceV2Contract::new();

    ub_v2_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ub_v2_contract.unfreeze_balance = unfreeze_balance.parse::<i64>()?;
    ub_v2_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));

    build_contract(&ub_v2_contract)
}

pub fn build_delegate_resource_contract(
    owner: &str,
    recipient: &str,
    resource: u8,
    amount: &str,
    lock: bool,
) -> Result<Contract, Error> {
    let mut dr_contract = DelegateResourceContract::new();

    dr_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    dr_contract.receiver_address = TronAddress::from_str(recipient)?.as_bytes().to_vec();
    dr_contract.balance = amount.parse::<i64>()?;
    dr_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));
    dr_contract.lock = lock;

    build_contract(&dr_contract)
}

pub fn build_undelegate_resource_contract(
    owner: &str,
    recipient: &str,
    resource: u8,
    amount: &str,
) -> Result<Contract, Error> {
    let mut ur_contract = UnDelegateResourceContract::new();

    ur_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    ur_contract.receiver_address = TronAddress::from_str(recipient)?.as_bytes().to_vec();
    ur_contract.balance = amount.parse::<i64>()?;
    ur_contract.resource = EnumOrUnknown::<ResourceCode>::new(to_resource_code(resource));

    build_contract(&ur_contract)
}
