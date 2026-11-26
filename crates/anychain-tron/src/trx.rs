use crate::{
    abi,
    protocol::{
        account_contract::{AccountCreateContract, AccountPermissionUpdateContract},
        balance_contract::{
            CancelAllUnfreezeV2Contract, DelegateResourceContract, FreezeBalanceV2Contract,
            TransferContract, UnDelegateResourceContract, UnfreezeBalanceV2Contract,
            WithdrawBalanceContract, WithdrawExpireUnfreezeContract,
        },
        common::ResourceCode,
        smart_contract::TriggerSmartContract,
        witness_contract::{vote_witness_contract::Vote, VoteWitnessContract},
        Tron::{
            permission::PermissionType,
            transaction::{contract::ContractType, Contract},
            AccountType, Key, Permission,
        },
    },
    TronAddress,
};
use anychain_core::Error;
use core::panic;
use jiff::Timestamp;
use protobuf::{well_known_types::any::Any, Enum, EnumOrUnknown, Message, MessageField};
use std::collections::HashSet;
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
impl_contract_pb_ext_for!(CancelAllUnfreezeV2Contract);
impl_contract_pb_ext_for!(WithdrawExpireUnfreezeContract);
impl_contract_pb_ext_for!(VoteWitnessContract);
impl_contract_pb_ext_for!(WithdrawBalanceContract);
impl_contract_pb_ext_for!(AccountPermissionUpdateContract);

/// Default TRON active permission operations bitmask (32 bytes):
/// Enables standard active contract types (0..=6, 8..=20, 30..=33, 41..=45, 48..=49, 54..=59),
/// excluding AccountPermissionUpdateContract (46), ShieldedTransferContract (51),
/// and Market DEX contracts (52, 53).
pub const DEFAULT_ACTIVE_OPERATIONS: [u8; 32] = [
    0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e, 0xc3, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Encodes a slice of TRON `ContractType`s into a 32-byte operations bitmask.
pub fn encode_permission_operations(contract_types: &[ContractType]) -> Vec<u8> {
    let mut ops = [0u8; 32];
    for ct in contract_types {
        let id = Enum::value(ct);
        if (0..256).contains(&id) {
            ops[(id / 8) as usize] |= 1u8 << ((id % 8) as u32);
        }
    }
    ops.to_vec()
}

/// Decodes a 32-byte TRON active permission operations bitmask into `ContractType`s.
pub fn decode_permission_operations(operations: &[u8]) -> Result<Vec<ContractType>, Error> {
    if operations.len() != 32 {
        return Err(Error::RuntimeError(format!(
            "operations must be 32 bytes, got {}",
            operations.len()
        )));
    }

    let mut result = Vec::new();
    for (byte_idx, &byte) in operations.iter().enumerate() {
        for bit_idx in 0..8 {
            if (byte & (1u8 << bit_idx)) != 0 {
                let id = (byte_idx * 8 + bit_idx) as i32;
                if let Some(ct) = ContractType::from_i32(id) {
                    result.push(ct);
                }
            }
        }
    }
    Ok(result)
}

/// Configuration for building a TRON account `Permission` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionConfig {
    pub permission_name: String,
    pub threshold: i64,
    pub keys: Vec<(String, i64)>,
    pub operations: Vec<u8>,
}

impl PermissionConfig {
    /// Creates a standard single-signature Owner permission for `owner`.
    pub fn default_owner(owner: &str) -> Self {
        Self {
            permission_name: "owner".to_string(),
            threshold: 1,
            keys: vec![(owner.to_string(), 1)],
            operations: Vec::new(),
        }
    }

    /// Creates a standard single-signature default Active permission for `owner`.
    pub fn default_active(owner: &str) -> Self {
        Self {
            permission_name: "active".to_string(),
            threshold: 1,
            keys: vec![(owner.to_string(), 1)],
            operations: DEFAULT_ACTIVE_OPERATIONS.to_vec(),
        }
    }

    /// Creates a single-address Active permission with the given `contract_types`.
    pub fn single_active(
        permission_name: &str,
        address: &str,
        contract_types: &[ContractType],
    ) -> Self {
        Self {
            permission_name: permission_name.to_string(),
            threshold: 1,
            keys: vec![(address.to_string(), 1)],
            operations: encode_permission_operations(contract_types),
        }
    }
}

fn to_resource_code(r: u8) -> ResourceCode {
    match r {
        0 => ResourceCode::BANDWIDTH,
        1 => ResourceCode::ENERGY,
        _ => panic!("Undefined resource"),
    }
}

pub fn timestamp_millis() -> i64 {
    Timestamp::now().as_millisecond()
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

pub fn build_cancel_unfreeze_contract(owner: &str) -> Result<Contract, Error> {
    let mut cu_contract = CancelAllUnfreezeV2Contract::new();
    cu_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    build_contract(&cu_contract)
}

pub fn build_withdraw_unfreeze_contract(owner: &str) -> Result<Contract, Error> {
    let mut wu_contract = WithdrawExpireUnfreezeContract::new();
    wu_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    build_contract(&wu_contract)
}

pub fn build_vote_witness_contract(
    owner: &str,
    votes: Vec<(&str, i64)>,
    support: bool,
) -> Result<Contract, Error> {
    let mut vw_contract = VoteWitnessContract::new();
    vw_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    vw_contract.support = support;

    vw_contract.votes = votes
        .iter()
        .map(|&(addr, vote_count)| {
            let mut vote = Vote::new();
            let addr = TronAddress::from_str(addr).unwrap().as_bytes().to_vec();
            vote.vote_address = addr;
            vote.vote_count = vote_count;
            vote
        })
        .collect::<Vec<Vote>>();

    build_contract(&vw_contract)
}

pub fn build_withdraw_vote_contract(owner: &str) -> Result<Contract, Error> {
    let mut wb_contract = WithdrawBalanceContract::new();
    wb_contract.owner_address = TronAddress::from_str(owner)?.as_bytes().to_vec();
    build_contract(&wb_contract)
}

fn build_permission(
    config: PermissionConfig,
    perm_type: PermissionType,
    id: i32,
) -> Result<Permission, Error> {
    if config.permission_name.len() > 32 {
        return Err(Error::RuntimeError(
            "permission_name length must not exceed 32 bytes".to_string(),
        ));
    }
    if config.threshold <= 0 {
        return Err(Error::RuntimeError(
            "permission threshold must be positive".to_string(),
        ));
    }
    if config.keys.is_empty() || config.keys.len() > 5 {
        return Err(Error::RuntimeError(
            "permission keys count must be between 1 and 5".to_string(),
        ));
    }

    let mut seen_addrs = HashSet::with_capacity(config.keys.len());
    let mut weight_sum: i64 = 0;
    let mut keys = Vec::with_capacity(config.keys.len());

    for (addr, weight) in config.keys {
        if weight <= 0 {
            return Err(Error::RuntimeError(
                "permission key weight must be positive".to_string(),
            ));
        }
        let addr_bytes = TronAddress::from_str(&addr)?.as_bytes().to_vec();
        if !seen_addrs.insert(addr_bytes.clone()) {
            return Err(Error::RuntimeError(
                "duplicate key address in permission".to_string(),
            ));
        }
        weight_sum = weight_sum
            .checked_add(weight)
            .ok_or_else(|| Error::RuntimeError("permission key weight sum overflow".to_string()))?;

        let mut key = Key::new();
        key.address = addr_bytes;
        key.weight = weight;
        keys.push(key);
    }

    if weight_sum < config.threshold {
        return Err(Error::RuntimeError(
            "sum of key weights must be >= threshold".to_string(),
        ));
    }

    match perm_type {
        PermissionType::Owner | PermissionType::Witness => {
            if !config.operations.is_empty() {
                return Err(Error::RuntimeError(
                    "non-active permission must not specify operations".to_string(),
                ));
            }
        }
        PermissionType::Active => {
            if config.operations.len() != 32 {
                return Err(Error::RuntimeError(
                    "active permission operations must be 32 bytes".to_string(),
                ));
            }
            if !config.operations.iter().any(|&b| b != 0) {
                return Err(Error::RuntimeError(
                    "active permission operations must not be empty".to_string(),
                ));
            }
        }
    }

    let mut perm = Permission::new();
    perm.type_ = EnumOrUnknown::new(perm_type);
    perm.id = id;
    perm.permission_name = config.permission_name;
    perm.threshold = config.threshold;
    perm.parent_id = 0;
    perm.operations = config.operations;
    perm.keys = keys;
    Ok(perm)
}

/// Builds a TRON `AccountPermissionUpdateContract`.
pub fn build_account_permission_update_contract(
    owner: &str,
    owner_permission: PermissionConfig,
    actives: Vec<PermissionConfig>,
) -> Result<Contract, Error> {
    let owner_bytes = TronAddress::from_str(owner)?.as_bytes().to_vec();
    if actives.is_empty() || actives.len() > 8 {
        return Err(Error::RuntimeError(
            "actives count must be between 1 and 8".to_string(),
        ));
    }

    let owner_perm = build_permission(owner_permission, PermissionType::Owner, 0)?;
    let active_perms = actives
        .into_iter()
        .enumerate()
        .map(|(idx, cfg)| build_permission(cfg, PermissionType::Active, 2 + idx as i32))
        .collect::<Result<Vec<_>, _>>()?;

    let mut apu_contract = AccountPermissionUpdateContract::new();
    apu_contract.owner_address = owner_bytes;
    apu_contract.owner = MessageField::some(owner_perm);
    apu_contract.witness = MessageField::none();
    apu_contract.actives = active_perms;

    build_contract(&apu_contract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TronTransaction, TronTransactionParameters};
    use anychain_core::Transaction;

    const OWNER_ADDR: &str = "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm";
    const AUTH_ADDR: &str = "TGn4LVcWSPtnFev44viMNnwDfxnLa9zBQW";

    #[test]
    fn test_permission_operations_bitmask() {
        let ops_two = encode_permission_operations(&[
            ContractType::DelegateResourceContract,
            ContractType::UnDelegateResourceContract,
        ]);
        assert_eq!(
            hex::encode(&ops_two),
            "0000000000000006000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            decode_permission_operations(&ops_two).unwrap(),
            vec![
                ContractType::DelegateResourceContract,
                ContractType::UnDelegateResourceContract,
            ]
        );

        let ops_three = encode_permission_operations(&[
            ContractType::TransferContract,
            ContractType::DelegateResourceContract,
            ContractType::UnDelegateResourceContract,
        ]);
        assert_eq!(
            hex::encode(&ops_three),
            "0200000000000006000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            decode_permission_operations(&ops_three).unwrap(),
            vec![
                ContractType::TransferContract,
                ContractType::DelegateResourceContract,
                ContractType::UnDelegateResourceContract,
            ]
        );

        let default_ops = decode_permission_operations(&DEFAULT_ACTIVE_OPERATIONS).unwrap();
        assert!(default_ops.contains(&ContractType::TransferContract));
        assert!(default_ops.contains(&ContractType::TriggerSmartContract));
        assert!(default_ops.contains(&ContractType::FreezeBalanceV2Contract));
        assert!(default_ops.contains(&ContractType::DelegateResourceContract));
        assert!(default_ops.contains(&ContractType::UnDelegateResourceContract));
        assert!(!default_ops.contains(&ContractType::AccountPermissionUpdateContract));
        assert!(!default_ops.contains(&ContractType::ShieldedTransferContract));
    }

    #[test]
    fn test_account_permission_update_round_trip() {
        let contract = build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![
                PermissionConfig::default_active(OWNER_ADDR),
                PermissionConfig::single_active(
                    "collect",
                    AUTH_ADDR,
                    &[
                        ContractType::DelegateResourceContract,
                        ContractType::UnDelegateResourceContract,
                    ],
                ),
            ],
        )
        .unwrap();

        let mut param = TronTransactionParameters::default();
        param.set_timestamp(1719572137182);
        param.set_ref_block(
            43785827,
            "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        );
        param.set_contract(contract);

        let tx = TronTransaction::new(&param).unwrap();
        let bytes = tx.to_bytes().unwrap();
        let decoded_tx = TronTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded_tx.data.contract.type_.unwrap(),
            ContractType::AccountPermissionUpdateContract
        );

        let raw_any = decoded_tx.data.contract.parameter.unwrap();
        let apu = AccountPermissionUpdateContract::parse_from_bytes(&raw_any.value).unwrap();
        assert_eq!(
            TronAddress::from_bytes(&apu.owner_address)
                .unwrap()
                .to_string(),
            OWNER_ADDR
        );
        assert!(apu.witness.is_none());

        let owner_perm = apu.owner.unwrap();
        assert_eq!(owner_perm.id, 0);
        assert_eq!(owner_perm.permission_name, "owner");
        assert_eq!(owner_perm.threshold, 1);
        assert_eq!(owner_perm.keys.len(), 1);
        assert_eq!(
            TronAddress::from_bytes(&owner_perm.keys[0].address)
                .unwrap()
                .to_string(),
            OWNER_ADDR
        );

        assert_eq!(apu.actives.len(), 2);
        assert_eq!(apu.actives[0].id, 2);
        assert_eq!(apu.actives[0].permission_name, "active");
        assert_eq!(apu.actives[0].operations, DEFAULT_ACTIVE_OPERATIONS);
        assert_eq!(apu.actives[1].id, 3);
        assert_eq!(apu.actives[1].permission_name, "collect");
        assert_eq!(apu.actives[1].threshold, 1);
        assert_eq!(apu.actives[1].keys.len(), 1);
        assert_eq!(apu.actives[1].keys[0].weight, 1);
        assert_eq!(
            TronAddress::from_bytes(&apu.actives[1].keys[0].address)
                .unwrap()
                .to_string(),
            AUTH_ADDR
        );
        assert_eq!(
            decode_permission_operations(&apu.actives[1].operations).unwrap(),
            vec![
                ContractType::DelegateResourceContract,
                ContractType::UnDelegateResourceContract,
            ]
        );

        // Reset / delete custom permissions (keep only default active)
        let reset_contract = build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![PermissionConfig::default_active(OWNER_ADDR)],
        )
        .unwrap();
        let reset_any = reset_contract.parameter.unwrap();
        let reset_apu =
            AccountPermissionUpdateContract::parse_from_bytes(&reset_any.value).unwrap();
        assert_eq!(reset_apu.actives.len(), 1);
        assert_eq!(reset_apu.actives[0].id, 2);
    }

    #[test]
    fn test_account_permission_update_validation_errors() {
        // Empty actives
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![],
        )
        .is_err());

        // More than 8 actives
        let too_many = (0..9)
            .map(|_| PermissionConfig::default_active(OWNER_ADDR))
            .collect();
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            too_many,
        )
        .is_err());

        // permission_name > 32 bytes
        let long_name = "a".repeat(33);
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![PermissionConfig::single_active(
                &long_name,
                AUTH_ADDR,
                &[ContractType::TransferContract],
            )],
        )
        .is_err());

        // Empty / all-zero active operations
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![PermissionConfig::single_active("empty", AUTH_ADDR, &[])],
        )
        .is_err());

        // Non-empty owner operations
        let mut bad_owner = PermissionConfig::default_owner(OWNER_ADDR);
        bad_owner.operations = vec![0u8; 32];
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            bad_owner,
            vec![PermissionConfig::default_active(OWNER_ADDR)],
        )
        .is_err());

        // Duplicate keys
        let mut dup_keys = PermissionConfig::default_active(OWNER_ADDR);
        dup_keys.keys.push((OWNER_ADDR.to_string(), 1));
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![dup_keys],
        )
        .is_err());

        // Weight <= 0
        let mut zero_weight = PermissionConfig::default_active(OWNER_ADDR);
        zero_weight.keys[0].1 = 0;
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![zero_weight],
        )
        .is_err());

        // Threshold <= 0
        let mut zero_threshold = PermissionConfig::default_active(OWNER_ADDR);
        zero_threshold.threshold = 0;
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![zero_threshold],
        )
        .is_err());

        // Weight sum < threshold
        let mut insufficient_weight = PermissionConfig::default_active(OWNER_ADDR);
        insufficient_weight.threshold = 2;
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![insufficient_weight],
        )
        .is_err());

        // Invalid TRON address
        assert!(build_account_permission_update_contract(
            OWNER_ADDR,
            PermissionConfig::default_owner(OWNER_ADDR),
            vec![PermissionConfig::single_active(
                "bad",
                "invalid_address",
                &[ContractType::TransferContract],
            )],
        )
        .is_err());
    }
}
