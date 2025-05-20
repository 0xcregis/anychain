use cml_chain::builders::input_builder::SingleInputBuilder;
use cml_chain::builders::output_builder::TransactionOutputBuilder;
use cml_chain::builders::tx_builder::{
    choose_change_selection_algo, ChangeSelectionAlgo, TransactionBuilder,
    TransactionBuilderConfigBuilder,
};
use cml_chain::crypto::hash::hash_transaction;
use cml_chain::crypto::utils::make_vkey_witness;
use cml_chain::fees::LinearFee;
use cml_chain::genesis::network_info::plutus_alonzo_cost_models;
use cml_chain::plutus::ExUnitPrices;
use cml_chain::transaction::{TransactionOutput, TransactionWitnessSet};
use cml_chain::utils::NetworkId;
use cml_chain::{SubCoin, Value};
use cml_core::serialization::Serialize;
use cml_crypto::{Ed25519Signature, RawBytesEncoding};

const MAX_VALUE_SIZE: u32 = 4000;
const MAX_TX_SIZE: u32 = 8000;

fn create_linear_fee(coefficient: u64, constant: u64) -> LinearFee {
    LinearFee::new(coefficient, constant, 0)
}

fn create_default_linear_fee() -> LinearFee {
    // create_linear_fee(500, 2)
    create_linear_fee(1000, 2)
}

fn create_tx_builder_full(
    linear_fee: LinearFee,
    pool_deposit: u64,
    key_deposit: u64,
    max_val_size: u32,
    coins_per_utxo_byte: u64,
) -> TransactionBuilder {
    let cfg = TransactionBuilderConfigBuilder::default()
        .fee_algo(linear_fee)
        .pool_deposit(pool_deposit)
        .key_deposit(key_deposit)
        .max_value_size(max_val_size)
        .max_tx_size(MAX_TX_SIZE)
        .coins_per_utxo_byte(coins_per_utxo_byte)
        .ex_unit_prices(ExUnitPrices::new(
            SubCoin::new(577, 10000),
            SubCoin::new(721, 10000000),
        ))
        .collateral_percentage(150)
        .max_collateral_inputs(3)
        .cost_models(plutus_alonzo_cost_models())
        .build()
        .unwrap();
    TransactionBuilder::new(cfg)
}

fn create_tx_builder(
    linear_fee: LinearFee,
    coins_per_utxo_byte: u64,
    pool_deposit: u64,
    key_deposit: u64,
) -> TransactionBuilder {
    create_tx_builder_full(
        linear_fee,
        pool_deposit,
        key_deposit,
        MAX_VALUE_SIZE,
        coins_per_utxo_byte,
    )
}

fn create_tx_builder_with_fee(linear_fee: LinearFee) -> TransactionBuilder {
    create_tx_builder(linear_fee, 1, 1, 1)
}

pub fn create_default_tx_builder() -> TransactionBuilder {
    create_tx_builder_with_fee(create_default_linear_fee())
}
