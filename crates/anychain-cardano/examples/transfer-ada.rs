use blockfrost::{BlockFrostSettings, BlockfrostAPI, BlockfrostResult, Pagination};
// use cml_chain::builders::tx_builder::TransactionUnspentOutput;
use cml_chain::transaction::TransactionInput;
use cml_crypto::TransactionHash;

//  const MNEMONIC_ALICE: &str = "oak anchor meadow nerve limb true banner lock arena brisk width lottery frame walnut barrel innocent enhance feature one gate parade small alert hollow";
const MNEMONIC_ALICE: &str = "toe deal rival umbrella oak inch water hover option lawn essence panda wealth morning summer change soon casino spot decline rural unknown quarter disagree";
//  const MNEMONIC_BOB: &str = "oak anchor meadow nerve limb true banner lock arena brisk width lottery frame walnut barrel innocent enhance feature one gate parade small alert hollow";
const MNEMONIC_BOB: &str = "rifle suffer defense test system measure dismiss ketchup enemy all iron clean assist tail rule razor cup source divert field that spatial food drop";

struct CardanoTransactionParameters {
    send_address: cml_chain::address::Address, // Sender's address
    recv_address: cml_chain::address::Address, // Receiver's address
    sender_private_key: String,                // Sender's private key
    amount: u64,                               // Amount to transfer in lovelace
    ttl: u64,                                  // Time-to-live (slot number)
    transaction_input: TransactionInput,       // Transaction hash
    transaction_output_amount: u64,
}

mod generating_keys {
    use bip39::Mnemonic;
    use cml_chain::address::{Address, BaseAddress};
    use cml_chain::certs::StakeCredential;
    use cml_chain::genesis::network_info::NetworkInfo;
    use cml_crypto::{Bip32PrivateKey, Bip32PublicKey};

    fn derive_key(
        private_key: &Bip32PrivateKey,
        account: u32,
        chain: u32,
        index: u32,
    ) -> Bip32PublicKey {
        private_key
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(account))
            .derive(chain)
            .derive(index)
            .to_public()
    }

    pub fn create_account(mnemonic_str: &str) -> Address {
        // Parse the mnemonic
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
            .unwrap_or_else(|e| panic!("Failed to parse mnemonic: {:?}", e));

        // Derive entropy and private key
        let entropy = mnemonic.to_entropy();
        let bip32_private_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);

        // Derive spend and stake keys
        let spend = derive_key(&bip32_private_key, 0, 0, 0);
        let stake = derive_key(&bip32_private_key, 0, 2, 0);

        // Create base address
        let spend_cred = StakeCredential::new_pub_key(spend.to_raw_key().hash());
        let stake_cred = StakeCredential::new_pub_key(stake.to_raw_key().hash());
        BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            spend_cred.clone(),
            stake_cred.clone(),
        )
        .to_address()
    }
    pub fn create_signing_key(mnemonic_str: &str) -> String {
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
            .unwrap_or_else(|e| panic!("Failed to parse mnemonic: {:?}", e));
        let entropy = mnemonic.to_entropy();
        let bip32_private_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);
        bip32_private_key
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_raw_key()
            .to_bech32()
    }

    fn harden(index: u32) -> u32 {
        index | 0x80_00_00_00
    }
}
mod tx_builder {
    use super::CardanoTransactionParameters;
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

    fn create_default_tx_builder() -> TransactionBuilder {
        create_tx_builder_with_fee(create_default_linear_fee())
    }

    pub fn build_tx_with_change(params: &CardanoTransactionParameters) -> Vec<u8> {
        let mut tx_builder = create_default_tx_builder();

        let input = {
            SingleInputBuilder::new(
                params.transaction_input.clone(),
                TransactionOutput::new(
                    params.send_address.clone(),
                    Value::from(params.transaction_output_amount),
                    None,
                    None,
                ),
            )
            .payment_key()
            .unwrap()
        };

        tx_builder.add_input(input).unwrap();

        tx_builder
            .add_output(
                TransactionOutputBuilder::new()
                    .with_address(params.recv_address.clone())
                    .next()
                    .unwrap()
                    .with_value(params.amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        // TODO: set fee
        tx_builder.set_ttl(params.ttl + 200);

        let change_addr = params.send_address.clone();

        let added_change = choose_change_selection_algo(ChangeSelectionAlgo::Default)(
            &mut tx_builder,
            &change_addr,
            false,
        );

        assert!(added_change.is_ok());
        assert!(added_change.unwrap());

        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::from(tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );

        // assert_eq!(tx_builder.full_size().unwrap(), 294);
        // assert_eq!(tx_builder.output_sizes(), vec![65, 65]);

        // TODO: set network id
        tx_builder.set_network_id(NetworkId::testnet());

        let final_tx = tx_builder.build(ChangeSelectionAlgo::Default, &change_addr);

        assert!(final_tx.is_ok());

        let final_tx_builder = final_tx.unwrap();
        let body = final_tx_builder.body();

        let mut witness_set = TransactionWitnessSet::new();

        let alice_private_key =
            cml_crypto::PrivateKey::from_bech32(&params.sender_private_key).unwrap();

        witness_set.vkeywitnesses = Some(
            vec![make_vkey_witness(
                &hash_transaction(&body),
                &alice_private_key,
            )]
            .into(),
        );

        let final_tx = cml_chain::transaction::Transaction::new(body, witness_set, true, None);
        let hex_encoded = hex::encode(final_tx.to_cbor_bytes());
        dbg!("Hex Encoded Transaction: {}", hex_encoded);

        final_tx.to_cbor_bytes()
    }
}

#[tokio::main]
async fn main() -> BlockfrostResult<()> {
    let address_alice = generating_keys::create_account(MNEMONIC_ALICE);
    let address_bob = generating_keys::create_account(MNEMONIC_BOB);

    let api = BlockfrostAPI::new(
        "preprodwYU86nDDxOQKRAkTvp660AQu2pxLfh9l",
        BlockFrostSettings::new(),
    );

    assert_eq!(
        address_alice.to_bech32(None).unwrap(),
        "addr_test1qztenh2rujsa47xgz0u53rjm4ape6urd4yua4f8u6h3rz2lg3cfqlr49zru49t7ejlwjxsdhy9rdafs3fs2yc2egzjeqfqgg4z"
    );
    assert_eq!(
        address_bob.to_bech32(None).unwrap(),
        "addr_test1qravems9gq7fqnnsx4u2eqpmx6v7d0h65slk0lsfpwhwew83s0t8du45gf8w86q27kadzqjwszck4hvf4avhjqu3l2esuqsd00"
    );

    /*
    let address = "addr_test1qp5tjpeph2su74qrg60se276u6zvd90umxmctufxr0jf8gr7dsy677qxztemp72yqgu3xv35w2fts5c5k2c9szlrn5fqttkd5z";
    let addresses = api.addresses(address).await;
    let addresses_total = api.addresses_total(address).await;
    let addresses_utxos = api.addresses_utxos(address, Pagination::default()).await;
    dbg!(&addresses);
    dbg!(&addresses_total);
    dbg!(&addresses_utxos);
     */

    let alice_address_content = api
        .addresses(&address_alice.to_bech32(None).unwrap())
        .await?;

    //print alice and bob address content in mutiple lines
    println!("Alice Address Content:");
    for amount in alice_address_content.amount {
        println!("{:?}", amount);
    }

    if let Ok(bob_address_content) = api.addresses(&address_bob.to_bech32(None).unwrap()).await {
        println!("Bob Address Content:");
        for amount in bob_address_content.amount {
            println!("{:?}", amount);
        }
    } else {
        println!("Bob address not found");
    }

    let slot = api.blocks_latest().await;
    let slot = slot?.slot.unwrap() as u64;

    let alice_utxos = api
        .addresses_utxos(&address_alice.to_bech32(None).unwrap(), Pagination::all())
        .await?;

    let alice_utxo = alice_utxos[0].clone();
    println!(
        "Alice UTXOs: {}:{}, {:?}",
        alice_utxo.tx_hash, alice_utxo.output_index, alice_utxo
    );

    let params = CardanoTransactionParameters {
        send_address: address_alice,
        recv_address: address_bob,
        sender_private_key: generating_keys::create_signing_key(MNEMONIC_ALICE),
        amount: 10_000_000,
        ttl: slot,
        transaction_input: TransactionInput::new(
            TransactionHash::from_hex(&alice_utxo.tx_hash).unwrap(),
            alice_utxo.output_index as u64,
        ),
        transaction_output_amount: alice_utxo
            .amount
            .iter()
            .find(|u| u.unit == "lovelace")
            .unwrap()
            .quantity
            .parse()
            .unwrap(),
    };

    // Should contain the correct cbor contents
    let transaction_data = tx_builder::build_tx_with_change(&params);
    let transaction_hash = api.transactions_submit(transaction_data).await?;
    dbg!(&transaction_hash);
    // println!("{}", transaction_hash);

    Ok(())
}
