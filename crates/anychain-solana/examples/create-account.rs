#![allow(deprecated)]

use bip39::{Mnemonic, Seed};
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    hash::Hash,
    pubkey::Pubkey,
    signature::Signer,
    signer::{
        keypair::Keypair,
        keypair::{keypair_from_seed, keypair_from_seed_and_derivation_path},
    },
    transaction::Transaction,
};
use solana_sdk_ids::system_program;
use solana_system_interface::instruction as system_instruction;
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use std::str::FromStr;

pub fn generate_keypair_from_mnemonic(mnemonic_str: &str) -> Keypair {
    let language = bip39::Language::English;
    let mnemonic = Mnemonic::from_phrase(mnemonic_str, language).unwrap();
    let passphrase = "";
    let seed = Seed::new(&mnemonic, passphrase);

    let derivation_path = None;
    match derivation_path {
        Some(_) => keypair_from_seed_and_derivation_path(seed.as_bytes(), derivation_path),
        None => keypair_from_seed(seed.as_bytes()),
    }
    .unwrap()
}

/// use a single invocation of SystemInstruction::CreateAccount to create a new account,
/// allocate some space, transfer it the minimum lamports for rent exemption,
/// and assign it to the system program
pub fn create_account(
    rpc_client: &RpcClient,
    payer: &Keypair,
    recent_blockhash: Hash,
    new_account: &Keypair,
    space: usize,
) -> anyhow::Result<()> {
    let rent = rpc_client.get_minimum_balance_for_rent_exemption(space)?;

    let create_instruction = system_instruction::create_account(
        &payer.pubkey(),
        &new_account.pubkey(),
        rent,
        space as u64,
        &system_program::ID,
    );

    let transaction = Transaction::new_signed_with_payer(
        &[create_instruction],
        Some(&payer.pubkey()),
        &[payer, new_account],
        recent_blockhash,
    );

    let sig = rpc_client.send_and_confirm_transaction(&transaction)?;
    println!("{sig}");

    Ok(())
}

pub fn create_token_account(
    rpc_client: &RpcClient,
    payer: &Keypair,
    recent_blockhash: Hash,
    new_account: &Pubkey,
    token_mint_address: &Pubkey,
) -> anyhow::Result<()> {
    // let expected_token_account_len = 165; // Account::LEN;
    // let expected_token_account_balance =
    // rpc_client.get_minimum_balance_for_rent_exemption(expected_token_account_len)?;

    let create_instruction = create_associated_token_account(
        &payer.pubkey(),
        new_account,
        token_mint_address,
        &spl_token::ID,
    );
    let mut transaction = Transaction::new_with_payer(&[create_instruction], Some(&payer.pubkey()));
    transaction.sign(&[payer], recent_blockhash);

    let sig = rpc_client.send_and_confirm_transaction(&transaction);
    dbg!(&sig);

    Ok(())
}

pub fn transfer_spl_token(
    rpc_client: &RpcClient,
    from_keypair: &Keypair,
    to_pubkey: &Pubkey,
    mint_authority: &Pubkey,
    amount: u64,
) -> anyhow::Result<()> {
    let blockhash = rpc_client.get_latest_blockhash().unwrap();

    let associated_token_address_source =
        get_associated_token_address(&from_keypair.pubkey(), mint_authority);
    let associated_token_address_destination =
        get_associated_token_address(to_pubkey, mint_authority);

    dbg!(
        "Associated token address for Source: {}",
        associated_token_address_source
    );
    dbg!(
        "Associated token address for Destination: {}",
        associated_token_address_destination
    );

    // Create a transfer instruction
    let transfer_instruction = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &associated_token_address_source,
        mint_authority,
        &associated_token_address_destination,
        &from_keypair.pubkey(),
        &[],
        amount,
        6,
    )
    .unwrap();

    // Create a transaction
    let mut transaction =
        Transaction::new_with_payer(&[transfer_instruction], Some(&from_keypair.pubkey()));

    // Sign the transaction
    transaction.sign(&[from_keypair], blockhash);

    // Send the transaction to the Solana network
    let _sig = rpc_client.send_and_confirm_transaction(&transaction)?;
    dbg!(&_sig);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let rpc_client = RpcClient::new("https://api.testnet.solana.com".to_string());
    let alice_keypair = Keypair::try_from(
        [
            41, 196, 252, 146, 80, 100, 13, 46, 69, 89, 172, 157, 224, 135, 23, 62, 54, 65, 52, 68,
            14, 50, 112, 112, 156, 210, 24, 236, 139, 169, 38, 63, 205, 66, 112, 255, 116, 177, 79,
            182, 192, 20, 240, 193, 219, 162, 23, 149, 26, 247, 181, 186, 145, 168, 26, 232, 228,
            76, 102, 109, 64, 189, 172, 44,
        ]
        .as_ref(),
    )
    .unwrap();

    let alice_pubkey: Pubkey = alice_keypair.pubkey();
    assert_eq!(
        "EpFLfuH524fk9QP9i9uL9AHtX6smBaxaMHwek9T11nK5",
        alice_pubkey.to_string()
    );

    let bob_keypair = generate_keypair_from_mnemonic(
        "tide label income foot rather novel erupt cattle dignity tag robot intact",
    );
    let bob_pubkey: Pubkey = bob_keypair.pubkey();
    assert_eq!(
        "FrnopYkANcjm98sHme5pAUcnfTGQBnJi3ZbLK2khFwjK",
        bob_pubkey.to_string()
    );

    let res = rpc_client.get_account(&bob_pubkey);
    match res {
        Ok(account_info) => println!("Account found: {account_info:?}"),
        Err(e) => match e.kind() {
            /*
            Bob Solana Account does not exist
            this case won't happen in cregis or anychain-solana wallet

            Alice creates and funds Bob's account:
            - Alice can use the `SystemProgram.createAccount` instruction to create a new account and set the public key of that account to Bob's public key.
            - At the same time, Alice can transfer funds to this newly created account, which is Bob's account
            */
            solana_rpc_client_api::client_error::ErrorKind::RpcError(
                solana_rpc_client_api::request::RpcError::ForUser(msg),
            ) if msg.contains("AccountNotFound:") => {
                println!("Bob Account not found.");
                let blockhash = rpc_client.get_latest_blockhash().unwrap();
                let _ =
                    create_account(&rpc_client, &alice_keypair, blockhash, &bob_keypair, 0usize);
            }
            _ => println!("Error fetching account: {e:?}"),
        },
    }

    // USDC in Solana Testnet
    // https://explorer.solana.com/address/Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr?cluster=testnet
    // https://solscan.io/token/Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr?cluster=testnet
    let mint_authority =
        solana_sdk::pubkey::Pubkey::from_str("Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr")
            .unwrap();

    let associated_token_address_alice =
        get_associated_token_address(&alice_keypair.pubkey(), &mint_authority);
    assert_eq!(
        "7x3cWuFuXMWtN9YJGGTD2Wj4uT8cXBXqA7dmoTnLnhSw",
        associated_token_address_alice.to_string()
    );

    let associated_token_address_bob =
        get_associated_token_address(&bob_keypair.pubkey(), &mint_authority);
    assert_eq!(
        "DoRuQrvyG6uPhwsNHtgTFHSjrhw7RbP9Lqi4VU4Ypz4q",
        associated_token_address_bob.to_string()
    );

    let res = rpc_client.get_token_account(&associated_token_address_alice);
    assert!(res.is_ok());
    /*
    &res = Ok(
        Some(
            UiTokenAccount {
                mint: "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
                owner: "EpFLfuH524fk9QP9i9uL9AHtX6smBaxaMHwek9T11nK5",
                token_amount: UiTokenAmount {
                    ui_amount: Some(
                        50.999997,
                    ),
                    decimals: 6,
                    amount: "50999997",
                    ui_amount_string: "50.999997",
                },
                delegate: None,
                state: Initialized,
                is_native: false,
                rent_exempt_reserve: None,
                delegated_amount: None,
                close_authority: None,
                extensions: [],
            },
        ),
    )

     */
    let res = rpc_client.get_token_account(&associated_token_address_bob);
    match res {
        Ok(_) => (),
        Err(e) => {
            dbg!(&e);
            let blockhash = rpc_client.get_latest_blockhash().unwrap();
            create_token_account(
                &rpc_client,
                &alice_keypair,
                blockhash,
                &bob_pubkey,
                &mint_authority,
            )
            .unwrap();
        }
    }
    // dbg!(&res);
    // assert!(res.is_err());
    /*
        &res = Err(
        Error {
            request: None,
            kind: RpcError(
                ForUser(
                    "Account could not be parsed as token account: pubkey=DoRuQrvyG6uPhwsNHtgTFHSjrhw7RbP9Lqi4VU4Ypz4q",
                ),
            ),
        },
    )
    */

    let amount: u64 = 1; // Decimals 6
    transfer_spl_token(
        &rpc_client,
        &alice_keypair,
        &bob_pubkey,
        &mint_authority,
        amount,
    )
    .unwrap();

    let balance_alice = rpc_client.get_token_account_balance(&associated_token_address_alice)?;
    dbg!(balance_alice);
    let balance_bob = rpc_client.get_token_account_balance(&associated_token_address_bob)?;
    dbg!(balance_bob);

    Ok(())

    /*
        balance_alice = UiTokenAmount {
        ui_amount: Some(
            50.999994,
        ),
        decimals: 6,
        amount: "50999994",
        ui_amount_string: "50.999994",
    }
        balance_bob = UiTokenAmount {
        ui_amount: Some(
            2e-6,
        ),
        decimals: 6,
        amount: "2",
        ui_amount_string: "0.000002",
    }

    */
}
