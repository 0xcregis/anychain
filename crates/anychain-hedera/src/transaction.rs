//! Example: Transfer HBAR from Alice to Bob
//!
//! This example demonstrates how to transfer HBAR (Hedera's native cryptocurrency)
//! from one account (Alice) to another account (Bob) on the Hedera network.
//!
//! # Prerequisites
//! - Set environment variables: ALICE_PRIVATE_KEY, ALICE_ACCOUNT_ID
//! - Ensure Alice's account has sufficient HBAR balance
//! - Bob's account should exist (or will be created)

use hiero_sdk::{AccountId, Client, Hbar, PrivateKey, TransferTransaction};
use std::str::FromStr;

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     println!("=== HBAR Transfer Example: Alice -> Bob ===\n");

//     // Step 1: Setup Alice's credentials
//     let (alice_private_key, alice_account_id) = setup_alice_account()?;
//     println!("✓ Alice's account configured: {}", alice_account_id);

//     // Step 2: Generate Bob's account (or use existing)
//     let (_, bob_account_id) = setup_bob_account()?;
//     println!("✓ Bob's account configured: {}", bob_account_id);

//     // Step 3: Connect to Hedera network
//     let client = setup_hedera_client(&alice_private_key, &alice_account_id)?;
//     println!("✓ Connected to Hedera testnet\n");

//     // Step 4: Define transfer amount
//     let transfer_amount = Hbar::new(10); // Transfer 10 HBAR
//     println!("Transferring {} from Alice to Bob...", transfer_amount);

//     // Step 5: Execute the transfer
//     execute_transfer(&client, &alice_account_id, &bob_account_id, transfer_amount).await?;

//     println!("\n✓ Transfer completed successfully!");
//     println!("  From: {}", alice_account_id);
//     println!("  To: {}", bob_account_id);
//     println!("  Amount: {}", transfer_amount);

//     Ok(())
// }

// /// Setup Alice's account from environment variables
// fn setup_alice_account() -> Result<(PrivateKey, AccountId), Box<dyn std::error::Error>> {
//     let key_str = "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
//     let private_key = PrivateKey::from_str(key_str)?;

//     let id_str = "0.0.8007608";
//     let account_id = AccountId::from_str(id_str)?;

//     Ok((private_key, account_id))
// }

// /// Setup Bob's account (generate new or use existing)
// fn setup_bob_account() -> Result<(PrivateKey, AccountId), Box<dyn std::error::Error>> {
//     let key_str = "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";
//     let private_key = PrivateKey::from_str(key_str)?;

//     let id_str = "0.0.8007608";
//     let account_id = AccountId::from_str(id_str)?;

//     Ok((private_key, account_id))
// }

// /// Setup and configure the Hedera client
// fn setup_hedera_client(
//     operator_key: &PrivateKey,
//     operator_id: &AccountId,
// ) -> Result<Client, Box<dyn std::error::Error>> {
//     // Create client for testnet
//     let client = Client::for_testnet();

//     // Set the operator (the account that will pay for transactions)
//     client.set_operator(*operator_id, operator_key.clone());

//     Ok(client)
// }

// /// Execute the HBAR transfer transaction
// async fn execute_transfer(
//     client: &Client,
//     from: &AccountId,
//     to: &AccountId,
//     amount: Hbar,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // Create a transfer transaction
//     let mut transaction = TransferTransaction::new();

//     // Configure the transfer:
//     // - Debit from Alice's account
//     // - Credit to Bob's account
//     transaction
//         .hbar_transfer(*from, -amount) // Negative = debit
//         .hbar_transfer(*to, amount); // Positive = credit

//     // Execute the transaction and get receipt
//     println!("Submitting transaction to Hedera network...");
//     let response = transaction.execute(client).await?;

//     println!("Transaction ID: {}", response.transaction_id);
//     println!("Waiting for transaction receipt...");

//     // Wait for the transaction to reach consensus
//     let receipt = response.get_receipt(client).await?;

//     println!("Transaction status: {:?}", receipt.status);

//     // Transaction receipt received - the transaction has been processed
//     // The status field contains the result code

//     Ok(())
// }
