use std::str::FromStr;

use anychain_bitcoin::{
    BitcoinAddress, BitcoinAmount, BitcoinFormat, BitcoinPublicKey, BitcoinTestnet as Testnet,
    BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
    BitcoinTransactionParameters, SignatureHash,
};

use anychain_core::{hex, Address, PublicKey, Transaction};

fn address_from_secret_key() {
    // Generates Bitcoin addresses from a secret key.
    // It generates three types of addresses: P2PKH, P2SH_P2WPKH, and Bech32.

    let secret_key = [
        1, 1, 0, 1, 1, 1, 1, 1, 2, 1, 1, 1, 71, 1, 1, 1, 1, 8, 1, 1, 1, 111, 1, 1, 103, 1, 1, 57,
        1, 1, 1, 1,
    ];

    let secret_key = libsecp256k1::SecretKey::parse(&secret_key).unwrap();

    let addr_p2pkh =
        BitcoinAddress::<Testnet>::from_secret_key(&secret_key, &BitcoinFormat::P2PKH).unwrap();

    let addr_p2sh_p2wpkh =
        BitcoinAddress::<Testnet>::from_secret_key(&secret_key, &BitcoinFormat::P2SH_P2WPKH)
            .unwrap();

    let addr_bech32 =
        BitcoinAddress::<Testnet>::from_secret_key(&secret_key, &BitcoinFormat::Bech32).unwrap();

    println!("address p2pkh = {}", addr_p2pkh);
    println!("address p2sh_p2wpkh = {}", addr_p2sh_p2wpkh);
    println!("address bech32 = {}", addr_bech32);
}

fn address_from_public_key() {
    // Generates Bitcoin addresses from a public key.
    // Generates three types of addresses: P2PKH, P2SH_P2WPKH, and Bech32.

    let public_key = [
        3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52,
        96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143,
    ];

    let public_key = libsecp256k1::PublicKey::parse_compressed(&public_key).unwrap();

    let public_key = BitcoinPublicKey::<Testnet>::from_secp256k1_public_key(public_key, true);

    let addr_p2pkh = public_key.to_address(&BitcoinFormat::P2PKH).unwrap();

    let addr_p2sh_p2wpkh = public_key.to_address(&BitcoinFormat::P2SH_P2WPKH).unwrap();

    let addr_bech32 = public_key.to_address(&BitcoinFormat::Bech32).unwrap();

    println!("\naddress p2pkh = {}", addr_p2pkh);
    println!("address p2sh_p2wpkh = {}", addr_p2sh_p2wpkh);
    println!("address bech32 = {}", addr_bech32);
}

fn address_from_str() {
    // Parses a Bitcoin address from a string.
    // It takes a string representation of a Bitcoin address and converts it into a BitcoinAddress object.

    let addr = "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf";

    let addr = BitcoinAddress::<Testnet>::from_str(addr).unwrap();

    println!("\naddress = {}", addr);
}

fn address_validation() {
    // Validates a Bitcoin address.
    // It checks whether a given string is a valid Bitcoin address.

    let addr = "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf";

    let status = BitcoinAddress::<Testnet>::is_valid(addr);

    println!("status = {}", status);
}

fn amount_gen() {
    // Generates Bitcoin amounts in satoshi from BTC and satoshi values.
    // It demonstrates how to create BitcoinAmount objects from BTC and satoshi values.

    let amount1 = BitcoinAmount::from_btc(1).unwrap();
    let amount2 = BitcoinAmount::from_satoshi(1000).unwrap();

    println!("amount1 = {} satoshi", amount1);
    println!("amount2 = {} satoshi", amount2);
}

fn transaction_gen() {
    // Generates a Bitcoin transaction.
    // It creates a transaction with multiple inputs and outputs, signs it with a secret key, and prints the transaction.

    let secret_key = [
        1, 1, 0, 1, 1, 1, 1, 1, 2, 1, 1, 1, 71, 1, 1, 1, 1, 8, 1, 1, 1, 111, 1, 1, 103, 1, 1, 57,
        1, 1, 1, 1,
    ];
    let secret_key = libsecp256k1::SecretKey::parse(&secret_key).unwrap();
    let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
    let public_key = BitcoinPublicKey::<Testnet>::from_secp256k1_public_key(public_key, true);

    let recipient = "2MsRNMaKe8YWcdUaRi8jwa2aHG85kzsbUHe";
    let amount = 500000;
    let fee = 1000;

    let inputs = [
        (
            "39f420dc156f4ac1ad753a9fae1206973d9eede39a004c04496b7f9f525c77b8",
            0,
            "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf",
            1378890,
        ),
        (
            "dc163eb31a9cdd5a8bb49066477375f9a0068791176e7b4a61e54751581449ae",
            1,
            "tb1q83t5qrd4yzrd477eskjp5f8ujtrf6enwgw87rn",
            1481548,
        ),
    ];

    for item in inputs.iter() {
        let input = BitcoinTransactionInput::new(
            hex::decode(item.0).unwrap(),
            item.1,
            None,
            None,
            Some(BitcoinAddress::<Testnet>::from_str(item.2).unwrap()),
            Some(BitcoinAmount::from_satoshi(item.3).unwrap()),
            SignatureHash::SIGHASH_ALL,
        )
        .unwrap();

        let output1 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(recipient).unwrap(),
            BitcoinAmount::from_satoshi(amount).unwrap(),
        )
        .unwrap();

        let output2 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(item.2).unwrap(),
            BitcoinAmount::from_satoshi(item.3 - amount - fee).unwrap(),
        )
        .unwrap();

        let mut tx = BitcoinTransaction::new(
            &BitcoinTransactionParameters::new(vec![input], vec![output1, output2]).unwrap(),
        )
        .unwrap();

        let hash = tx.digest(0).unwrap();
        let msg = libsecp256k1::Message::parse_slice(&hash).unwrap();
        let sig = libsecp256k1::sign(&msg, &secret_key).0.serialize().to_vec();

        let _ = tx.input(0).unwrap().sign(sig, public_key.serialize());

        println!("tx = {}\n", tx);
    }
}

fn main() {
    // Generates Bitcoin addresses from a secret key
    address_from_secret_key();

    // Generates Bitcoin addresses from a public key
    address_from_public_key();

    // Parses a Bitcoin address from a string
    address_from_str();

    // Validates a Bitcoin address
    address_validation();

    // Generates Bitcoin amounts in satoshi from BTC and satoshi values
    amount_gen();

    // Generates a Bitcoin transaction
    transaction_gen();
}
