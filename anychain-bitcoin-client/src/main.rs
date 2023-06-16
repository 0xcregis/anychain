use std::str::FromStr;

use anychain_bitcoin::{
    amount::BitcoinAmount,
    public_key::BitcoinPublicKey,
    transaction::{
        BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
        BitcoinTransactionParameters,
    },
    BitcoinTestnet as Testnet, BitcoinAddress, BitcoinFormat,
};

use anychain_core::{hex, libsecp256k1, Address, PublicKey, Transaction};

fn address_from_secret_key() {
    let secret_key = [
        1, 1, 0, 1, 1, 1, 1, 1, 2, 1, 1, 1, 71, 1, 1, 1, 1, 8, 1, 1, 1, 111, 1, 1, 103, 1, 1, 57, 1, 1,
        1, 1,
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
    let addr = "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf";

    let addr = BitcoinAddress::<Testnet>::from_str(addr).unwrap();

    println!("\naddress = {}", addr);
}

fn address_validation() {
    let addr = "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf";

    let status = BitcoinAddress::<Testnet>::is_valid(addr);

    println!("status = {}", status);
}

fn amount_gen() {
    let amount1 = BitcoinAmount::from_btc(1).unwrap();
    let amount2 = BitcoinAmount::from_satoshi(1000).unwrap();

    println!("amount1 = {} satoshi", amount1);
    println!("amount2 = {} satoshi", amount2);
}

fn transaction_gen() {
    let secret_key = [
        1, 1, 0, 1, 1, 1, 1, 1, 2, 1, 1, 1, 71, 1, 1, 1, 1, 8, 1, 1, 1, 111, 1, 1, 103, 1, 1, 57, 1, 1,
        1, 1,
    ];
    let secret_key = libsecp256k1::SecretKey::parse(&secret_key).unwrap();
    let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key).serialize_compressed().to_vec();

    let recipient = "2MsRNMaKe8YWcdUaRi8jwa2aHG85kzsbUHe";
    let amount = 500000;
    let fee = 1000;

    let inputs = [
        (
            "39f420dc156f4ac1ad753a9fae1206973d9eede39a004c04496b7f9f525c77b8",
            0,
            "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf",
            1378890
        ),
        (
            "312afea64f1efeefc6bdf73827daeee99ff025c9f1dc036bb62ff708c4eedcad",
            0,
            "2NCwYikg4pdCGPjgiK3T4Y1DW6Dnp5eobfy",
            1818565
        ),
        (
            "dc163eb31a9cdd5a8bb49066477375f9a0068791176e7b4a61e54751581449ae",
            1,
            "tb1q83t5qrd4yzrd477eskjp5f8ujtrf6enwgw87rn",
            1481548
        )
    ];

    for i in 0..inputs.len() {
        let input = BitcoinTransactionInput::new(
            hex::decode(inputs[i].0).unwrap(),
            inputs[i].1,
            Some(BitcoinAddress::<Testnet>::from_str(inputs[i].2).unwrap()),
            Some(BitcoinAmount::from_satoshi(inputs[i].3).unwrap()),
        )
        .unwrap();

        let output1 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(recipient).unwrap(),
            BitcoinAmount::from_satoshi(amount).unwrap(),
        )
        .unwrap();

        let output2 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(inputs[i].2).unwrap(),
            BitcoinAmount::from_satoshi(inputs[i].3 - amount - fee).unwrap(),
        )
        .unwrap();

        let mut tx = BitcoinTransaction::new(
            &BitcoinTransactionParameters::new(vec![input], vec![output1, output2]).unwrap(),
        )
        .unwrap();

        let hash = tx.digest(0).unwrap();
        let msg = libsecp256k1::Message::parse_slice(&hash).unwrap();
        let sig = libsecp256k1::sign(&msg, &secret_key).0.serialize().to_vec();

        let _ = tx.sign(sig, public_key.clone(), i as u32);

        println!("tx = {}\n", tx);
    }
}

fn main() {
    address_from_secret_key();
    address_from_public_key();
    address_from_str();
    address_validation();
    amount_gen();
    transaction_gen();
}
