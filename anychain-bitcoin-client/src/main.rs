use std::str::FromStr;

use anychain_bitcoin::{
    amount::BitcoinAmount,
    public_key::BitcoinPublicKey,
    transaction::{
        BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
        BitcoinTransactionParameters, SignatureHash,
    },
    BitcoinAddress, BitcoinFormat, BitcoinTestnet as Testnet,
};

use anychain_core::{hex, libsecp256k1, Address, PublicKey, Transaction};

fn address_from_secret_key() {
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
            "c226dd928aa04b83dc5f2ab4100374e0eb16ff60885fa17d924ea2af15a64692",
            1,
            public_key.clone(),
            BitcoinFormat::P2PKH,
            "mm21MpCm2cVYBxZvxk6DaQC7C4o5Ukq2Wf",
            868890,
        ),
        (
            "312afea64f1efeefc6bdf73827daeee99ff025c9f1dc036bb62ff708c4eedcad",
            0,
            public_key.clone(),
            BitcoinFormat::P2SH_P2WPKH,
            "2NCwYikg4pdCGPjgiK3T4Y1DW6Dnp5eobfy",
            1818565,
        ),
        (
            "dc163eb31a9cdd5a8bb49066477375f9a0068791176e7b4a61e54751581449ae",
            1,
            public_key.clone(),
            BitcoinFormat::Bech32,
            "tb1q83t5qrd4yzrd477eskjp5f8ujtrf6enwgw87rn",
            1481548,
        ),
    ];

    for item in inputs.iter() {
        let item = item.clone();
        let input = BitcoinTransactionInput::new(
            hex::decode(item.0).unwrap(),
            item.1,
            Some(item.2),
            Some(item.3),
            Some(BitcoinAddress::<Testnet>::from_str(item.4).unwrap()),
            Some(BitcoinAmount::from_satoshi(item.5).unwrap()),
            SignatureHash::SIGHASH_ALL,
        )
        .unwrap();

        let output1 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(recipient).unwrap(),
            BitcoinAmount::from_satoshi(amount).unwrap(),
        )
        .unwrap();

        let output2 = BitcoinTransactionOutput::new(
            BitcoinAddress::<Testnet>::from_str(item.4).unwrap(),
            BitcoinAmount::from_satoshi(item.5 - amount - fee).unwrap(),
        )
        .unwrap();

        let mut tx = BitcoinTransaction::new(
            &BitcoinTransactionParameters::new(vec![input], vec![output1, output2]).unwrap(),
        )
        .unwrap();

        let hash = tx.digest(0).unwrap();
        let msg = libsecp256k1::Message::parse_slice(&hash).unwrap();
        let sig = libsecp256k1::sign(&msg, &secret_key).0.serialize().to_vec();

        tx.sign(sig, public_key.serialize(), 0).unwrap();

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

    let tx = "02000000019246a615afa24e927da15f8860ff16ebe0740310b42a5fdc834ba08a92dd26c2010000006a473044022075b8936ba7858379784d1116a56ff44a4df0be53765d6e6e23d9c62954aa125a0220020c8f1acd486616b635e7061ddb690501b1e7deeab00faace712143f5327557012103a966dcbd7ce115d3bb14f178dc22f1b3c92d28902bc73e8dc56063dc3e53d13fffffffff0220a107000000000017a91401eb24e4b97fc5650f4cf422852a791732a968f987129d0500000000001976a9143c57400db52086dafbd985a41a24fc92c69d666e88ac00000000";
    let tx = BitcoinTransaction::<Testnet>::from_str(tx).unwrap();
    println!("tx = {}", tx);

    let tx = "02000000000101addceec408f72fb66b03dcf1c925f09fe9eeda2738f7bdc6effe1e4fa6fe2a3100000000171600143c57400db52086dafbd985a41a24fc92c69d666effffffff0220a107000000000017a91401eb24e4b97fc5650f4cf422852a791732a968f987bd1a14000000000017a914d80aaa4dc0c5bb20b71afd3a5023c19d798a52f9870247304402202cf5672b41ca517ab054626b2c074e19298dab1cf951f0a8f0bb374c3d62b4cc02204d76f3e7447548f10505632515c5e55b2ecde41b8b302cf9bc524f316fa13b17012103a966dcbd7ce115d3bb14f178dc22f1b3c92d28902bc73e8dc56063dc3e53d13f00000000";
    let tx = BitcoinTransaction::<Testnet>::from_str(tx).unwrap();
    println!("tx = {}", tx);

    let tx = "02000000000101ae4914585147e5614a7b6e17918706a0f97573476690b48b5add9c1ab33e16dc0100000000ffffffff0220a107000000000017a91401eb24e4b97fc5650f4cf422852a791732a968f98744f60e00000000001600143c57400db52086dafbd985a41a24fc92c69d666e0247304402200c1a4881ccf9f5acc09bdad24206b89f75b28f1dabca41963ecfa0ca79e8c1c702200e5ffab32145ff66ab1c821eb6ab840e201a0c2fef25dcfadf07834970b654cf012103a966dcbd7ce115d3bb14f178dc22f1b3c92d28902bc73e8dc56063dc3e53d13f00000000";
    let tx = BitcoinTransaction::<Testnet>::from_str(tx).unwrap();
    println!("tx = {}", tx);
}
