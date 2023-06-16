use std::str::FromStr;

use anychain_bitcoin::{
    amount::BitcoinAmount,
    public_key::BitcoinPublicKey,
    transaction::{
        BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
        BitcoinTransactionParameters,
    },
    Bitcoin as Mainnet, BitcoinAddress, BitcoinFormat,
};

use anychain_core::{hex, libsecp256k1, Address, PublicKey, Transaction};

fn address_from_secret_key() {
    let secret_key = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1,
    ];

    let secret_key = libsecp256k1::SecretKey::parse(&secret_key).unwrap();

    let addr_p2pkh =
        BitcoinAddress::<Mainnet>::from_secret_key(&secret_key, &BitcoinFormat::P2PKH).unwrap();

    let addr_p2sh_p2wpkh =
        BitcoinAddress::<Mainnet>::from_secret_key(&secret_key, &BitcoinFormat::P2SH_P2WPKH)
            .unwrap();

    let addr_bech32 =
        BitcoinAddress::<Mainnet>::from_secret_key(&secret_key, &BitcoinFormat::Bech32).unwrap();

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

    let public_key = BitcoinPublicKey::<Mainnet>::from_secp256k1_public_key(public_key, true);

    let addr_p2pkh = public_key.to_address(&BitcoinFormat::P2PKH).unwrap();

    let addr_p2sh_p2wpkh = public_key.to_address(&BitcoinFormat::P2SH_P2WPKH).unwrap();

    let addr_bech32 = public_key.to_address(&BitcoinFormat::Bech32).unwrap();

    println!("\naddress p2pkh = {}", addr_p2pkh);
    println!("address p2sh_p2wpkh = {}", addr_p2sh_p2wpkh);
    println!("address bech32 = {}", addr_bech32);
}

fn address_from_str() {
    let addr = "1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD";

    let addr = BitcoinAddress::<Mainnet>::from_str(addr).unwrap();

    println!("\naddress = {}", addr);
}

fn address_validation() {
    let addr = "1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD";

    let status = BitcoinAddress::<Mainnet>::is_valid(addr);

    println!("status = {}", status);
}

fn amount_gen() {
    let amount1 = BitcoinAmount::from_btc(1).unwrap();
    let amount2 = BitcoinAmount::from_satoshi(1000).unwrap();

    println!("amount1 = {} satoshi", amount1);
    println!("amount2 = {} satoshi", amount2);
}

fn transaction_gen() {
    let input = BitcoinTransactionInput::new(
        hex::decode("211e7bf8fcfd7d530e4ea3bb3d9fb11914e76bb98c1d34b7704bb898b943bb24").unwrap(),
        1,
        Some(BitcoinAddress::<Mainnet>::from_str("1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD").unwrap()),
        Some(BitcoinAmount::from_btc(1).unwrap()),
    )
    .unwrap();

    let output = BitcoinTransactionOutput::new(
        BitcoinAddress::<Mainnet>::from_str("1JF7WT1RoBRrwmNBnzSsqHG63rusDrqQNy").unwrap(),
        BitcoinAmount::from_ubtc(1000).unwrap(),
    )
    .unwrap();

    let mut tx = BitcoinTransaction::new(
        &BitcoinTransactionParameters::new(vec![input], vec![output]).unwrap(),
    )
    .unwrap();

    let _hash = tx.digest(0).unwrap();

    println!("tx = {}", tx);
}

fn main() {
    address_from_secret_key();
    address_from_public_key();
    address_from_str();
    address_validation();
    amount_gen();
    transaction_gen();
}
