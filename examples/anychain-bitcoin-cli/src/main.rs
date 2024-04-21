use clap::{Arg, Command};
use serde_json::Value;
use std::str::FromStr;

use anychain_bitcoin::{
    Bitcoin, BitcoinAddress, BitcoinAmount, BitcoinCash, BitcoinCashTestnet, BitcoinFormat,
    BitcoinNetwork, BitcoinPublicKey, BitcoinTestnet, BitcoinTransaction, BitcoinTransactionInput,
    BitcoinTransactionOutput, BitcoinTransactionParameters, Dogecoin, DogecoinTestnet, Litecoin,
    LitecoinTestnet, SignatureHash,
};

use anychain_core::{hex, Address, PublicKey, Transaction};

fn address_from_public_key<N: BitcoinNetwork>(
    public_key: libsecp256k1::PublicKey,
) -> Vec<(BitcoinFormat, String)> {
    let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);
    let converter = |addr: BitcoinAddress<N>| Ok(addr.to_string());
    let addresses: Vec<(BitcoinFormat, String)> = vec![
        (
            BitcoinFormat::P2PKH,
            public_key
                .to_address(&BitcoinFormat::P2PKH)
                .and_then(converter),
        ),
        (
            BitcoinFormat::P2SH_P2WPKH,
            public_key
                .to_address(&BitcoinFormat::P2SH_P2WPKH)
                .and_then(converter),
        ),
        (
            BitcoinFormat::Bech32,
            public_key
                .to_address(&BitcoinFormat::Bech32)
                .and_then(converter),
        ),
        (
            BitcoinFormat::CashAddr,
            public_key
                .to_address(&BitcoinFormat::CashAddr)
                .and_then(converter),
        ),
    ]
    .iter()
    .map(|tuple| {
        if tuple.1.is_ok() {
            (tuple.0.clone(), tuple.1.as_ref().unwrap().to_string())
        } else {
            (tuple.0.clone(), "null".to_string())
        }
    })
    .collect();

    addresses
}

fn address_validation<N: BitcoinNetwork>(address: &str) {
    if BitcoinAddress::<N>::is_valid(address) {
        println!("{} is a valid {} address", address, N::NAME);
    } else {
        println!("{} is not a valid {} address", address, N::NAME);
    }
}

fn tx_gen<N: BitcoinNetwork>(
    inputs: Vec<&String>,
    outputs: Vec<&String>,
    is_fork_id: bool,
) -> String {
    let inputs: Vec<(BitcoinTransactionInput<N>, Option<libsecp256k1::SecretKey>)> = inputs
        .iter()
        .map(|&input| {
            let input = serde_json::from_str::<Value>(input).unwrap();

            let txid = input["txid"].clone();
            let index = input["index"].clone();
            let format = input["format"].clone();
            let balance = input["balance"].clone();
            let private_key = input["private_key"].clone();
            let public_key = input["public_key"].clone();
            let signature = input["signature"].clone();

            if txid.is_null() {
                panic!("Txid not provided");
            }

            if index.is_null() {
                panic!("Index not provided");
            }

            let txid = txid.as_str().unwrap();
            let txid = hex::decode(txid).unwrap();

            let index = index.as_u64().unwrap() as u32;

            let sighash = if is_fork_id {
                SignatureHash::SIGHASH_ALL_SIGHASH_FORKID
            } else {
                SignatureHash::SIGHASH_ALL
            };

            let format = if !format.is_null() {
                let f = format.as_str().unwrap();
                BitcoinFormat::from_str(f).unwrap()
            } else {
                BitcoinFormat::P2PKH
            };

            let balance = if format != BitcoinFormat::P2PKH {
                if balance.is_null() {
                    panic!("Balance not provided");
                }
                let balance = BitcoinAmount(balance.as_i64().unwrap());
                Some(balance)
            } else {
                None
            };

            let mut input = BitcoinTransactionInput::<N>::new(
                txid,
                index,
                None,
                Some(format),
                None,
                balance,
                sighash,
            )
            .unwrap();

            let secret_key = if !signature.is_null() {
                let signature = signature.as_str().unwrap();
                if signature.len() != 128 {
                    panic!("Invalid signature length");
                }
                let signature = hex::decode(signature).unwrap();
                if !public_key.is_null() {
                    let k = public_key.as_str().unwrap();
                    if k.len() != 66 {
                        panic!("Invalid public key length");
                    }
                    let k = hex::decode(k).unwrap();
                    input.sign(signature, k).unwrap();
                    None
                } else if !private_key.is_null() {
                    let k = private_key.as_str().unwrap();
                    if k.len() != 64 {
                        panic!("Invalid private key length");
                    }
                    let k = hex::decode(k).unwrap();
                    let k = libsecp256k1::SecretKey::parse_slice(&k).unwrap();
                    let pk = libsecp256k1::PublicKey::from_secret_key(&k);
                    let pk = pk.serialize_compressed().to_vec();
                    input.sign(signature, pk).unwrap();
                    None
                } else {
                    panic!("Neither a private key nor a public key is provided");
                }
            } else if !private_key.is_null() {
                let k = private_key.as_str().unwrap();
                let k = hex::decode(k).unwrap();
                let k = libsecp256k1::SecretKey::parse_slice(&k).unwrap();
                Some(k)
            } else {
                panic!("Private key not provided");
            };
            (input, secret_key)
        })
        .collect();

    let outputs: Vec<BitcoinTransactionOutput> = outputs
        .iter()
        .map(|&output| {
            let output = serde_json::from_str::<Value>(output).unwrap();

            let to = output["to"].clone();
            let amount = output["amount"].clone();

            let to = to.as_str().unwrap();
            let amount = amount.as_i64().unwrap();

            BitcoinTransactionOutput::new(
                BitcoinAddress::<N>::from_str(to).unwrap(),
                BitcoinAmount::from_satoshi(amount).unwrap(),
            )
            .unwrap()
        })
        .collect();

    let mut tx = BitcoinTransaction::<N>::new(
        &BitcoinTransactionParameters::<N>::new(
            inputs.iter().map(|input| input.0.clone()).collect(),
            outputs,
        )
        .unwrap(),
    )
    .unwrap();

    for i in 0..inputs.len() {
        let i = i as u32;
        let input = tx.input(i).unwrap();
        let secret_key = &inputs[i as usize].1;
        if !input.is_signed {
            match secret_key {
                Some(k) => {
                    let pk = BitcoinPublicKey::<N>::from_secret_key(k);
                    let format = input.get_format().unwrap();
                    input.set_public_key(pk.clone(), format).unwrap();
                    let hash = tx.digest(i).unwrap();
                    let msg = libsecp256k1::Message::parse_slice(&hash).unwrap();
                    let sig = libsecp256k1::sign(&msg, k).0;
                    let sig = sig.serialize().to_vec();
                    let pk = pk.serialize();
                    tx.input(i).unwrap().sign(sig, pk).unwrap();
                }
                None => panic!("Private key missing"),
            }
        }
    }

    tx.set_segwit().unwrap();

    hex::encode(tx.to_bytes().unwrap())
}

fn main() {
    let matches = Command::new("anychain")
        .subcommands(vec![
            Command::new("address-gen")
                .about("Generate an address of a utxo-typed blockchain")
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .num_args(1)
                        .help("Specify the network of the address to be generated"),
                )
                .arg(
                    Arg::new("private_key")
                        .long("priv")
                        .num_args(1..)
                        .help("Generate an address from a private key in hex format"),
                )
                .arg(
                    Arg::new("public_key")
                        .long("pub")
                        .num_args(1..)
                        .help("Generate an address from a compressed public key in hex format"),
                ),
            Command::new("address-validate")
                .about("Check if an address of a utxo-typed blockchain is valid")
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .num_args(1)
                        .help("Specify the network of the address to be validated"),
                )
                .arg(
                    Arg::new("address")
                        .num_args(1..)
                        .help("Specify the address to be validated"),
                ),
            Command::new("tx-gen")
                .about("Generate a transaction of a utxo-typed blockchain")
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .num_args(1)
                        .help("Specify the network of the transaction to be generated"),
                )
                .arg(
                    Arg::new("inputs")
                        .num_args(1..)
                        .long("input")
                        .short('i')
                        .help("Specify the input of the transaction to be generated"),
                )
                .arg(
                    Arg::new("outputs")
                        .num_args(1..)
                        .long("output")
                        .short('o')
                        .help("Specify the output of the transaction to be generated"),
                ),
        ])
        .get_matches();

    match matches.subcommand() {
        Some(("address-gen", sub_matches)) => {
            let network = sub_matches.get_one::<String>("network");
            if network.is_none() {
                println!("Network not specified");
                return;
            }
            let private_keys = sub_matches.get_many::<String>("private_key");
            let public_keys = sub_matches.get_many::<String>("public_key");

            let public_keys = if let Some(private_keys) = private_keys {
                if public_keys.is_some() {
                    println!("Public keys are needless in presence of private keys");
                    return;
                }
                let private_keys: Vec<&String> = private_keys.collect();
                let public_keys: Vec<libsecp256k1::PublicKey> = private_keys
                    .iter()
                    .map(|&private_key| {
                        if private_key.len() != 64 {
                            panic!("Invalid private key");
                        }
                        let private_key = hex::decode(private_key).unwrap();
                        let private_key =
                            libsecp256k1::SecretKey::parse_slice(&private_key).unwrap();
                        libsecp256k1::PublicKey::from_secret_key(&private_key)
                    })
                    .collect();
                public_keys
            } else if let Some(public_keys) = public_keys {
                let public_keys: Vec<&String> = public_keys.collect();
                let public_keys: Vec<libsecp256k1::PublicKey> = public_keys
                    .iter()
                    .map(|&public_key| {
                        if public_key.len() != 66 {
                            panic!("Invalid compressed public key");
                        }
                        let public_key = hex::decode(public_key).unwrap();
                        libsecp256k1::PublicKey::parse_slice(&public_key, None).unwrap()
                    })
                    .collect();
                public_keys
            } else {
                println!("Neither a private key nor a public key is provided");
                return;
            };

            let network = network.unwrap().clone();

            for public_key in public_keys {
                let addresses = match network.as_str() {
                    "bitcoin" => address_from_public_key::<Bitcoin>(public_key),
                    "bitcoin_testnet" => address_from_public_key::<BitcoinTestnet>(public_key),
                    "bitcoincash" => address_from_public_key::<BitcoinCash>(public_key),
                    "bitcoincash_testnet" => {
                        address_from_public_key::<BitcoinCashTestnet>(public_key)
                    }
                    "litecoin" => address_from_public_key::<Litecoin>(public_key),
                    "litecoin_testnet" => address_from_public_key::<LitecoinTestnet>(public_key),
                    "dogecoin" => address_from_public_key::<Dogecoin>(public_key),
                    "dogecoin_testnet" => address_from_public_key::<DogecoinTestnet>(public_key),
                    _ => {
                        println!("Unsupported network");
                        return;
                    }
                };
                for (format, address) in addresses {
                    println!("{} ({})", address, format,);
                }
                println!();
            }
        }
        Some(("address-validate", sub_matches)) => {
            let network = sub_matches.get_one::<String>("network");
            let address = sub_matches.get_one::<String>("address");

            if network.is_none() {
                println!("Network not provided");
                return;
            }

            if address.is_none() {
                println!("Address not provided");
                return;
            }

            let address = address.unwrap().clone();
            let network = network.unwrap().clone();

            match network.as_str() {
                "bitcoin" => address_validation::<Bitcoin>(&address),
                "bitcoin_testnet" => address_validation::<BitcoinTestnet>(&address),
                "bitcoincash" => address_validation::<BitcoinCash>(&address),
                "bitcoincash_testnet" => address_validation::<BitcoinCashTestnet>(&address),
                "litecoin" => address_validation::<Litecoin>(&address),
                "litecoin_testnet" => address_validation::<LitecoinTestnet>(&address),
                "dogecoin" => address_validation::<Dogecoin>(&address),
                "dogecoin_testnet" => address_validation::<DogecoinTestnet>(&address),
                _ => println!("Unsupported network"),
            };
        }
        Some(("tx-gen", sub_matches)) => {
            let network = sub_matches.get_one::<String>("network");
            let inputs = sub_matches.get_many::<String>("inputs");
            let outputs = sub_matches.get_many::<String>("outputs");

            if network.is_none() {
                println!("Network not provided");
                return;
            }

            if inputs.is_none() {
                println!("No input is provided");
                return;
            }

            if outputs.is_none() {
                println!("No output is provided");
                return;
            }

            let network = network.unwrap().clone();
            let inputs: Vec<&String> = inputs.unwrap().collect();
            let outputs: Vec<&String> = outputs.unwrap().collect();

            let tx = match network.as_str() {
                "bitcoin" => tx_gen::<Bitcoin>(inputs, outputs, false),
                "bitcoin_testnet" => tx_gen::<BitcoinTestnet>(inputs, outputs, false),
                "bitcoincash" => tx_gen::<BitcoinCash>(inputs, outputs, true),
                "bitcoincash_testnet" => tx_gen::<BitcoinCashTestnet>(inputs, outputs, true),
                "litecoin" => tx_gen::<Litecoin>(inputs, outputs, false),
                "litecoin_testnet" => tx_gen::<LitecoinTestnet>(inputs, outputs, false),
                "dogecoin" => tx_gen::<Dogecoin>(inputs, outputs, false),
                "dogecoin_testnet" => tx_gen::<DogecoinTestnet>(inputs, outputs, false),
                _ => {
                    println!("Unsupported network");
                    return;
                }
            };

            println!("tx = {}", tx);
        }
        _ => {}
    };
}
