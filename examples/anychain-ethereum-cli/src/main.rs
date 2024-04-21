use clap::value_parser;
use clap::{Arg, Command};
use primitive_types::H160;
use primitive_types::U256;
use rlp::Encodable;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::str::FromStr;

use anychain_ethereum::{encode_transfer, EthereumAddress, EthereumFormat, EthereumPublicKey};

use anychain_core::{hex, Address, PublicKey};

fn trim0x(s: &str) -> String {
    // str to lower case
    let s = s.to_lowercase();
    // remove 0x prefix
    let s = s.trim_start_matches("0x");
    s.to_string()
}

struct EIP155Transaction {
    nonce: u64,
    gas_price: U256,
    gas_limit: u64,
    to: H160,
    value: U256,
    data: Vec<u8>,
    v: u64, // {0, 1} + chain_id * 2 + 35, since EIP-155
    r: U256,
    s: U256,
}

impl Encodable for EIP155Transaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.to);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }
}

impl Display for EIP155Transaction {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let encoded = rlp::encode(self);
        let hex = hex::encode(&encoded);
        write!(f, "0x{}", hex)
    }
}

fn main() {
    let matches = Command::new("anychain")
        .subcommands(vec![
            Command::new("address-gen")
                .about("Generate an address ethereum-compatible blockchain")
                .arg(
                    Arg::new("private_key")
                        .long("prv")
                        .num_args(1)
                        .help("Generate an address from a private key in hex format"),
                )
                .arg(
                    Arg::new("public_key")
                        .long("pub")
                        .num_args(1)
                        .help("Generate an address from a public key in hex format"),
                ),
            Command::new("address-validate")
                .about("Check if an address is valid")
                .arg(
                    Arg::new("address")
                        .num_args(1)
                        .help("Specify the address to validate"),
                ),
            Command::new("towei")
                .about("Convert ether/gwei/wei to wei")
                .arg(
                    Arg::new("value")
                        .num_args(1)
                        .help("Specify the ether to be converted"),
                ),
            Command::new("maketx")
                .about("Generate an EIP-155 transaction")
                .arg(
                    Arg::new("mode")
                        .long("mode")
                        .num_args(1)
                        .help("transaction mode: main / erc20 / any"),
                )
                .arg(
                    Arg::new("network")
                        .long("network")
                        .num_args(1)
                        .help("Specify the network, according to https://chainid.network/"),
                )
                .arg(
                    Arg::new("nonce")
                        .long("nonce")
                        .num_args(1)
                        .value_parser(value_parser!(u64))
                        .help("nonce of the sender"),
                )
                .arg(
                    Arg::new("gas_price")
                        .long("gasprice")
                        .num_args(1)
                        .help("gas price of the transaction"),
                )
                .arg(
                    Arg::new("gas_limit")
                        .long("gaslimit")
                        .num_args(1)
                        .value_parser(value_parser!(u64))
                        .help("gas limit of the transaction"),
                )
                .arg(
                    Arg::new("to")
                        .long("to")
                        .num_args(1)
                        .help("address of the receiver"),
                )
                .arg(
                    Arg::new("token")
                        .long("token")
                        .num_args(1)
                        .help("address of the token contract (erc20)"),
                )
                .arg(
                    Arg::new("value")
                        .long("value")
                        .num_args(1)
                        .value_parser(value_parser!(u64))
                        .help("value of the transaction"),
                )
                .arg(
                    Arg::new("data")
                        .long("data")
                        .num_args(1)
                        .help("data of the transaction"),
                )
                .arg(
                    Arg::new("r")
                        .long("r")
                        .short('r')
                        .num_args(1)
                        .default_value("0")
                        .help("r of the signature"),
                )
                .arg(
                    Arg::new("s")
                        .long("s")
                        .short('s')
                        .num_args(1)
                        .default_value("0")
                        .help("s of the signature"),
                )
                .arg(
                    Arg::new("v")
                        .long("v")
                        .short('v')
                        .num_args(1)
                        .default_value("0")
                        .value_parser(value_parser!(u64))
                        .help("v of the signature"),
                ),
        ])
        .get_matches();

    match matches.subcommand() {
        Some(("address-gen", sub_matches)) => {
            let private_key = sub_matches.get_one::<String>("private_key");
            let public_key = sub_matches.get_one::<String>("public_key");
            let public_key = match (private_key, public_key) {
                (Some(_), Some(_)) => {
                    println!("Both private key and public key are provided");
                    return;
                }
                (Some(private_key), None) => {
                    let private_key = trim0x(private_key);
                    if private_key.len() != 64 {
                        println!("Invalid private key");
                        return;
                    }
                    let private_key = hex::decode(private_key).unwrap();
                    let private_key = libsecp256k1::SecretKey::parse_slice(&private_key).unwrap();
                    libsecp256k1::PublicKey::from_secret_key(&private_key)
                }
                (None, Some(public_key)) => {
                    let public_key = trim0x(public_key);
                    let public_key = hex::decode(public_key).unwrap();
                    // parse_slice can handle both compressed and uncompressed public key
                    // therefore we don't need to check the length and prefix of the public key
                    libsecp256k1::PublicKey::parse_slice(&public_key, None).unwrap()
                }
                (None, None) => {
                    println!("No private key or public key is provided");
                    return;
                }
            };
            println!("{}", address_from_public_key(public_key))
        }
        Some(("address-validate", sub_matches)) => {
            let address = sub_matches.get_one::<String>("address");

            if address.is_none() {
                println!("Address not provided");
                return;
            }
            let address = address.unwrap();
            if EthereumAddress::is_valid(address) {
                println!("Valid");
            } else {
                println!("Invalid");
            }
        }
        Some(("towei", sub_matches)) => {
            let value = sub_matches.get_one::<String>("value");

            if value.is_none() {
                println!("Value not provided");
                return;
            }
            let value = towei(value.unwrap());
            match value {
                Some(value) => println!("{}", value),
                None => println!("Invalid value"),
            }
        }
        Some(("maketx", sub_matches)) => {
            let network = sub_matches.get_one::<String>("network").unwrap();
            let chainid = network_to_chainid(network);
            let nonce = *sub_matches.get_one::<u64>("nonce").unwrap();
            let gas_price = sub_matches.get_one::<String>("gas_price").unwrap();
            let gas_price = towei(gas_price).unwrap();
            let gas_limit = *sub_matches.get_one::<u64>("gas_limit").unwrap();

            let mut r = U256::from_str(sub_matches.get_one::<String>("r").unwrap()).unwrap();
            let mut s = U256::from_str(sub_matches.get_one::<String>("s").unwrap()).unwrap();
            let mut v = *sub_matches.get_one::<u64>("v").unwrap();
            if r == U256::from(0) || s == U256::from(0) {
                // unsigned
                r = U256::from(0);
                s = U256::from(0);
                v = chainid;
            } else {
                // signed
                v = v + chainid * 2 + 35; // according to EIP155, https://eips.ethereum.org/EIPS/eip-155
            }

            let to;
            let value;
            let data;
            let mode = sub_matches.get_one::<String>("mode").unwrap();
            match mode.as_str() {
                "main" => {
                    to = H160::from_str(sub_matches.get_one::<String>("to").unwrap()).unwrap(); // to is to
                    value = U256::from(*sub_matches.get_one::<u64>("value").unwrap()); // value is value
                    data = Vec::<u8>::new(); // data is empty
                }
                "erc20" => {
                    to = H160::from_str(sub_matches.get_one::<String>("token").unwrap()).unwrap(); // to is token
                    value = U256::from(0); // value is 0
                    let recepient = sub_matches.get_one::<String>("to").unwrap();
                    let recepient = EthereumAddress::from_str(recepient).unwrap();
                    let amount = U256::from(*sub_matches.get_one::<u64>("value").unwrap());
                    data = encode_transfer("transfer", &recepient, amount); // data is encoded transfer(recepient, amount)
                }
                "any" => {
                    to = H160::from_str(sub_matches.get_one::<String>("to").unwrap()).unwrap(); // as is
                    value = U256::from(*sub_matches.get_one::<u64>("value").unwrap()); // as is
                    data = hex::decode(sub_matches.get_one::<String>("data").unwrap()).unwrap();
                    // as is
                }
                _ => {
                    println!("Invalid mode");
                    return;
                }
            }

            let tx = EIP155Transaction {
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                v,
                r,
                s,
            };
            println!("tx = {}", tx);
        }
        _ => {}
    };
}

fn address_from_public_key(public_key: libsecp256k1::PublicKey) -> EthereumAddress {
    let public_key = EthereumPublicKey::from_secp256k1_public_key(public_key);
    public_key.to_address(&EthereumFormat::Standard).unwrap()
}

fn network_to_chainid(network: &str) -> u64 {
    // to lower
    let network = network.to_lowercase();
    match network.as_str() {
        "eth" => 1,
        "ethereum" => 1,
        "etc" => 61,
        "ethereum_classic" => 61,
        "goerli" => 5,
        "sepolia" => 11155111,
        _ => panic!("Invalid network"),
    }
}

fn towei(value: &str) -> Option<U256> {
    let value = value.to_lowercase();
    // println!("{}", value);
    if value.ends_with("ether") {
        let value = value.trim_end_matches("ether");
        let value = value.parse::<f64>().unwrap();
        let value = value * 1e18;
        Some(U256::from(value as u128))
    } else if value.ends_with("gwei") {
        let value = value.trim_end_matches("gwei");
        let value = value.parse::<f64>().unwrap();
        let value = value * 1e9;
        Some(U256::from(value as u128))
    } else if value.ends_with("wei") {
        let value = value.trim_end_matches("wei");
        let value = value.parse::<f64>().unwrap();
        Some(U256::from(value as u128))
    } else {
        None
    }
}
