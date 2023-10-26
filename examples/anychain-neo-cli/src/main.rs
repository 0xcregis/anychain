use clap::{Arg, Command};

fn main() {
    let matches = Command::new("anychain-neo-cli")
        .subcommands(vec![
            Command::new("address-gen")
                .about("Generate an address of a utxo-typed blockchain")
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
                    Arg::new("address")
                        .num_args(1..)
                        .help("Specify the address to be validated"),
                ),
            Command::new("tx-gen")
                .about("Generate a transaction of a utxo-typed blockchain")
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
            let _private_key = sub_matches.get_one::<String>("private_key");
            let _public_key = sub_matches.get_one::<String>("public_key");
        }
        Some(("address-validate", sub_matches)) => {
            let _address = sub_matches.get_one::<String>("address");

            if _address.is_none() {
                println!("Address not provided");
            }
        }
        Some(("tx-gen", sub_matches)) => {
            let inputs = sub_matches.get_many::<String>("inputs");
            let outputs = sub_matches.get_many::<String>("outputs");

            if inputs.is_none() {
                println!("No input is provided");
                return;
            }

            if outputs.is_none() {
                println!("No output is provided");
                return;
            }

            let _inputs: Vec<&String> = inputs.unwrap().collect();
            let _outputs: Vec<&String> = outputs.unwrap().collect();
        }
        _ => {}
    };
}
