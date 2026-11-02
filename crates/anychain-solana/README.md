# anychain-solana

anychain-solana is a Rust library that provides a simple and unified interface for interacting with the Solana
blockchain.

## Features

- **Transaction Processing**: Functionality to create, sign, and broadcast transactions on the Solana network
- **Integration with Solana RPC API**: Interact with the Solana RPC API for querying account information, transaction
  details, etc.
- **Wallet Management**: Creating and managing Solana wallets, including keypair
  generation, public/private key management, etc.

## Installation

Add the following to your Cargo.toml file:

```toml
[dependencies]
anychain-solana= "0.1.10"
```

Then, run cargo build to download and compile the library.

## Usage

```shell
cargo build --example create-account
cargo run --example create-account
```

## License

anychain-solana released under the MIT License. See the [LICENSE](LICENSE) file for more information. 
