# Anychain

A Rust library for multi-chain cryptowallet, supporting transactions of crypto assets on many different
public blockchains including Bitcoin, Ethereum, Tron, Filecoin, etc.

[![Rust CI](https://github.com/uduncloud/anychain/actions/workflows/rust.yml/badge.svg)](https://github.com/uduncloud/anychain/actions/workflows/rust.yml)

### Features

#### Common Traits when it comes to building transactions for different blockchains, they are
* PublicKey
* Address
* Amount
* Transaction
* Network
* Format

#### Common crates used in building transactions for different blockchains, they are
* base58
* secp256k1
* hex
* rand


### Functions

* Build raw unsigned transactions for different blockchains according to parameters taken from the user of this library

* Build signed transactions for different blockchains by merging the raw transaction and the corresponding signature 
  taken from the user of this library


### Build the source
	
    cargo build --release

## Crates

| Name                  | Description            | Crates.io                                                                    | Documentation                                                                    |
|-----------------------|------------------------|------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [`anychain-core`]     | Core types and traits. | [![Crates.io](https://img.shields.io/crates/v/anychain-core)][anychain-core] | [![Documentation](https://shields.io/docsrs/anychain-core)][anychain-core-docs]  |
| [`anychain-bitcoin`]  | Bitcoin impl.          | [![Crates.io](https://img.shields.io/crates/v/anychain-bitcoin)][anychain-bitcoin] | [![Documentation](https://shields.io/docsrs/anychain-bitcoin)][anychain-bitcoin-docs] |
| [`anychain-ethereum`] | Ethereum impl.         | [![Crates.io](https://img.shields.io/crates/v/anychain-ethereum)][anychain-ethereum]       | [![Documentation](https://shields.io/docsrs/anychain-ethereum)][anychain-ethereum-docs] |
| [`anychain-filecoin`] | Filecoin impl.         | [![Crates.io](https://img.shields.io/crates/v/anychain-filecoin)][anychain-filecoin]       | [![Documentation](https://shields.io/docsrs/anychain-filecoin)][anychain-filecoin-docs] |
| [`anychain-tron`]     | Tron impl.       | [![Crates.io](https://img.shields.io/crates/v/anychain-tron)][anychain-tron]       | [![Documentation](https://shields.io/docsrs/anychain-tron)][anychain-tron-docs]     |

## License

This project is licensed under the [MIT license][license].

[`anychain-core`]: https://github.com/0xcregis/anychain/tree/main/anychain-core
[`anychain-bitcoin`]: https://github.com/0xcregis/anychain/tree/main/anychain-bitcoin
[`anychain-ethereum`]: https://github.com/0xcregis/anychain/tree/main/anychain-ethereum
[`anychain-filecoin`]: https://github.com/0xcregis/anychain/tree/main/anychain-filecoin
[`anychain-tron`]: https://github.com/0xcregis/anychain/tree/main/anychain-tron
[anychain-core]: https://crates.io/crates/anychain-core
[anychain-bitcoin]: https://crates.io/crates/anychain-bitcoin
[anychain-ethereum]: https://crates.io/crates/anychain-ethereum
[anychain-filecoin]: https://crates.io/crates/anychain-filecoin
[anychain-tron]: https://crates.io/crates/anychain-tron
[anychain-core-docs]: https://docs.rs/anychain-core
[anychain-bitcoin-docs]: https://docs.rs/anychain-bitcoin
[anychain-ethereum-docs]: https://docs.rs/anychain-ethereum
[anychain-filecoin-docs]: https://docs.rs/anychain-filecoin
[anychain-tron-docs]: https://docs.rs/anychain-tron
[license]: https://github.com/0xcregis/anychain/blob/main/LICENSE
