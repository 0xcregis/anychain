# anychain

A Rust library for multi-chain cryptowallet, supporting transactions of crypto assets on many different
public blockchains including Bitcoin, Ethereum, Tron, Filecoin, etc.

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
