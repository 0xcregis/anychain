# Design Principles for AnyChain Wallet SDK

1. Support transfer transactions for the top 100 tokens by market cap and TVL, including: BTC, ETH, USDT, BNB, SOL, USDC, TON, etc. Correspondingly, the blockchains to be integrated include: Bitcoin, Ethereum, Solana, as well as L2 networks on various chains.
2. Implement cross-platform compilation for wide compatibility. Language choice limited to C/C++/Rust due to source code and toolchain considerations.

## Abstraction of Public Chain Features

### Core Features Most Public Chains Need to Support

- PublicKey
- PrivateKey
- Address
- Amount
- Transaction
- Network
- Format

anychain-core, as a comprehensive abstract Trait, defines the following common methods:

```rust
pub trait PublicKey {
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

pub trait Address {
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError>;
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError>;
}

pub trait Amount {}

pub trait Format {}

pub trait Transaction {
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError>;
    fn sign();
    fn from_bytes();
    fn to_bytes(&self);
    fn to_transaction_id(&self);
}
```

### Trait Implementation for Various Chains

Let's take TronAddress from anychain-tron as an example:

```rust
pub struct TronAddress([u8; 21]);

impl Address for TronAddress {
    type Format = TronFormat;
    type PrivateKey = TronPrivateKey;
    type PublicKey = TronPublicKey;

    fn from_private_key(
        private_key: &Self::PrivateKey, 
        format: &Self::Format
    ) -> Result<Self, AddressError> {
        todo!()
    }

    fn from_public_key(
        public_key: &Self::PublicKey, 
        format: &Self::Format
    ) -> Result<Self, AddressError> {
        todo!()
    }
}
```

By introducing the abstraction layer of anychain-core and the specific implementations of chains such as anychain-bitcoin and anychain-tron, upper-level applications can use unified code and interfaces to call the anychain SDK.

## Cross-Platform Compilation

| Platform | Target File Format |
| --- | --- |
| iOS | .a (Static Library) |
| Android | .so (Shared Object) |
| Web/Wasm | .wasm (WebAssembly) |
| Windows | .dll (Dynamic-Link Library) |
| macOS | .dylib (Dynamic Library) |
| Embedded Devices | ELF (Executable and Linkable Format) |
| Trusted Execution Environment (TEE) | .eif (Encrypted Image File) |

### iOS platform calling hierarchy

```
+-------------------+
| iOS Application   |
+-------------------+
        |
        | Link
        v
+-------------------+
| C Library (.dylib)|
+-------------------+
        |
        | FFI
        v
+-------------------+
| Rust Library      |
+-------------------+
        |
        | Compile
        v
+-------------------+
| Rust Source Code  |
+-------------------+
```

### iOS Platform Compilation Steps:

1. Creating a Rust library
2. Using FFI (Foreign Function Interface) in Rust
3. Defining C-ABI functions
4. Compiling the library file
5. Linking the library file to the iOS application
6. Handling data types
7. Testing and debugging

### Compiled Target Sizes

| **Platform/Format** | **File Name** | **Size** |
| --- | --- | --- |
| Docker image | enclave-server | < 17M |
| WebAssembly package | anychain_wasm_bg.wasm | 81K |
| STM32 | ROM | < 10M |
| iOS | anychain-ethereum-cli | 7.4M |

In comparison, web3.js/node_modules requires the inclusion of third-party packages up to 29M

## Anychain-KMS

### Anychain's BIP32/BIP39-based utility functions

- Private Key
- Public Key
- Mnemonic
- Seed
- Extended Key
- Extended Private Key
- Extended Public Key
- Derivation Path

These utility functions are used to support wallet generation for various blockchains.