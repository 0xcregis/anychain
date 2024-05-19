# anychain-ethereum-cli

A command line program for the generation and/or validation of addresses and transactions of evm compatible blockchains

### Build

cd anychain/anychain-ethereum-cli

cargo build --release



### Run
```
cd ../target/release
```

#### 0. Generate Address 

##### from public key

```bash
./anychain-ethereum-cli address-gen --pub 0x0299bb27e93fba02d13d78b1d7807cc811266e31e7b6feae3e09d42d49482fda95
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
./anychain-ethereum-cli address-gen --pub 0299bb27e93fba02d13d78b1d7807cc811266e31e7b6feae3e09d42d49482fda95
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
./anychain-ethereum-cli address-gen --pub 0499bb27e93fba02d13d78b1d7807cc811266e31e7b6feae3e09d42d49482fda9519127e684ded784c50d4559d87e0723c801635f6c387bb36cb4bf72e33201934
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
./anychain-ethereum-cli address-gen --pub 0x0499bb27e93fba02d13d78b1d7807cc811266e31e7b6feae3e09d42d49482fda9519127e684ded784c50d4559d87e0723c801635f6c387bb36cb4bf72e33201934
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
```

##### from private key

```bash
./anychain-ethereum-cli address-gen --prv 0xb2ab8cfd1de774907de3fb12c8f3bafb76a575e1004f9f33309f1c570be18baf
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
./anychain-ethereum-cli address-gen --prv b2ab8cfd1de774907de3fb12c8f3bafb76a575e1004f9f33309f1c570be18baf
0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
```

#### 1. Parse Address from String & Validate Address

```bash
./anychain-ethereum-cli address-validate E0709D3C521fe51CA7E65E00929D7EEFCF0b1814
Valid
./anychain-ethereum-cli address-validate 0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1814
Valid
./anychain-ethereum-cli address-validate 0xE0709D3C521fe51CA7E65E00929D7EEFCF0b1815
Valid # anychain does not check the checksum
./anychain-ethereum-cli address-validate 0xE0709D3C521fe51CA7E65E00929D7EEFCF0b18145
Invalid
```

#### 2. Generate wei from ether and vice versa

```bash
./anychain-ethereum-cli towei 0.12345678ether
123456780000000000
./anychain-ethereum-cli towei 1gwei
1000000000
./anychain-ethereum-cli towei 1.1Gwei
1100000000
```


#### 3. Make Transaction

This is a "Do What I Mean" (DWIM) style command, which will generate a transaction from the given parameters.
The parameters are:

| your intent | mode | to | token | value | data | rsv |
| ----------- | ---- | -- | ----- | ----- | ---- | --- |
| unsigned ether transfer | main | recepient | leave empty | amount in wei | leave empty | leave empty |
| unsigned token transfer | erc20 | recepient | token contract | amount of token | leave empty | leave empty |
| unsigned any transaction | any | to | leave empty | value | data | leave empty |
| signed ether transfer | main | recepient | leave empty | amount in wei | leave empty | rsv |
| signed token transfer | erc20 | recepient | token contract | amount of token | leave empty | rsv |
| signed any transaction | any | to | leave empty | value | data | rsv |


##### Make an ether transaction's preimage

```bash
./anychain-ethereum-cli maketx --mode main --network sepolia --nonce 4 --gasprice 2gwei --gaslimit 21000 --to 0x717648D7d50fF001cc1088E8dc416Dfa26c32CB9 --value 1145141919810893 
```
which outputs:
```
tx = 0xed04847735940082520894717648d7d50ff001cc1088e8dc416dfa26c32cb9870411802159054d8083aa36a78080
```

##### Make a signed ether transaction

```bash
./anychain-ethereum-cli maketx --mode main --network sepolia --nonce 4 --gasprice 2gwei --gaslimit 21000 --to 0x717648D7d50fF001cc1088E8dc416Dfa26c32CB9 --value 1145141919810893 -r 371efe039d17f0bf74b732c94a5d7c4a04f4bf747bde94a779dd8fd7b180d106 -s 0eacd1b265ddfea09f4c20400429dba2224af8eed462a732358f7da8f1848e18 -v 0
```
which outputs:
```
tx = 0xf86e04847735940082520894717648d7d50ff001cc1088e8dc416dfa26c32cb9870411802159054d808401546d71a0371efe039d17f0bf74b732c94a5d7c4a04f4bf747bde94a779dd8fd7b180d106a00eacd1b265ddfea09f4c20400429dba2224af8eed462a732358f7da8f1848e18
```

this tx can successfully broadcast: https://sepolia.etherscan.io/tx/0x9abef6656c8c246af1e68d5bca943507727b10597fd2b1cf84d14a868e7da3fb

##### make an erc-20 transaction's preimage

```bash
./anychain-ethereum-cli maketx --mode erc20 --network sepolia --nonce 5 --gasprice 2gwei --gaslimit 51000 --to 0x717648D7d50fF001cc1088E8dc416Dfa26c32CB9 --token 0x779877A7B0D9E8603169DdbD7836e478b4624789 --value 1145141919810893 
```
which outputs
```
tx = 0xf86b05847735940082c73894779877a7b0d9e8603169ddbd7836e478b462478980b844a9059cbb000000000000000000000000717648d7d50ff001cc1088e8dc416dfa26c32cb9000000000000000000000000000000000000000000000000000411802159054d83aa36a78080
```

##### make a signed erc-20 transaction

```bash
./anychain-ethereum-cli maketx --mode erc20 --network sepolia --nonce 5 --gasprice 2gwei --gaslimit 51000 --to 0x717648D7d50fF001cc1088E8dc416Dfa26c32CB9 --token 0x779877A7B0D9E8603169DdbD7836e478b4624789 --value 1145141919810893 -r 2fe49c0b946b77bb2c95a60a57c2ec9e5cb25504d0e549eb3a3cbfed8bc9cc54 -s 0x0e050e046dec65c1505653fe6147eb1fa20c63f6b8c7b78c7138b74f48a260a1 -v 0
```
which outputs
```
tx = 0xf8ac05847735940082c73894779877a7b0d9e8603169ddbd7836e478b462478980b844a9059cbb000000000000000000000000717648d7d50ff001cc1088e8dc416dfa26c32cb9000000000000000000000000000000000000000000000000000411802159054d8401546d71a02fe49c0b946b77bb2c95a60a57c2ec9e5cb25504d0e549eb3a3cbfed8bc9cc54a00e050e046dec65c1505653fe6147eb1fa20c63f6b8c7b78c7138b74f48a260a1
```
this tx can successfully broadcast: https://sepolia.etherscan.io/tx/0x9646b0732437f7f004798fb6ce923c61030934796e8f77db748d9ef32e68b597

