# anychain-neo-cli

A command line program for the generation and/or validation of addresses and transactions of utxo compatible blockchains

### Build

cd anychain/anychain-neo-cli

cargo build --release



### Run
```
cd ../target/release
```

#### Address Generation

* we can generate addresses by providing a corresponding private key:
```
./anychain-neo-cli address-gen --priv [private_key]
```

e.g.
```
./anychain-neo-cli address-gen --priv cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564
```

(the private key being a 64-byte hex string)

* we can also generate addresses by providing a corresponding public key:

```
./anychain-neo-cli address-gen --pub [public_key]
```

e.g.
```
./anychain-neo-cli address-gen --pub 02d215a89dc4aab5191d9480535aba2db9994c3c8fa068102fdb71fba676179e39
```

(the public key being a 66-byte hex string)


#### Address Validation

* we can check if a provided address is a valid one for a specified blockchain network:

```
./anychain-neo-cli address-validate [address]
```

e.g.
```
./anychain-neo-cli address-validate NVEqR4e73afGKpVBzBXLEnY5F5uZSmSKZZ
```

#### Transaction Generation

* we can generate a transaction for a specified blockchain network by providing several inputs and several outputs:

```
./anychain-neo-cli tx-gen -i [input] [input] ...  -o [output] [output] ...
```

##### Generate a Transfer Transaction
e.g.
```
./anychain-neo-cli tx-gen -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 0, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\"}" -o "{\"to\": \"15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg\", \"amount\": 3300000}"
```

