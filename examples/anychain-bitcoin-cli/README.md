# anychain-bitcoin-cli

A command line program for the generation and/or validation of addresses and transactions of utxo compatible blockchains

### Build

cd anychain/anychain-bitcoin-cli

cargo build --release



### Run
```
cd ../target/release
```

#### Address Generation

* we can generate addresses by providing a corresponding private key:
```
./anychain-bitcoin-cli address-gen -n [network] --priv [private_key]
```

e.g.
```
./anychain-bitcoin-cli address-gen -n bitcoin --priv cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564
```

(the private key being a 64-byte hex string)

* we can also generate addresses by providing a corresponding public key:

```
./anychain-bitcoin-cli address-gen -n [network] --pub [public_key]
```

e.g.
```
./anychain-bitcoin-cli address-gen -n dogecoin --pub 02d215a89dc4aab5191d9480535aba2db9994c3c8fa068102fdb71fba676179e39
```

(the public key being a 66-byte hex string)

[network] could be any item following:
```
  bitcoin
  bitcoin_testnet
  bitcoincash
  bitcoincash_testnet
  litecoin
  litecoin_testnet
  dogecoin
  dogecoin_testnet
```


#### Address Validation

* we can check if a provided address is a valid one for a specified blockchain network:

```
./anychain-bitcoin-cli address-validate -n [network] [address]
```

e.g.
```
./anychain-bitcoin-cli address-validate -n bitcoin 15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg
```

[network] could be any item following:
```
  bitcoin
  bitcoin_testnet
  bitcoincash
  bitcoincash_testnet
  litecoin
  litecoin_testnet
  dogecoin
  dogecoin_testnet
```

#### Transaction Generation

* we can generate a transaction for a specified blockchain network by providing several inputs and several outputs:

```
./anychain-bitcoin-cli tx-gen -n [network] -i [input] [input] ...  -o [output] [output] ...
```

##### Generate a P2PKH Transaction
e.g.
```
./anychain-bitcoin-cli tx-gen -n bitcoin -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 0, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\"}" -o "{\"to\": \"15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg\", \"amount\": 3300000}"
```

##### Generate a P2SH_P2WPKH Transaction
e.g.
```
./anychain-bitcoin-cli tx-gen -n bitcoin -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 0, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\", \"format\": \"p2sh_p2wpkh\", \"balance\": 8800000}" -o "{\"to\": \"15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg\", \"amount\": 3300000}"
```

##### Generate a Bech32 Transaction
e.g.
```
./anychain-bitcoin-cli tx-gen -n bitcoin -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 0, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\", \"format\": \"bech32\", \"balance\": 8800000}" -o "{\"to\": \"15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg\", \"amount\": 3300000}"
```

##### Generate a CashAddr Transaction (Bitcoin Cash Only)
e.g.
```
./anychain-bitcoin-cli tx-gen -n bitcoincash -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 0, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\", \"format\": \"cash_addr\", \"balance\": 8800000}" -o "{\"to\": \"bitcoincash:qp20yqd2260z7rqvm29ntst8vljw5zge352yqrlsql\", \"amount\": 3300000}"
```

##### Generate a Transaction with multiple inputs in multiple formats
e.g.
```
./anychain-bitcoin-cli tx-gen -n bitcoin -i "{\"txid\": \"9975deeace71258149e8b0d02ed83d59335a658dd348d8cae7bf4ff9ed9db2d0\", \"index\": 3, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\"}" "{\"txid\": \"36d3815b142fc9a93c1fff1ef7994fe6f3919ccc54a51c891e8418ca95a51020\", \"index\": 1, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\", \"format\": \"p2sh_p2wpkh\", \"balance\": 8090000}" "{\"txid\": \"ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b\", \"index\": 2, \"private_key\": \"cd483a289c081698fc5a5a47291550962f1de7c98a7d5fcd77be765335e4f564\", \"format\": \"bech32\", \"balance\": 31370000}" -o "{\"to\": \"15dcrsqEnb7uAsqByxbrUbigpHjPTarbqg\", \"amount\": 3300000}" "{\"to\": \"1AWccoPWBihK9kHi1UkZnqpreW55PCugYR\", \"amount\": 9000000}"
```
