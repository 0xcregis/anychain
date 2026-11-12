use anychain_bitcoin::{
    create_script_pub_key, Bitcoin, BitcoinAddress, BitcoinAmount, BitcoinCash,
    BitcoinTransactionOutput,
};
use std::str::FromStr;

#[test]
fn test_create_script_pub_key() {
    let cash_p2sh = BitcoinAddress::<BitcoinCash>::from_str(
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    )
    .unwrap();
    let legacy_p2sh =
        BitcoinAddress::<BitcoinCash>::from_str("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC").unwrap();
    let cash_p2pkh = BitcoinAddress::<BitcoinCash>::from_str(
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    )
    .unwrap();

    let legacy_p2sh_script = create_script_pub_key(&legacy_p2sh).unwrap();
    let cash_p2sh_script = create_script_pub_key(&cash_p2sh).unwrap();
    let cash_p2pkh_script = create_script_pub_key(&cash_p2pkh).unwrap();

    // Both P2SH encodings embed the same hash160, so they must produce the
    // same P2SH script: OP_HASH160 <20-byte hash> OP_EQUAL.
    assert_eq!(
        hex::encode(&legacy_p2sh_script),
        "a91476a04053bda0a88bda5177b86a15c3b29f55987387"
    );
    assert_eq!(cash_p2sh_script, legacy_p2sh_script);
    assert_eq!(
        BitcoinAddress::<BitcoinCash>::from_script_pub_key(&cash_p2sh_script).unwrap(),
        cash_p2sh
    );

    // The P2PKH address shares the hash160 but uses the P2PKH script:
    // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG.
    assert_eq!(
        hex::encode(&cash_p2pkh_script),
        "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac"
    );

    // The hash160 embedded in all three scripts is identical.
    assert_eq!(&legacy_p2sh_script[2..22], &cash_p2sh_script[2..22]);
    assert_eq!(&cash_p2sh_script[2..22], &cash_p2pkh_script[3..23]);

    // P2SH and P2PKH scripts still differ in structure.
    assert_ne!(cash_p2sh_script, cash_p2pkh_script);

    let output = BitcoinTransactionOutput::new(cash_p2sh, BitcoinAmount(100_000)).unwrap();
    assert_eq!(output.script_pub_key, legacy_p2sh_script);
    dbg!("expected P2SH: {}", hex::encode(&legacy_p2sh_script));
    dbg!("actual output: {}", hex::encode(&output.script_pub_key));
}

#[test]
fn test_bech32m_bip350_outputs() {
    // Valid Taproot P2TR (witness v1) encoded with Bech32m
    let p2tr = BitcoinAddress::<Bitcoin>::from_str(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
    )
    .unwrap();
    let output = BitcoinTransactionOutput::new(p2tr.clone(), BitcoinAmount(50_000)).unwrap();
    assert_eq!(
        hex::encode(&output.script_pub_key),
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(
        BitcoinAddress::<Bitcoin>::from_script_pub_key(&output.script_pub_key).unwrap(),
        p2tr
    );

    // Witness v1 encoded with Bech32 (wrong variant) and witness v0 encoded with Bech32m must fail
    assert!(BitcoinAddress::<Bitcoin>::from_str(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"
    )
    .is_err());
    assert!(
        BitcoinAddress::<Bitcoin>::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh").is_err()
    );
}

#[test]
#[ignore = "20261109, reproduces the pre-fix CashAddr P2SH bug; expected to fail after the fix"]
fn test_cashaddr_p2sh_was_treated_as_p2pkh() {
    let cash_p2sh = BitcoinAddress::<BitcoinCash>::from_str(
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    )
    .unwrap();
    let legacy_p2sh =
        BitcoinAddress::<BitcoinCash>::from_str("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC").unwrap();
    let cash_p2pkh = BitcoinAddress::<BitcoinCash>::from_str(
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    )
    .unwrap();

    let expected = create_script_pub_key(&legacy_p2sh).unwrap();
    let actual = create_script_pub_key(&cash_p2sh).unwrap();
    assert_eq!(
        hex::encode(&expected),
        "a91476a04053bda0a88bda5177b86a15c3b29f55987387"
    );
    assert_eq!(
        hex::encode(&actual),
        "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac"
    );
    assert_ne!(actual, expected); // Equivalent P2SH addresses produce different scripts.
    assert_eq!(actual, create_script_pub_key(&cash_p2pkh).unwrap());

    let output = BitcoinTransactionOutput::new(cash_p2sh, BitcoinAmount(100_000)).unwrap();
    assert_eq!(output.script_pub_key, actual);
    dbg!("expected P2SH: {}", hex::encode(expected));
    dbg!("actual output: {}", hex::encode(output.script_pub_key));
}
