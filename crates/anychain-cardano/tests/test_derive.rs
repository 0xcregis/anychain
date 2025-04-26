use bip39::Mnemonic;
use cml_chain::{
    address::{Address, AddressKind, BaseAddress},
    certs::StakeCredential,
    genesis::network_info::NetworkInfo,
};
use cml_crypto::{Bip32PrivateKey, Bip32PublicKey};

fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

static BASE_ADDR_ALICE: &str = "addr_test1qp5tjpeph2su74qrg60se276u6zvd90umxmctufxr0jf8gr7dsy677qxztemp72yqgu3xv35w2fts5c5k2c9szlrn5fqttkd5z";
static BASE_ADDR_BOB: &str = "addr_test1qz68r5889sfly48tvr3kmlcf2uc8dxvyk598mkt8qd200z8r8yuyp7vaas4ezh9pdn5vu3wzlntj0h6qdnt4mrmqu0pqt62yar";

/// Helper function to derive keys
fn derive_key(
    private_key: &Bip32PrivateKey,
    account: u32,
    chain: u32,
    index: u32,
) -> Bip32PublicKey {
    private_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(account))
        .derive(chain)
        .derive(index)
        .to_public()
}

#[test]
fn test_derive_alice() {
    // Parse the mnemonic
    let mnemonic_str = "lazy habit orient public finger other absorb shine cause mind general spend exit innocent drama";
    let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
        .unwrap_or_else(|e| panic!("Failed to parse mnemonic: {:?}", e));

    // Derive entropy and private key
    let entropy = mnemonic.to_entropy();
    let bip32_private_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);
    // dbg!(&bip32_private_key.to_bech32());
    let bip32_public_key = bip32_private_key.to_public();

    // Verify the public key
    assert_eq!(
        bip32_public_key.to_bech32(),
        "xpub1gyuwtxy45wmzjsetlrx82mhg86c98zvnwvl7yvaxwt5g5f7aau9usq4e9gwraq2qh5j2ywml0smhflslxfsj0hjqnmzspclprkp5tkcmfgu4v"
    );

    // Derive spend and stake keys
    let spend = derive_key(&bip32_private_key, 0, 0, 0);
    let stake = derive_key(&bip32_private_key, 0, 2, 0);

    // Create base address
    let spend_cred = StakeCredential::new_pub_key(spend.to_raw_key().hash());
    let stake_cred = StakeCredential::new_pub_key(stake.to_raw_key().hash());
    let address =
        BaseAddress::new(NetworkInfo::testnet().network_id(), spend_cred, stake_cred).to_address();

    // Verify the base address
    let address_bech32 = address.to_bech32(None).unwrap();
    assert_eq!(address_bech32, BASE_ADDR_ALICE);
}

#[test]
fn test_derive_bob() {
    // Parse the mnemonic
    let mnemonic_str = "oak anchor meadow nerve limb true banner lock arena brisk width lottery frame walnut barrel innocent enhance feature one gate parade small alert hollow";
    let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
        .unwrap_or_else(|e| panic!("Failed to parse mnemonic: {:?}", e));

    // Derive entropy and private key
    let entropy = mnemonic.to_entropy();
    let bip32_private_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);

    // Derive spend and stake keys
    let spend = derive_key(&bip32_private_key, 0, 0, 0);
    let stake = derive_key(&bip32_private_key, 0, 2, 0);

    // Create base address
    let spend_cred = StakeCredential::new_pub_key(spend.to_raw_key().hash());
    let stake_cred = StakeCredential::new_pub_key(stake.to_raw_key().hash());
    let address =
        BaseAddress::new(NetworkInfo::testnet().network_id(), spend_cred, stake_cred).to_address();

    // Verify the base address
    let address_bech32 = address.to_bech32(None).unwrap();
    assert_eq!(address_bech32, BASE_ADDR_BOB);
}
#[test]
fn test_from_address() {
    // Parse the base address
    let base_address = Address::from_bech32(BASE_ADDR_ALICE)
        .unwrap_or_else(|e| panic!("Failed to parse address: {:?}", e));

    // Verify address properties
    assert_eq!(AddressKind::Base, base_address.kind());
    assert_eq!(
        base_address.network_id().unwrap(),
        NetworkInfo::testnet().network_id()
    );
}
