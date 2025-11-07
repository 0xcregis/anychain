#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bip32;
pub mod bip39;
pub mod crypto;
pub mod error;

use anychain_core::crypto::sha256;
use anyhow::{anyhow, Result};
use bip32::PrivateKey;
use curve25519_dalek::Scalar;
use ed25519_dalek::{hazmat::ExpandedSecretKey, Signature};
use sha2::Sha512;

pub fn secp256k1_sign(sk: &[u8], msg: &[u8]) -> Result<(Vec<u8>, u8)> {
    let sk = libsecp256k1::SecretKey::parse_slice(sk)?;
    let msg = libsecp256k1::Message::parse_slice(msg)?;
    let (sig, recid) = libsecp256k1::sign(&msg, &sk);
    Ok((sig.serialize().to_vec(), recid.into()))
}

pub fn ed25519_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != 32 {
        return Err(anyhow!("Invalid private key length".to_string()));
    }
    let sk = sk.to_vec();
    let scalar = Scalar::from_bytes_mod_order(sk.clone().try_into().unwrap());
    let nonce = sha256(&sk).to_vec();
    let xsk = [sk, nonce].concat();
    // let xsk = ExpandedSecretKey::from_bytes(&xsk).unwrap();
    let xsk = ExpandedSecretKey::from_slice(&xsk).unwrap();
    let pk = PrivateKey::public_key(&scalar);
    let sig: Signature = ed25519_dalek::hazmat::raw_sign::<Sha512>(&xsk, msg, &pk);
    let sig_vec = sig.to_bytes().to_vec();
    Ok(sig_vec)
}

#[cfg(test)]
mod tests {
    use crate::bip32::{ChildNumber, DerivationPath, Prefix, XprvSecp256k1, XpubSecp256k1};
    use crate::bip39::{Language, Mnemonic, Seed};

    #[test]
    fn test_mnemonic() {
        let phrase = "heavy face learn track claw jaguar pigeon uncle seven enough glow where";
        // let mnemonic =  Mnemonic::new(MnemonicType::Words12,Language::English);
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        assert_eq!(phrase, mnemonic.phrase());
        println!("phrase:{:#?}", phrase);
        let seed = Seed::new(&mnemonic, "");
        println!("seed:{:X}", seed);

        let path: DerivationPath = "m/44'/196'/300049'/0".parse().unwrap();
        let xprv = XprvSecp256k1::new_from_path(seed, &path).unwrap();
        let _ek = xprv.to_extended_key(Prefix::XPRV);
        println!("xprv:{:?}", xprv);
        let cp: ChildNumber = 1u32.into();
        let cx = xprv.derive_child(cp).unwrap();
        let mut hex = String::new();
        for b in cx.to_bytes() {
            hex.push_str(format!("{:X}", b).as_str());
        }
        println!("{}", hex)
    }

    #[test]
    fn test_master_xprv() {
        let phrase = "heavy face learn track claw jaguar pigeon uncle seven enough glow where";
        // let mnemonic =  Mnemonic::new(MnemonicType::Words12,Language::English);
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        let seed = Seed::new(&mnemonic, "");
        // let path: DerivationPath = "m".parse().unwrap();
        let xprv = XprvSecp256k1::new(seed).unwrap();
        let _secret = xprv.private_key();
        //let ek = xprv.to_extended_key(Prefix::XPRV);
        println!("xprv:{:}", xprv.to_string(Prefix::XPRV).as_str());
    }

    #[test]
    fn test_xpub() {
        let phrase =
            "deal pretty baby midnight federal capital suggest cheese creek mutual boil shine";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        let seed = Seed::new(&mnemonic, "");
        let path: DerivationPath = "m/44'/60".parse().unwrap();
        let xprv = XprvSecp256k1::new_from_path(seed, &path).unwrap();
        let xpub: XpubSecp256k1 = xprv.public_key();

        println!("{}", xpub.to_string(Prefix::XPUB));
    }
}
