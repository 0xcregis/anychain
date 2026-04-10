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
    let sk = sk.to_vec();
    let sk: [u8; 32] = sk
        .try_into()
        .map_err(|_| anyhow!("Invalid private key length".to_string()))?;

    /* * NOTE: We intentionally bypass the standard Ed25519 "clamping" process
     * (clearing the lowest 3 bits and specific MSB bits).
     *
     * In standard RFC 8032, clamping is required to prevent small-subgroup attacks.
     * However, clamping breaks the additivity of scalars, which is essential for
     * Hierarchical Deterministic (HD) wallets. By using raw scalars without clamping,
     * we enable "non-hardened derivation," allowing sub-public keys and addresses
     * to be derived directly from a parent public key without exposing the private key.
     *
     * Warning: This makes the implementation non-compliant with standard Ed25519
     * and should only be used within protocols that handle the co-factor 8 issue
     * (e.g., via Ristretto or ensuring all points are in the prime-order subgroup).
     */
    let scalar = Scalar::from_bytes_mod_order(sk);
    let nonce = sha256(&sk).to_vec();
    let nonce: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("Invalid nonce length".to_string()))?;

    let xsk = ExpandedSecretKey {
        scalar,
        hash_prefix: nonce,
    };

    let pk = PrivateKey::public_key(&scalar);
    let sig: Signature = ed25519_dalek::hazmat::raw_sign::<Sha512>(&xsk, msg, &pk);
    let sig_vec = sig.to_bytes().to_vec();

    Ok(sig_vec)
}

#[cfg(test)]
mod tests {
    use super::ed25519_sign;
    use crate::bip32::{ChildNumber, DerivationPath, Prefix, XprvSecp256k1, XpubSecp256k1};
    use crate::bip39::{Language, Mnemonic, Seed};
    use ed25519_dalek::{
        hazmat::{self, ExpandedSecretKey},
        Signature, Signer, SigningKey, VerifyingKey,
    };
    use sha2::Sha512;

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

    #[test]
    fn test_stand_ed25519_sign() {
        // ed25519-dalek v2.2.0

        let secret_key_bytes: [u8; 32] = [
            224, 90, 166, 77, 51, 213, 200, 177, 62, 18, 172, 127, 11, 124, 215, 1, 150, 165, 56,
            139, 192, 234, 139, 72, 131, 7, 67, 224, 44, 17, 79, 101,
        ];

        let secret_key = ed25519_dalek::SecretKey::from(secret_key_bytes);
        let expanded_secret_key: ExpandedSecretKey = ExpandedSecretKey::from(&secret_key);
        let verifying_key = VerifyingKey::from(&expanded_secret_key);

        let message = b"helloworld";
        let raw_signature: Signature =
            hazmat::raw_sign::<Sha512>(&expanded_secret_key, message, &verifying_key);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let standard_signature = signing_key.sign(message);

        assert_eq!(raw_signature, standard_signature);

        let custom_signature_result = ed25519_sign(&expanded_secret_key.scalar.to_bytes(), message);
        assert!(custom_signature_result.is_ok());

        let custom_signature_bytes = custom_signature_result.unwrap();

        // custom_signature_bytes does not equal raw_signature
        assert_ne!(custom_signature_bytes.as_slice(), raw_signature.to_bytes());
    }

    #[test]
    fn test_ed25519_sign() {
        let sk = [1u8; 32];
        let msg = b"hello world";
        let sig = super::ed25519_sign(&sk, msg);
        assert!(sig.is_ok());

        let sig = sig.unwrap();
        let expected_sig = [
            5, 0, 237, 32, 228, 86, 144, 1, 231, 127, 241, 133, 219, 99, 108, 67, 2, 122, 193, 83,
            79, 26, 253, 179, 22, 235, 248, 218, 171, 222, 240, 37, 141, 35, 38, 109, 86, 242, 219,
            149, 203, 118, 228, 214, 173, 156, 71, 238, 246, 140, 200, 129, 33, 217, 203, 199, 44,
            91, 144, 161, 185, 213, 14, 6,
        ];
        assert_eq!(expected_sig.as_slice(), sig);
    }
}
