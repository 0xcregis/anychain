use crate::address::SuiAddress;
use crate::format::SuiFormat;
use anychain_core::{Address, AddressError, PublicKey, PublicKeyError};

use derive_more::{AsMut, AsRef, From};
use fastcrypto::ed25519::{
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519PublicKeyAsBytes, Ed25519Signature,
    Ed25519SignatureAsBytes,
};
use fastcrypto::encoding::{Base64, Bech32, Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::secp256k1::{
    Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1PublicKeyAsBytes, Secp256k1Signature,
    Secp256k1SignatureAsBytes, SECP256K1,
};
use fastcrypto::secp256r1::{
    Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1PublicKeyAsBytes, Secp256r1Signature,
    Secp256r1SignatureAsBytes,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, From, PartialEq, Eq)]
pub enum SuiPrivateKey {
    Ed25519(Ed25519PrivateKey),
    Secp256k1(Secp256k1PrivateKey),
    Secp256r1(Secp256r1PrivateKey),
}

#[derive(Clone, Debug)]
pub enum SuiPublicKey {
    Ed25519(Ed25519PublicKeyAsBytes),
    Secp256k1(Secp256k1PublicKeyAsBytes),
    Secp256r1(Secp256r1PublicKeyAsBytes),
    // ZkLogin(ZkLoginPublicIdentifier),
}

#[derive(Clone, Copy)]
pub enum SignatureScheme {
    ED25519,
    Secp256k1,
    Secp256r1,
    BLS12381, // This is currently not supported for user Sui Address.
    MultiSig,
    ZkLoginAuthenticator,
}

impl SignatureScheme {
    pub fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
            SignatureScheme::Secp256r1 => 0x02,
            SignatureScheme::MultiSig => 0x03,
            SignatureScheme::BLS12381 => 0x04, // This is currently not supported for user Sui Address.
            SignatureScheme::ZkLoginAuthenticator => 0x05,
        }
    }

    pub fn from_flag(flag: &str) -> Result<SignatureScheme, PublicKeyError> {
        let byte_int = flag
            .parse::<u8>()
            .map_err(|_| PublicKeyError::Crate("Invalid key scheme", flag.to_string()))?;
        Self::from_flag_byte(&byte_int)
    }

    pub fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme, PublicKeyError> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            0x02 => Ok(SignatureScheme::Secp256r1),
            0x03 => Ok(SignatureScheme::MultiSig),
            0x04 => Ok(SignatureScheme::BLS12381),
            0x05 => Ok(SignatureScheme::ZkLoginAuthenticator),
            _ => Err(PublicKeyError::Crate(
                "Invalid key scheme",
                byte_int.to_string(),
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginPublicIdentifier(#[schemars(with = "Base64")] pub Vec<u8>);

impl PublicKey for SuiPublicKey {
    type SecretKey = SuiPrivateKey;
    type Address = SuiAddress;
    type Format = SuiFormat;

    /// Returns the sui public key corresponding to the given secret key.
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        match secret_key {
            Self::SecretKey::Ed25519(sk) => {
                let pk = &Ed25519PublicKey::from(sk);
                Self::Ed25519(pk.into())
            }
            Self::SecretKey::Secp256k1(sk) => {
                let pk = &Secp256k1PublicKey::from(sk);
                Self::Secp256k1(pk.into())
            }
            Self::SecretKey::Secp256r1(sk) => {
                let pk = &Secp256r1PublicKey::from(sk);
                Self::Secp256r1(pk.into())
            }
        }
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        let mut hasher = Blake2b256::default();
        hasher.update([self.flag()]);
        hasher.update(self);
        let g_arr = hasher.finalize();
        Ok(SuiAddress::new(g_arr.digest))
    }
}

impl AsRef<[u8]> for SuiPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SuiPublicKey::Ed25519(pk) => &pk.0,
            SuiPublicKey::Secp256k1(pk) => &pk.0,
            SuiPublicKey::Secp256r1(pk) => &pk.0,
            // PublicKey::ZkLogin(z) => &z.0,
        }
    }
}

impl SuiPublicKey {
    pub fn flag(&self) -> u8 {
        // self.scheme().flag()
        let signature_scheme = match self {
            SuiPublicKey::Ed25519(_) => SignatureScheme::ED25519,
            SuiPublicKey::Secp256k1(_) => SignatureScheme::Secp256k1,
            SuiPublicKey::Secp256r1(_) => SignatureScheme::Secp256r1,
        };
        signature_scheme.flag()
    }

    // pub fn scheme(&self) -> SignatureScheme {
    //     match self {
    //         SuiPublicKey::Ed25519(_) => Ed25519SuiSignature::SCHEME,
    //         SuiPublicKey::Secp256k1(_) => Secp256k1SuiSignature::SCHEME,
    //         SuiPublicKey::Secp256r1(_) => Secp256r1SuiSignature::SCHEME,
    //         // SuiPublicKey::ZkLogin(_) => SignatureScheme::ZkLoginAuthenticator,
    //     }
    // }
}

impl FromStr for SuiPublicKey {
    type Err = PublicKeyError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for SuiPublicKey {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
