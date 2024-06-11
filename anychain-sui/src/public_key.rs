use crate::{address::SuiAddress, format::SuiFormat};
use anychain_core::{AddressError, PublicKey, PublicKeyError};
use derive_more::From;
use fastcrypto::{
    ed25519::{
        Ed25519PrivateKey, Ed25519PublicKey, Ed25519PublicKeyAsBytes, ED25519_PUBLIC_KEY_LENGTH,
    },
    encoding::{Base64, Encoding},
    hash::{Blake2b256, HashFunction},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1PublicKeyAsBytes},
    secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1PublicKeyAsBytes},
    traits::{KeyPair, ToFromBytes},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{clone::Clone, fmt::Display, ops::Deref, str::FromStr};
use sui_types::crypto::SuiKeyPair as RawSuiKeyPair;

#[derive(Debug)]
pub struct SuiKeyPair(pub RawSuiKeyPair);

impl SuiKeyPair {
    pub fn from_raw(keypair: RawSuiKeyPair) -> Self {
        Self(keypair)
    }

    pub fn pubkey(&self) -> SuiPublicKey {
        match &self.0 {
            RawSuiKeyPair::Ed25519(kp) => SuiPublicKey::Ed25519(kp.public().into()),
            RawSuiKeyPair::Secp256k1(kp) => SuiPublicKey::Secp256k1(kp.public().into()),
            RawSuiKeyPair::Secp256r1(kp) => SuiPublicKey::Secp256r1(kp.public().into()),
        }
    }
}

impl Clone for SuiKeyPair {
    fn clone(&self) -> Self {
        Self(self.0.copy())
    }
}

impl Deref for SuiKeyPair {
    type Target = RawSuiKeyPair;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
        }
    }
}

impl SuiPublicKey {
    pub fn flag(&self) -> u8 {
        let signature_scheme = match self {
            SuiPublicKey::Ed25519(_) => SignatureScheme::ED25519,
            SuiPublicKey::Secp256k1(_) => SignatureScheme::Secp256k1,
            SuiPublicKey::Secp256r1(_) => SignatureScheme::Secp256r1,
        };
        signature_scheme.flag()
    }

    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[self.flag()]);
        bytes.extend_from_slice(self.as_ref());
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> Result<Self, PublicKeyError> {
        let bytes = Base64::decode(value).map_err(|err| {
            PublicKeyError::Crate(
                "Decode Sui public key failed with error",
                format!("{}", err),
            )
        })?;
        match bytes.first() {
            Some(x) => {
                if x == &SignatureScheme::ED25519.flag() {
                    let pk: Ed25519PublicKey = Ed25519PublicKey::from_bytes(bytes.get(1..).ok_or(
                        PublicKeyError::InvalidByteLength(ED25519_PUBLIC_KEY_LENGTH + 1),
                    )?)
                    .map_err(|err| {
                        PublicKeyError::Crate(
                            "Decode Ed25519 Sui public key failed",
                            format!("{}", err),
                        )
                    })?;
                    Ok(SuiPublicKey::Ed25519((&pk).into()))
                } else if x == &SignatureScheme::Secp256k1.flag() {
                    let pk = Secp256k1PublicKey::from_bytes(bytes.get(1..).ok_or(
                        PublicKeyError::InvalidByteLength(ED25519_PUBLIC_KEY_LENGTH + 1),
                    )?)
                    .map_err(|err| {
                        PublicKeyError::Crate(
                            "Decode Secp256k1 Sui public key failed",
                            format!("{}", err),
                        )
                    })?;
                    Ok(SuiPublicKey::Secp256k1((&pk).into()))
                } else if x == &SignatureScheme::Secp256r1.flag() {
                    let pk = Secp256r1PublicKey::from_bytes(bytes.get(1..).ok_or(
                        PublicKeyError::InvalidByteLength(ED25519_PUBLIC_KEY_LENGTH + 1),
                    )?)
                    .map_err(|err| {
                        PublicKeyError::Crate(
                            "Decode Secp256r1 Sui public key failed",
                            format!("{}", err),
                        )
                    })?;
                    Ok(SuiPublicKey::Secp256r1((&pk).into()))
                } else {
                    Err(PublicKeyError::Crate(
                        "Invalid public key input",
                        "".to_string(),
                    ))
                }
            }
            _ => Err(PublicKeyError::Crate(
                "Invalid public key input",
                "".to_string(),
            )),
        }
    }
}

impl FromStr for SuiPublicKey {
    type Err = PublicKeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s)
    }
}

impl Display for SuiPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode_base64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::{
        ed25519::Ed25519KeyPair,
        secp256k1::Secp256k1KeyPair,
        secp256r1::Secp256r1KeyPair,
        traits::{KeyPair, ToFromBytes},
    };

    const SAMPLE_ED25519_PK: &str = "AIhMzab/WG2MwPWJX+ojRNKRgXS7eERBLKh7jVzk2jrS";
    const SAMPLE_ED25519_ADDRESS: &str =
        "0xb6e7529acddc998333f553c385d400c8be99746e2cd6cd9818e9a4475862df65";

    const SAMPLE_SECP256K1_PK: &str = "AQKFqpb4i7Md3H0dWi16Xq3xHnwbCY6hqSiz8WSGd119AQ==";
    const SAMPLE_SECP256K1_ADDRESS: &str =
        "0x7607cd694df3a99be051c2400123fee106135086a192e1df7a2f344ea15bcd83";

    const SAMPLE_SECP256R1_PK: &str = "AgKEWLOwlrPvO8vwrm1RXxGKZeu221OcR7YIUrWGqsD4yw==";
    const SAMPLE_SECP256R1_ADDRESS: &str =
        "0x73b4e70d671ba8171a1792d7d6116df4bd9870c6550ca4c6422f5e00396f82aa";

    const SAMPLE_SEED: [u8; 32] = [
        51, 95, 147, 235, 93, 221, 105, 227, 208, 198, 105, 132, 164, 28, 174, 83, 68, 231, 82,
        133, 50, 67, 181, 184, 126, 93, 85, 244, 135, 108, 205, 101,
    ];

    #[inline]
    fn check_different_curve_pk(expected_pk: &str, key_type: SignatureScheme, seed: &[u8]) {
        let sk = match key_type {
            SignatureScheme::ED25519 => {
                let keypair = Ed25519KeyPair::from_bytes(seed).unwrap();
                SuiPrivateKey::Ed25519(keypair.copy().private())
            }
            SignatureScheme::Secp256k1 => {
                let keypair = Secp256k1KeyPair::from_bytes(seed).unwrap();
                SuiPrivateKey::Secp256k1(keypair.copy().private())
            }
            SignatureScheme::Secp256r1 => {
                let keypair = Secp256r1KeyPair::from_bytes(seed).unwrap();
                SuiPrivateKey::Secp256r1(keypair.copy().private())
            }
            _ => {
                panic!("The public key type is not supported!");
            }
        };

        let pk_from_secret_key = SuiPublicKey::from_secret_key(&sk);
        assert_eq!(expected_pk.to_string(), format!("{}", pk_from_secret_key));
    }

    #[inline]
    fn check_pk_to_address(expected_addr: &str, pk: &str) {
        let pk = SuiPublicKey::from_str(pk).unwrap();
        let addr = pk.to_address(&SuiFormat::Hex).unwrap();
        assert_eq!(expected_addr.to_string(), format!("{}", addr));
    }

    #[test]
    fn test_ed25519_pk_from_secret_key() {
        check_different_curve_pk(SAMPLE_ED25519_PK, SignatureScheme::ED25519, &SAMPLE_SEED);
    }

    #[test]
    fn test_ed25519_pk_address() {
        check_pk_to_address(SAMPLE_ED25519_ADDRESS, SAMPLE_ED25519_PK);
    }

    #[test]
    fn test_secp256k1_pk_from_secret_key() {
        check_different_curve_pk(
            SAMPLE_SECP256K1_PK,
            SignatureScheme::Secp256k1,
            &SAMPLE_SEED,
        );
    }

    #[test]
    fn test_secp256k1_pk_address() {
        check_pk_to_address(SAMPLE_SECP256K1_ADDRESS, SAMPLE_SECP256K1_PK);
    }

    #[test]
    fn test_secp256r1_pk_from_secret_key() {
        check_different_curve_pk(
            SAMPLE_SECP256R1_PK,
            SignatureScheme::Secp256r1,
            &SAMPLE_SEED,
        );
    }

    #[test]
    fn test_secp256r1_pk_address() {
        check_pk_to_address(SAMPLE_SECP256R1_ADDRESS, SAMPLE_SECP256R1_PK);
    }
}
