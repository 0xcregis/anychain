use crate::{TronFormat, TronPublicKey};
use anychain_core::{Address, AddressError, PublicKey};
use base58::{FromBase58, ToBase58};
use ethabi::Token;
use hex::FromHex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::fmt;
use std::str::FromStr;

const ADDRESS_TYPE_PREFIX: u8 = 0x41;

#[derive(Clone, PartialEq, Eq, Serialize, Hash)]
pub struct TronAddress([u8; 21]);

impl Address for TronAddress {
    type SecretKey = libsecp256k1::SecretKey;
    type Format = TronFormat;
    type PublicKey = TronPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::from_public_key(&TronPublicKey::from_secret_key(secret_key), format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _format: &Self::Format,
    ) -> Result<Self, AddressError> {
        let mut hasher = Keccak256::new();

        hasher.update(&public_key.to_secp256k1_public_key().serialize()[1..]);
        let digest = hasher.finalize();
        let mut raw = [ADDRESS_TYPE_PREFIX; 21];
        raw[1..21].copy_from_slice(&digest[digest.len() - 20..]);

        Ok(TronAddress(raw))
    }
}

impl TronAddress {
    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, AddressError> {
        if raw.len() != 21 {
            return Err(AddressError::InvalidAddress("Invalid length".to_string()));
        }

        let mut address = [0u8; 21];
        address.copy_from_slice(raw);
        Ok(TronAddress(address))

        // assert!(raw.len() == 21);
        // unsafe { std::mem::transmute(&raw[0]) }
    }

    pub fn to_base58(&self) -> String {
        self.to_string()
    }

    pub fn to_token(&self) -> Token {
        let mut bytes = [0u8; 11].to_vec();
        bytes.extend_from_slice(self.as_bytes());
        Token::FixedBytes(bytes)
    }
}

impl Default for TronAddress {
    fn default() -> Self {
        TronAddress([
            0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }
}

impl fmt::Display for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        b58encode_check(self.0).fmt(f)
    }
}

impl ::std::fmt::Debug for TronAddress {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.debug_tuple("Address").field(&self.to_string()).finish()
    }
}

impl TryFrom<&[u8]> for TronAddress {
    type Error = AddressError;

    fn try_from(value: &[u8]) -> Result<Self, AddressError> {
        if value.len() != 21 {
            Err(AddressError::InvalidAddress("Invalid length".to_string()))
        } else if value[0] != ADDRESS_TYPE_PREFIX {
            Err(AddressError::Message(format!(
                "Invalid version byte {}",
                value[0]
            )))
        } else {
            let mut raw = [0u8; 21];
            raw[..21].copy_from_slice(value);
            Ok(TronAddress(raw))
        }
    }
}

impl TryFrom<Vec<u8>> for TronAddress {
    type Error = AddressError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&Vec<u8>> for TronAddress {
    type Error = AddressError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&str> for TronAddress {
    type Error = AddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        TronAddress::from_str(value)
    }
}

impl FromHex for TronAddress {
    type Error = AddressError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        TronAddress::try_from(hex.as_ref())
    }
}

impl FromStr for TronAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, AddressError>
    where
        Self: Sized,
    {
        if s.len() == 34 {
            b58decode_check(s).and_then(TronAddress::try_from)
        } else if s.len() == 42 && s[..2] == hex::encode([ADDRESS_TYPE_PREFIX]) {
            Vec::from_hex(s)
                .map_err(|_| AddressError::InvalidAddress("InvalidAddress".to_string()))
                .and_then(TronAddress::try_from)
        } else if s.len() == 44 && (s.starts_with("0x") || s.starts_with("0X")) {
            Vec::from_hex(&s.as_bytes()[2..])
                .map_err(|_| AddressError::InvalidAddress("InvalidAddress".to_string()))
                .and_then(TronAddress::try_from)
        } else if s == "_" || s == "0x0" || s == "/0" {
            "410000000000000000000000000000000000000000".parse()
        } else {
            eprintln!("len={} prefix={:x}", s.len(), s.as_bytes()[0]);
            Err(AddressError::InvalidAddress("Invalid length".to_string()))
        }
    }
}

// NOTE: AsRef<[u8]> implies ToHex
impl AsRef<[u8]> for TronAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Base58check encode.
pub fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_ref());
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(digest1);
    let digest = hasher.finalize();

    let mut raw = raw.as_ref().to_owned();
    raw.extend(&digest[..4]);
    raw.to_base58()
}

/// Base58check decode.
pub fn b58decode_check(s: &str) -> Result<Vec<u8>, AddressError> {
    let mut result = s
        .from_base58()
        .map_err(|_| AddressError::InvalidAddress("".to_string()))?;

    let check = result.split_off(result.len() - 4);

    let mut hasher = Sha256::new();
    hasher.update(&result);
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(digest1);
    let digest = hasher.finalize();

    if check != digest[..4] {
        Err(AddressError::InvalidAddress("".to_string()))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;

    #[test]
    fn test_address() {
        let addr = TronAddress([
            65, 150, 163, 186, 206, 90, 218, 207, 99, 126, 183, 204, 121, 213, 120, 127, 66, 71,
            218, 75, 190,
        ]);

        assert_eq!("TPhiVyQZ5xyvVK2KS2LTke8YvXJU5wxnbN", format!("{:}", addr));
        assert_eq!(
            addr,
            "TPhiVyQZ5xyvVK2KS2LTke8YvXJU5wxnbN"
                .parse()
                .expect("parse error")
        );
        assert_eq!(
            addr,
            "4196a3bace5adacf637eb7cc79d5787f4247da4bbe"
                .parse()
                .expect("parse error")
        );

        assert_eq!(
            addr.as_bytes().encode_hex::<String>(),
            "4196a3bace5adacf637eb7cc79d5787f4247da4bbe"
        )
    }

    #[test]
    fn test_address_from_public() {
        let public = TronPublicKey::from_str("56f19ba7de92264d94f9b6600ec05c16c0b25a064e2ee1cf5bf0dd9661d04515c99c3a6b42b2c574232a5b951bf57cf706bbfd36377b406f9313772f65612cd0").unwrap();

        let addr = TronAddress::from_public_key(&public, &TronFormat::Standard).unwrap();
        assert_eq!(addr.to_string(), "TQHAvs2ZFTbsd93ycTfw1Wuf1e4WsPZWCp");
    }

    #[test]
    fn test_address_from_bytes() {
        let bytes = [
            65, 150, 163, 186, 206, 90, 218, 207, 99, 126, 183, 204, 121, 213, 120, 127, 66, 71,
            218, 75, 190,
        ];
        let addr = TronAddress::from_bytes(&bytes);
        assert!(addr.is_ok());

        let malicious_bytes: [u8; 22] = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let addr = TronAddress::from_bytes(&malicious_bytes);
        assert!(addr.is_err());
    }
}
