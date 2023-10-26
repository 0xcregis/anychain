use crate::{NeoAddress, NeoFormat};
use anychain_core::{hex, Address, AddressError, PublicKey, PublicKeyError};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeoPublicKey(pub p256::PublicKey);

impl PublicKey for NeoPublicKey {
    type SecretKey = p256::SecretKey;
    type Address = NeoAddress;
    type Format = NeoFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let scalar = secret_key.to_nonzero_scalar();
        Self(p256::PublicKey::from_secret_scalar(&scalar))
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl NeoPublicKey {
    pub fn serialize_compressed(&self) -> Vec<u8> {
        p256::CompressedPoint::from(self.0).as_slice().to_vec()
    }
}

impl FromStr for NeoPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bin = hex::decode(s)?;
        let public_key = p256::PublicKey::from_sec1_bytes(&bin).unwrap();
        Ok(NeoPublicKey(public_key))
    }
}

impl Display for NeoPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0.to_sec1_bytes().to_vec();
        let s = hex::encode(bytes);
        write!(f, "pk = {}, len = {}", s, s.len())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::NeoPublicKey;
    use anychain_core::PublicKey;

    #[test]
    fn test_public_key_from_str() {
        let sk = [
            1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1,
        ];

        let sk = p256::SecretKey::from_slice(&sk).unwrap();
        let _public_key = NeoPublicKey::from_secret_key(&sk);

        let public_key = "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a";

        let pb = NeoPublicKey::from_str(public_key);
        assert!(pb.is_ok());
    }
}
