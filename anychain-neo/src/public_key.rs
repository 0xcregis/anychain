use std::{str::FromStr, fmt::Display};
use anychain_core::{PublicKey, PublicKeyError, AddressError, hex, Address};
use crate::{NeoFormat, NeoAddress};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeoPublicKey(pub p256::PublicKey);

impl PublicKey for NeoPublicKey {
    type Format = NeoFormat;
    type SecretKey = p256::SecretKey;
    type Address = NeoAddress;
    
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

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for NeoPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0.to_sec1_bytes().to_vec();
        let s = hex::encode(&bytes);
        write!(f, "pk = {}, len = {}", s, s.len())
    }
}

#[cfg(test)]
mod test {
    use anychain_core::PublicKey;
    use crate::{NeoPublicKey, NeoFormat};

    #[test]
    fn test() {
        let mut sk = [
            1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        let format = NeoFormat::Standard;

        for i in 0..10 {
            sk[3] = i;
            let sk = p256::SecretKey::from_slice(&sk).unwrap();
            let addr = NeoPublicKey::from_secret_key(&sk).to_address(&format).unwrap();
            println!("{}", addr);
        }
    }
}