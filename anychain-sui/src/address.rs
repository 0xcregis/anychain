use crate::format::SuiFormat;
use crate::public_key::SuiPrivateKey;
use crate::{public_key::SuiPublicKey, utils::*};
use anychain_core::{Address, AddressError, PublicKey};

use fastcrypto::encoding::Hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

pub const SUI_ADDRESS_LENGTH: usize = 32;

#[serde_as]
#[derive(
    Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Serialize, Deserialize, JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(proptest_derive::Arbitrary))]
pub struct SuiAddress(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<Hex, _>")]
    [u8; SUI_ADDRESS_LENGTH],
);

impl SuiAddress {
    pub const ZERO: Self = Self([0u8; SUI_ADDRESS_LENGTH]);

    pub fn new(data: [u8; SUI_ADDRESS_LENGTH]) -> Self {
        SuiAddress(data)
    }

    /// Parse a SuiAddress from a byte array or buffer.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, AddressError> {
        <[u8; SUI_ADDRESS_LENGTH]>::try_from(bytes.as_ref())
            .map_err(|err| AddressError::InvalidAddress(format!("Parse bytes failed: {}", err)))
            .map(SuiAddress)
    }
}

impl Address for SuiAddress {
    type SecretKey = SuiPrivateKey;
    type Format = SuiFormat;
    type PublicKey = SuiPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::from_public_key(&SuiPublicKey::from_secret_key(secret_key), format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        public_key.to_address(format)
    }
}

impl TryFrom<&[u8]> for SuiAddress {
    type Error = AddressError;

    /// Tries to convert the provided byte array into a SuiAddress.
    fn try_from(bytes: &[u8]) -> Result<Self, AddressError> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for SuiAddress {
    type Error = AddressError;

    /// Tries to convert the provided byte buffer into a SuiAddress.
    fn try_from(bytes: Vec<u8>) -> Result<Self, AddressError> {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for SuiAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for SuiAddress {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, AddressError>
    where
        Self: Sized,
    {
        let s = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(s)
            .map_err(|err| {
                AddressError::InvalidAddress(format!(
                    "Sui address should be hex format but decode failed: {}",
                    err
                ))
            })
            .and_then(|bytes| SuiAddress::try_from(&bytes[..]))
    }
}

impl Display for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.as_ref()))
    }
}

impl Debug for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.as_ref()))
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

    const SAMPLE_ADDRESS: &str = "af306e86c74e937552df132b41a6cb3af58559f5342c6e82a98f7d1f7a4a9f30";
    const SAMPLE_ADDRESS_VEC: [u8; 32] = [
        175, 48, 110, 134, 199, 78, 147, 117, 82, 223, 19, 43, 65, 166, 203, 58, 245, 133, 89, 245,
        52, 44, 110, 130, 169, 143, 125, 31, 122, 74, 159, 48,
    ];

    #[test]
    fn test_address_display() {
        let hex = SAMPLE_ADDRESS;
        let id = SuiAddress::from_str(hex).unwrap();

        assert_eq!(id.0, SAMPLE_ADDRESS_VEC);
        assert_eq!(format!("{:?}", id), format!("0x{hex}"));
    }

    enum KeyType {
        Ed25519,
        Secp256k1,
        Secp256r1,
    }

    #[inline]
    fn test_different_curve_address(expected_address: &str, key_type: KeyType, seed: &[u8]) {
        let (sk, pk) = match key_type {
            KeyType::Ed25519 => {
                let keypair = Ed25519KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Ed25519(keypair.copy().private());
                let pk = SuiPublicKey::Ed25519(keypair.public().into());
                (sk, pk)
            }
            KeyType::Secp256k1 => {
                let keypair = Secp256k1KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Secp256k1(keypair.copy().private());
                let pk = SuiPublicKey::Secp256k1(keypair.public().into());
                (sk, pk)
            }
            KeyType::Secp256r1 => {
                let keypair = Secp256r1KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Secp256r1(keypair.copy().private());
                let pk = SuiPublicKey::Secp256r1(keypair.public().into());
                (sk, pk)
            }
        };

        let address_from_secret_key = SuiAddress::from_secret_key(&sk, &SuiFormat::Hex);
        assert!(address_from_secret_key.is_ok());
        assert_eq!(
            address_from_secret_key.unwrap(),
            SuiAddress::from_str(expected_address).unwrap()
        );

        let address_from_public_key = SuiAddress::from_public_key(&pk, &SuiFormat::Hex);
        assert!(address_from_public_key.is_ok());
        assert_eq!(
            address_from_public_key.unwrap(),
            SuiAddress::from_str(expected_address).unwrap()
        );
    }

    #[test]
    fn test_address_ed25519() {
        let expected_address = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
        test_different_curve_address(expected_address, KeyType::Ed25519, &[1; 32]);
    }

    #[test]
    fn test_address_secp256k1() {
        let expected_address = "0xf87edcc926ae7dded7f91ffddcb0ba6c9e3373946e89ec47e478c1bca90c750d";
        test_different_curve_address(expected_address, KeyType::Secp256k1, &[1; 32]);
    }

    #[test]
    fn test_address_secp256r1() {
        let expected_address = "0x575dc0072a3309367790cb4415ddc87df5ffa4360ccd2c29f7ec0515026cc0e1";
        test_different_curve_address(expected_address, KeyType::Secp256r1, &[1; 32]);
    }
}
