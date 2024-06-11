use crate::format::SuiFormat;
use crate::{
    public_key::{SuiPrivateKey, SuiPublicKey},
    utils::*,
};
use anychain_core::{Address, AddressError, PublicKey};

use fastcrypto::encoding::Hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};
use sui_types::base_types::SuiAddress as RawSuiAddress;

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

    pub fn to_raw(&self) -> RawSuiAddress {
        RawSuiAddress::from_bytes(self.0).expect("Failed to convert sui address to raw type")
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
    use crate::public_key::SignatureScheme;
    use fastcrypto::{
        ed25519::Ed25519KeyPair,
        secp256k1::Secp256k1KeyPair,
        secp256r1::Secp256r1KeyPair,
        traits::{KeyPair, ToFromBytes},
    };

    const SAMPLE_SEED: [u8; 32] = [
        51, 95, 147, 235, 93, 221, 105, 227, 208, 198, 105, 132, 164, 28, 174, 83, 68, 231, 82,
        133, 50, 67, 181, 184, 126, 93, 85, 244, 135, 108, 205, 101,
    ];

    #[test]
    fn test_address_display() {
        let sample_address = "af306e86c74e937552df132b41a6cb3af58559f5342c6e82a98f7d1f7a4a9f30";
        let address = SuiAddress::from_str(sample_address).unwrap();

        let sample_address_vec: [u8; 32] = [
            175, 48, 110, 134, 199, 78, 147, 117, 82, 223, 19, 43, 65, 166, 203, 58, 245, 133, 89,
            245, 52, 44, 110, 130, 169, 143, 125, 31, 122, 74, 159, 48,
        ];
        assert_eq!(address.0, sample_address_vec);
        assert_eq!(format!("{:?}", address), format!("0x{sample_address}"));
    }

    #[inline]
    fn check_different_curve_address(
        expected_address: &str,
        key_type: SignatureScheme,
        seed: &[u8],
    ) {
        let (sk, pk) = match key_type {
            SignatureScheme::ED25519 => {
                let keypair = Ed25519KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Ed25519(keypair.copy().private());
                let pk = SuiPublicKey::Ed25519(keypair.public().into());
                (sk, pk)
            }
            SignatureScheme::Secp256k1 => {
                let keypair = Secp256k1KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Secp256k1(keypair.copy().private());
                let pk = SuiPublicKey::Secp256k1(keypair.public().into());
                (sk, pk)
            }
            SignatureScheme::Secp256r1 => {
                let keypair = Secp256r1KeyPair::from_bytes(seed).unwrap();
                let sk = SuiPrivateKey::Secp256r1(keypair.copy().private());
                let pk = SuiPublicKey::Secp256r1(keypair.public().into());
                (sk, pk)
            }
            _ => {
                panic!("The public key type is not supported!");
            }
        };

        let address_from_secret_key = SuiAddress::from_secret_key(&sk, &SuiFormat::Hex).unwrap();
        assert_eq!(
            address_from_secret_key,
            SuiAddress::from_str(expected_address).unwrap()
        );

        let address_from_public_key = SuiAddress::from_public_key(&pk, &SuiFormat::Hex).unwrap();
        assert_eq!(
            address_from_public_key,
            SuiAddress::from_str(expected_address).unwrap()
        );
    }

    #[test]
    fn test_address_ed25519() {
        let expected_address = "0xb6e7529acddc998333f553c385d400c8be99746e2cd6cd9818e9a4475862df65";
        check_different_curve_address(expected_address, SignatureScheme::ED25519, &SAMPLE_SEED);
    }

    #[test]
    fn test_address_secp256k1() {
        let expected_address = "0x7607cd694df3a99be051c2400123fee106135086a192e1df7a2f344ea15bcd83";
        check_different_curve_address(expected_address, SignatureScheme::Secp256k1, &SAMPLE_SEED);
    }

    #[test]
    fn test_address_secp256r1() {
        let expected_address = "0x73b4e70d671ba8171a1792d7d6116df4bd9870c6550ca4c6422f5e00396f82aa";
        check_different_curve_address(expected_address, SignatureScheme::Secp256r1, &SAMPLE_SEED);
    }
}
