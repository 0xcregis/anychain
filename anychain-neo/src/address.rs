use std::{str::FromStr, fmt::Display};
use anychain_core::{Address, AddressError, crypto::{hash160, checksum}, PublicKey};
use crate::{NeoFormat, NeoPublicKey};
use base58::ToBase58;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NeoAddress(pub String);

impl Address for NeoAddress {
    type Format = NeoFormat;
    type SecretKey = p256::SecretKey;
    type PublicKey = NeoPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _format: &Self::Format,
    ) -> Result<Self, AddressError> {
        let bytes = p256::CompressedPoint::from(public_key.0).as_slice().to_vec();
        let bytes = [
            vec![0x0c /* PushData1 */, 0x21 /* compressed key length */],
            bytes, /* compressed public key bytes */
            vec![0x41 /* Opcode.Syscall */, 0x56, 0xe7, 0xb3, 0x27 /* System.Crypto.CheckSig */],
        ].concat();

        let hash = hash160(&bytes);
        let payload = [vec![0x35u8 /* version byte */], hash].concat();

        let checksum = checksum(&payload)[..4].to_vec();
        let res = [payload, checksum].concat();

        Ok(Self(res.to_base58()))
    }
}

impl FromStr for NeoAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for NeoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
