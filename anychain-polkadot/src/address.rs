use std::{fmt::Display, str::FromStr, marker::PhantomData};

use anychain_core::{Address, TransactionError, libsecp256k1, PublicKey};

use crate::{PolkadotFormat, PolkadotPublicKey, PolkadotNetwork};
use sp_core::hashing::{blake2_256, blake2_512};
use base58::ToBase58;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PolkadotAddress<N: PolkadotNetwork> {
    addr: String,
    _network: PhantomData<N>,
}

impl<N: PolkadotNetwork> Address for PolkadotAddress<N> {
    type SecretKey = libsecp256k1::SecretKey;
    type PublicKey = PolkadotPublicKey<N>;
    type Format = PolkadotFormat;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _format: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        let pk_hash = blake2_256(&public_key.serialize()).to_vec();
        let network = N::version();
        let payload = [vec![network], pk_hash].concat();

        let ss_prefix = vec![0x53u8, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45];

        let checksum = blake2_512(&[ss_prefix, payload.clone()].concat()).to_vec();
        let addr = [payload, checksum[..2].to_vec()].concat().to_base58();

        Ok(PolkadotAddress {
            addr,
            _network: PhantomData::<N>,
        })
    }
}

impl<N: PolkadotNetwork> FromStr for PolkadotAddress<N> {
    type Err = TransactionError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<N: PolkadotNetwork> Display for PolkadotAddress<N> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
