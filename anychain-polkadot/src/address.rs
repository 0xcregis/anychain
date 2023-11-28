use std::{fmt::Display, str::FromStr, marker::PhantomData};

use anychain_core::{Address, AddressError, TransactionError, PublicKey, hex, libsecp256k1};

use crate::{PolkadotFormat, PolkadotPublicKey, PolkadotNetwork};
use sp_core::hashing::{blake2_256, blake2_512};
use base58::{ToBase58, FromBase58};

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
        Self::from_pk_hash(&hex::encode(&pk_hash))
    }
}

impl<N: PolkadotNetwork> PolkadotAddress<N> {
    pub fn from_pk_hash(pk_hash: &str) -> Result<Self, AddressError> {
        let pk_hash = hex::decode(pk_hash).unwrap();
        let payload = [vec![N::version()], pk_hash].concat();

        let ss_prefix = vec![0x53u8, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45];

        let checksum = blake2_512(&[ss_prefix, payload.clone()].concat()).to_vec();
        let addr = [payload, checksum[..2].to_vec()].concat().to_base58();

        Ok(PolkadotAddress {
            addr,
            _network: PhantomData::<N>,
        })
    }

    pub fn to_pk_hash(&self) -> Result<Vec<u8>, AddressError> {
        let bin = self.addr.as_str().from_base58()?;
        Ok(bin[1..33].to_vec())
    }
}

impl<N: PolkadotNetwork> FromStr for PolkadotAddress<N> {
    type Err = TransactionError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<N: PolkadotNetwork> Display for PolkadotAddress<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[cfg(test)]
mod tests {
    use anychain_core::Address;
    use super::libsecp256k1::SecretKey;
    use crate::{PolkadotAddress, Polkadot, PolkadotFormat};

    #[test]
    fn test_address() {
        let sk = [
            1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let sk = SecretKey::parse_slice(&sk).unwrap();

        let address = PolkadotAddress::<Polkadot>::from_secret_key(
            &sk,
            &PolkadotFormat::Standard
        ).unwrap();
        
        println!("address = {}", address);
    }

    #[test]
    fn test_address_2() {
        let hash = "0c2f3c6dabb4a0600eccae87aeaa39242042f9a576aa8dca01e1b419cf17d7a2";
        let address = PolkadotAddress::<Polkadot>::from_pk_hash(hash).unwrap();
        println!("address = {}", address);
    }
}
