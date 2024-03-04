use std::{fmt::Display, marker::PhantomData, str::FromStr};

use anychain_core::{hex, Address, AddressError, PublicKey, TransactionError};

use crate::{PolkadotFormat, PolkadotNetwork, PolkadotPublicKey, PolkadotSecretKey};
use base58::{FromBase58, ToBase58};
use sp_core::hashing::blake2_512;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PolkadotAddress<N: PolkadotNetwork> {
    addr: String,
    _network: PhantomData<N>,
}

impl<N: PolkadotNetwork> Address for PolkadotAddress<N> {
    type SecretKey = PolkadotSecretKey;
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
        Self::from_payload(&hex::encode(public_key.address_payload()))
    }
}

impl<N: PolkadotNetwork> PolkadotAddress<N> {
    pub fn from_payload(payload: &str) -> Result<Self, AddressError> {
        let payload = hex::decode(payload).unwrap();
        let payload = [vec![N::VERSION], payload].concat();

        let ss_prefix = vec![0x53u8, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45];

        let checksum = blake2_512(&[ss_prefix, payload.clone()].concat()).to_vec();
        let addr = [payload, checksum[..2].to_vec()].concat().to_base58();

        Ok(PolkadotAddress {
            addr,
            _network: PhantomData::<N>,
        })
    }

    pub fn to_payload(&self) -> Result<Vec<u8>, AddressError> {
        let bin = self.addr.as_str().from_base58()?;
        Ok(bin[1..33].to_vec())
    }
}

impl<N: PolkadotNetwork> FromStr for PolkadotAddress<N> {
    type Err = TransactionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58()?;
        if N::VERSION != bytes[0] {
            return Err(TransactionError::Message(format!(
                "Invalid version byte {} for polkadot network {}",
                bytes[0],
                N::NAME,
            )));
        }
        let checksum_provided = bytes[33..].to_vec();
        let ss_prefix = vec![0x53u8, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45];
        let checksum_expected =
            blake2_512(&[ss_prefix, bytes[..33].to_vec()].concat())[..2].to_vec();
        if checksum_expected != checksum_provided {
            return Err(TransactionError::Message(format!(
                "Invalid {} address",
                N::NAME
            )));
        }
        Ok(PolkadotAddress {
            addr: s.to_string(),
            _network: PhantomData,
        })
    }
}

impl<N: PolkadotNetwork> Display for PolkadotAddress<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{PolkadotAddress, PolkadotFormat, PolkadotSecretKey, Westend};
    use anychain_core::{hex, Address};
    use ed25519_dalek::SecretKey;

    #[test]
    fn test_address() {
        let sk = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let h = hex::encode(sk);
        println!("{}", h);

        let sk: SecretKey = sk[..ed25519_dalek::SECRET_KEY_LENGTH].try_into().unwrap();
        let sk = PolkadotSecretKey::Ed25519(sk);

        let address =
            PolkadotAddress::<Westend>::from_secret_key(&sk, &PolkadotFormat::Standard).unwrap();

        assert_eq!(
            "5EpHX5foDtnhZngj4GsKq5eKGpUvuMqbpUG48ZfCCCs7EzKR",
            address.addr
        );
    }

    #[test]
    fn test_address_2() {
        let hash = "8ee504148e75c34e8f051899b3c6e4241ff18dc1c9211260b6a6a434bedb485f";
        let address = PolkadotAddress::<Westend>::from_payload(hash).unwrap();
        assert_eq!(
            "5FJ4gu9eVX6DG4qYi1hxkUgu1yaTm1CnQ4MiiZPjPVaXiATo",
            address.addr
        );
    }

    #[test]
    fn test_address_3() {
        let addr = "5DoW9HHuqSfpf55Ux5pLdJbHFWvbngeg8Ynhub9DrdtxmZeV";
        let addr = PolkadotAddress::<Westend>::from_str(addr).unwrap();
        let payload = addr.to_payload().unwrap();
        let payload = hex::encode(payload);
        assert_eq!(
            "4ce05abd387b560855a3d486eba6237b9a08c6e9dfe351302a5ceda90be801fe",
            payload
        );
    }
}
