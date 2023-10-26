use crate::{NeoFormat, NeoPublicKey};
use anychain_core::{
    crypto::{checksum, hash160},
    Address, AddressError, PublicKey,
};
use base58::{FromBase58, ToBase58};
use std::{fmt::Display, str::FromStr};

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
        let bytes = public_key.serialize_compressed();
        let bytes = [
            vec![
                0x0c, /* PushData1 */
                0x21, /* compressed key length */
            ],
            bytes, /* compressed public key bytes */
            vec![
                0x41, /* Opcode.Syscall */
                0x56, 0xe7, 0xb3, 0x27, /* System.Crypto.CheckSig */
            ],
        ]
        .concat();

        let hash = hash160(&bytes);
        let payload = [vec![0x35u8 /* version byte */], hash].concat();

        let checksum = checksum(&payload)[..4].to_vec();
        let res = [payload, checksum].concat();

        Ok(Self(res.to_base58()))
    }
}

impl NeoAddress {
    pub fn to_script_hash(&self) -> Vec<u8> {
        let bytes = self.0.as_str().from_base58().unwrap();
        // strip the version byte and the checksum
        bytes[1..21].to_vec()
    }
}

impl FromStr for NeoAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58()?;
        let checksum_provided = bytes[21..].to_vec();
        let checksum_gen = checksum(&bytes[..21])[..4].to_vec();

        if checksum_gen != checksum_provided {
            return Err(AddressError::Message(format!("Invalid address {}", s)));
        }

        Ok(Self(s.to_string()))
    }
}

impl Display for NeoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    // use anychain_core::{Address, PublicKey};
    // use super::{NeoFormat, NeoAddress, NeoPublicKey};
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_address_from_secret_key() {
        // Create a secret key for testing
        let mut rng = OsRng;
        let secret_key = p256::SecretKey::random(&mut rng);

        // Define the desired format
        let format = NeoFormat::Standard;
        let result = NeoAddress::from_secret_key(&secret_key, &format);

        assert!(result.is_ok());

        let address = result.unwrap();
        assert_eq!(address.to_script_hash().len(), 20);
    }

    #[test]
    fn test_address_from_public_key() {
        // Create a public key for testing

        let mut rng = OsRng;
        let secret_key = p256::SecretKey::random(&mut rng);
        let public_key = NeoPublicKey::from_secret_key(&secret_key);

        let format = NeoFormat::Standard;
        let result = NeoAddress::from_public_key(&public_key, &format);

        assert!(result.is_ok());

        let address = result.unwrap();
        assert_eq!(address.to_script_hash().len(), 20);
    }

    #[test]
    fn test_address_from_str() {
        let address_str = "NVEqR4e73afGKpVBzBXLEnY5F5uZSmSKZZ";
        let address = NeoAddress::from_str(address_str);

        assert!(address.is_ok());

        let parsed_address = address.unwrap();
        assert_eq!(parsed_address.to_string(), address_str);
    }

    #[test]
    fn tesa_addresses_from_sk() {
        let mut sk = [
            1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1,
        ];

        let format = NeoFormat::Standard;

        let addresses = [
            "NKvAasuNZqDc8dQDXd6Wm2XccTh6Dt3nr4",
            "NUz6PKTAM7NbPJzkKJFNay3VckQtcDkgWo",
            "NgZs1i1hZSWh9Lpj9mVRZyNLT3gvydn5Y7",
            "NVKhps7L2souj2xUSw9dWuyGn5Sdgv8g6J",
            "NcBrH4zAwCf3XhywpxgWPcTv3y67y8C1C2",
            "NdvNCaDAt4gn4cWz1Ua8AUp6RQ3u5uABpK",
            "NMkKsN8SrmSTDB4j6EsbELxnJ5UmcUZLVS",
            "NYQLdcRTgLcnsZ3fWjnobBxZkzc4rRnbtb",
            "NbnMx2Bt6b6AWgZzuK7c3iuNFySoGhyg5S",
            "NWUTErT9hs9QiphzhkxbFzhpfKQXX5xvqf",
        ];

        for i in 0..10 {
            sk[3] = i;
            let sk = p256::SecretKey::from_slice(&sk).unwrap();
            let addr = NeoPublicKey::from_secret_key(&sk)
                .to_address(&format)
                .unwrap();
            assert_eq!(format!("{}", addr), addresses[i as usize]);
        }
    }
}
