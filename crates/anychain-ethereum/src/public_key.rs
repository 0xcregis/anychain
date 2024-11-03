use crate::address::EthereumAddress;
use crate::format::EthereumFormat;
use anychain_core::{hex, Address, AddressError, PublicKey, PublicKeyError};
use core::{fmt, fmt::Display, str::FromStr};

/// Represents an Ethereum public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumPublicKey(libsecp256k1::PublicKey);

impl PublicKey for EthereumPublicKey {
    type SecretKey = libsecp256k1::SecretKey;
    type Address = EthereumAddress;
    type Format = EthereumFormat;

    /// Returns the public key corresponding to the given private key.
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self(libsecp256k1::PublicKey::from_secret_key(secret_key))
    }

    /// Returns the address of this public key.
    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, _format)
    }
}

impl EthereumPublicKey {
    /// Returns a public key given a secp256k1 public key.
    pub fn from_secp256k1_public_key(public_key: libsecp256k1::PublicKey) -> Self {
        Self(public_key)
    }

    pub fn from_slice(sl: &[u8]) -> Result<Self, PublicKeyError> {
        libsecp256k1::PublicKey::parse_slice(sl, None)
            .map(Self)
            .map_err(|e| PublicKeyError::Crate("from splice", format!("{:?}", e)))
    }

    /// Returns the secp256k1 public key of the public key
    pub fn to_secp256k1_public_key(&self) -> libsecp256k1::PublicKey {
        self.0
    }
}

impl FromStr for EthereumPublicKey {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        let p = hex::decode(public_key)
            .map_err(|error| PublicKeyError::Crate("hex", format!("{:?}", error)))?;
        let public_key = libsecp256k1::PublicKey::parse_slice(p.as_slice(), None)
            .map_err(|error| PublicKeyError::Crate("libsecp256k1", format!("{:?}", error)))?;

        Ok(Self(public_key))
    }
}

impl Display for EthereumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for s in &self.0.serialize()[1..] {
            write!(f, "{:02x}", s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsecp256k1::SecretKey;

    fn test_from_secret_key(expected_public_key: &EthereumPublicKey, secret_key: &SecretKey) {
        let public_key = EthereumPublicKey::from_secret_key(secret_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address(expected_address: &EthereumAddress, public_key: &EthereumPublicKey) {
        let address = public_key.to_address(&EthereumFormat::Standard).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str(expected_public_key: &str, expected_address: &str) {
        let public_key = EthereumPublicKey::from_str(expected_public_key).unwrap();
        let address = public_key.to_address(&EthereumFormat::Standard).unwrap();
        assert_eq!(expected_public_key, public_key.to_string());
        assert_eq!(expected_address, address.to_string());
    }

    fn test_to_str(expected_public_key: &str, public_key: &EthereumPublicKey) {
        assert_eq!(expected_public_key, public_key.to_string());
    }

    mod checksum_address {
        use super::*;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "2f46188bd601ece2a4446fa31de9419ee9baabf5305d65a5a7aea8badee27a5a",
                "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c",
                "0x9Ed0C5817aE96Cb886BF74EB02B238De682e9B07"
            ),
            (
                "d96c4c30bbabde58653e4fb4f4d97d064c70e300a37ab8780a8ecc15220423fb",
                "bfe0746c85802c3ca1c2d5e4f4d23fb8321b8b1009af67855cc9a4aed8285567d7045bb700e27d5e33572ae5d84a8d1e11bb134f6f14f37ffcb2fa73f7c6b0ac",
                "0xBc90633A78dA594ace8e25AAA3517F924C76099d"
            ),
            (
                "c677a1215eebd35d20337d8896ee6579c78f41f93946b17c8d4ccb772c25cde4",
                "ff3e50efb509efd0d18ff9074bc8b253419d2437e0c1e81661c1ba419f877162eed685d80bdd3b33adde4ff2a0946dd97460f126992064059a129e2a7172d566",
                "0xA99E404A60ab8561F7c844529F735A88D7A61C5A"
            ),
            (
                "b681e5bd4ddffefe1a691fe7c6375775c11992b9a25e4f9e3f235eb054d49343",
                "d9ed72afa68a9732df005df2dbbfb2abcad050579bd8dfeb32389d0f1e492d130ca33f9e71345d558da5859026fee86c03be685f95a4c8ddc55e048c5ff8b398",
                "0x28826C9f713c96ee63e59Ed9220c77b021FAfC3e"
            ),
            (
                "da5d359af6827e76e0a1b71c75c375f0d33f63bae4fd551d81ee10faa34e33e9",
                "0b752d5e89126b62a99edfe40a4cbd9122cfb04257a28d225858d38bc92a0e1517e797e9029e810b329afa32a1d46268e84eb10c700314b0059f506130d1e9e6",
                "0x9eC59170674DbEfeF40efE2ED03175b39fCA921a"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(secret_key, public_key, _)| {
                let public_key = EthereumPublicKey::from_str(public_key).unwrap();
                let secret_key = hex::decode(*secret_key).unwrap();
                let secret_key = SecretKey::parse_slice(&secret_key).unwrap();
                test_from_secret_key(&public_key, &secret_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = EthereumAddress::from_str(address).unwrap();
                let public_key = EthereumPublicKey::from_str(public_key).unwrap();
                test_to_address(&address, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(_, expected_public_key, expected_address)| {
                    test_from_str(expected_public_key, expected_address);
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = EthereumPublicKey::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }

        #[test]
        fn test_pubkey() {
            let str = "b9b77d6ac1380a581d3efc136a21a939f5a6ce59afeb3eddf6a52b342b33f5be455b3610100ee1129d1638e99272879be60519835e2b3b7703eb4791af3daa7f";
            let public_key = EthereumPublicKey::from_str(str).unwrap();
            let address = EthereumAddress::checksum_address(&public_key);
            assert_eq!(
                "0xDF3e1897f4b01f6b17870b98B4548BaBE14A007C",
                address.to_string()
            );
        }
    }

    #[test]
    fn test_checksum_address_invalid() {
        // Invalid public key length

        let public_key = "0";
        assert!(EthereumPublicKey::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b014";
        assert!(EthereumPublicKey::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721";
        assert!(EthereumPublicKey::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f3593";
        assert!(EthereumPublicKey::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c";
        assert!(EthereumPublicKey::from_str(public_key).is_err());
    }

    #[test]
    fn address_gen() {
        let raw_pk = [
            68, 157, 12, 4, 213, 228, 35, 105, 155, 249, 86, 130, 216, 186, 113, 85, 31, 137, 113,
            153, 70, 239, 218, 142, 132, 65, 222, 134, 52, 145, 148, 88, 63, 245, 105, 222, 219,
            39, 56, 192, 195, 4, 38, 29, 9, 78, 172, 238, 179, 168, 66, 80, 132, 123, 45, 104, 145,
            132, 159, 243, 144, 62, 194, 164,
        ];
        let raw_pk1 = [
            117, 243, 73, 0, 152, 143, 226, 83, 116, 252, 10, 247, 191, 14, 206, 13, 110, 192, 140,
            32, 250, 238, 177, 101, 109, 113, 26, 254, 67, 191, 47, 11, 155, 57, 117, 158, 227,
            111, 235, 20, 65, 167, 102, 64, 98, 103, 106, 226, 241, 213, 193, 36, 72, 57, 163, 202,
            72, 21, 35, 233, 194, 163, 225, 28,
        ];

        let pk = EthereumPublicKey::from_slice(&raw_pk);
        assert!(pk.is_ok());
        let pk1 = EthereumPublicKey::from_slice(&raw_pk1);
        assert!(pk1.is_ok());

        let addr = pk.unwrap().to_address(&EthereumFormat::Standard).unwrap();
        let addr1 = pk1.unwrap().to_address(&EthereumFormat::Standard).unwrap();

        assert_eq!(
            "0xE28D6881aC932066611A259a8C343E545b0b55B7",
            addr.to_string()
        );
        assert_eq!(
            "0xCd28AF3e09527D2a756F1e7c7aD7A8A9BdEB080d",
            addr1.to_string()
        );
    }

    #[test]
    fn test_public_key_from_invalid_slice() {
        let invalid_slice = [1u8; 31]; // A 31-byte slice, invalid as a public key
        let public_key = EthereumPublicKey::from_slice(&invalid_slice);
        assert!(public_key.is_err());

        let invalid_slice = [0u8; 65]; // A 31-byte slice, invalid as a public key
        let public_key = EthereumPublicKey::from_slice(&invalid_slice);
        assert!(public_key.is_err());
    }
}
