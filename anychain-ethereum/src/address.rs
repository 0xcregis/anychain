use crate::format::EthereumFormat;
use crate::public_key::EthereumPublicKey;
use anychain_core::{to_hex_string, Address, AddressError, Error, PublicKey};

use anychain_core::hex;
use anychain_core::utilities::crypto::keccak256;
use core::{convert::TryFrom, fmt, str::FromStr};
use libsecp256k1::SecretKey;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Represents an Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Default)]
pub struct EthereumAddress(String);

impl Address for EthereumAddress {
    type SecretKey = SecretKey;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_secret_key(
        secret_key: &Self::SecretKey,
        _format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::from_public_key(&EthereumPublicKey::from_secret_key(secret_key), _format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        // public_key.from_private_key();
        Ok(Self::checksum_address(public_key))
    }
}

impl EthereumAddress {
    /// Returns the checksum address given a public key.
    /// Adheres to EIP-55 <https://eips.ethereum.org/EIPS/eip-55>.
    pub fn checksum_address(public_key: &EthereumPublicKey) -> Self {
        let hash = keccak256(&public_key.to_secp256k1_public_key().serialize()[1..]);
        let address = to_hex_string(&hash[12..]).to_lowercase();

        let hash = to_hex_string(&keccak256(address.as_bytes()));
        let mut checksum_address = "0x".to_string();
        for c in 0..40 {
            let ch = match &hash[c..=c] {
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => address[c..=c].to_lowercase(),
                _ => address[c..=c].to_uppercase(),
            };
            checksum_address.push_str(&ch);
        }

        EthereumAddress(checksum_address)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let regex = Regex::new(r"^0x").unwrap();
        let address = self.0.clone();
        let address = address.to_lowercase();
        let address = regex.replace_all(&address, "").to_string();
        Ok(hex::decode(address)?)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> TryFrom<&'a str> for EthereumAddress {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl FromStr for EthereumAddress {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^0x").unwrap();
        let address = address.to_lowercase();
        let address = regex.replace_all(&address, "").to_string();

        if address.len() != 40 {
            let err = AddressError::InvalidByteLength(address.len());
            return Err(err);
        }

        let hash = to_hex_string(&keccak256(address.as_bytes()));
        let mut checksum_address = "0x".to_string();
        for c in 0..40 {
            let ch = match &hash[c..=c] {
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => address[c..=c].to_lowercase(),
                _ => address[c..=c].to_uppercase(),
            };
            checksum_address.push_str(&ch);
        }

        Ok(EthereumAddress(checksum_address))
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anychain_core::public_key::PublicKey;

    fn test_from_str(expected_address: &str) {
        let address = EthereumAddress::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_to_str(expected_address: &str, address: &EthereumAddress) {
        assert_eq!(expected_address, address.to_string());
    }

    #[test]
    fn test_public_key_bytes_to_address() {
        let public_key = &[
            48, 197, 53, 33, 226, 92, 169, 86, 37, 63, 188, 254, 37, 235, 20, 135, 106, 56, 177,
            59, 236, 29, 192, 201, 164, 68, 243, 209, 167, 158, 75, 249, 32, 161, 71, 27, 58, 76,
            240, 10, 117, 87, 201, 40, 236, 137, 172, 167, 140, 5, 65, 94, 239, 146, 230, 155, 0,
            250, 200, 93, 219, 69, 123, 168,
        ];

        let public_key = libsecp256k1::PublicKey::parse_slice(public_key, None).unwrap();
        let public_key = EthereumPublicKey::from_secp256k1_public_key(public_key);
        let address = public_key.to_address(&EthereumFormat::Standard).unwrap();

        assert_eq!(
            "0x0Df2f15895AB69A7eF06519F6c4732e648719f04",
            address.to_string()
        );
    }

    mod checksum_address {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "f89f23eaeac18252fedf81bb8318d3c111d48c19b0680dcf6e0a8d5136caf287",
                "0x9141B7539E7902872095C408BfA294435e2b8c8a",
            ),
            (
                "a93701ea343247db13466f6448ffbca658726e2b4a77530db3eca3c9250b4f0d",
                "0xa0967B1F698DC497A694FE955666D1dDd398145C",
            ),
            (
                "de61e35e2e5eb9504d52f5042126591d80144d49f74b8ced68f4959a3e8edffd",
                "0xD5d13d1dD277BB9041e560A63ee29c086D370b0A",
            ),
            (
                "56f01d5e01b6fd1cc123d8d1eae0d148e00c025b5be2ef624775f7a1b802e9c1",
                "0xc4488ebbE882fa2aF1D466CB2C8ecafE316c067a",
            ),
            (
                "363af8b4d3ff22bb0e4ffc2ff198b4b5be0316f8a507ad5fe32f021c3d1ae8ad",
                "0xF9001e6AEE6EA439D713fBbF960EbA76f4770E2B",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = EthereumAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_address() {
        let pubkey = EthereumPublicKey::from_str(
            "040b4fed878e6b0ff6847e2ac9c13b556d161e1344cd270ed6cafac21f0144399d9ef31f2\
             67722fdeccba59ffd57ff84a020a2d3b416344c68e840bc7d97e77570",
        )
        .unwrap();
        let address = EthereumAddress::from_public_key(&pubkey, &EthereumFormat::Standard).unwrap();
        assert_eq!(
            "0x5a2a8410875E882aEe87bF8e5F2e1eDE8810617b",
            address.to_string()
        )
    }
}
