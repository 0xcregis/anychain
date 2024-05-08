use base58::{FromBase58, ToBase58};
use std::{fmt::Display, str::FromStr};

use crate::{RippleFormat, RipplePublicKey};
use anychain_core::{
    crypto::{checksum, hash160},
    Address, AddressError, PublicKey,
};

// fn map_gen(from: &str, to: &str) {
//     let from = from.as_bytes();
//     let to = to.as_bytes();

//     let mut table = [-1i8; 128];

//     for i in 0..58 {
//         table[from[i] as usize] = to[i] as i8;
//     }

//     println!("{:?}", table);
// }

/// You can run this test function to generate the 2 maps below
// #[test]
// fn gen_map() {
//     let ripple_alphabet: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
//     let bitcoin_alphabet: &str ="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//     map_gen(bitcoin_alphabet, ripple_alphabet);
//     map_gen(ripple_alphabet, bitcoin_alphabet);
// }

/// Utility for mapping the bitcoin base58 alphabet to ripple base58 alphabet
static BTC_2_XRP_BS58_MAP: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 114, 112, 115, 104, 110, 97, 102, 51, 57, -1, -1, -1, -1, -1, -1, -1, 119, 66, 85, 68, 78,
    69, 71, 72, -1, 74, 75, 76, 77, 52, -1, 80, 81, 82, 83, 84, 55, 86, 87, 88, 89, 90, -1, -1, -1,
    -1, -1, -1, 50, 98, 99, 100, 101, 67, 103, 54, 53, 106, 107, -1, 109, 56, 111, 70, 113, 105,
    49, 116, 117, 118, 65, 120, 121, 122, -1, -1, -1, -1, -1,
];

/// Utility for mapping the ripple base58 alphabet to bitcoin base58 alphabet
static XRP_2_BTC_BS58_MAP: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 115, 97, 56, 78, 105, 104, 85, 110, 57, -1, -1, -1, -1, -1, -1, -1, 119, 66, 102, 68, 70,
    112, 71, 72, -1, 74, 75, 76, 77, 69, -1, 80, 81, 82, 83, 84, 67, 86, 87, 88, 89, 90, -1, -1,
    -1, -1, -1, -1, 54, 98, 99, 100, 101, 55, 103, 52, 114, 106, 107, -1, 109, 53, 111, 50, 113,
    49, 51, 116, 117, 118, 65, 120, 121, 122, -1, -1, -1, -1, -1,
];

/// Map the string in bitcoin base58 format to ripple base58 format
fn to_xrp_bs58(s: &str) -> Result<String, AddressError> {
    let to: Vec<u8> = s
        .as_bytes()
        .iter()
        .map(|b| BTC_2_XRP_BS58_MAP[*b as usize] as u8)
        .collect();

    Ok(String::from_utf8(to)?)
}

/// Map the string in ripple base58 format to bitcoin base58 format
fn to_btc_bs58(s: &str) -> Result<String, AddressError> {
    let to: Vec<u8> = s
        .as_bytes()
        .iter()
        .map(|b| XRP_2_BTC_BS58_MAP[*b as usize] as u8)
        .collect();

    Ok(String::from_utf8(to)?)
}

/// Represents a Ripple address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RippleAddress(String);

impl Address for RippleAddress {
    type SecretKey = libsecp256k1::SecretKey;
    type PublicKey = RipplePublicKey;
    type Format = RippleFormat;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, anychain_core::AddressError> {
        let hash = hash160(&public_key.serialize());
        Self::from_hash160(&hash)
    }
}

impl FromStr for RippleAddress {
    type Err = AddressError;
    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let s = to_btc_bs58(addr)?;
        let data = s.from_base58()?;
        if data.len() != 25 {
            return Err(AddressError::InvalidByteLength(s.len()));
        }
        if data[0] != 0 {
            return Err(AddressError::Message(format!(
                "Invalid version byte {}",
                data[0]
            )));
        }

        // Check if the payload produces the provided checksum
        let expected_checksum = &checksum(&data[..21])[..4];
        let provided_checksum = &data[21..];

        if *expected_checksum != *provided_checksum {
            return Err(AddressError::InvalidChecksum(
                to_xrp_bs58(
                    &[data[..21].to_vec(), expected_checksum.to_vec()]
                        .concat()
                        .to_base58(),
                )?,
                addr.to_string(),
            ));
        }

        Ok(RippleAddress(addr.to_string()))
    }
}

impl Display for RippleAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl RippleAddress {
    pub fn to_hash160(&self) -> Result<[u8; 20], AddressError> {
        let _ = Self::from_str(&self.0)?;
        let btc_bs58 = to_btc_bs58(&self.0)?;
        let bytes = btc_bs58.from_base58()?;

        let mut ret = [0u8; 20];

        // strip version bytes and checksum
        ret.copy_from_slice(&bytes[1..21]);

        Ok(ret)
    }

    pub fn from_hash160(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::Message("Illegal hash160 length".to_string()));
        }
        let mut data = [0u8; 25];
        data[1..21].copy_from_slice(hash);
        let checksum = &checksum(&data[..21])[..4];
        data[21..].copy_from_slice(checksum);

        Ok(RippleAddress(to_xrp_bs58(&data.to_base58())?))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{Address, RippleAddress, RippleFormat};

    #[test]
    fn test_from_secret_key() {
        let sk = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1,
        ];

        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let addr = RippleAddress::from_secret_key(&sk, &RippleFormat::Standard).unwrap();

        println!("addr = {}", addr);
    }

    #[test]
    fn test_from_str() {
        let addrs = [
            "rJ6HEKFe8T2mkZQqzuGbFEmE8SKtadxd8n",
            "rBbvWBK4pmibqtwNMWhPMTgJUGfaNh71Yk",
        ];

        addrs.iter().for_each(|&addr| {
            let addr = RippleAddress::from_str(addr).unwrap();
            println!("address = {}", addr);
        });
    }
}
