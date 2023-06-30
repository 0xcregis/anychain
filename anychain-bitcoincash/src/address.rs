use anychain_core::{
    crypto::{checksum as double_sha2, hash160},
    libsecp256k1,
    no_std::String,
    Address, AddressError, PublicKey,
};
use base58::{FromBase58, ToBase58};
use bech32::ToBase32;
use core::{fmt, marker::PhantomData, str::FromStr};

use crate::{BitcoincashFormat, BitcoincashNetwork, BitcoincashPublicKey};

/// Represents a Bitcoin cash address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashAddress<N: BitcoincashNetwork> {
    /// The Bitcoin cash address
    address: String,
    /// The address format
    format: BitcoincashFormat,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: BitcoincashNetwork> BitcoincashAddress<N> {
    pub fn from_hash160(hash: &[u8], format: &BitcoincashFormat) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::InvalidByteLength(hash.len()));
        }

        match format {
            BitcoincashFormat::CashAddr => {
                let mut payload = vec![0u8]; // payload starts with version byte: 0
                payload.extend(hash);

                let payload: Vec<u8> = payload
                    .to_base32()
                    .iter()
                    .map(|byte| BASE32_ENCODE_TABLE[byte.to_u8() as usize])
                    .collect();

                let payload = String::from_utf8(payload)?;
                let checksum = compute_checksum(payload.as_str(), N::prefix())?;

                Ok(Self {
                    address: format!("{}:{}{}", N::prefix(), payload, checksum),
                    format: format.clone(),
                    _network: PhantomData,
                })
            }
            BitcoincashFormat::Legacy => {
                let mut payload = vec![N::legacy_prefix()];
                payload.extend(hash);

                let checksum = double_sha2(&payload)[..4].to_vec();
                payload.extend(checksum);

                Ok(Self {
                    address: payload.to_base58(),
                    format: format.clone(),
                    _network: PhantomData,
                })
            }
        }
    }

    pub fn format(&self) -> BitcoincashFormat {
        self.format.clone()
    }
}

impl<N: BitcoincashNetwork> Address for BitcoincashAddress<N> {
    type SecretKey = libsecp256k1::SecretKey;
    type Format = BitcoincashFormat;
    type PublicKey = BitcoincashPublicKey<N>;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        let public_key = match public_key.is_compressed() {
            true => public_key
                .to_secp256k1_public_key()
                .serialize_compressed()
                .to_vec(),
            false => public_key.to_secp256k1_public_key().serialize().to_vec(),
        };
        let hash = hash160(&public_key);

        Self::from_hash160(&hash, format)
    }
}

impl<N: BitcoincashNetwork> FromStr for BitcoincashAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.starts_with(format!("{}:", N::prefix()).as_str()) {
            // the address is in CashAddr format
            if address.len() != N::prefix().len() + 1 + 34 + 8 {
                return Err(AddressError::InvalidCharacterLength(
                    address.len() - N::prefix().len() - 1,
                ));
            }
            let payload = &address[N::prefix().len() + 1..N::prefix().len() + 1 + 34];
            let checksum_provided = &address[address.len() - 8..address.len()];

            let checksum_gen = compute_checksum(payload, N::prefix())?;
            if checksum_provided != checksum_gen {
                return Err(AddressError::InvalidChecksum(
                    checksum_provided.to_string(),
                    checksum_gen,
                ));
            }

            Ok(BitcoincashAddress {
                address: address.to_string(),
                format: BitcoincashFormat::CashAddr,
                _network: PhantomData,
            })
        } else {
            // the address is in Legacy format, i.e., the Bitcoin P2PKH address format
            let bytes = address.from_base58()?;

            if bytes.len() != 25 {
                return Err(AddressError::InvalidAddress(address.to_string()));
            }

            if bytes[0] != N::legacy_prefix() {
                return Err(AddressError::Message(format!(
                    "Invalid address for {}",
                    N::NAME
                )));
            }

            let checksum_gen = &double_sha2(&bytes[..21])[..4];
            let checksum_provided = &bytes[21..];
            if *checksum_gen != *checksum_provided {
                return Err(AddressError::InvalidChecksum(
                    address.to_string(),
                    [bytes[..21].to_vec(), checksum_gen.to_vec()]
                        .concat()
                        .to_base58(),
                ));
            }

            Ok(BitcoincashAddress {
                address: address.to_string(),
                format: BitcoincashFormat::Legacy,
                _network: PhantomData,
            })
        }
    }
}

impl<N: BitcoincashNetwork> fmt::Display for BitcoincashAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

pub static BASE32_ENCODE_TABLE: [u8; 32] = [
    b'q', b'p', b'z', b'r', b'y', b'9', b'x', b'8', b'g', b'f', b'2', b't', b'v', b'd', b'w', b'0',
    b's', b'3', b'j', b'n', b'5', b'4', b'k', b'h', b'c', b'e', b'6', b'm', b'u', b'a', b'7', b'l',
];

pub static BASE32_DECODE_TABLE: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6,
    4, 2, -1, -1, -1, -1, -1,
];

fn checksum(feed: Vec<u8>) -> [u8; 5] {
    let mut c = 1u64;

    for d in feed.iter() {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07ffffffff) << 5) ^ (*d as u64);

        if c0 & 0x01 != 0 {
            c ^= 0x98f2bc8e61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x79b76d99e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0xf33e5fb3c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0xae2eabe2a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x1e4f43e470;
        }
    }

    c ^= 1;

    let mut ret = [0u8; 5];

    for (i, byte) in ret.iter_mut().enumerate() {
        *byte = (c >> (8 * i)) as u8;
    }

    ret
}

fn compute_checksum(payload: &str, prefix: &str) -> Result<String, AddressError> {
    let mut payload = payload.as_bytes().to_vec();
    for byte in payload.clone() {
        match BASE32_DECODE_TABLE.get(byte as usize) {
            Some(val) if *val != -1 => {}
            _ => {
                return Err(AddressError::Message(format!(
                    "Invalid base32 character '{}' for Bitcoin cash",
                    byte as char
                )))
            }
        }
    }

    payload
        .iter_mut()
        .for_each(|byte| *byte = BASE32_DECODE_TABLE[*byte as usize] as u8);

    let prefix = prefix.as_bytes().to_vec();
    let prefix: Vec<u8> = prefix.iter().map(|byte| byte & 0x1f).collect();
    let template = vec![0u8; 8];

    let mut feed = prefix;

    feed.push(0);
    feed.extend(&payload);
    feed.extend(&template);

    let mut chechsum = checksum(feed).to_vec();
    chechsum.reverse();

    let chechsum: Vec<u8> = chechsum
        .to_base32()
        .iter()
        .map(|byte| BASE32_ENCODE_TABLE[byte.to_u8() as usize])
        .collect();

    Ok(String::from_utf8(chechsum)?)
}

#[cfg(test)]
mod tests {
    use crate::{BitcoincashAddress, BitcoincashFormat, Mainnet, Testnet};
    use anychain_core::{libsecp256k1::SecretKey, Address};
    use std::str::FromStr;

    #[test]
    fn test_from_str() {
        let addresses_mainnet = [
            "bitcoincash:qpkxa3xypl6rfp4nzewh9xrqnv90n2yxrcr0pmwas4",
            "bitcoincash:qp2903ztagawgs9cxr9234yjc3pkguvrtyvlhw6qps",
            "1Ko5EALYpShk2nafGexgCBNxRuwqxvXFm",
        ];

        let addresses_testnet = [
            "bchtest:qqpcmun00mm0q6zezvtfhn2xg2zx2ufpvs6l92y3g0",
            "bchtest:qzuu4gwvj0xjy4p7xj7n5gn4ewk4m3ujeqx3crgj59",
            "mkWpcBriDmEemBqmmKzaEstLFZHsV3cMqA",
        ];

        addresses_mainnet.iter().for_each(|addr| {
            println!("{}", BitcoincashAddress::<Mainnet>::from_str(addr).unwrap())
        });

        addresses_testnet.iter().for_each(|addr| {
            println!("{}", BitcoincashAddress::<Testnet>::from_str(addr).unwrap())
        });
    }

    #[test]
    fn test_from_secret_key() {
        let secret_keys: [[u8; 32]; 2] = [
            [
                56, 127, 139, 242, 234, 208, 96, 112, 134, 251, 100, 45, 230, 217, 251, 107, 58,
                234, 218, 188, 213, 253, 10, 92, 251, 17, 190, 150, 100, 177, 1, 22,
            ],
            [
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
        ];

        let addresses: Vec<BitcoincashAddress<Mainnet>> = secret_keys
            .iter()
            .map(|sk| {
                let format = BitcoincashFormat::CashAddr;
                let sk = SecretKey::parse(sk).unwrap();
                BitcoincashAddress::<Mainnet>::from_secret_key(&sk, &format).unwrap()
            })
            .collect();

        addresses.iter().for_each(|addr| println!("{}", addr));
    }
}
