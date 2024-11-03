use crate::{BitcoinFormat, BitcoinNetwork, BitcoinPublicKey, Opcode, Prefix, WitnessProgram};
use anychain_core::{
    crypto::{checksum, hash160},
    Address, AddressError,
};
use anychain_core::{no_std::*, PublicKey};

use base58::{FromBase58, ToBase58};
use bech32::{self, u5, FromBase32, ToBase32, Variant};
use core::hash::Hash;
use core::{fmt, marker::PhantomData, str::FromStr};
use sha2::{Digest, Sha256};

/// Represents a Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAddress<N: BitcoinNetwork> {
    /// The Bitcoin address
    address: String,
    /// The format of the address
    format: BitcoinFormat,
    /// PhantomData
    _network: PhantomData<N>,
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

fn checksum_bch(feed: Vec<u8>) -> [u8; 5] {
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

fn compute_checksum_bch(payload: &str, prefix: &str) -> Result<String, AddressError> {
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

    let mut chechsum = checksum_bch(feed).to_vec();
    chechsum.reverse();

    let chechsum: Vec<u8> = chechsum
        .to_base32()
        .iter()
        .map(|byte| BASE32_ENCODE_TABLE[byte.to_u8() as usize])
        .collect();

    Ok(String::from_utf8(chechsum)?)
}

impl<N: BitcoinNetwork> Address for BitcoinAddress<N> {
    type SecretKey = libsecp256k1::SecretKey;
    type Format = BitcoinFormat;
    type PublicKey = BitcoinPublicKey<N>;

    /// Returns the address corresponding to the given Bitcoin private key.
    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    /// Returns the address corresponding to the given Bitcoin public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        match format {
            BitcoinFormat::P2PKH => Self::p2pkh(public_key),
            BitcoinFormat::P2WSH => Err(AddressError::IncompatibleFormats(
                String::from("non-script"),
                String::from("p2wsh address"),
            )),
            BitcoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(public_key),
            BitcoinFormat::Bech32 => Self::bech32(public_key),
            BitcoinFormat::CashAddr => Self::cash_addr(public_key),
        }
    }
}

impl<N: BitcoinNetwork> BitcoinAddress<N> {
    /// Generate a P2PKH address from a hash160.
    pub fn p2pkh_from_hash(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::Message("Illegal hash160 length".to_string()));
        }

        let mut data = [0u8; 25];
        data[0] = N::to_address_prefix(BitcoinFormat::P2PKH)?.version();
        data[1..21].copy_from_slice(hash);

        let checksum = &checksum(&data[..21])[..4];
        data[21..].copy_from_slice(checksum);

        Ok(Self {
            address: data.to_base58(),
            format: BitcoinFormat::P2PKH,
            _network: PhantomData,
        })
    }

    /// Generate a P2SH_P2WPKH address from a hash160
    pub fn p2sh_p2wpkh_from_hash(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::Message("Illegal hash160 length".to_string()));
        }

        let mut data = [0u8; 25];
        data[0] = N::to_address_prefix(BitcoinFormat::P2SH_P2WPKH)?.version();
        data[1..21].copy_from_slice(hash);

        let checksum = &checksum(&data[..21])[..4];
        data[21..].copy_from_slice(checksum);

        Ok(Self {
            address: data.to_base58(),
            format: BitcoinFormat::P2SH_P2WPKH,
            _network: PhantomData,
        })
    }

    // Generate a P2WSH address in Bech32 format from a sha256 script hash
    pub fn p2wsh_from_hash(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 32 {
            return Err(AddressError::Message("Illegal sha256 length".to_string()));
        }

        let v = N::to_address_prefix(BitcoinFormat::P2WSH)?.version();
        let version = u5::try_from_u8(v)?;

        let mut data = vec![version];

        data.extend_from_slice(&hash.to_vec().to_base32());

        let prefix = N::to_address_prefix(BitcoinFormat::Bech32)?.prefix();
        let bech32 = bech32::encode(&prefix, data, Variant::Bech32)?;

        Ok(Self {
            address: bech32,
            format: BitcoinFormat::P2WSH,
            _network: PhantomData,
        })
    }

    /// Generate a Bech32 address from a hash160
    pub fn bech32_from_hash(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::Message("Illegal hash160 length".to_string()));
        }

        let data = [
            vec![u5::try_from_u8(0)?], // version byte: 0
            hash.to_base32(),
        ]
        .concat();

        let prefix = N::to_address_prefix(BitcoinFormat::Bech32)?.prefix();
        let bech32 = bech32::encode(&prefix, data, Variant::Bech32)?;

        Ok(Self {
            address: bech32,
            format: BitcoinFormat::Bech32,
            _network: PhantomData,
        })
    }

    /// Generate a CashAddr address from a hash160
    pub fn cash_addr_from_hash(hash: &[u8]) -> Result<Self, AddressError> {
        if hash.len() != 20 {
            return Err(AddressError::Message("Illegal hash160 length".to_string()));
        }

        let mut payload = vec![0u8]; // payload starts with version byte: 0
        payload.extend(hash);

        let payload: Vec<u8> = payload
            .to_base32()
            .iter()
            .map(|byte| BASE32_ENCODE_TABLE[byte.to_u8() as usize])
            .collect();

        let payload = String::from_utf8(payload)?;
        let prefix = N::to_address_prefix(BitcoinFormat::CashAddr)?.prefix();
        let checksum = compute_checksum_bch(&payload, &prefix)?;

        Ok(Self {
            address: format!("{}:{}{}", prefix, payload, checksum),
            format: BitcoinFormat::CashAddr,
            _network: PhantomData,
        })
    }

    /// Generate a P2PKH address from a given Bitcoin public key.
    pub fn p2pkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let hash = hash160(&public_key.serialize());
        Self::p2pkh_from_hash(&hash)
    }

    // Generate a P2WSH address in Bech32 format from a given Bitcoin script
    pub fn p2wsh(original_script: &[u8]) -> Result<Self, AddressError> {
        let hash = Sha256::digest(original_script).to_vec();
        Self::p2wsh_from_hash(&hash)
    }

    /// Generate a P2SH_P2WPKH address from a given Bitcoin public key.
    pub fn p2sh_p2wpkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let hash = hash160(&Self::create_redeem_script(public_key));
        Self::p2sh_p2wpkh_from_hash(&hash)
    }

    /// Generate a Bech32 address from a given Bitcoin public key.
    pub fn bech32(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let hash = hash160(&public_key.serialize());
        Self::bech32_from_hash(&hash)
    }

    /// Generate a CashAddr address from a given Bitcoin public key.
    pub fn cash_addr(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let hash = hash160(&public_key.serialize());
        Self::cash_addr_from_hash(&hash)
    }

    /// Return the format of the Bitcoin address.
    pub fn format(&self) -> BitcoinFormat {
        self.format.clone()
    }

    /// Generate a redeem script from a given Bitcoin public key.
    pub fn create_redeem_script(public_key: &<Self as Address>::PublicKey) -> [u8; 22] {
        let mut redeem = [0u8; 22];
        redeem[1] = Opcode::OP_PUSHBYTES_20 as u8;
        redeem[2..].copy_from_slice(&hash160(&public_key.serialize()));
        redeem
    }

    /// Decode the 'script_pub_key' to a bitcoin address
    pub fn from_script_pub_key(script_pub_key: &[u8]) -> Result<Self, AddressError> {
        if script_pub_key.len() == 25
            && script_pub_key[0] == Opcode::OP_DUP as u8
            && script_pub_key[1] == Opcode::OP_HASH160 as u8
            && script_pub_key[2] == 20
            && script_pub_key[23] == Opcode::OP_EQUALVERIFY as u8
            && script_pub_key[24] == Opcode::OP_CHECKSIG as u8
        {
            // we are handling a p2pkh script
            if N::NAME.starts_with("bitcoin cash") {
                BitcoinAddress::<N>::cash_addr_from_hash(&script_pub_key[3..23])
            } else {
                BitcoinAddress::<N>::p2pkh_from_hash(&script_pub_key[3..23])
            }
        } else if script_pub_key.len() == 23
            && script_pub_key[0] == Opcode::OP_HASH160 as u8
            && script_pub_key[1] == 20
            && script_pub_key[22] == Opcode::OP_EQUAL as u8
        {
            // we are handling a p2sh_p2wpkh script
            BitcoinAddress::<N>::p2sh_p2wpkh_from_hash(&script_pub_key[2..22])
        } else if script_pub_key.len() == 34 && script_pub_key[0] == 0 && script_pub_key[1] == 32 {
            // we are handling a p2wsh script
            BitcoinAddress::<N>::p2wsh_from_hash(&script_pub_key[2..])
        } else if script_pub_key.len() == 22 && script_pub_key[0] == 0 && script_pub_key[1] == 20 {
            // we are handling a bech32 script
            BitcoinAddress::<N>::bech32_from_hash(&script_pub_key[2..])
        } else {
            return Err(AddressError::Message(
                "Illegal utxo script public key".to_string(),
            ));
        }
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.starts_with("bitcoincash") || address.starts_with("bchtest") {
            // we are processing a bitcoin cash address in CashAddr format
            let prefix = address.split(':').collect::<Vec<&str>>()[0];

            // check if the address prefix corresponds to the correct network.
            let _ = N::from_address_prefix(Prefix::from_prefix(prefix))?;

            if address.len() != prefix.len() + 1 + 34 + 8 {
                return Err(AddressError::InvalidCharacterLength(
                    address.len() - prefix.len() - 1,
                ));
            }
            let payload = &address[prefix.len() + 1..prefix.len() + 1 + 34];
            let checksum_provided = &address[address.len() - 8..address.len()];

            // check if the payload produces the provided checksum
            let checksum_gen = compute_checksum_bch(payload, prefix)?;
            if checksum_provided != checksum_gen {
                return Err(AddressError::InvalidChecksum(
                    checksum_provided.to_string(),
                    checksum_gen,
                ));
            }

            Ok(BitcoinAddress {
                address: address.to_string(),
                format: BitcoinFormat::CashAddr,
                _network: PhantomData,
            })
        } else if address.starts_with("bc1")
            || address.starts_with("tb1")
            || address.starts_with("ltc1")
            || address.starts_with("tltc1")
        {
            // we are processing an address in Bech32 format
            let (hrp, data, _) = bech32::decode(address)?;

            if data.is_empty() {
                return Err(AddressError::InvalidAddress(address.to_owned()));
            }

            // check if the address prefix corresponds to the correct network.
            let _ = N::from_address_prefix(Prefix::from_prefix(&hrp))?;

            let version = data[0].to_u8();
            let mut program = Vec::from_base32(&data[1..])?;

            let mut data = vec![version, program.len() as u8];
            data.append(&mut program);

            // check if the witness program is valid.
            let _ = WitnessProgram::new(data.as_slice())?;

            Ok(Self {
                address: address.to_string(),
                format: BitcoinFormat::Bech32,
                _network: PhantomData,
            })
        } else {
            let has_uppercase = |s: &str| {
                for c in s.chars() {
                    if c.is_ascii_uppercase() {
                        return true;
                    }
                }
                false
            };

            if has_uppercase(address) {
                // we are processing an address in p2pkh or p2sh_p2wpkh format
                let data = address.from_base58()?;

                if data.len() != 25 {
                    return Err(AddressError::InvalidByteLength(data.len()));
                }

                let version = Prefix::from_version(data[0]);

                // check if the address prefix corresponds to the correct network
                let _ = N::from_address_prefix(version.clone())?;

                let format = BitcoinFormat::from_address_prefix(version)?;

                // check if the payload produces the provided checksum
                match format {
                    BitcoinFormat::P2PKH | BitcoinFormat::P2SH_P2WPKH => {
                        let checksum_gen = &checksum(&data[..21])[..4];
                        let checksum_provided = &data[21..];
                        if *checksum_gen != *checksum_provided {
                            return Err(AddressError::InvalidChecksum(
                                [data[..21].to_vec(), checksum_gen.to_vec()]
                                    .concat()
                                    .to_base58(),
                                address.to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(AddressError::Message(format!(
                            "Unrecognized version byte {}",
                            data[0],
                        )))
                    }
                }

                Ok(Self {
                    address: address.to_string(),
                    format,
                    _network: PhantomData,
                })
            } else {
                // we are processing a bitcoin cash address in CashAddr format without an explicit prefix
                let prefix = N::to_address_prefix(BitcoinFormat::CashAddr)?.prefix();

                if address.len() != 42 {
                    return Err(AddressError::InvalidCharacterLength(address.len()));
                }

                let payload = &address[..34];
                let checksum_provided = &address[34..];

                // check if the payload produces the provided checksum
                let checksum_gen = compute_checksum_bch(payload, &prefix)?;
                if checksum_provided != checksum_gen {
                    return Err(AddressError::InvalidChecksum(
                        checksum_provided.to_string(),
                        checksum_gen,
                    ));
                }

                Ok(Self {
                    address: address.to_string(),
                    format: BitcoinFormat::CashAddr,
                    _network: PhantomData,
                })
            }
        }
    }
}

impl<N: BitcoinNetwork> fmt::Display for BitcoinAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_script_pub_key, network::*};
    use anychain_core::{hex, Network};
    use rand::thread_rng;

    fn test_from_str<N: BitcoinNetwork>(expected_address: &str, expected_format: &BitcoinFormat) {
        let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: BitcoinNetwork>(expected_address: &str, address: &BitcoinAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Bitcoin;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "L2o7RUmise9WoxNzmnVZeK83Mmt5Nn1NBpeftbthG5nsLWCzSKVg",
                "1GUwicFwsZbdE3XyJYjmPryiiuTiK7mZgS",
            ),
            (
                "KzjKw25tuQoiDyQjUG38ZRNBdnfr5eMBnTsU4JahrVDwFCpRZP1J",
                "1J2shZV5b53GRVmTqmr3tJhkVbBML29C1z",
            ),
            (
                "L2N8YRtxNMAVFAtxBt9PFSADtdvbmzFFHLSU61CtLdhYhrCGPfWh",
                "13TdfCiGPagApSJZu1o1Y3mpfqpp6oK2GB",
            ),
            (
                "KwXH1Mu4FBtGN9nRn2VkBpienaVGZKvCAkZAdE96kK71dHR1oDRs",
                "1HaeDGHf3A2Uxeh3sKjVLYTn1hnEyuzLjF",
            ),
            (
                "KwN7qiBnU4GNhboBhuPaPaFingTDKU4r27pGggwQYz865TvBT74V",
                "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Bitcoin;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm",
                "18Bap2Lh5HJckiZcg8SYXoF5iPxkUoCN8u",
            ),
            (
                "5KiudZRwr9wH5auJaW66WK3CGR1UzL7ZXiicvZEEaFScbbEt9Qs",
                "192JSK8wNP867JGxHNHay3obNSXqEyyhtx",
            ),
            (
                "5KCxYELatMGyVZfZFcSAw1Hz4ngiURKS22x7ydNRxcXfUzhgWMH",
                "1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT",
            ),
            (
                "5KT9CMP2Kgh2Afi8GbmFAHJXsH5DhcpH9KY3aH4Hkv5W6dASy7F",
                "1NyGFd49x4nqoau8RJvjf9tGZkoUNjwd5a",
            ),
            (
                "5J4cXobHh2cF2MHpLvTFjEHZCtrNHzyDzKGE8LuST2VWP129pAE",
                "17nsg1F155BR6ie2miiLrSnMhF8GWcGq6V",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        type N = BitcoinTestnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
                "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w",
            ),
            (
                "cNp5uMWdh68Nk3pwShjxsSwhGPoCYgFvE1ANuPsk6qhcT4Jvp57n",
                "myH91eNrQKuuM7TeQYYddzL4URn6HiYbxW",
            ),
            (
                "cN9aUHNMMLT9yqBJ3S5qnEPtP11nhT7ivkFK1FqNYQMozZPgMTjJ",
                "mho8tsQtF7fx2bPKudMcXvGpUVYRHHiH4m",
            ),
            (
                "cSRpda6Bhog5SUyot96HSwSzn7FZNWzudKzoCzkgZrf9hUaL3Ass",
                "n3DgWHuAkg7eiPGH5gP8jeg3SbHBhuPJWS",
            ),
            (
                "cTqLNf3iCaW61ofgmyf4ZxChUL8DZoCEPmNTCKRsexLSdNuGWQT1",
                "mjhMXrTdq4X1dcqTaNDjwGdVaJEGBKpCRj",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        type N = BitcoinTestnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
                "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho",
            ),
            (
                "91dTfyLPPneZA6RsAXqNuT6qTQdAuuGVCUjmBtzgd1Tnd4RQT5K",
                "mw4afqNgGjn34okVmv9qH2WkvhfyTyNbde",
            ),
            (
                "92GweXA6j4RCF3zHXGGy2ShJq6T7u9rrjmuYd9ktLHgNrWznzUC",
                "moYi3FQZKtcc66edT3uMwVQCcswenpNscU",
            ),
            (
                "92QAQdzrEDkMExM9hHV5faWqKTdXcTgXguRBcyAyYqFCjVzhDLE",
                "mpRYQJ64ofurTCA3KKkaCjjUNqjYkUvB4w",
            ),
            (
                "92H9Kf4ikaqNAJLc5tbwvbmiBWJzNDGtYmnvrigZeDVD3aqJ85Q",
                "mvqRXtgQKqumMosPY3dLvhdYsQJV2AswkA",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        type N = Bitcoin;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "L3YPi4msjWdkqiH3ojfg3nwDmNYBrDScAtcugYBJSgsc3HTcqqjP",
                "38EMCierP738rgYVHjj1qJANHKgx1166TN",
            ),
            (
                "KxxFoGgBdqqyGznT6he2wKYcFKm5urSANec7qjLeu3caEadSo5pv",
                "3Kc9Vqzi4eUn42g1KWewVPvtTpWpUwjNFv",
            ),
            (
                "KziUnVFNBniwmvei7JvNJNcQZ27TDZe5VNn7ieRNK7QgMEVfKdo9",
                "3C2niRgmFP2kz47AAWASqq5nWobDke1AfJ",
            ),
            (
                "Kx5veRe18jnV1rZiJA7Xerh5qLpwnbjV38r83sKcF1W9d1K2TGSp",
                "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK",
            ),
            (
                "L4RrcBy6hZMw3xD4eAFXDTWPhasd9N3rYrYgfiR9pnGuLdv7UsWZ",
                "3LW5tQGWBCiRLfCgk1FEUpwKoymFF8Lk7P",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2sh_p2wpkh_testnet {
        use super::*;

        type N = BitcoinTestnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSoLwgnCNXck57BGxdGRV4SQ42EUExV6ykdMK1RKwcEaB9MDZWki",
                "2N9e892o8DNZs25xHBwRPZLsrZK3dBsrH3d",
            ),
            (
                "cQEUStvLToCNEQ6QGPyTmGFCTiMWWzQDkkj2tUPEiAzafybgUyu4",
                "2MwX52EZPfK1sq12H3ikgTybrUvKG62b9rV",
            ),
            (
                "cRv6jkNhTNEL7563ezNuwWP9W7gEcjh19YbmHtTbrDUQsXF5PjoG",
                "2N2XaYpYxX6C6attRQ1NXJUgZdm861CPHJ7",
            ),
            (
                "cNyZJwad53Y38RthGrmYyoHAtsT7cPisjW92HJ4RcAP1mC6xBpSm",
                "2N3HzUQ4DzfEbxYp3XtpEKBBSdBS1uc2DLk",
            ),
            (
                "cUqEZZwzvdWv6pmnWV5eb68hNeWt3jDZgtCGf66rqk3bnbsXArVE",
                "2N5isk4qJHAKfLV987ePAqjLobJkrWVCuhj",
            ),
        ];

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod bech32_mainnet {
        use super::*;

        type N = Bitcoin;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "KyQ2StwnZ644hRLXdMrRUBGKT9WJcVVhnuzz2u528VHeAr5kFimR",
                "bc1qztqceddvavsxdgju4cz6z42tawu444m8uttmxg",
            ),
            (
                "L3aeYHnEBqNt6tKTgUyweY9HvZ3mcLMsq7KQZkSu9Mj8Z1JN9oC2",
                "bc1q0s92yg9m0zqjjc07z5lhhlu3k6ue93fgzku2wy",
            ),
            (
                "L3w7zoPzip7o6oXz3zVLNHbT2UyLBWuVG7uaEZDqneRjgjw9vmCE",
                "bc1q7rzq3xup0hdklkg6p8harn97zszuqwuaqc9l8t",
            ),
            (
                "L2C75eEmRTU8yWeSwtQ6xeumoNVmCb2uEMfzuo5dkdMwpUWwYtRU",
                "bc1qgw90ly6jkpprh6g8atk5cxnwcavh4e0p2k3h65",
            ),
            (
                "L2CJfT3w1VPDDLQfJKTmSb6gtSGyE1HxWYsitaq5Y1XLXTMC5Qmx",
                "bc1qgfzgf6pzuk7y88zk54nxluzg6dv9jett9suzuf",
            ),
        ];

        const INVALID: [&str; 7] = [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // invalid checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // invalid witness version
            "bc1rw5uspcuh",                               // invalid program length
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // invalid program length
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // invalid program length for witness version 0 (per BIP141)
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", // invalid padding
            "bc1gmk9yu",                            // empty data section
        ];

        #[test]
        fn from_invalid_address() {
            INVALID.iter().for_each(|invalid_bech32| {
                assert!(BitcoinAddress::<N>::from_str(invalid_bech32).is_err());
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod bech32_testnet {
        use super::*;

        type N = BitcoinTestnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cVQmTtLoCjDJAXVj778xyww1ZbpJQt7Vq9sDt8Mdmw97Rg7TaNes",
                "tb1qmkvfprg8pkr3apv9gyykmhe26fexyla076ss0g",
            ),
            (
                "cTxHRG8MgrnSQstuMs5VnQcFBjrs67NmiJGo1kevnJDS7QFGLUAi",
                "tb1qfe0dnfpxp4c9lfdjzvmf5q72jg83emgknmcxxd",
            ),
            (
                "cSN1N2Vmhg9jPSUpXyQj8WbNUgeLHbC3Yj8SFX2N834YMepMwNZH",
                "tb1qx4jm2s3ks5vadh2ja3flsn4ckjzhdxmxmmrrzx",
            ),
            (
                "cMvmoqYYzr4dgzNZ22PvaqSnNx98evXc1b7m8FfK9SdCqhiWdP2c",
                "tb1ql0g42pusevlgd0jh9gyr32s0h0pe96wpnrqg3m",
            ),
            (
                "cVodD5ifcBjYVUs19GLwz6YzU2hUhdNagBx9QQcZp7TgjLuuFYn3",
                "tb1qwnh7hu5qfrjsk9pyn3vvmzr48v4l8kp4ug0txn",
            ),
        ];

        const INVALID: [&str; 3] = [
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // invalid hrp
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // Mixed case
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        ];

        #[test]
        fn from_invalid_address() {
            INVALID.iter().for_each(|invalid_bech32| {
                assert!(BitcoinAddress::<N>::from_str(invalid_bech32).is_err());
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2wsh_mainnet {
        use super::*;

        type N = Bitcoin;

        #[test]
        fn test_addr() {
            let script = "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac";
            let script_hex = hex::decode(script).unwrap();
            let new_address = BitcoinAddress::<N>::p2wsh(&script_hex).unwrap();
            println!("address:{}", new_address);
        }
    }

    mod p2wsh_testnet {
        use super::*;

        type N = BitcoinTestnet;

        const SCRIPTPAIRS: [(&str, &str); 2] = [
            (
                "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            ),
            (
                "210253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7cac",
                "tb1qhmdep02f0jpjxs36ckyzjtfesknu8a8xmhnva7f3vw95t9g6q4ksaqhl9x",
            ),
        ];

        #[test]
        fn from_str() {
            SCRIPTPAIRS.iter().for_each(|(script, address)| {
                let script_hex = hex::decode(script).unwrap();
                let new_address = BitcoinAddress::<N>::p2wsh(&script_hex).unwrap();
                assert_eq!(new_address.to_string(), address.to_string());
                assert_eq!(new_address.format, BitcoinFormat::P2WSH);
            });
        }

        #[test]
        fn to_str() {
            SCRIPTPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn f() {
        let secret_key = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1,
        ];

        let secret_key = libsecp256k1::SecretKey::parse(&secret_key).unwrap();

        let formats = [
            BitcoinFormat::P2PKH,
            BitcoinFormat::P2SH_P2WPKH,
            // BitcoinFormat::Bech32,
            // BitcoinFormat::CashAddr
        ];

        for format in formats {
            let address = BitcoinAddress::<Bitcoin>::from_secret_key(&secret_key, &format).unwrap();
            println!("{} {} address = \n{}\n", Bitcoin::NAME, format, address);

            let address =
                BitcoinAddress::<BitcoinTestnet>::from_secret_key(&secret_key, &format).unwrap();
            println!(
                "{} {} address = \n{}\n",
                BitcoinTestnet::NAME,
                format,
                address
            );

            let address =
                BitcoinAddress::<BitcoinCash>::from_secret_key(&secret_key, &format).unwrap();
            println!("{} {} address = \n{}\n", BitcoinCash::NAME, format, address);

            let address =
                BitcoinAddress::<BitcoinCashTestnet>::from_secret_key(&secret_key, &format)
                    .unwrap();
            println!(
                "{} {} address = \n{}\n",
                BitcoinCashTestnet::NAME,
                format,
                address
            );

            let address =
                BitcoinAddress::<Litecoin>::from_secret_key(&secret_key, &format).unwrap();
            println!("{} {} address = \n{}\n", Litecoin::NAME, format, address);

            let address =
                BitcoinAddress::<LitecoinTestnet>::from_secret_key(&secret_key, &format).unwrap();
            println!(
                "{} {} address = \n{}\n",
                LitecoinTestnet::NAME,
                format,
                address
            );

            let address =
                BitcoinAddress::<Dogecoin>::from_secret_key(&secret_key, &format).unwrap();
            println!("{} {} address = \n{}\n", Dogecoin::NAME, format, address);

            let address =
                BitcoinAddress::<DogecoinTestnet>::from_secret_key(&secret_key, &format).unwrap();
            println!(
                "{} {} address = \n{}\n",
                DogecoinTestnet::NAME,
                format,
                address
            );
        }
    }

    #[test]
    fn ff() {
        let addr1 = "qzuu4gwvj0xjy4p7xj7n5gn4ewk4m3ujeqx3crgj59";
        let addr2 = "qpkxa3xypl6rfp4nzewh9xrqnv90n2yxrcr0pmwas4";
        let addr3 = "bchtest:qzuu4gwvj0xjy4p7xj7n5gn4ewk4m3ujeqx3crgj59";
        let addr4 = "bitcoincash:qpkxa3xypl6rfp4nzewh9xrqnv90n2yxrcr0pmwas4";
        let addr5 = "2MvtZ4txAvbaWRW2gXRmmrcUpQfsqNgpfUm";

        let addr1 = BitcoinAddress::<BitcoinCashTestnet>::from_str(addr1).unwrap();
        let addr2 = BitcoinAddress::<BitcoinCash>::from_str(addr2).unwrap();
        let addr3 = BitcoinAddress::<BitcoinCashTestnet>::from_str(addr3).unwrap();
        let addr4 = BitcoinAddress::<BitcoinCash>::from_str(addr4).unwrap();
        let addr5 = BitcoinAddress::<BitcoinTestnet>::from_str(addr5).unwrap();

        println!(
            "address1 = {}\naddress2 = {}\naddress3 = {}\naddress4 = {}\naddress5 = {}",
            addr1, addr2, addr3, addr4, addr5,
        );
    }

    #[test]
    fn test_decode_script() {
        let mut rng = thread_rng();

        let sk = libsecp256k1::SecretKey::random(&mut rng);
        let addr = BitcoinAddress::<Bitcoin>::from_secret_key(&sk, &BitcoinFormat::P2PKH).unwrap();
        println!("{}", addr);
        let script = create_script_pub_key(&addr).unwrap();
        let addr = BitcoinAddress::<Bitcoin>::from_script_pub_key(&script).unwrap();
        println!("{}", addr);

        let sk = libsecp256k1::SecretKey::random(&mut rng);
        let addr =
            BitcoinAddress::<Bitcoin>::from_secret_key(&sk, &BitcoinFormat::P2SH_P2WPKH).unwrap();
        println!("{}", addr);
        let script = create_script_pub_key(&addr).unwrap();
        let addr = BitcoinAddress::<Bitcoin>::from_script_pub_key(&script).unwrap();
        println!("{}", addr);

        let sk = libsecp256k1::SecretKey::random(&mut rng);
        let addr = BitcoinAddress::<Bitcoin>::from_secret_key(&sk, &BitcoinFormat::Bech32).unwrap();
        println!("{}", addr);
        let script = create_script_pub_key(&addr).unwrap();
        let addr = BitcoinAddress::<Bitcoin>::from_script_pub_key(&script).unwrap();
        println!("{}", addr);

        let sk = libsecp256k1::SecretKey::random(&mut rng);
        let addr =
            BitcoinAddress::<Bitcoin>::p2wsh_from_hash(&Sha256::digest(sk.serialize())).unwrap();
        println!("{}", addr);
        let script = create_script_pub_key(&addr).unwrap();
        let addr = BitcoinAddress::<Bitcoin>::from_script_pub_key(&script).unwrap();
        println!("{}", addr);

        let sk = libsecp256k1::SecretKey::random(&mut rng);
        let addr =
            BitcoinAddress::<BitcoinCash>::from_secret_key(&sk, &BitcoinFormat::CashAddr).unwrap();
        println!("{}", addr);
        let script = create_script_pub_key(&addr).unwrap();
        let addr = BitcoinAddress::<BitcoinCash>::from_script_pub_key(&script).unwrap();
        println!("{}", addr);
    }
}
