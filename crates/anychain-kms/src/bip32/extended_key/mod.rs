//! Parser for extended key types (i.e. `xprv` and `xpub`)

pub(crate) mod attrs;
pub(crate) mod extended_private_key;
pub(crate) mod extended_public_key;

use crate::bip32::{ChildNumber, Error, ExtendedKeyAttrs, Prefix, Result, Version, KEY_SIZE};
use core::{
    fmt::{self, Display},
    str::{self, FromStr},
};
use zeroize::Zeroize;

/// Serialized extended key (e.g. `xprv` and `xpub`).
#[derive(Clone)]
pub struct ExtendedKey {
    /// [`Prefix`] (a.k.a. "version") of the key (e.g. `xprv`, `xpub`)
    pub prefix: Prefix,

    /// Extended key attributes.
    pub attrs: ExtendedKeyAttrs,

    /// Key material (may be public or private).
    ///
    /// Includes an extra byte for a public key's SEC1 tag.
    pub key_bytes: [u8; KEY_SIZE + 1],
}

impl ExtendedKey {
    /// Size of an extended key when deserialized into bytes from Base58.
    pub const BYTE_SIZE: usize = 78;

    /// Maximum size of a Base58Check-encoded extended key in bytes.
    ///
    /// Note that extended keys can also be 111-bytes.
    pub const MAX_BASE58_SIZE: usize = 112;

    /// Write a Base58-encoded key to the provided buffer, returning a `&str`
    /// containing the serialized data.
    ///
    /// Note that this type also impls [`Display`] and therefore you can
    /// obtain an owned string by calling `to_string()`.
    pub fn write_base58<'a>(&self, buffer: &'a mut [u8; Self::MAX_BASE58_SIZE]) -> Result<&'a str> {
        let mut bytes = [0u8; Self::BYTE_SIZE]; // with 4-byte checksum
        bytes[..4].copy_from_slice(&self.prefix.to_bytes());
        bytes[4] = self.attrs.depth;
        bytes[5..9].copy_from_slice(&self.attrs.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.attrs.child_number.to_bytes());
        bytes[13..45].copy_from_slice(&self.attrs.chain_code);
        bytes[45..78].copy_from_slice(&self.key_bytes);

        let base58_len = bs58::encode(&bytes).with_check().into(buffer.as_mut())?;
        bytes.zeroize();

        str::from_utf8(&buffer[..base58_len]).map_err(|_| Error::Base58)
    }
}

impl Display for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; Self::MAX_BASE58_SIZE];
        self.write_base58(&mut buf)
            .map_err(|_| fmt::Error)
            .and_then(|base58| f.write_str(base58))
    }
}

impl FromStr for ExtendedKey {
    type Err = Error;

    fn from_str(base58: &str) -> Result<Self> {
        let mut bytes = [0u8; Self::BYTE_SIZE + 4]; // with 4-byte checksum
        let decoded_len = bs58::decode(base58).with_check(None).into(&mut bytes)?;

        if decoded_len != Self::BYTE_SIZE {
            return Err(Error::Decode);
        }

        let prefix = base58.get(..4).ok_or(Error::Decode).and_then(|chars| {
            Prefix::validate_str(chars)?;
            let version = Version::from_be_bytes(bytes[..4].try_into()?);
            Ok(Prefix::from_parts_unchecked(chars, version))
        })?;

        let depth = bytes[4];
        let parent_fingerprint = bytes[5..9].try_into()?;
        let child_number = ChildNumber::from_bytes(bytes[9..13].try_into()?);
        let chain_code = bytes[13..45].try_into()?;
        let key_bytes = bytes[45..78].try_into()?;
        bytes.zeroize();

        let attrs = ExtendedKeyAttrs {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
        };

        Ok(ExtendedKey {
            prefix,
            attrs,
            key_bytes,
        })
    }
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

// TODO(tarcieri): consolidate test vectors

#[cfg(test)]
mod tests {
    use crate::bip32::{DerivationPath, ExtendedKey};
    use crate::bip32::{Prefix, XprvSecp256k1};
    use alloc::string::ToString;
    use hex_literal::hex;

    #[test]
    fn bip32_test_vector_1_xprv() {
        let xprv_base58 = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP\
             qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let xprv = xprv_base58.parse::<ExtendedKey>().unwrap();
        assert_eq!(xprv.prefix.as_str(), "xprv");
        assert_eq!(xprv.attrs.depth, 0);
        assert_eq!(xprv.attrs.parent_fingerprint, [0u8; 4]);
        assert_eq!(xprv.attrs.child_number.0, 0);
        assert_eq!(
            xprv.attrs.chain_code,
            hex!("873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508")
        );
        assert_eq!(
            xprv.key_bytes,
            hex!("00E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35")
        );
        assert_eq!(&xprv.to_string(), xprv_base58);
    }

    #[test]
    fn bip32_test_vector_1_xpub() {
        let xpub_base58 = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let xpub = xpub_base58.parse::<ExtendedKey>().unwrap();
        assert_eq!(xpub.prefix.as_str(), "xpub");
        assert_eq!(xpub.attrs.depth, 0);
        assert_eq!(xpub.attrs.parent_fingerprint, [0u8; 4]);
        assert_eq!(xpub.attrs.child_number.0, 0);
        assert_eq!(
            xpub.attrs.chain_code,
            hex!("873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508")
        );
        assert_eq!(
            xpub.key_bytes,
            hex!("0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2")
        );
        assert_eq!(&xpub.to_string(), xpub_base58);
    }

    fn debug_extend_key(ek: &ExtendedKey) {
        println!("prefix:{}", ek.prefix.as_str());
        println!("depth:{}", ek.attrs.depth);
        println!(
            "parent_fingerprint:{}",
            hex::encode(ek.attrs.parent_fingerprint)
        );
        println!("child_number:{}", ek.attrs.child_number);
        println!("chain_code:{}", hex::encode(ek.attrs.chain_code));
        println!("key_bytes:{}", hex::encode(ek.key_bytes));
    }

    #[test]
    fn test_master_xprv() {
        let xprv_base58 = "xprv9s21ZrQH143K3BMzbzRA1EtW4bTSDzvzPWeyUjjw6DdBGwM3GDNgd7wyAmy8R6KayQHRuTVQG4yvACbv4HLsyc9BPEGzu8GtYFTZTdncGnJ";

        let xprv = xprv_base58.parse::<ExtendedKey>().unwrap();
        debug_extend_key(&xprv);

        let xprv_base58_2 = "xprv9s21ZrQH143K4UgTbVuwLxTrB8u488uJxogG9CA7eAEL7hmcPtyG7zT8BtpmvibJQ8q1nxnXRUpQAo1BVa9tbvXery13KY1dSsC5A155c5k";
        let xprv2 = xprv_base58_2.parse::<ExtendedKey>().unwrap();
        debug_extend_key(&xprv2);
    }

    #[test]
    fn test_xprv() {
        let _seed = hex::decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let seed2 = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be".as_bytes();
        let path: DerivationPath = "m/44'/60/0'/10001".parse().unwrap();
        let xprv = XprvSecp256k1::new_from_path(seed2, &path).unwrap();
        println!("xprv: {}", xprv.to_extended_key(Prefix::XPRV));

        let xpub = xprv.public_key();
        println!("xpub: {}", xpub.to_extended_key(Prefix::XPUB));
        println!("{}", hex::encode(xpub.public_key().serialize()));
        // 040b4fed878e6b0ff6847e2ac9c13b556d161e1344cd270ed6cafac21f0144399d9ef31f267722fdeccba59ffd57ff84a020a2d3b416344c68e840bc7d97e77570
        // 0x5a2a8410875e882aee87bf8e5f2e1ede8810617b
    }

    #[test]
    fn test_hex() {
        let raw = "2b727519fa377f4195aabe4b5047849a3a55d838d15adc773bcc1ad89ed32b59c7d091795f578bdb6a523545edb9d3da514c7e5d3c130087c3b4f17b0ad1dd39";
        let bytes = raw.as_bytes();
        let str = String::from_utf8(bytes.to_vec()).unwrap();
        println!("{}", str.len());
    }
}
