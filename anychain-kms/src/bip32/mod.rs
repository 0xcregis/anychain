mod child_number;
mod derivation_path;
mod error;
mod extended_key;
mod prefix;
mod private_key;
mod public_key;

pub use child_number::ChildNumber;
pub use error::{Error, Result};
pub use extended_key::{
    attrs::ExtendedKeyAttrs, extended_private_key::ExtendedPrivateKey,
    extended_public_key::ExtendedPublicKey, ExtendedKey,
};
pub use extended_key::{
    extended_private_key::XprvSecp256k1,
    extended_public_key::{XpubEd25519, XpubSecp256k1},
};
pub use prefix::Prefix;
pub use private_key::PrivateKey;
pub use public_key::PublicKey;

pub use derivation_path::DerivationPath;

/// Chain code: extension for both private and public keys which provides an
/// additional 256-bits of entropy.
pub type ChainCode = [u8; KEY_SIZE];

/// Derivation depth.
pub type Depth = u8;

/// BIP32 key fingerprints.
pub type KeyFingerprint = [u8; 4];

/// BIP32 "versions": integer representation of the key prefix.
pub type Version = u32;

/// HMAC with SHA-512
pub type HmacSha512 = hmac::Hmac<sha2::Sha512>;

pub const KEY_SIZE: usize = 32;

#[cfg(test)]
mod test_mod {
    use super::*;

    pub(crate) struct TestVector {
        pub seed: &'static str,
        pub ckd: [(&'static str, &'static str, &'static str); 6],
    }

    // bip32 standard test vectors
    const VECTORS :[TestVector;1] = [
        TestVector{
            seed: "000102030405060708090a0b0c0d0e0f",
            ckd: [
                (
                    "m",
                    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                ),
                (
                    "m/0'",
                    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
                ),
                (
                    "m/0'/1",
                    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                ),
                (
                    "m/0'/1/2'",
                    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
                ),
                (
                    "m/0'/1/2'/2",
                    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                ),
                (
                    "m/0'/1/2'/2/1000000000",
                    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                )
            ]
        }
    ];

    #[test]
    pub fn test_vectors() {
        VECTORS.iter().for_each(|vector| {
            let seed = hex::decode(vector.seed).unwrap();
            vector.ckd.iter().for_each(|item| {
                let path: DerivationPath = item.0.parse().unwrap();
                let xprv = XprvSecp256k1::new_from_path(seed.clone(), &path).unwrap();
                let xpub = xprv.public_key();
                assert_eq!(item.1, xprv.to_string(Prefix::XPRV).as_str());
                assert_eq!(item.2, xpub.to_string(Prefix::XPUB).as_str());
            })
        })
    }
}
