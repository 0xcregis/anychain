use {
    crate::{address::CardanoAddress, format::CardanoFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    cml_crypto::{Bip32PrivateKey, Bip32PublicKey},
    core::{fmt, str::FromStr},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoPublicKey(pub Bip32PublicKey);

impl PublicKey for CardanoPublicKey {
    type SecretKey = Bip32PrivateKey;
    type Address = CardanoAddress;
    type Format = CardanoFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self(secret_key.to_public())
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for CardanoPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bip32PublicKey::from_bech32(s)
            .map_err(|error| PublicKeyError::Crate("bech32", format!("{:?}", error)))
            .map(Self)
    }
}

impl fmt::Display for CardanoPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_bech32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_from_str() {
        let pubkey_str = "xpub1gyuwtxy45wmzjsetlrx82mhg86c98zvnwvl7yvaxwt5g5f7aau9usq4e9gwraq2qh5j2ywml0smhflslxfsj0hjqnmzspclprkp5tkcmfgu4v";
        let pubkey_res = CardanoPublicKey::from_str(pubkey_str);
        assert!(pubkey_res.is_ok());
        let pubkey = pubkey_res.unwrap();
        assert_eq!(pubkey.to_string(), pubkey_str);
    }
}
