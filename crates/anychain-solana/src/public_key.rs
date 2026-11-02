use {
    crate::{address::SolanaAddress, format::SolanaFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    core::{convert::TryInto, fmt, str::FromStr},
    curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as G, Scalar},
    ed25519_dalek::PUBLIC_KEY_LENGTH,
    group::GroupEncoding,
};

/// Maximum string length of a base58 encoded pubkey
pub const MAX_BASE58_LEN: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for SolanaPublicKey {
    type SecretKey = Scalar;
    type Address = SolanaAddress;
    type Format = SolanaFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let public_key = secret_key * G;
        let public_key = public_key.to_bytes();
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        SolanaPublicKey(public_key)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for SolanaPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(PublicKeyError::InvalidByteLength(s.len()));
        }
        let pubkey_vec = bs58::decode(s)
            .into_vec()
            .map_err(|error| PublicKeyError::Crate("base58", format!("{error:?}")))?;
        if pubkey_vec.len() != PUBLIC_KEY_LENGTH {
            return Err(PublicKeyError::InvalidByteLength(pubkey_vec.len()));
        }
        let buffer: [u8; PUBLIC_KEY_LENGTH] = pubkey_vec.as_slice().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&buffer)
            .map_err(|error| PublicKeyError::Crate("base58", format!("{error:?}")))?;
        Ok(SolanaPublicKey(verifying_key))
    }
}

impl fmt::Display for SolanaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(self.0.to_bytes()).into_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_from_str() {
        let pubkey_str = "EpFLfuH524fk9QP9i9uL9AHtX6smBaxaMHwek9T11nK5";
        let pubkey_res = SolanaPublicKey::from_str(pubkey_str);
        assert!(pubkey_res.is_ok());
        let pubkey = pubkey_res.unwrap();
        assert_eq!(pubkey.to_string(), pubkey_str);
    }
}
