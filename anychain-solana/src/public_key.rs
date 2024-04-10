use {
    crate::{address::SolanaAddress, format::SolanaFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    core::{convert::TryInto, fmt, str::FromStr},
    ed25519_dalek::PUBLIC_KEY_LENGTH,
};

/// Maximum string length of a base58 encoded pubkey
pub const MAX_BASE58_LEN: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for SolanaPublicKey {
    type SecretKey = ed25519_dalek::SecretKey;
    type Address = SolanaAddress;
    type Format = SolanaFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
        let verifying_key = signing_key.verifying_key();
        SolanaPublicKey(verifying_key)
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
            .map_err(|error| PublicKeyError::Crate("base58", format!("{:?}", error)))?;
        if pubkey_vec.len() != PUBLIC_KEY_LENGTH {
            return Err(PublicKeyError::InvalidByteLength(pubkey_vec.len()));
        }
        let buffer: [u8; PUBLIC_KEY_LENGTH] = pubkey_vec.as_slice().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&buffer)
            .map_err(|error| PublicKeyError::Crate("base58", format!("{:?}", error)))?;
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
    use anychain_core::PublicKey;
    use core::convert::From;
    use ed25519_dalek::{SecretKey, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

    #[test]
    fn test_public_key_from_str() {
        let pubkey_str = "EpFLfuH524fk9QP9i9uL9AHtX6smBaxaMHwek9T11nK5";
        let pubkey_res = SolanaPublicKey::from_str(pubkey_str);
        assert!(pubkey_res.is_ok());
        let pubkey = pubkey_res.unwrap();
        assert_eq!(pubkey.to_string(), pubkey_str);
    }

    #[test]
    fn test_public_key_from_from_secret_key() {
        // let public_bytes :[u8;PUBLIC_KEY_LENGTH] = [0xu8;PUBLIC_KEY_LENGTH];
        let pubkey_str = "EpFLfuH524fk9QP9i9uL9AHtX6smBaxaMHwek9T11nK5";

        let mut secret_bytes: [u8; PUBLIC_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        let keypair_bytes: [u8; KEYPAIR_LENGTH] = [
            41, 196, 252, 146, 80, 100, 13, 46, 69, 89, 172, 157, 224, 135, 23, 62, 54, 65, 52, 68,
            14, 50, 112, 112, 156, 210, 24, 236, 139, 169, 38, 63, 205, 66, 112, 255, 116, 177, 79,
            182, 192, 20, 240, 193, 219, 162, 23, 149, 26, 247, 181, 186, 145, 168, 26, 232, 228,
            76, 102, 109, 64, 189, 172, 44,
        ];
        secret_bytes.copy_from_slice(&keypair_bytes[0..SECRET_KEY_LENGTH]);

        let secret_key: SecretKey = SecretKey::from(secret_bytes);
        let public_key = SolanaPublicKey::from_secret_key(&secret_key);
        assert_eq!(public_key.to_string(), pubkey_str);
    }
}
