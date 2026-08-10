use {
    crate::{format::HederaFormat, public_key::HederaPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    ed25519_dalek::SigningKey,
};

/// Represents a Hedera address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HederaAddress(pub String);

impl Address for HederaAddress {
    type SecretKey = SigningKey;
    type Format = HederaFormat;
    type PublicKey = HederaPublicKey;

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
        public_key.to_address(format)
    }

    fn is_valid(address: &str) -> bool {
        Self::from_str(address).is_ok()
    }
}

impl FromStr for HederaAddress {
    type Err = AddressError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let public_key = HederaPublicKey::from_str(addr)?;
        public_key.to_address(&HederaFormat::Standard)
    }
}

impl Display for HederaAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    fn assert_address_from_secret_key(private_hex: &str) {
        let private_key_bytes = hex::decode(private_hex).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);

        let address =
            HederaAddress::from_secret_key(&signing_key, &HederaFormat::Standard).unwrap();
        let public_key = HederaPublicKey::from_secret_key(&signing_key);
        assert_eq!(address.to_string(), public_key.to_string());
    }

    fn assert_address_from_public_key(private_hex: &str) {
        let private_key_bytes = hex::decode(private_hex).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let public_key = HederaPublicKey::from_secret_key(&signing_key);
        let address = HederaAddress::from_public_key(&public_key, &HederaFormat::Standard).unwrap();
        assert_eq!(address.to_string(), public_key.to_string());
    }

    fn assert_address_from_secret_key_matches_from_public_key(private_hex: &str) {
        let private_key_bytes = hex::decode(private_hex).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);

        let address_from_secret =
            HederaAddress::from_secret_key(&signing_key, &HederaFormat::Standard).unwrap();
        let public_key = HederaPublicKey::from_secret_key(&signing_key);
        let address_from_public =
            HederaAddress::from_public_key(&public_key, &HederaFormat::Standard).unwrap();

        assert_eq!(
            address_from_secret.to_string(),
            address_from_public.to_string()
        );
    }

    #[test]
    fn test_address_from_secret_key() {
        assert_address_from_secret_key(PRIVATE_HEX_ALICE);
        assert_address_from_secret_key(PRIVATE_HEX_BOB);
    }

    #[test]
    fn test_address_from_public_key() {
        assert_address_from_public_key(PRIVATE_HEX_ALICE);
        assert_address_from_public_key(PRIVATE_HEX_BOB);
    }

    #[test]
    fn test_address_from_secret_key_matches_from_public_key() {
        assert_address_from_secret_key_matches_from_public_key(PRIVATE_HEX_ALICE);
        assert_address_from_secret_key_matches_from_public_key(PRIVATE_HEX_BOB);
    }

    #[test]
    fn test_is_valid_address() {
        let private_key_bytes =
            hex::decode(PRIVATE_HEX_ALICE).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let public_key = HederaPublicKey::from_secret_key(&signing_key);

        assert!(HederaAddress::is_valid(&public_key.to_string()));
        assert!(!HederaAddress::is_valid("invalid"));
        assert!(!HederaAddress::is_valid(""));
    }

    #[test]
    fn test_address_from_str() {
        let private_key_bytes =
            hex::decode(PRIVATE_HEX_ALICE).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_arr);
        let public_key = HederaPublicKey::from_secret_key(&signing_key);

        let address = HederaAddress::from_str(&public_key.to_string()).unwrap();
        assert_eq!(address.to_string(), public_key.to_string());
    }
}
