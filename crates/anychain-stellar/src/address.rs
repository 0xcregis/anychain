use {
    crate::{format::StellarFormat, public_key::StellarPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    curve25519_dalek::Scalar,
};

/// Represents a Solana address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StellarAddress(pub String);

impl Address for StellarAddress {
    type SecretKey = Scalar;
    type Format = StellarFormat;
    type PublicKey = StellarPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        let public_key = stellar_strkey::ed25519::PublicKey::from_payload(public_key.0.as_bytes())
            .map_err(|e| AddressError::Crate("public_key", format!("{e:?}")))?;
        Ok(Self(public_key.to_string()))
    }

    fn is_valid(address: &str) -> bool {
        Self::from_str(address).is_ok()
    }
}

impl FromStr for StellarAddress {
    type Err = AddressError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let public_key = stellar_strkey::ed25519::PublicKey::from_str(addr)
            .map_err(|e| AddressError::Crate("from", format!("{e:?}")))?;
        Ok(Self(public_key.to_string()))
    }
}

impl Display for StellarAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_ALICE: &str = "GDB7S3TDJIJSHHRZ3FNFGSAXH7JNXN44PXPPOG6ISIRMPMNFZHBS2AHQ";
    const ADDRESS_BOB: &str = "GAVMFTW4Y7EFICACWXKKDEIOKAD3YNXUPMZ77VLDRRZB25FJSHLU6WZR";

    #[test]
    fn test_address_alice() {
        let addr = StellarAddress::from_str(ADDRESS_ALICE).expect("failed to parse alice address");
        assert_eq!(addr.0, ADDRESS_ALICE);
        assert_eq!(addr.to_string(), ADDRESS_ALICE);
    }

    #[test]
    fn test_address_bob() {
        let addr = StellarAddress::from_str(ADDRESS_BOB).expect("failed to parse bob address");
        assert_eq!(addr.0, ADDRESS_BOB);
        assert_eq!(addr.to_string(), ADDRESS_BOB);
    }

    #[test]
    fn test_is_valid_address() {
        assert!(StellarAddress::is_valid(
            "GDB7S3TDJIJSHHRZ3FNFGSAXH7JNXN44PXPPOG6ISIRMPMNFZHBS2AHQ"
        ));
        assert!(StellarAddress::is_valid(
            "GAVMFTW4Y7EFICACWXKKDEIOKAD3YNXUPMZ77VLDRRZB25FJSHLU6WZR"
        ));
        assert!(!StellarAddress::is_valid("foo"))
    }
}
