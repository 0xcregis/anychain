use {
    crate::{address::StellarAddress, format::StellarFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    core::{fmt, str::FromStr},
    curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as G, Scalar},
    ed25519_dalek::VerifyingKey,
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StellarPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for StellarPublicKey {
    type SecretKey = Scalar;
    type Address = StellarAddress;
    type Format = StellarFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let public_key = secret_key * G;
        let public_key = public_key.to_bytes();
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        StellarPublicKey(public_key)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for StellarPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let public_key = stellar_strkey::ed25519::PublicKey::from_str(s)
            .map_err(|e| PublicKeyError::Crate("from", format!("{e:?}")))?;

        let public_key_bytes = public_key.0;
        Ok(StellarPublicKey(
            VerifyingKey::from_bytes(&public_key_bytes).unwrap(),
        ))
    }
}

impl fmt::Display for StellarPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let public_key =
            stellar_strkey::ed25519::PublicKey::from_payload(self.0.as_bytes()).unwrap();
        write!(f, "{}", public_key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_ALICE: &str = "GDB7S3TDJIJSHHRZ3FNFGSAXH7JNXN44PXPPOG6ISIRMPMNFZHBS2AHQ";
    const ADDRESS_BOB: &str = "GAVMFTW4Y7EFICACWXKKDEIOKAD3YNXUPMZ77VLDRRZB25FJSHLU6WZR";
    #[test]
    fn test_public_key_from_secret_alice() {
        let _seed_alice: [u8; 32] = [
            213, 71, 121, 237, 63, 103, 154, 87, 235, 22, 84, 108, 166, 24, 202, 7, 122, 228, 21,
            99, 226, 170, 169, 147, 92, 226, 198, 21, 74, 105, 226, 192,
        ];
        let alice_scalar: [u8; 32] = [
            247, 201, 84, 161, 207, 61, 75, 43, 206, 55, 32, 240, 130, 48, 183, 64, 185, 86, 215,
            30, 180, 223, 126, 175, 15, 115, 113, 102, 169, 229, 96, 4,
        ];
        let secret_key = Scalar::from_bytes_mod_order(alice_scalar);
        let public_key = StellarPublicKey::from_secret_key(&secret_key);
        dbg!(&public_key.to_string());
        assert_eq!(public_key.to_string(), ADDRESS_ALICE);
    }

    #[test]
    fn test_public_key_from_secret_bob() {
        let _seed_bob: [u8; 32] = [
            129, 247, 189, 23, 54, 229, 197, 34, 231, 118, 157, 117, 176, 61, 2, 224, 72, 66, 97,
            189, 195, 1, 34, 68, 151, 165, 243, 218, 165, 173, 24, 203,
        ];
        let bob_scalar: [u8; 32] = [
            140, 8, 44, 197, 144, 78, 162, 160, 190, 107, 3, 11, 155, 170, 235, 176, 153, 163, 229,
            170, 20, 212, 132, 179, 135, 202, 132, 79, 130, 157, 54, 3,
        ];

        let secret_key = Scalar::from_bytes_mod_order(bob_scalar);
        let public_key = StellarPublicKey::from_secret_key(&secret_key);
        dbg!(&public_key.to_string());
        assert_eq!(public_key.to_string(), ADDRESS_BOB);
    }

    #[test]
    fn test_public_key_from_str() {
        let pubkey_res = StellarPublicKey::from_str(ADDRESS_ALICE);
        assert!(pubkey_res.is_ok());

        let pubkey = pubkey_res.unwrap();
        assert_eq!(
            pubkey.0.as_bytes(),
            &[
                195, 249, 110, 99, 74, 19, 35, 158, 57, 217, 90, 83, 72, 23, 63, 210, 219, 183,
                156, 125, 222, 247, 27, 200, 146, 34, 199, 177, 165, 201, 195, 45
            ],
        );

        assert_eq!(pubkey.to_string(), ADDRESS_ALICE);
    }
}
