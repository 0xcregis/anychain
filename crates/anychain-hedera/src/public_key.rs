use {
    crate::{address::HederaAddress, format::HederaFormat},
    anychain_core::{AddressError, PublicKey, PublicKeyError},
    core::{fmt, str::FromStr},
    ed25519_dalek::{SigningKey, VerifyingKey},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HederaPublicKey(pub VerifyingKey);

impl PublicKey for HederaPublicKey {
    type SecretKey = SigningKey;
    type Address = HederaAddress;
    type Format = HederaFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        HederaPublicKey(secret_key.verifying_key())
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        Ok(HederaAddress(self.to_string()))
    }
}

impl FromStr for HederaPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw_bytes =
            hex::decode(s).map_err(|error| PublicKeyError::Crate("hex", format!("{error:?}")))?;

        let raw_bytes_len = raw_bytes.len();
        if raw_bytes_len != 32 {
            return Err(PublicKeyError::InvalidByteLength(raw_bytes_len));
        }

        let bytes_array: [u8; 32] = raw_bytes
            .try_into()
            .map_err(|_| PublicKeyError::Crate("slice", "invalid slice length".to_string()))?;

        let public_key = VerifyingKey::from_bytes(&bytes_array)
            .map_err(|error| PublicKeyError::Crate("VerifyingKey", format!("{error:?}")))?;
        Ok(HederaPublicKey(public_key))
    }
}

impl fmt::Display for HederaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = self.0.to_bytes();
        write!(f, "{}", hex::encode(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    // We will generate the correct public hex keys from the private keys
    #[test]
    fn print_derived_public_keys() {
        let alice_bytes = hex::decode(PRIVATE_HEX_ALICE).unwrap();
        let alice_arr: [u8; 32] = alice_bytes.try_into().unwrap();
        let alice_sk = SigningKey::from_bytes(&alice_arr);
        let alice_pk = HederaPublicKey::from_secret_key(&alice_sk);
        println!("ALICE PUBLIC KEY: {}", alice_pk);

        let bob_bytes = hex::decode(PRIVATE_HEX_BOB).unwrap();
        let bob_arr: [u8; 32] = bob_bytes.try_into().unwrap();
        let bob_sk = SigningKey::from_bytes(&bob_arr);
        let bob_pk = HederaPublicKey::from_secret_key(&bob_sk);
        println!("BOB PUBLIC KEY: {}", bob_pk);
    }
}
