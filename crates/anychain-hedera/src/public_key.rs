use {
    crate::{address::HederaAddress, format::HederaFormat},
    anychain_core::{AddressError, PublicKey, PublicKeyError},
    core::{fmt, str::FromStr},
    k256::ecdsa::{SigningKey, VerifyingKey},
    // k256::pkcs8,
    // k256::pkcs8::der::{asn1::BitStringRef, oid::ObjectIdentifier, Encode},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HederaPublicKey(VerifyingKey);

impl PublicKey for HederaPublicKey {
    type SecretKey = SigningKey;
    type Address = HederaAddress;
    type Format = HederaFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        HederaPublicKey(*secret_key.verifying_key())
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        Ok(HederaAddress(self.to_string()))
    }
}

// Hedera SDK exposes a compact DER wrapper around a compressed SEC1 public key.
// This is not RFC5480 SPKI, so k256::pkcs8::DecodePublicKey cannot parse it directly.
// fn sec1_from_hedera_der(der: &[u8]) -> Result<&[u8], String> {
//     const HEDERA_DER_PREFIX: &[u8] = &[
//         0x30, 0x2d, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x22, 0x00,
//     ];
//     const COMPRESSED_SEC1_LEN: usize = 33;
//
//     if der.len() != HEDERA_DER_PREFIX.len() + COMPRESSED_SEC1_LEN {
//         return Err(format!("unexpected DER length: {}", der.len()));
//     }
//     if !der.starts_with(HEDERA_DER_PREFIX) {
//         return Err("unexpected DER prefix".to_string());
//     }
//
//     Ok(&der[HEDERA_DER_PREFIX.len()..])
// }

impl FromStr for HederaPublicKey {
    type Err = PublicKeyError;

    // fn from_str_der(s: &str) -> Result<Self, Self::Err> {
    //     let der_bytes =
    //         hex::decode(s).map_err(|error| PublicKeyError::Crate("hex", format!("{error:?}")))?;
    //     let sec1_from_der = sec1_from_hedera_der(&der_bytes).map_err(|error| {
    //         PublicKeyError::Crate(
    //             "DER should contain compressed SEC1 payload",
    //             format!("{error:?}"),
    //         )
    //     })?;
    //     //                .expect("");
    //     let vk_from_der = VerifyingKey::from_sec1_bytes(sec1_from_der)
    //         .map_err(|error| PublicKeyError::Crate("DER", format!("{error:?}")))?;
    //
    //     Ok(HederaPublicKey(vk_from_der))
    // }
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw_bytes =
            hex::decode(s).map_err(|error| PublicKeyError::Crate("hex", format!("{error:?}")))?;

        let raw_bytes_len = raw_bytes.len();
        if raw_bytes_len != 33 && raw_bytes_len != 65 {
            return Err(PublicKeyError::InvalidByteLength(raw_bytes_len));
        }

        let public_key = VerifyingKey::from_sec1_bytes(&raw_bytes)
            .map_err(|error| PublicKeyError::Crate("VerifyingKey", format!("{error:?}")))?;
        Ok(HederaPublicKey(public_key))
    }
}

impl fmt::Display for HederaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // public_key.to_string_raw
        let buf = self.0.to_encoded_point(true).to_bytes().into_vec();
        write!(f, "{}", hex::encode(&buf))

        // public_key.to_string_der
        // let mut buf = Vec::with_capacity(64);
        // {
        //     let key = self.0.to_encoded_point(true);
        //     let info = pkcs8::SubjectPublicKeyInfoRef {
        //         algorithm: pkcs8::AlgorithmIdentifierRef {
        //             parameters: None,
        //             oid: ObjectIdentifier::new_unwrap("1.3.132.0.10"),
        //         },
        //         subject_public_key: BitStringRef::from_bytes(key.as_bytes()).unwrap(),
        //     };
        //
        //     info.encode_to_vec(&mut buf).unwrap();
        // }
        //
        // write!(f, "{}", hex::encode(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // const DER_HEX_ALICE: &str = "302d300706052b8104000a0322000242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768" ;
    // const DER_HEX_BOB: &str = "302d300706052b8104000a03220003d638f8acfffc03fb05c1958afaf5431bd79bb2fe569121217478cfdc850ad089" ;
    const RAW_HEX_ALICE: &str =
        "0242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768";
    const RAW_HEX_BOB: &str = "03d638f8acfffc03fb05c1958afaf5431bd79bb2fe569121217478cfdc850ad089";
    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    fn assert_public_key_from_str_roundtrip(raw_hex: &str) {
        let public_key = HederaPublicKey::from_str(raw_hex).expect("public key should parse");
        assert_eq!(public_key.to_string(), raw_hex);
    }

    fn assert_public_key_to_address(raw_hex: &str) {
        let public_key = HederaPublicKey::from_str(raw_hex).expect("public key should parse");
        let address = public_key
            .to_address(&HederaFormat::Standard)
            .expect("address conversion should succeed");
        assert_eq!(address.to_string(), raw_hex);
    }

    fn assert_public_key_from_secret_key(private_hex: &str, expected_public_key_hex: &str) {
        let private_key_bytes = hex::decode(private_hex).expect("private key hex should decode");
        dbg!(&private_key_bytes);
        let signing_key =
            SigningKey::from_slice(&private_key_bytes).expect("private key should be valid");

        let public_key = HederaPublicKey::from_secret_key(&signing_key);
        assert_eq!(public_key.to_string(), expected_public_key_hex);
    }

    #[test]
    fn test_public_key_from_str() {
        assert_public_key_from_str_roundtrip(RAW_HEX_ALICE);
        assert_public_key_from_str_roundtrip(RAW_HEX_BOB);
    }

    #[test]
    fn test_public_key_to_address() {
        assert_public_key_to_address(RAW_HEX_ALICE);
        assert_public_key_to_address(RAW_HEX_BOB);
    }

    #[test]
    fn test_public_key_from_secret_key() {
        assert_public_key_from_secret_key(PRIVATE_HEX_ALICE, RAW_HEX_ALICE);
        assert_public_key_from_secret_key(PRIVATE_HEX_BOB, RAW_HEX_BOB);
    }
}
