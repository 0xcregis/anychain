use {
    crate::{format::HederaFormat, protobuf, public_key::HederaPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    data_encoding::BASE32_NOPAD,
    ed25519_dalek::{SigningKey, VerifyingKey},
    hiero_sdk::{AccountId as HieroAccountId, PublicKey as HieroPublicKey},
    prost::Message,
};

/// Represents a Hedera address (either `<shard>.<realm>.<num>` or HIP-32 `<shard>.<realm>.<base32>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HederaAddress(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedHederaAccount {
    Numeric {
        shard: u64,
        realm: u64,
        num: u64,
    },
    Hip32Alias {
        shard: u64,
        realm: u64,
        public_key: Box<HieroPublicKey>,
        canonical: String,
    },
}

impl ParsedHederaAccount {
    pub(crate) fn to_canonical_string(&self) -> String {
        match self {
            Self::Numeric { shard, realm, num } => format!("{}.{}.{}", shard, realm, num),
            Self::Hip32Alias { canonical, .. } => canonical.clone(),
        }
    }

    pub(crate) fn to_hiero_account_id(&self) -> HieroAccountId {
        match self {
            Self::Numeric { shard, realm, num } => HieroAccountId::new(*shard, *realm, *num),
            Self::Hip32Alias {
                shard,
                realm,
                public_key,
                ..
            } => public_key.to_account_id(*shard, *realm),
        }
    }
}

/// Encode a 32-byte Ed25519 public key into a HIP-32 long-form account ID:
/// `<shard>.<realm>.<base32_nopad(protobuf(Key { ed25519 }))>`.
pub(crate) fn encode_ed25519_hip32(shard: u64, realm: u64, pubkey: &[u8; 32]) -> String {
    let proto_key = protobuf::Key {
        key: Some(protobuf::key::Key::Ed25519(pubkey.to_vec())),
    };
    let alias = BASE32_NOPAD.encode(&proto_key.encode_to_vec());
    format!("{}.{}.{}", shard, realm, alias)
}

/// Validate canonical serialized HAPI primitive `Key` bytes for a HIP-32 alias.
/// Supports Ed25519 (32 bytes) and compressed ECDSA secp256k1 (33 bytes) primitive keys.
pub(crate) fn parse_hip32_key_bytes(alias_bytes: &[u8]) -> Result<HieroPublicKey, AddressError> {
    let proto_key = protobuf::Key::decode(alias_bytes)
        .map_err(|e| AddressError::Crate("prost", format!("{e:?}")))?;

    // Reject unknown fields, trailing bytes, or non-canonical protobuf wire encodings.
    if proto_key.encode_to_vec() != alias_bytes {
        return Err(AddressError::InvalidAddress(
            "non-canonical protobuf Key in HIP-32 alias".to_string(),
        ));
    }

    match proto_key.key {
        Some(protobuf::key::Key::Ed25519(pk_bytes)) => {
            if pk_bytes.len() != 32 {
                return Err(AddressError::InvalidByteLength(pk_bytes.len()));
            }
            let arr: [u8; 32] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| AddressError::InvalidByteLength(pk_bytes.len()))?;
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| AddressError::Crate("ed25519_dalek", format!("{e:?}")))?;
            HieroPublicKey::from_bytes_ed25519(&pk_bytes)
                .map_err(|e| AddressError::Crate("hiero_sdk", format!("{e:?}")))
        }
        Some(protobuf::key::Key::EcdsaSecp256k1(pk_bytes)) => {
            if pk_bytes.len() != 33 {
                return Err(AddressError::InvalidByteLength(pk_bytes.len()));
            }
            HieroPublicKey::from_bytes_ecdsa(&pk_bytes)
                .map_err(|e| AddressError::Crate("hiero_sdk", format!("{e:?}")))
        }
        None => Err(AddressError::InvalidAddress(
            "empty protobuf Key in HIP-32 alias".to_string(),
        )),
    }
}

/// Validate canonical HIP-32 protobuf `Key` bytes and return their RFC 4648 base32 (no padding) encoding.
pub(crate) fn encode_hip32_alias_bytes(alias_bytes: &[u8]) -> Result<String, AddressError> {
    parse_hip32_key_bytes(alias_bytes)?;
    Ok(BASE32_NOPAD.encode(alias_bytes))
}

fn parse_non_negative_id_part(part: &str) -> Result<u64, AddressError> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AddressError::InvalidAddress(part.to_string()));
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(AddressError::InvalidAddress(part.to_string()));
    }
    let value = part
        .parse::<u64>()
        .map_err(|_| AddressError::InvalidAddress(part.to_string()))?;
    if value > i64::MAX as u64 {
        return Err(AddressError::InvalidAddress(part.to_string()));
    }
    Ok(value)
}

pub(crate) fn parse_hedera_account(s: &str) -> Result<ParsedHederaAccount, AddressError> {
    let mut parts = s.split('.');
    let shard_str = parts
        .next()
        .ok_or_else(|| AddressError::InvalidAddress(s.to_string()))?;
    let realm_str = parts
        .next()
        .ok_or_else(|| AddressError::InvalidAddress(s.to_string()))?;
    let account_str = parts
        .next()
        .ok_or_else(|| AddressError::InvalidAddress(s.to_string()))?;
    if parts.next().is_some() {
        return Err(AddressError::InvalidAddress(s.to_string()));
    }

    let shard = parse_non_negative_id_part(shard_str)?;
    let realm = parse_non_negative_id_part(realm_str)?;

    if account_str.is_empty() {
        return Err(AddressError::InvalidAddress(s.to_string()));
    }

    if account_str.bytes().all(|b| b.is_ascii_digit()) {
        let num = parse_non_negative_id_part(account_str)?;
        return Ok(ParsedHederaAccount::Numeric { shard, realm, num });
    }

    // HIP-32 regex: \d+\.\d+\.[2-7A-Z]+
    if !account_str
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
    {
        return Err(AddressError::InvalidAddress(s.to_string()));
    }

    let alias_bytes = BASE32_NOPAD
        .decode(account_str.as_bytes())
        .map_err(|e| AddressError::Crate("data_encoding", format!("{e:?}")))?;

    let public_key = parse_hip32_key_bytes(&alias_bytes)?;

    Ok(ParsedHederaAccount::Hip32Alias {
        shard,
        realm,
        public_key: Box::new(public_key),
        canonical: format!("{}.{}.{}", shard, realm, account_str),
    })
}

impl HederaAddress {
    /// Convert this address into a `hiero_sdk::AccountId` (numeric or HIP-32 alias).
    pub fn to_account_id(&self) -> Result<HieroAccountId, AddressError> {
        Ok(parse_hedera_account(&self.0)?.to_hiero_account_id())
    }

    /// Returns `true` if this address is a HIP-32 long-form alias account ID.
    pub fn is_alias(&self) -> bool {
        matches!(
            parse_hedera_account(&self.0),
            Ok(ParsedHederaAccount::Hip32Alias { .. })
        )
    }
}

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
        let parsed = parse_hedera_account(addr)?;
        Ok(HederaAddress(parsed.to_canonical_string()))
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
    use hiero_sdk::PrivateKey;

    const PRIVATE_HEX_ALICE: &str =
        "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
    const PRIVATE_HEX_BOB: &str =
        "ceb3a264b2a2c1516ecc8d87c183c6bb0ae0a2fb89993e1f7ffbda188e15236a";

    // Official HIP-32 specification example vector
    const HIP32_SPEC_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const HIP32_SPEC_ADDRESS: &str = "0.0.CIQNOWUYAGBLCCVX2VF75U6JMQDTUDXBOLZ5VJRDEWXQEGTI64DVCGQ";

    // Live Hedera Testnet account 0.0.9549757 (Ed25519 alias verified on Mirror Node)
    const TESTNET_BOB_PUBKEY_HEX: &str =
        "a3178efa027cb60f4d8b1ffb53872d24d05ce97cec3511dae909b66112a9c3d7";
    const TESTNET_BOB_HIP32_ADDRESS: &str =
        "0.0.CIQKGF4O7IBHZNQPJWFR762TQ4WSJUC45F6OYNIR3LUQTNTBCKU4HVY";

    fn signing_key_from_hex(private_hex: &str) -> SigningKey {
        let private_key_bytes = hex::decode(private_hex).expect("private key hex should decode");
        let private_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        SigningKey::from_bytes(&private_arr)
    }

    #[test]
    fn test_hip32_spec_vector() {
        let pk = HederaPublicKey::from_str(HIP32_SPEC_PUBKEY_HEX).unwrap();
        let addr = HederaAddress::from_public_key(&pk, &HederaFormat::Standard).unwrap();
        assert_eq!(addr.to_string(), HIP32_SPEC_ADDRESS);
        assert!(addr.is_alias());
        assert!(HederaAddress::is_valid(HIP32_SPEC_ADDRESS));

        let parsed = HederaAddress::from_str(HIP32_SPEC_ADDRESS).unwrap();
        assert_eq!(parsed, addr);

        let account_id = parsed.to_account_id().unwrap();
        assert_eq!(account_id.shard, 0);
        assert_eq!(account_id.realm, 0);
        assert_eq!(account_id.num, 0);
        assert_eq!(
            account_id.alias.unwrap().to_bytes_raw(),
            hex::decode(HIP32_SPEC_PUBKEY_HEX).unwrap()
        );
    }

    #[test]
    fn test_testnet_bob_hip32_vector() {
        let pk = HederaPublicKey::from_str(TESTNET_BOB_PUBKEY_HEX).unwrap();
        let addr = HederaAddress::from_public_key(&pk, &HederaFormat::Standard).unwrap();
        assert_eq!(addr.to_string(), TESTNET_BOB_HIP32_ADDRESS);
        assert!(HederaAddress::is_valid(TESTNET_BOB_HIP32_ADDRESS));
    }

    #[test]
    fn test_address_from_secret_key() {
        for private_hex in [PRIVATE_HEX_ALICE, PRIVATE_HEX_BOB] {
            let signing_key = signing_key_from_hex(private_hex);
            let address =
                HederaAddress::from_secret_key(&signing_key, &HederaFormat::Standard).unwrap();
            let public_key = HederaPublicKey::from_secret_key(&signing_key);

            assert!(address.to_string().starts_with("0.0.CIQ"));
            assert_eq!(address.to_string().len(), 4 + 55);
            assert!(address.is_alias());
            assert!(HederaAddress::is_valid(&address.to_string()));
            assert_ne!(address.to_string(), public_key.to_string());
        }
    }

    #[test]
    fn test_address_from_secret_key_matches_from_public_key() {
        for private_hex in [PRIVATE_HEX_ALICE, PRIVATE_HEX_BOB] {
            let signing_key = signing_key_from_hex(private_hex);
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
    }

    #[test]
    fn test_ecdsa_secp256k1_hip32_alias_parsing() {
        let sk = PrivateKey::from_str_ecdsa(PRIVATE_HEX_ALICE).unwrap();
        let compressed_pk = sk.public_key().to_bytes_raw();
        assert_eq!(compressed_pk.len(), 33);

        let proto_key = protobuf::Key {
            key: Some(protobuf::key::Key::EcdsaSecp256k1(compressed_pk.clone())),
        };
        let hip32 = format!("0.0.{}", BASE32_NOPAD.encode(&proto_key.encode_to_vec()));
        assert!(hip32.starts_with("0.0.HIQQ"));
        assert!(HederaAddress::is_valid(&hip32));

        let addr = HederaAddress::from_str(&hip32).unwrap();
        assert!(addr.is_alias());
        let account_id = addr.to_account_id().unwrap();
        assert_eq!(account_id.alias.unwrap().to_bytes_raw(), compressed_pk);
    }

    #[test]
    fn test_numeric_account_id_parsing() {
        for valid in ["0.0.3", "0.0.9549757", "0.0.0", "1.2.345"] {
            let addr = HederaAddress::from_str(valid).unwrap();
            assert_eq!(addr.to_string(), valid);
            assert!(!addr.is_alias());
            assert!(HederaAddress::is_valid(valid));
            let account_id = addr.to_account_id().unwrap();
            assert!(account_id.alias.is_none());
        }
    }

    #[test]
    fn test_invalid_addresses_rejected() {
        let signing_key = signing_key_from_hex(PRIVATE_HEX_ALICE);
        let public_key = HederaPublicKey::from_secret_key(&signing_key);

        // Pure hex ed25519 public key (legacy format) must be rejected
        assert!(!HederaAddress::is_valid(&public_key.to_string()));
        assert!(!HederaAddress::is_valid(&format!("0.0.{}", public_key)));

        // Non-HIP-32 formats
        assert!(!HederaAddress::is_valid(""));
        assert!(!HederaAddress::is_valid("invalid"));
        assert!(!HederaAddress::is_valid("12345"));
        assert!(!HederaAddress::is_valid("0.0."));
        assert!(!HederaAddress::is_valid("0.0.1.2"));
        assert!(!HederaAddress::is_valid("00.0.1"));
        assert!(!HederaAddress::is_valid("0.00.1"));
        assert!(!HederaAddress::is_valid("0.0.01"));
        assert!(!HederaAddress::is_valid("-1.0.1"));
        assert!(!HederaAddress::is_valid("0.0.-1"));
        assert!(!HederaAddress::is_valid("0.0.9223372036854775808"));
        assert!(!HederaAddress::is_valid(
            "0x302a300506032b6570032100114e6abc371b82da"
        ));
        assert!(!HederaAddress::is_valid(
            "0.0.302a300506032b6570032100114e6abc371b82dab5c15ea149f02d34a012087b163516dd70f44acafabf7777"
        ));

        // Lowercase base32 and padded base32 must be rejected
        assert!(!HederaAddress::is_valid(&HIP32_SPEC_ADDRESS.to_lowercase()));
        assert!(!HederaAddress::is_valid(&format!(
            "{}=",
            HIP32_SPEC_ADDRESS
        )));

        // Mutated trailing bits in last base32 char (non-zero padding bits)
        let mut bad_trailing = HIP32_SPEC_ADDRESS.to_string();
        bad_trailing.pop();
        bad_trailing.push('R');
        assert!(!HederaAddress::is_valid(&bad_trailing));

        // Protobuf Key with extra unknown trailing field must be rejected
        let mut extra_field = protobuf::Key {
            key: Some(protobuf::key::Key::Ed25519(
                hex::decode(HIP32_SPEC_PUBKEY_HEX).unwrap(),
            )),
        }
        .encode_to_vec();
        extra_field.extend_from_slice(&[0x50, 0x01]); // unknown field tag 10, varint 1
        let bad_proto_addr = format!("0.0.{}", BASE32_NOPAD.encode(&extra_field));
        assert!(!HederaAddress::is_valid(&bad_proto_addr));

        // Wrong Ed25519 key length wrapped in protobuf Key must be rejected
        let short_key = protobuf::Key {
            key: Some(protobuf::key::Key::Ed25519(vec![0u8; 31])),
        }
        .encode_to_vec();
        let short_key_addr = format!("0.0.{}", BASE32_NOPAD.encode(&short_key));
        assert!(!HederaAddress::is_valid(&short_key_addr));

        // Invalid curve point (non-decompressible compressed Edwards Y coordinate)
        // y = 2 is not a valid compressed Ed25519 point on Curve25519
        let mut non_curve_bytes = [0u8; 32];
        non_curve_bytes[0] = 2;
        assert!(VerifyingKey::from_bytes(&non_curve_bytes).is_err());
        let non_curve_addr = encode_ed25519_hip32(0, 0, &non_curve_bytes);
        assert!(!HederaAddress::is_valid(&non_curve_addr));

        // Invalid secp256k1 point (wrong prefix 0x04 in 33 bytes)
        let mut bad_secp = vec![0x04u8; 33];
        bad_secp[1] = 0x01;
        let bad_secp_proto = protobuf::Key {
            key: Some(protobuf::key::Key::EcdsaSecp256k1(bad_secp)),
        }
        .encode_to_vec();
        let bad_secp_addr = format!("0.0.{}", BASE32_NOPAD.encode(&bad_secp_proto));
        assert!(!HederaAddress::is_valid(&bad_secp_addr));
    }
}
