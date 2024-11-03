use crate::address::ADDRESS_ENCODER as BASE32_ENCODER;
use crate::address::{FilecoinAddress, Protocol};
use crate::amount::FilecoinAmount;
use crate::format::FilecoinFormat;
use crate::public_key::FilecoinPublicKey;
use crate::utilities::crypto::blake2b_256;
use anychain_core::{Transaction, TransactionError, TransactionId};

use anyhow::anyhow;
use fvm_ipld_encoding::de::{Deserialize, Deserializer};
use fvm_ipld_encoding::ser::{Serialize, Serializer};
pub use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::{de, ser, serde_bytes, Cbor};

use forest_encoding::tuple::*;
use fvm_ipld_encoding::repr::*;
use fvm_shared::bigint::bigint_ser::{BigIntDe, BigIntSer};
use fvm_shared::MethodNum;
use num_derive::FromPrimitive;

use core::panic;
use std::borrow::Cow;
use std::fmt::{self, Display};
use std::str::FromStr;

use self::json::FilecoinTransactionJson;

/// Represents the parameters for a filecoin transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FilecoinTransactionParameters {
    pub version: i64,
    pub from: FilecoinAddress,
    pub to: FilecoinAddress,
    pub sequence: u64,
    pub value: FilecoinAmount,
    pub method_num: MethodNum,
    pub params: RawBytes,
    pub gas_limit: i64,
    pub gas_fee_cap: FilecoinAmount,
    pub gas_premium: FilecoinAmount,
}

impl Cbor for FilecoinTransactionParameters {}

impl FilecoinTransactionParameters {
    /// Helper function to convert the message into signing bytes.
    /// This function returns the message `Cid` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Safe to unwrap here, unsigned message cannot fail to serialize.
        self.cid().unwrap().to_bytes()
    }

    /// Does some basic checks on the Message to see if the fields are valid.
    pub fn check(self: &FilecoinTransactionParameters) -> anyhow::Result<()> {
        if self.gas_limit == 0 {
            return Err(anyhow!("Message has no gas limit set"));
        }
        if self.gas_limit < 0 {
            return Err(anyhow!("Message has negative gas limit"));
        }
        Ok(())
    }
}

impl Serialize for FilecoinTransactionParameters {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            &self.version,
            &self.to,
            &self.from,
            &self.sequence,
            BigIntSer(&self.value),
            &self.gas_limit,
            BigIntSer(&self.gas_fee_cap),
            BigIntSer(&self.gas_premium),
            &self.method_num,
            &self.params,
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for FilecoinTransactionParameters {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (
            version,
            to,
            from,
            sequence,
            BigIntDe(value),
            gas_limit,
            BigIntDe(gas_fee_cap),
            BigIntDe(gas_premium),
            method_num,
            params,
        ) = Deserialize::deserialize(deserializer)?;
        Ok(Self {
            version,
            from,
            to,
            sequence,
            value,
            method_num,
            params,
            gas_limit,
            gas_fee_cap,
            gas_premium,
        })
    }
}

/// Signature variants for Filecoin signatures.
#[derive(
    Clone,
    Debug,
    PartialEq,
    FromPrimitive,
    Copy,
    Eq,
    Serialize_repr,
    Deserialize_repr,
    Hash,
    Default,
)]
#[repr(u8)]
pub enum FilecoinSignatureType {
    #[default]
    Secp256k1 = 1,
    BLS = 2,
}

/// A cryptographic signature, represented in bytes, of any key protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct FilecoinSignature {
    pub sig_type: FilecoinSignatureType,
    pub bytes: Vec<u8>,
}

impl Cbor for FilecoinSignature {}

impl ser::Serialize for FilecoinSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut bytes = Vec::with_capacity(self.bytes.len() + 1);
        // Insert signature type byte
        bytes.push(self.sig_type as u8);
        bytes.extend_from_slice(&self.bytes);

        serde_bytes::Serialize::serialize(&bytes, serializer)
    }
}

impl<'de> de::Deserialize<'de> for FilecoinSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: Cow<'de, [u8]> = serde_bytes::Deserialize::deserialize(deserializer)?;
        if bytes.is_empty() {
            return Err(de::Error::custom("Cannot deserialize empty bytes"));
        }

        // Remove signature type byte
        let mut sig_type = FilecoinSignatureType::Secp256k1;
        let b = bytes[0];
        if b == 1 {
        } else if b == 2 {
            sig_type = FilecoinSignatureType::BLS;
        } else {
            panic!("Invalid signature type byte (must be 1 or 2)")
        }

        Ok(FilecoinSignature {
            bytes: bytes[1..].to_vec(),
            sig_type,
        })
    }
}

/// Represents a filecoin transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FilecoinTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for FilecoinTransactionId {}

impl fmt::Display for FilecoinTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &BASE32_ENCODER.encode(&self.txid[..]))
    }
}

/// Represents a wrapped filecoin transaction with signature bytes.
#[derive(PartialEq, Clone, Debug, Serialize_tuple, Deserialize_tuple, Hash, Eq, Default)]
pub struct FilecoinTransaction {
    pub params: FilecoinTransactionParameters,
    pub signature: FilecoinSignature,
}

impl Cbor for FilecoinTransaction {}

impl Transaction for FilecoinTransaction {
    type Address = FilecoinAddress;
    type Format = FilecoinFormat;
    type PublicKey = FilecoinPublicKey;
    type TransactionId = FilecoinTransactionId;
    type TransactionParameters = FilecoinTransactionParameters;

    /// Returns a new filecoin transaction given the transaction parameters
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            params: parameters.clone(),
            signature: FilecoinSignature::default(),
        })
    }

    /// Reconstruct a filecoin transaction from the given binary stream and return it
    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        Ok(serde_json::from_slice::<FilecoinTransactionJson>(transaction)?.0)
    }

    /// Insert the given signature into this filecoin transaction to make it signed,
    /// and return the binary stream of it
    fn sign(&mut self, mut signature: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        signature.push(recid);
        let sig = FilecoinSignature {
            sig_type: match self.params.from.protocol() {
                Protocol::Secp256k1 => FilecoinSignatureType::Secp256k1,
                Protocol::BLS => FilecoinSignatureType::BLS,
                _ => panic!("Unrecognized signature type"),
            },
            bytes: signature,
        };
        self.signature = sig;
        self.to_bytes()
    }

    /// Returns the binary stream of this filecoin transaction
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(
            serde_json::to_string(&json::FilecoinTransactionJsonRef(self))?
                .as_bytes()
                .to_vec(),
        )
    }

    /// Returns the transaction id of this filecoin transaction
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let stream = self.to_bytes().unwrap();
        Ok(FilecoinTransactionId {
            txid: blake2b_256(&stream).to_vec(),
        })
    }
}

impl FilecoinTransaction {
    pub fn digest(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(blake2b_256(&self.params.to_bytes()).to_vec())
    }
}

impl FromStr for FilecoinTransaction {
    type Err = TransactionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str::<FilecoinTransactionJson>(s)?.0)
    }
}

impl Display for FilecoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(self.to_bytes().unwrap()).unwrap()
        )
    }
}

pub mod json {
    use super::*;
    use cid::Cid;
    use serde::{ser, Deserialize, Deserializer, Serialize, Serializer};

    /// Wrapper for serializing and de-serializing a `FilecoinTransaction` from JSON.
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct FilecoinTransactionJson(#[serde(with = "self")] pub FilecoinTransaction);

    /// Wrapper for serializing a `FilecoinTransaction` reference to JSON.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub struct FilecoinTransactionJsonRef<'a>(#[serde(with = "self")] pub &'a FilecoinTransaction);

    impl From<FilecoinTransactionJson> for FilecoinTransaction {
        fn from(wrapper: FilecoinTransactionJson) -> Self {
            wrapper.0
        }
    }

    impl From<FilecoinTransaction> for FilecoinTransactionJson {
        fn from(tx: FilecoinTransaction) -> Self {
            FilecoinTransactionJson(tx)
        }
    }

    pub fn serialize<S>(tx: &FilecoinTransaction, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct FilecoinTransactionSer<'a> {
            #[serde(with = "parameter_json")]
            message: &'a FilecoinTransactionParameters,
            #[serde(with = "signature_json")]
            signature: &'a FilecoinSignature,
            #[serde(default, rename = "CID", with = "cid_json::opt")]
            cid: Option<Cid>,
        }
        FilecoinTransactionSer {
            message: &tx.params,
            signature: &tx.signature,
            cid: Some(tx.cid().map_err(ser::Error::custom)?),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinTransaction, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct FilecoinTransactionDe {
            #[serde(with = "parameter_json")]
            message: FilecoinTransactionParameters,
            #[serde(with = "signature_json")]
            signature: FilecoinSignature,
        }
        let FilecoinTransactionDe { message, signature } = Deserialize::deserialize(deserializer)?;
        Ok(FilecoinTransaction {
            params: message,
            signature,
        })
    }
}

pub mod parameter_json {

    use super::address_json::AddressJson;
    use super::amount_json;
    use super::cid_json;
    use super::Cbor;
    use super::FilecoinAmount;
    use super::FilecoinTransactionParameters;
    use super::RawBytes;
    use base64::{engine::general_purpose, Engine as _};
    use cid::Cid;
    use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

    /// Wrapper for serializing and de-serializing a Message from JSON.
    #[derive(Deserialize, Serialize, Debug)]
    #[serde(transparent)]
    pub struct ParameterJson(#[serde(with = "self")] pub FilecoinTransactionParameters);

    /// Wrapper for serializing a Message reference to JSON.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub struct ParameterJsonRef<'a>(#[serde(with = "self")] pub &'a FilecoinTransactionParameters);

    impl From<ParameterJson> for FilecoinTransactionParameters {
        fn from(wrapper: ParameterJson) -> Self {
            wrapper.0
        }
    }

    impl From<FilecoinTransactionParameters> for ParameterJson {
        fn from(wrapper: FilecoinTransactionParameters) -> Self {
            ParameterJson(wrapper)
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct JsonHelper {
        version: i64,
        to: AddressJson,
        from: AddressJson,
        #[serde(rename = "Nonce")]
        sequence: u64,
        #[serde(with = "amount_json")]
        value: FilecoinAmount,
        gas_limit: i64,
        #[serde(with = "amount_json")]
        gas_fee_cap: FilecoinAmount,
        #[serde(with = "amount_json")]
        gas_premium: FilecoinAmount,
        #[serde(rename = "Method")]
        method_num: u64,
        params: Option<String>,
        #[serde(default, rename = "CID", with = "cid_json::opt")]
        cid: Option<Cid>,
    }

    pub fn serialize<S>(
        params: &FilecoinTransactionParameters,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        JsonHelper {
            version: params.version,
            to: params.to.into(),
            from: params.from.into(),
            sequence: params.sequence,
            value: params.value.clone(),
            gas_limit: params.gas_limit,
            gas_fee_cap: params.gas_fee_cap.clone(),
            gas_premium: params.gas_premium.clone(),
            method_num: params.method_num,
            params: Some(general_purpose::STANDARD.encode(params.params.bytes())),
            cid: Some(params.cid().map_err(ser::Error::custom)?),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinTransactionParameters, D::Error>
    where
        D: Deserializer<'de>,
    {
        let m: JsonHelper = Deserialize::deserialize(deserializer)?;
        Ok(FilecoinTransactionParameters {
            version: m.version,
            to: m.to.into(),
            from: m.from.into(),
            sequence: m.sequence,
            value: m.value,
            gas_limit: m.gas_limit,
            gas_fee_cap: m.gas_fee_cap,
            gas_premium: m.gas_premium,
            method_num: m.method_num,
            params: RawBytes::new(
                general_purpose::STANDARD
                    .decode(m.params.unwrap_or_default())
                    .map_err(de::Error::custom)?,
            ),
        })
    }
}

pub mod signature_json {
    use super::{FilecoinSignature, FilecoinSignatureType};
    use base64::{engine::general_purpose, Engine as _};
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    // Wrapper for serializing and deserializing a Signature from JSON.
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct SignatureJson(#[serde(with = "self")] pub FilecoinSignature);

    /// Wrapper for serializing a Signature reference to JSON.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub struct SignatureJsonRef<'a>(#[serde(with = "self")] pub &'a FilecoinSignature);

    #[derive(Serialize, Deserialize)]
    struct JsonHelper {
        #[serde(rename = "Type")]
        sig_type: FilecoinSignatureType,
        #[serde(rename = "Data")]
        bytes: String,
    }

    pub fn serialize<S>(sig: &FilecoinSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        JsonHelper {
            sig_type: sig.sig_type,
            bytes: general_purpose::STANDARD.encode(&sig.bytes),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let JsonHelper { sig_type, bytes } = Deserialize::deserialize(deserializer)?;
        Ok(FilecoinSignature {
            sig_type,
            bytes: general_purpose::STANDARD
                .decode(bytes)
                .map_err(de::Error::custom)?,
        })
    }

    pub mod signature_type {
        use super::*;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(rename_all = "lowercase")]
        enum JsonHelperEnum {
            Bls,
            Secp256k1,
        }

        #[derive(Debug, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct SignatureTypeJson(#[serde(with = "self")] pub FilecoinSignatureType);

        pub fn serialize<S>(
            sig_type: &FilecoinSignatureType,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let json = match sig_type {
                FilecoinSignatureType::BLS => JsonHelperEnum::Bls,
                FilecoinSignatureType::Secp256k1 => JsonHelperEnum::Secp256k1,
            };
            json.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinSignatureType, D::Error>
        where
            D: Deserializer<'de>,
        {
            let json_enum: JsonHelperEnum = Deserialize::deserialize(deserializer)?;

            let signature_type = match json_enum {
                JsonHelperEnum::Bls => FilecoinSignatureType::BLS,
                JsonHelperEnum::Secp256k1 => FilecoinSignatureType::Secp256k1,
            };
            Ok(signature_type)
        }
    }
}

pub mod cid_json {
    use cid::Cid;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    /// Wrapper for serializing and de-serializing a Cid from JSON.
    #[derive(Deserialize, Serialize, Clone, Debug)]
    #[serde(transparent)]
    pub struct CidJson(#[serde(with = "self")] pub Cid);

    /// Wrapper for serializing a CID reference to JSON.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub struct CidJsonRef<'a>(#[serde(with = "self")] pub &'a Cid);

    impl From<CidJson> for Cid {
        fn from(wrapper: CidJson) -> Self {
            wrapper.0
        }
    }

    pub fn serialize<S>(c: &Cid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CidMap { cid: c.to_string() }.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CidMap { cid } = Deserialize::deserialize(deserializer)?;
        cid.parse().map_err(de::Error::custom)
    }

    /// Structure just used as a helper to serialize a CID into a map with key "/"
    #[derive(Serialize, Deserialize)]
    struct CidMap {
        #[serde(rename = "/")]
        cid: String,
    }

    pub mod opt {
        use super::{Cid, CidJson, CidJsonRef};
        use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S>(v: &Option<Cid>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            v.as_ref().map(CidJsonRef).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Cid>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s: Option<CidJson> = Deserialize::deserialize(deserializer)?;
            Ok(s.map(|v| v.0))
        }
    }
}

pub mod address_json {
    use super::FilecoinAddress;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;
    use std::str::FromStr;

    /// Wrapper for serializing and de-serializing a `FilecoinAddress` from JSON.
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AddressJson(#[serde(with = "self")] pub FilecoinAddress);

    /// Wrapper for serializing a `FilecoinAddress` reference to JSON.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub struct AddressJsonRef<'a>(#[serde(with = "self")] pub &'a FilecoinAddress);

    impl From<FilecoinAddress> for AddressJson {
        fn from(addr: FilecoinAddress) -> Self {
            Self(addr)
        }
    }

    impl From<AddressJson> for FilecoinAddress {
        fn from(addr: AddressJson) -> Self {
            addr.0
        }
    }

    pub fn serialize<S>(addr: &FilecoinAddress, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        let address_as_string: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
        FilecoinAddress::from_str(&address_as_string).map_err(de::Error::custom)
    }
}

pub mod amount_json {
    use super::FilecoinAmount;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    /// Serializes `FilecoinAmount` as String
    pub fn serialize<S>(amount: &FilecoinAmount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::serialize(&amount.to_string(), serializer)
    }

    /// De-serializes String into `BigInt`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<FilecoinAmount, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FilecoinAmount::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anychain_core::Transaction;
    use fvm_ipld_encoding::RawBytes;

    use crate::{
        FilecoinAddress, FilecoinAmount, FilecoinAmountConverter, FilecoinTransaction,
        FilecoinTransactionParameters,
    };

    #[test]
    fn filecoin_transaction_serialization_test() {
        let params = FilecoinTransactionParameters {
            version: 0,
            from: FilecoinAddress::from_str("f1lhjzzj6on64czzsgfw5jxsf7y5uv5qvh7dmpevy").unwrap(),
            to: FilecoinAddress::from_str("t1meiag3eum5xtxi5tivnw4fjhkrdtaqu4v5t4nly").unwrap(),
            sequence: 999,
            value: FilecoinAmount::from_fil("1"),
            method_num: 0,
            params: RawBytes::new(vec![]),
            gas_limit: 500000,
            gas_fee_cap: FilecoinAmount::from_milli_fil("1"),
            gas_premium: FilecoinAmount::from_milli_fil("100"),
        };

        let tx = FilecoinTransaction::new(&params).unwrap();

        println!("tx = {}", tx);
    }

    #[test]
    fn filecoin_transaction_deserialization_test() {
        let s = r#"{"Message":{"Version":0,"To":"t1meiag3eum5xtxi5tivnw4fjhkrdtaqu4v5t4nly","From":"f1lhjzzj6on64czzsgfw5jxsf7y5uv5qvh7dmpevy","Nonce":999,"Value":"1000000000000000000","GasLimit":500000,"GasFeeCap":"1000000000000000","GasPremium":"100000000000000000","Method":0,"Params":"","CID":{"/":"bafy2bzacea2dufcc2vhvrt3pzn24t2zmuhnbdmf5kgch6blkxsppukc4rp6bu"}},"Signature":{"Type":1,"Data":""},"CID":{"/":"bafy2bzacebx42rzvvl3v6mio44ileyxwohj2d2i34otmk7wwqsd4rdl4b3bhq"}}"#;
        let tx = FilecoinTransaction::from_bytes(s.as_bytes()).unwrap();

        println!("tx = {}", tx);
    }
}
