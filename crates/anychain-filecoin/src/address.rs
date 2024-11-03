use crate::format::FilecoinFormat;
use crate::public_key::FilecoinPublicKey;

use std::borrow::Cow;
use std::default::Default;
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

use crate::utilities::crypto::{blake2b_160, blake2b_checksum};
use anychain_core::PublicKey;
use anychain_core::{Address, AddressError};
use bls_signatures::Serialize as BlsSerialize;

use data_encoding::DecodeError;
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;
use fvm_ipld_encoding::{serde_bytes, Cbor};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Represents a filecoin address
#[derive(PartialEq, Eq, Clone, Debug, Hash, Copy, Default)]
#[cfg_attr(feature = "arb", derive(arbitrary::Arbitrary))]
pub struct FilecoinAddress {
    network: Network,
    payload: Payload,
}

impl Address for FilecoinAddress {
    type SecretKey = super::public_key::FilecoinSecretKey;
    type Format = FilecoinFormat;
    type PublicKey = FilecoinPublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_secret_key(
        secret_key: &Self::SecretKey,
        _format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::from_public_key(&FilecoinPublicKey::from_secret_key(secret_key), _format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        match public_key {
            FilecoinPublicKey::Secp256k1(key) => {
                Ok(FilecoinAddress::new_secp256k1(&key.serialize()).unwrap())
            }
            FilecoinPublicKey::Bls(key) => Ok(FilecoinAddress::new_bls(&key.as_bytes()).unwrap()),
        }
    }
}

impl Cbor for FilecoinAddress {}

impl FilecoinAddress {
    /// Address constructor
    fn new(network: Network, protocol: Protocol, bz: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            network,
            payload: Payload::new(protocol, bz)?,
        })
    }

    /// Creates address from encoded bytes
    pub fn from_bytes(bz: &[u8]) -> Result<Self, Error> {
        if bz.len() < 2 {
            Err(Error::InvalidLength)
        } else {
            let protocol = Protocol::from_byte(bz[0]).ok_or(Error::UnknownProtocol)?;
            Self::new(NETWORK_DEFAULT, protocol, &bz[1..])
        }
    }

    /// Generates new address using ID protocol
    pub const fn new_id(id: u64) -> Self {
        Self {
            network: NETWORK_DEFAULT,
            payload: Payload::ID(id),
        }
    }

    /// Generates new address using Secp256k1 pubkey
    pub fn new_secp256k1(pubkey: &[u8]) -> Result<Self, Error> {
        if pubkey.len() != 65 {
            return Err(Error::InvalidSECPLength(pubkey.len()));
        }
        Ok(Self {
            network: NETWORK_DEFAULT,
            payload: Payload::Secp256k1(blake2b_160(pubkey)),
        })
    }

    pub fn new_secp256k1_v2(
        network: Network,
        pubkey: libsecp256k1::PublicKey,
    ) -> Result<Self, Error> {
        Ok(Self {
            network,
            payload: Payload::Secp256k1(blake2b_160(&pubkey.serialize())),
        })
    }

    /// Generates new address using the Actor protocol
    pub fn new_actor(data: &[u8]) -> Self {
        Self {
            network: NETWORK_DEFAULT,
            payload: Payload::Actor(blake2b_160(data)),
        }
    }

    /// Generates new address using BLS pubkey
    pub fn new_bls(pubkey: &[u8]) -> Result<Self, Error> {
        if pubkey.len() != BLS_PUB_LEN {
            return Err(Error::InvalidBLSLength(pubkey.len()));
        }
        let mut key = [0u8; BLS_PUB_LEN];
        key.copy_from_slice(pubkey);
        Ok(Self {
            network: NETWORK_DEFAULT,
            payload: Payload::BLS(key),
        })
    }

    pub fn is_bls_zero_address(&self) -> bool {
        match self.payload {
            Payload::BLS(payload_bytes) => payload_bytes == *BLS_ZERO_ADDR_BYTES,
            _ => false,
        }
    }

    /// Returns protocol for Address
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.payload)
    }

    /// Returns the `Payload` object from the address, where the respective protocol data is kept
    /// in an enum separated by protocol
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Converts Address into `Payload` object, where the respective protocol data is kept
    /// in an enum separated by protocol
    pub fn into_payload(self) -> Payload {
        self.payload
    }

    /// Returns the raw bytes data payload of the Address
    pub fn payload_bytes(&self) -> Vec<u8> {
        self.payload.to_raw_bytes()
    }

    /// Returns network configuration of Address
    pub fn network(&self) -> Network {
        self.network
    }

    /// Sets the network for the address and returns a mutable reference to it
    pub fn set_network(&mut self, network: Network) -> &mut Self {
        self.network = network;
        self
    }

    /// Returns encoded bytes of Address
    pub fn to_bytes(self) -> Vec<u8> {
        self.payload.to_bytes()
    }

    /// Get ID of the address. ID protocol only.
    pub fn id(&self) -> Result<u64, Error> {
        match self.payload {
            Payload::ID(id) => Ok(id),
            _ => Err(Error::NonIDAddress),
        }
    }
}

impl fmt::Display for FilecoinAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encode(self))
    }
}

impl FromStr for FilecoinAddress {
    type Err = Error;
    fn from_str(addr: &str) -> Result<Self, Error> {
        if addr.len() > MAX_ADDRESS_LEN || addr.len() < 3 {
            return Err(Error::InvalidLength);
        }
        // ensure the network character is valid before converting
        let network: Network = match addr.get(0..1).ok_or(Error::UnknownNetwork)? {
            TESTNET_PREFIX => Network::Testnet,
            MAINNET_PREFIX => Network::Mainnet,
            _ => {
                return Err(Error::UnknownNetwork);
            }
        };

        // get protocol from second character
        let protocol: Protocol = match addr.get(1..2).ok_or(Error::UnknownProtocol)? {
            "0" => Protocol::ID,
            "1" => Protocol::Secp256k1,
            "2" => Protocol::Actor,
            "3" => Protocol::BLS,
            _ => {
                return Err(Error::UnknownProtocol);
            }
        };

        // bytes after the protocol character is the data payload of the address
        let raw = addr.get(2..).ok_or(Error::InvalidPayload)?;
        if protocol == Protocol::ID {
            if raw.len() > 20 {
                // 20 is max u64 as string
                return Err(Error::InvalidLength);
            }
            let id = raw.parse::<u64>().unwrap();
            return Ok(FilecoinAddress {
                network,
                payload: Payload::ID(id),
            });
        }

        // decode using byte32 encoding
        let mut payload = ADDRESS_ENCODER.decode(raw.as_bytes())?;
        // payload includes checksum at end, so split after decoding
        let cksm = payload.split_off(payload.len() - CHECKSUM_HASH_LEN);

        // sanity check to make sure address hash values are correct length
        if (protocol == Protocol::Secp256k1 || protocol == Protocol::Actor)
            && payload.len() != PAYLOAD_HASH_LEN
        {
            return Err(Error::InvalidPayload);
        }

        // sanity check to make sure bls pub key is correct length
        if protocol == Protocol::BLS && payload.len() != BLS_PUB_LEN {
            return Err(Error::InvalidPayload);
        }

        // validate checksum
        let mut ingest = payload.clone();
        ingest.insert(0, protocol as u8);
        if !validate_checksum(&ingest, cksm) {
            return Err(Error::InvalidChecksum);
        }

        FilecoinAddress::new(network, protocol, &payload)
    }
}

impl Serialize for FilecoinAddress {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let address_bytes = self.to_bytes();
        serde_bytes::Serialize::serialize(&address_bytes, s)
    }
}

impl<'de> Deserialize<'de> for FilecoinAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bz: Cow<'de, [u8]> = serde_bytes::Deserialize::deserialize(deserializer)?;

        // Create and return created address of unmarshalled bytes
        FilecoinAddress::from_bytes(&bz).map_err(de::Error::custom)
    }
}

/// encode converts the address into a string
fn encode(addr: &FilecoinAddress) -> String {
    match addr.protocol() {
        Protocol::Secp256k1 | Protocol::Actor | Protocol::BLS => {
            let ingest = addr.to_bytes();
            let mut bz = addr.payload_bytes();

            // payload bytes followed by calculated checksum
            bz.extend(blake2b_checksum(&ingest));
            format!(
                "{}{}{}",
                addr.network.to_prefix(),
                addr.protocol(),
                ADDRESS_ENCODER.encode(bz.as_mut()),
            )
        }
        Protocol::ID => format!(
            "{}{}{}",
            addr.network.to_prefix(),
            addr.protocol(),
            from_leb_bytes(&addr.payload_bytes()).expect("should read encoded bytes"),
        ),
    }
}

pub(crate) fn to_leb_bytes(id: u64) -> Result<Vec<u8>, Error> {
    // write id to buffer in leb128 format
    Ok(unsigned_varint::encode::u64(id, &mut unsigned_varint::encode::u64_buffer()).into())
}

pub(crate) fn from_leb_bytes(bz: &[u8]) -> Result<u64, Error> {
    // write id to buffer in leb128 format
    let (id, remaining) = unsigned_varint::decode::u64(bz).unwrap();
    if !remaining.is_empty() {
        return Err(Error::InvalidPayload);
    }
    Ok(id)
}

/// Validates the checksum against the ingest data
pub fn validate_checksum(ingest: &[u8], expect: Vec<u8>) -> bool {
    let digest = blake2b_checksum(ingest);
    digest == expect
}

/// Protocol defines the addressing protocol used to derive data to an address
#[derive(PartialEq, Eq, Copy, Clone, FromPrimitive, Debug, Hash)]
#[repr(u8)]
pub enum Protocol {
    /// ID protocol addressing
    ID = 0,
    /// SECP256K1 key addressing
    Secp256k1 = 1,
    /// Actor protocol addressing
    Actor = 2,
    /// BLS key addressing
    BLS = 3,
}

impl Protocol {
    /// from_byte allows referencing back to Protocol from encoded byte
    pub(super) fn from_byte(b: u8) -> Option<Protocol> {
        FromPrimitive::from_u8(b)
    }
}

/// allows conversion of Protocol value to string
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let i = *self as u8;
        write!(f, "{}", i)
    }
}

/// Payload is the data of the Address. Variants are the supported Address protocols.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "arb", derive(arbitrary::Arbitrary))]
pub enum Payload {
    /// ID protocol address.
    ID(u64),
    /// SECP256K1 key address, 20 byte hash of PublicKey
    Secp256k1([u8; PAYLOAD_HASH_LEN]),
    /// Actor protocol address, 20 byte hash of actor data
    Actor([u8; PAYLOAD_HASH_LEN]),
    /// BLS key address, full 48 byte public key
    BLS([u8; BLS_PUB_LEN]),
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Secp256k1([0; PAYLOAD_HASH_LEN])
    }
}

impl Payload {
    /// Returns encoded bytes of Address without the protocol byte.
    pub fn to_raw_bytes(self) -> Vec<u8> {
        use Payload::*;
        match self {
            ID(i) => to_leb_bytes(i).unwrap(),
            Secp256k1(arr) => arr.to_vec(),
            Actor(arr) => arr.to_vec(),
            BLS(arr) => arr.to_vec(),
        }
    }

    /// Returns encoded bytes of Address including the protocol byte.
    pub fn to_bytes(self) -> Vec<u8> {
        use Payload::*;
        let mut bz = match self {
            ID(i) => to_leb_bytes(i).unwrap(),
            Secp256k1(arr) => arr.to_vec(),
            Actor(arr) => arr.to_vec(),
            BLS(arr) => arr.to_vec(),
        };

        bz.insert(0, Protocol::from(self) as u8);
        bz
    }

    /// Generates payload from raw bytes and protocol.
    pub fn new(protocol: Protocol, payload: &[u8]) -> Result<Self, Error> {
        let payload = match protocol {
            Protocol::ID => Self::ID(from_leb_bytes(payload)?),
            Protocol::Secp256k1 => Self::Secp256k1(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::Actor => Self::Actor(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::BLS => Self::BLS(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
        };
        Ok(payload)
    }
}

impl From<Payload> for Protocol {
    fn from(pl: Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
        }
    }
}

impl From<&Payload> for Protocol {
    fn from(pl: &Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
        }
    }
}

/// Address error
#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error("Unknown address network")]
    UnknownNetwork,
    #[error("Unknown address protocol")]
    UnknownProtocol,
    #[error("Invalid address payload")]
    InvalidPayload,
    #[error("Invalid address length")]
    InvalidLength,
    #[error("Invalid payload length, wanted: {} got: {0}", PAYLOAD_HASH_LEN)]
    InvalidPayloadLength(usize),
    #[error("Invalid BLS pub key length, wanted: {} got: {0}", BLS_PUB_LEN)]
    InvalidBLSLength(usize),
    #[error("Invalid SECP pub key length, wanted: {} got: {0}", SECP_PUB_LEN)]
    InvalidSECPLength(usize),
    #[error("Invalid address checksum")]
    InvalidChecksum,
    #[error("Decoding for address failed: {0}")]
    Base32Decoding(#[from] DecodeError),
    #[error("Cannot get id from non id address")]
    NonIDAddress,
}

/// Network defines the preconfigured networks to use with address encoding
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default, Hash)]
#[cfg_attr(feature = "arb", derive(arbitrary::Arbitrary))]
pub enum Network {
    #[default]
    Mainnet = 0,
    Testnet = 1,
}

impl Network {
    /// to_prefix is used to convert the network into a string
    /// used when converting address to string
    pub(super) fn to_prefix(self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_PREFIX,
            Network::Testnet => TESTNET_PREFIX,
        }
    }
}

/// defines the encoder for base32 encoding with the provided string with no padding
pub const ADDRESS_ENCODER: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz234567",
    padding: None,
};

/// Hash length of payload for Secp and Actor addresses.
pub const PAYLOAD_HASH_LEN: usize = 20;

/// Uncompressed secp public key used for validation of Secp addresses.
pub const SECP_PUB_LEN: usize = 65;

/// BLS public key length used for validation of BLS addresses.
pub const BLS_PUB_LEN: usize = 48;

lazy_static::lazy_static! {
    static ref BLS_ZERO_ADDR_BYTES: [u8; BLS_PUB_LEN] = {
        let bz_addr = FilecoinAddress::from_str("f3yaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaby2smx7a");
        if let Ok(FilecoinAddress {payload: Payload::BLS(pubkey), ..}) = bz_addr {
            pubkey
        } else {
            panic!("failed to parse BLS address from provided BLS_ZERO_ADDR string")
        }
    };
}

/// Length of the checksum hash for string encodings.
pub const CHECKSUM_HASH_LEN: usize = 4;

const MAX_ADDRESS_LEN: usize = 84 + 2;
const MAINNET_PREFIX: &str = "f";
const TESTNET_PREFIX: &str = "t";

// TODO pull network from config (probably)
// TODO: can we do this using build flags?
pub const NETWORK_DEFAULT: Network = Network::Testnet;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base32_to_internal_address() {
        let addr = FilecoinAddress::from_str("f2qexjxohk7c7j6r2tud6kgab6yd62fhdszjukcra").unwrap();
        println!("{}", addr);
    }
}
