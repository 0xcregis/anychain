//! This adds a few utility functions for serializing and deserializing
//! [arkworks](http://arkworks.rs/) types that implement [CanonicalSerialize] and [CanonicalDeserialize].

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde_with::Bytes;

//
// Serialization with serde
//

//
// Serialization with [serde_with]
//

/// You can use [SerdeAs] with [serde_with] in order to serialize and deserialize types that implement [CanonicalSerialize] and [CanonicalDeserialize],
/// or containers of types that implement these traits (Vec, arrays, etc.)
/// Simply add annotations like `#[serde_as(as = "o1_utils::serialization::SerdeAs")]`
/// See <https://docs.rs/serde_with/1.10.0/serde_with/guide/serde_as/index.html#switching-from-serdes-with-to-serde_as>
pub struct SerdeAs;

impl<T> serde_with::SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        if serializer.is_human_readable() {
            hex::serde::serialize(bytes, serializer)
        } else {
            Bytes::serialize_as(&bytes, serializer)
        }
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = if deserializer.is_human_readable() {
            hex::serde::deserialize(deserializer)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}
