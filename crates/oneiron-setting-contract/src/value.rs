//! The contract every stored setting value meets.

use std::fmt;

use oneiron_contracts::error::{Error, Result};
use schemars::JsonSchema;
use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value a setting row may hold: stored as a MessagePack named map, described to clients by
/// its JSON Schema, and normalised or refused by [`Self::check`] before it is stored. A value
/// type's `normalized()` or `validate()` moves into `check` unchanged.
pub trait SettingValue:
    Serialize + DeserializeOwned + JsonSchema + Clone + PartialEq + Send + Sync + 'static
{
    /// The value as it will be stored.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` naming what is wrong with it.
    fn check(self) -> Result<Self> {
        Ok(self)
    }
}

impl SettingValue for bool {}
impl SettingValue for u8 {}
impl SettingValue for u16 {}
impl SettingValue for u32 {}
impl SettingValue for u64 {}
impl SettingValue for i64 {}
impl SettingValue for String {}
impl SettingValue for Vec<String> {}

impl SettingValue for f64 {
    fn check(self) -> Result<Self> {
        if self.is_finite() {
            Ok(self)
        } else {
            Err(Error::InvalidConfig("a setting number is finite".into()))
        }
    }
}

/// For a key whose smaller value is the tighter one (a cap, a budget): whether `a` is at least
/// as tight as `b`.
#[must_use]
pub fn lower_is_tighter<T: PartialOrd>(a: &T, b: &T) -> bool {
    a <= b
}

/// For a key whose larger value is the tighter one (a floor, a wait): whether `a` is at least as
/// tight as `b`.
#[must_use]
pub fn higher_is_tighter<T: PartialOrd>(a: &T, b: &T) -> bool {
    a >= b
}

/// A value as a row stores it: its MessagePack named map, carried inside the row as one binary
/// field, so a row decodes whole whatever its value type is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedValue(pub Vec<u8>);

impl EncodedValue {
    /// `value` checked ([`SettingValue::check`]) and encoded.
    ///
    /// # Errors
    ///
    /// `check`'s refusal; a value that does not encode.
    pub fn checked<T: SettingValue>(value: T) -> Result<Self> {
        Self::encode(&value.check()?)
    }

    /// `value` encoded as it is, for a default or a value already checked.
    ///
    /// # Errors
    ///
    /// A value that does not encode.
    pub fn encode<T: Serialize>(value: &T) -> Result<Self> {
        rmp_serde::to_vec_named(value).map(Self).map_err(|error| {
            Error::InvalidConfig(format!("a setting value does not encode: {error}"))
        })
    }

    /// The value these bytes hold, or `None` when they do not decode as `T`.
    #[must_use]
    pub fn decode<T: DeserializeOwned>(&self) -> Option<T> {
        rmp_serde::from_slice(&self.0).ok()
    }
}

impl Serialize for EncodedValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for EncodedValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = EncodedValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a setting value's bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                Ok(EncodedValue(bytes.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                Ok(EncodedValue(bytes))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(EncodedValue(bytes))
            }
        }
        deserializer.deserialize_bytes(Bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodedValue, SettingValue};

    #[test]
    fn a_value_round_trips_and_a_wrong_type_does_not_decode() {
        let encoded = EncodedValue::checked(7_u64).expect("encodes");
        assert_eq!(encoded.decode::<u64>(), Some(7));
        assert_eq!(encoded.decode::<String>(), None);
        let row = rmp_serde::to_vec_named(&encoded).expect("a row encodes");
        assert_eq!(
            rmp_serde::from_slice::<EncodedValue>(&row).expect("a row decodes"),
            encoded
        );
        assert!(f64::NAN.check().is_err());
    }
}
