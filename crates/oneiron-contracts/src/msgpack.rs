//! The one reader for untyped MessagePack rows (PLAN-UC-08).
//!
//! One policy for every row the engine stores or sends as an untyped [`Value`]:
//! - [`decode`] reads exactly one value and refuses bytes after it;
//! - [`Entries::get`] and every getter built on it refuse a key that appears twice;
//! - [`Entries::exact_keys`] refuses a key that is not text, a key outside the declared
//!   set, a repeated key and a missing required key;
//! - [`decode_row`] reads a typed (serde) row and refuses bytes after it, as [`decode`] does.
//!
//! There is no first-wins lookup and no trailer-tolerant decode. A caller keeps its own
//! error kind and message by mapping [`MsgpackError`]; this module never chooses an engine
//! [`Error`](crate::Error) kind for it. A body that needs a size budget before decoding
//! checks it first (`oneiron_base::msgpack_shape::over_budget`).

use std::io::Cursor;

use rmpv::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Why the reader refused a body. Variants that concern one map key name it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MsgpackError {
    /// The bytes do not hold one whole MessagePack value (or the typed row's shape):
    /// empty, truncated, a bad marker, or a value the target type does not accept.
    /// It carries the decoder's own message unchanged.
    #[error("{0}")]
    Malformed(String),
    /// Bytes follow the one value.
    #[error("bytes follow the MessagePack value")]
    Trailing,
    /// The value is not a map where a map is required.
    #[error("MessagePack value is not a map")]
    NotMap,
    /// A map key that is not a UTF-8 text string, in a map whose keys are checked.
    #[error("MessagePack map has a key that is not text")]
    NonTextKey,
    /// The named key appears more than once.
    #[error("MessagePack map key `{0}` appears more than once")]
    DuplicateKey(String),
    /// The named key is outside the declared key set.
    #[error("MessagePack map key `{0}` is not allowed")]
    UnknownKey(String),
    /// The named required key is absent.
    #[error("MessagePack map key `{0}` is missing")]
    MissingKey(String),
    /// The named key holds a value of another type than the getter reads.
    #[error("MessagePack map key `{0}` holds the wrong type")]
    WrongType(String),
    /// A typed row did not serialize. It carries the encoder's own message unchanged.
    #[error("{0}")]
    Unencodable(String),
}

/// The MessagePack bytes of `value`: the most compact spelling of each item, as
/// `rmpv::encode::write_value` writes it.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .expect("rmpv writes a value into a Vec without an I/O error");
    bytes
}

/// Reads exactly one value from `bytes`. Empty or truncated input is
/// [`MsgpackError::Malformed`]; any byte after the value is [`MsgpackError::Trailing`].
pub fn decode(bytes: &[u8]) -> Result<Value, MsgpackError> {
    let mut rest = bytes;
    let value = rmpv::decode::read_value(&mut rest)
        .map_err(|error| MsgpackError::Malformed(error.to_string()))?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(MsgpackError::Trailing)
    }
}

/// [`decode`], then the value's map entries. A value that is not a map is
/// [`MsgpackError::NotMap`]; the entries are not checked here (see [`Entries`]).
pub fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>, MsgpackError> {
    match decode(bytes)? {
        Value::Map(entries) => Ok(entries),
        _ => Err(MsgpackError::NotMap),
    }
}

/// The MessagePack bytes of a typed row: `rmp_serde::to_vec_named` (struct fields as a
/// map keyed by field name).
pub fn encode_row<T: Serialize + ?Sized>(row: &T) -> Result<Vec<u8>, MsgpackError> {
    rmp_serde::to_vec_named(row).map_err(|error| MsgpackError::Unencodable(error.to_string()))
}

/// Reads exactly one typed row from `bytes`, as `rmp_serde::from_slice` reads it
/// (same configuration and depth limit), and refuses any byte after it with
/// [`MsgpackError::Trailing`]. A decode error keeps `rmp_serde`'s message.
pub fn decode_row<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MsgpackError> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let row: T = Deserialize::deserialize(&mut deserializer)
        .map_err(|error| MsgpackError::Malformed(error.to_string()))?;
    if deserializer.position() == bytes.len() as u64 {
        Ok(row)
    } else {
        Err(MsgpackError::Trailing)
    }
}

/// A read-only view of one map's entries, in their stored order. Every keyed read
/// compares text keys only (a key that is not UTF-8 text never matches) and refuses
/// a key that appears twice.
#[derive(Debug, Clone, Copy)]
pub struct Entries<'a> {
    entries: &'a [(Value, Value)],
}

impl<'a> Entries<'a> {
    /// The entries of `value`, or [`MsgpackError::NotMap`].
    pub fn of(value: &'a Value) -> Result<Self, MsgpackError> {
        match value {
            Value::Map(entries) => Ok(Self { entries }),
            _ => Err(MsgpackError::NotMap),
        }
    }

    /// A view of entries the caller already holds (for example from [`decode_map`]).
    #[must_use]
    pub fn new(entries: &'a [(Value, Value)]) -> Self {
        Self { entries }
    }

    /// The entries as stored, duplicates and non-text keys included.
    #[must_use]
    pub fn as_slice(self) -> &'a [(Value, Value)] {
        self.entries
    }

    /// The value under `key`, `None` when it is absent, or
    /// [`MsgpackError::DuplicateKey`] when it appears more than once.
    pub fn get(self, key: &str) -> Result<Option<&'a Value>, MsgpackError> {
        let mut found = None;
        for (candidate, value) in self.entries {
            if candidate.as_str() == Some(key) {
                if found.is_some() {
                    return Err(MsgpackError::DuplicateKey(key.to_owned()));
                }
                found = Some(value);
            }
        }
        Ok(found)
    }

    /// The value under `key`, or [`MsgpackError::MissingKey`] when it is absent
    /// (and [`MsgpackError::DuplicateKey`] as [`Entries::get`]).
    pub fn require(self, key: &str) -> Result<&'a Value, MsgpackError> {
        self.get(key)?
            .ok_or_else(|| MsgpackError::MissingKey(key.to_owned()))
    }

    /// Checks the whole key set: every key is text and one of `required` or
    /// `optional`, no key appears twice, and every `required` key is present. A key
    /// listed in both counts as required. Errors come in entry order (the first bad
    /// key), then the first missing required key in `required` order. Returns `self`,
    /// so a caller can check and read in one chain.
    pub fn exact_keys(self, required: &[&str], optional: &[&str]) -> Result<Self, MsgpackError> {
        let declared = || required.iter().chain(optional);
        let mut seen = vec![false; required.len() + optional.len()];
        for (key, _) in self.entries {
            let key = key.as_str().ok_or(MsgpackError::NonTextKey)?;
            let Some(index) = declared().position(|known| *known == key) else {
                return Err(MsgpackError::UnknownKey(key.to_owned()));
            };
            if seen[index] {
                return Err(MsgpackError::DuplicateKey(key.to_owned()));
            }
            seen[index] = true;
        }
        match required.iter().zip(&seen).find(|(_, present)| !**present) {
            Some((missing, _)) => Err(MsgpackError::MissingKey((*missing).to_owned())),
            None => Ok(self),
        }
    }

    /// The required UTF-8 text under `key`. A string that is not UTF-8 is
    /// [`MsgpackError::WrongType`].
    pub fn str(self, key: &str) -> Result<&'a str, MsgpackError> {
        self.typed(key, Value::as_str)
    }

    /// The required unsigned integer under `key` (a negative integer is
    /// [`MsgpackError::WrongType`]).
    pub fn u64(self, key: &str) -> Result<u64, MsgpackError> {
        self.typed(key, Value::as_u64)
    }

    /// The required signed integer under `key` (an unsigned integer above
    /// `i64::MAX` is [`MsgpackError::WrongType`]).
    pub fn i64(self, key: &str) -> Result<i64, MsgpackError> {
        self.typed(key, Value::as_i64)
    }

    /// The required boolean under `key`.
    pub fn bool(self, key: &str) -> Result<bool, MsgpackError> {
        self.typed(key, Value::as_bool)
    }

    /// The required binary under `key` (a string is [`MsgpackError::WrongType`]).
    pub fn bytes(self, key: &str) -> Result<&'a [u8], MsgpackError> {
        self.typed(key, |value| match value {
            Value::Binary(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }

    /// The required array under `key`.
    pub fn array(self, key: &str) -> Result<&'a [Value], MsgpackError> {
        self.typed(key, |value| value.as_array().map(Vec::as_slice))
    }

    /// The required map under `key`, as a view.
    pub fn map(self, key: &str) -> Result<Entries<'a>, MsgpackError> {
        self.typed(key, |value| {
            value
                .as_map()
                .map(|entries| Entries::new(entries.as_slice()))
        })
    }

    fn typed<T>(
        self,
        key: &str,
        read: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Result<T, MsgpackError> {
        read(self.require(key)?).ok_or_else(|| MsgpackError::WrongType(key.to_owned()))
    }
}
