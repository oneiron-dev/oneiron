//! A MessagePack value, as the protocol carries args, bodies, reports and
//! asks (protocol 2.0, FIX 6191).
//!
//! Nothing a value does recurses over its depth: it encodes and decodes
//! through the protocol's own codec, and it drops, clones, compares and
//! prints with a stack of its own on the heap. So the protocol takes a
//! value of any depth and any number of entries; what bounds one is the
//! memory its receiver books for it before building it.
//!
//! Its variants are MessagePack's own. An integer keeps its value, not its
//! marker; a string that is not UTF-8 reads as a binary.

use std::fmt;

mod ops;
mod wire;

pub(crate) use ops::Open;
pub(crate) use wire::{VALUE_TOKEN, decode as decode_value};

/// One MessagePack value.
#[derive(Default)]
pub enum Value {
    #[default]
    Nil,
    Boolean(bool),
    Integer(Integer),
    F32(f32),
    F64(f64),
    String(String),
    Binary(Vec<u8>),
    Array(Vec<Value>),
    /// Its entries in order; a key may repeat, as MessagePack allows.
    Map(Vec<(Value, Value)>),
    /// An extension: its type and its bytes.
    Ext(i8, Vec<u8>),
}

/// A MessagePack integer: any value from `i64::MIN` to `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Integer(i128);

impl Integer {
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        u64::try_from(self.0).ok()
    }

    #[must_use]
    pub fn as_i64(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }

    /// The integer as a float, rounded to the nearest one.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.0 as f64
    }

    pub(crate) fn get(self) -> i128 {
        self.0
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

macro_rules! integer_from {
    ($($ty:ty),*) => {$(
        impl From<$ty> for Integer {
            fn from(value: $ty) -> Self {
                Self(i128::from(value))
            }
        }
        impl From<$ty> for Value {
            fn from(value: $ty) -> Self {
                Self::Integer(Integer::from(value))
            }
        }
    )*};
}

integer_from!(u8, u16, u32, u64, i8, i16, i32, i64);

impl From<usize> for Integer {
    fn from(value: usize) -> Self {
        Self(value as i128)
    }
}

impl From<isize> for Integer {
    fn from(value: isize) -> Self {
        Self(value as i128)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Integer(Integer::from(value))
    }
}

impl From<isize> for Value {
    fn from(value: isize) -> Self {
        Self::Integer(Integer::from(value))
    }
}

impl From<Integer> for Value {
    fn from(value: Integer) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Self::F32(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::F64(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Binary(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Binary(value.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        Self::Array(value)
    }
}

impl From<Vec<(Value, Value)>> for Value {
    fn from(value: Vec<(Value, Value)>) -> Self {
        Self::Map(value)
    }
}

impl Value {
    #[must_use]
    pub fn is_nil(&self) -> bool {
        matches!(self, Self::Nil)
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => value.as_u64(),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => value.as_i64(),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F32(value) => Some(f64::from(*value)),
            Self::F64(value) => Some(*value),
            Self::Integer(value) => Some(value.as_f64()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// A binary's bytes.
    #[must_use]
    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_map(&self) -> Option<&Vec<(Value, Value)>> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The value of the first entry whose key is the string `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    }

    /// A map's entries, taken out of it; any other value comes back as it
    /// was. A value drops without recursing, so its variants are taken out
    /// this way rather than by a pattern.
    ///
    /// # Errors
    /// The value itself, when it is not a map.
    pub fn into_map(mut self) -> Result<Vec<(Value, Value)>, Value> {
        if let Self::Map(entries) = &mut self {
            return Ok(std::mem::take(entries));
        }
        Err(self)
    }

    /// An array's items, taken out of it, as [`Self::into_map`] takes a
    /// map's entries.
    ///
    /// # Errors
    /// The value itself, when it is not an array.
    pub fn into_array(mut self) -> Result<Vec<Value>, Value> {
        if let Self::Array(items) = &mut self {
            return Ok(std::mem::take(items));
        }
        Err(self)
    }
}
