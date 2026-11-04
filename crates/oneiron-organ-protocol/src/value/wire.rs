//! A value on the wire: written piece by piece and read token by token, with
//! no recursion, and carried through serde past its recursive visitor.
//!
//! Inside a serde type a value takes a newtype marker ([`VALUE_TOKEN`]). The
//! protocol's codec sees the marker and writes the value's own encoding
//! where it stands, then reads it back as one slice for [`decode`]. Any
//! other binary serializer gets the same encoding as a sequence of binaries,
//! and reads it back the same way. A human-readable one (JSON) gets the
//! value as its natural tree, which does recurse over the value's depth.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use serde_bytes::{ByteBuf, Bytes};

use super::Value;
use super::ops::Builder;
use crate::codec::{CodecError, Head, Reader, Token};

/// The newtype name a value takes inside a serde type, which the protocol's
/// codec reads as "the encoding of one value stands here".
pub(crate) const VALUE_TOKEN: &str = "$oneiron_organ_protocol::Value";

/// Writes `value`'s MessagePack, one piece at a time: a header, then any
/// bytes it carries. Walks in order with a stack on the heap.
///
/// # Errors
/// Whatever `put` returns.
pub(crate) fn write<E>(
    value: &Value,
    mut put: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Nil => put(Head::nil().as_slice())?,
            Value::Boolean(flag) => put(Head::bool(*flag).as_slice())?,
            Value::Integer(integer) => put(Head::integer(integer.get()).as_slice())?,
            Value::F32(float) => put(Head::f32(*float).as_slice())?,
            Value::F64(float) => put(Head::f64(*float).as_slice())?,
            Value::String(text) => {
                put(Head::str(text.len() as u64).as_slice())?;
                put(text.as_bytes())?;
            }
            Value::Binary(bytes) => {
                put(Head::bin(bytes.len() as u64).as_slice())?;
                put(bytes)?;
            }
            Value::Ext(kind, bytes) => {
                put(Head::ext(*kind, bytes.len() as u64).as_slice())?;
                put(bytes)?;
            }
            Value::Array(items) => {
                put(Head::array(items.len() as u64).as_slice())?;
                stack.extend(items.iter().rev());
            }
            Value::Map(entries) => {
                put(Head::map(entries.len() as u64).as_slice())?;
                for (key, item) in entries.iter().rev() {
                    stack.push(item);
                    stack.push(key);
                }
            }
        }
    }
    Ok(())
}

/// One whole value from `bytes`, which must hold nothing after it.
///
/// # Errors
/// The bytes are not one MessagePack value.
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, CodecError> {
    let mut reader = Reader::new(bytes);
    let value = read(&mut reader)?;
    if !reader.is_empty() {
        return Err(CodecError::Invalid("bytes after the value"));
    }
    Ok(value)
}

/// The next whole value `reader` holds, built with no recursion. A
/// container's claimed length is checked against the bytes left before
/// anything is allocated for it: every value takes at least one byte.
///
/// # Errors
/// The bytes are not a MessagePack value.
pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Value, CodecError> {
    let mut builder = Builder::default();
    let mut owed = 1u64;
    while owed > 0 {
        owed -= 1;
        match reader.token()? {
            Token::Array(len) => {
                owed = owed.saturating_add(len);
                check_owed(owed, reader)?;
                builder.array(len, reader.left());
            }
            Token::Map(len) => {
                owed = owed.saturating_add(len.saturating_mul(2));
                check_owed(owed, reader)?;
                builder.map(len, reader.left() / 2);
            }
            token => builder.leaf(leaf(token)),
        }
    }
    builder.finish().ok_or(CodecError::Eof)
}

fn check_owed(owed: u64, reader: &Reader<'_>) -> Result<(), CodecError> {
    if owed > reader.left() as u64 {
        Err(CodecError::Invalid(
            "a container claims more values than the bytes hold",
        ))
    } else {
        Ok(())
    }
}

/// A token that is a whole value by itself.
fn leaf(token: Token<'_>) -> Value {
    match token {
        Token::Nil | Token::Array(_) | Token::Map(_) => Value::Nil,
        Token::Bool(flag) => Value::Boolean(flag),
        Token::Uint(integer) => Value::from(integer),
        Token::Int(integer) => Value::from(integer),
        Token::F32(float) => Value::F32(float),
        Token::F64(float) => Value::F64(float),
        Token::Str(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => Value::String(text.to_owned()),
            Err(_) => Value::Binary(bytes.to_vec()),
        },
        Token::Bin(bytes) => Value::Binary(bytes.to_vec()),
        Token::Ext(kind, bytes) => Value::Ext(kind, bytes.to_vec()),
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            return Natural(self).serialize(serializer);
        }
        serializer.serialize_newtype_struct(VALUE_TOKEN, &Pieces(self))
    }
}

/// A value as the run of its encoded pieces: the protocol's codec writes
/// each where it stands; another serializer gets a sequence of binaries.
struct Pieces<'a>(&'a Value);

impl Serialize for Pieces<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        write(self.0, |piece| seq.serialize_element(Bytes::new(piece)))?;
        seq.end()
    }
}

/// A value as its natural tree, for a human-readable serializer.
struct Natural<'a>(&'a Value);

impl Serialize for Natural<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Nil => serializer.serialize_unit(),
            Value::Boolean(flag) => serializer.serialize_bool(*flag),
            Value::Integer(integer) => match (integer.as_u64(), integer.as_i64()) {
                (Some(unsigned), _) => serializer.serialize_u64(unsigned),
                (None, Some(signed)) => serializer.serialize_i64(signed),
                (None, None) => serializer.serialize_unit(),
            },
            Value::F32(float) => serializer.serialize_f32(*float),
            Value::F64(float) => serializer.serialize_f64(*float),
            Value::String(text) => serializer.serialize_str(text),
            Value::Binary(bytes) => serializer.serialize_bytes(bytes),
            Value::Ext(kind, bytes) => (kind, Bytes::new(bytes)).serialize(serializer),
            Value::Array(items) => serializer.collect_seq(items.iter().map(Natural)),
            Value::Map(entries) => serializer.collect_map(
                entries
                    .iter()
                    .map(|(key, item)| (Natural(key), Natural(item))),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            return deserializer.deserialize_any(NaturalVisitor);
        }
        deserializer.deserialize_newtype_struct(VALUE_TOKEN, Encoded)
    }
}

/// A value's encoding: one slice from the protocol's codec, or a sequence of
/// binaries from another.
struct Encoded;

impl<'de> Visitor<'de> for Encoded {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("one MessagePack value")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Value, E> {
        decode(bytes).map_err(E::custom)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Value, D::Error> {
        inner.deserialize_seq(Joined)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Value, A::Error> {
        Joined.visit_seq(seq)
    }
}

/// A value's pieces, as another binary codec carried them.
struct Joined;

impl<'de> Visitor<'de> for Joined {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the pieces of one MessagePack value")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut bytes = Vec::new();
        while let Some(piece) = seq.next_element::<ByteBuf>()? {
            bytes.extend_from_slice(&piece);
        }
        decode(&bytes).map_err(de::Error::custom)
    }
}

/// A value as a human-readable format's natural tree.
struct NaturalVisitor;

impl<'de> Visitor<'de> for NaturalVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Nil)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Nil)
    }

    fn visit_some<D: Deserializer<'de>>(self, inner: D) -> Result<Value, D::Error> {
        inner.deserialize_any(Self)
    }

    fn visit_bool<E: de::Error>(self, flag: bool) -> Result<Value, E> {
        Ok(Value::Boolean(flag))
    }

    fn visit_i64<E: de::Error>(self, integer: i64) -> Result<Value, E> {
        Ok(Value::from(integer))
    }

    fn visit_u64<E: de::Error>(self, integer: u64) -> Result<Value, E> {
        Ok(Value::from(integer))
    }

    fn visit_f32<E: de::Error>(self, float: f32) -> Result<Value, E> {
        Ok(Value::F32(float))
    }

    fn visit_f64<E: de::Error>(self, float: f64) -> Result<Value, E> {
        Ok(Value::F64(float))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Value, E> {
        Ok(Value::from(text))
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<Value, E> {
        Ok(Value::String(text))
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Value, E> {
        Ok(Value::from(bytes))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Value, E> {
        Ok(Value::Binary(bytes))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(NaturalSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry_seed(NaturalSeed, NaturalSeed)? {
            entries.push(entry);
        }
        Ok(Value::Map(entries))
    }
}

/// One element of a natural tree.
struct NaturalSeed;

impl<'de> de::DeserializeSeed<'de> for NaturalSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(NaturalVisitor)
    }
}
