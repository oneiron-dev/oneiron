//! The decoder: MessagePack with named fields onto serde's data model. A
//! [`crate::Value`] inside a message is handed its encoding as one slice
//! and builds itself without recursing ([`VALUE_TOKEN`]); a field the type
//! does not know is stepped over with a count, however deep it is.

use rmp_serde::MSGPACK_EXT_STRUCT_NAME;
use serde::de::value::{BorrowedBytesDeserializer, I8Deserializer, SeqDeserializer};
use serde::de::{self, DeserializeSeed, Visitor};
use serde::forward_to_deserialize_any;

use super::{CodecError, Reader, Token};
use crate::value::VALUE_TOKEN;

pub(crate) struct Deserializer<'de> {
    reader: Reader<'de>,
}

impl<'de> Deserializer<'de> {
    pub(crate) fn new(bytes: &'de [u8]) -> Self {
        Self {
            reader: Reader::new(bytes),
        }
    }

    /// Whether every byte was read.
    pub(crate) fn finished(&self) -> bool {
        self.reader.is_empty()
    }

    /// One token already read, onto the visitor.
    fn any<V: Visitor<'de>>(
        &mut self,
        token: Token<'de>,
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        match token {
            Token::Nil => visitor.visit_unit(),
            Token::Bool(flag) => visitor.visit_bool(flag),
            Token::Uint(integer) => visitor.visit_u64(integer),
            Token::Int(integer) => visitor.visit_i64(integer),
            Token::F32(float) => visitor.visit_f32(float),
            Token::F64(float) => visitor.visit_f64(float),
            Token::Str(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => visitor.visit_borrowed_str(text),
                Err(_) => visitor.visit_borrowed_bytes(bytes),
            },
            Token::Bin(bytes) => visitor.visit_borrowed_bytes(bytes),
            Token::Ext(tag, bytes) => visitor.visit_newtype_struct(ExtDeserializer { tag, bytes }),
            Token::Array(len) => self.seq(visitor, len),
            Token::Map(len) => self.map(visitor, len),
        }
    }

    fn seq<V: Visitor<'de>>(&mut self, visitor: V, len: u64) -> Result<V::Value, CodecError> {
        let mut access = Access {
            de: &mut *self,
            left: len,
        };
        let value = visitor.visit_seq(&mut access)?;
        if access.left == 0 {
            Ok(value)
        } else {
            Err(CodecError::Invalid("a sequence longer than its type"))
        }
    }

    fn map<V: Visitor<'de>>(&mut self, visitor: V, len: u64) -> Result<V::Value, CodecError> {
        let mut access = Access {
            de: &mut *self,
            left: len,
        };
        let value = visitor.visit_map(&mut access)?;
        if access.left == 0 {
            Ok(value)
        } else {
            Err(CodecError::Invalid("a map longer than its type"))
        }
    }
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = CodecError;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let token = self.reader.token()?;
        self.any(token, visitor)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        match self.reader.token()? {
            // Bytes as the sequence of their own values, as with
            // rmp-serde; `bytes` and `byte_buf` still read them whole.
            Token::Bin(bytes) => visitor.visit_seq(SeqDeserializer::new(bytes.iter().copied())),
            token => self.any(token, visitor),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        // As a sequence: a fixed array reads bytes element by element.
        match self.reader.token()? {
            Token::Bin(bytes) => {
                let mut seq = SeqDeserializer::new(bytes.iter().copied());
                let value = visitor.visit_seq(&mut seq)?;
                seq.end()?;
                Ok(value)
            }
            token => self.any(token, visitor),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        if self.reader.peek() == Some(0xc0) {
            self.reader.token()?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        if name == VALUE_TOKEN {
            // The value's own encoding, as one slice.
            let from = self.reader.at();
            self.reader.skip()?;
            visitor.visit_borrowed_bytes(self.reader.since(from))
        } else if name == MSGPACK_EXT_STRUCT_NAME {
            match self.reader.token()? {
                Token::Ext(tag, bytes) => {
                    visitor.visit_newtype_struct(ExtDeserializer { tag, bytes })
                }
                _ => Err(CodecError::Invalid("an extension is a tag and its bytes")),
            }
        } else {
            visitor.visit_newtype_struct(self)
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        match self.reader.token()? {
            Token::Str(bytes) => {
                let name = std::str::from_utf8(bytes)
                    .map_err(|_| CodecError::Invalid("a variant name that is not UTF-8"))?;
                let unit: de::value::BorrowedStrDeserializer<'de, CodecError> =
                    de::value::BorrowedStrDeserializer::new(name);
                visitor.visit_enum(unit)
            }
            Token::Map(1) => visitor.visit_enum(Variant { de: &mut *self }),
            _ => Err(CodecError::Invalid(
                "a variant is its name, or a one-entry map from its name",
            )),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.reader.skip()?;
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct tuple_struct map struct identifier
    }
}

/// The elements of a sequence, or the entries of a map, still to come.
struct Access<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    left: u64,
}

impl<'de> de::SeqAccess<'de> for &mut Access<'_, 'de> {
    type Error = CodecError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, CodecError> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        // A hint only: a claimed length is not room until its bytes come.
        usize::try_from(self.left)
            .ok()
            .map(|left| left.min(self.de.reader.left()))
    }
}

impl<'de> de::MapAccess<'de> for &mut Access<'_, 'de> {
    type Error = CodecError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, CodecError> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, CodecError> {
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> {
        usize::try_from(self.left)
            .ok()
            .map(|left| left.min(self.de.reader.left() / 2))
    }
}

/// A variant written as a one-entry map from its name to its content.
struct Variant<'a, 'de> {
    de: &'a mut Deserializer<'de>,
}

impl<'de> de::EnumAccess<'de> for Variant<'_, 'de> {
    type Error = CodecError;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self), CodecError> {
        let name = seed.deserialize(&mut *self.de)?;
        Ok((name, self))
    }
}

impl<'de> de::VariantAccess<'de> for Variant<'_, 'de> {
    type Error = CodecError;

    /// A unit variant in map form: its content, whatever it is, is
    /// stepped over.
    fn unit_variant(self) -> Result<(), CodecError> {
        self.de.reader.skip()
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, CodecError> {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }
}

/// An extension as serde sees it ([`MSGPACK_EXT_STRUCT_NAME`]): a tag and
/// its bytes, read as the two fields of a tuple.
struct ExtDeserializer<'de> {
    tag: i8,
    bytes: &'de [u8],
}

impl<'de> de::Deserializer<'de> for ExtDeserializer<'de> {
    type Error = CodecError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        visitor.visit_seq(ExtSeq {
            tag: Some(self.tag),
            bytes: Some(self.bytes),
        })
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

/// An extension's tag, then its bytes.
struct ExtSeq<'de> {
    tag: Option<i8>,
    bytes: Option<&'de [u8]>,
}

impl<'de> de::SeqAccess<'de> for ExtSeq<'de> {
    type Error = CodecError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, CodecError> {
        if let Some(tag) = self.tag.take() {
            seed.deserialize(I8Deserializer::new(tag)).map(Some)
        } else if let Some(bytes) = self.bytes.take() {
            seed.deserialize(BorrowedBytesDeserializer::new(bytes))
                .map(Some)
        } else {
            Ok(None)
        }
    }
}
