//! Borrowed decoding for the two fixed-size memory control types. Their
//! derived visitors keep the wire field rules; ignored fields need no walk.
//! This stays private to memory control: a general typed result can allocate.

use serde::de::value::{BorrowedStrDeserializer, MapDeserializer, SeqDeserializer};
use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};
use serde::forward_to_deserialize_any;

use crate::{CodecError, Value};

#[derive(Clone, Copy)]
pub(super) struct Control<'a>(pub(super) &'a Value);

impl<'de> IntoDeserializer<'de, CodecError> for Control<'de> {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> de::Deserializer<'de> for Control<'de> {
    type Error = CodecError;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        match self.0 {
            Value::Nil => visitor.visit_unit(),
            Value::Boolean(value) => visitor.visit_bool(*value),
            Value::Integer(value) => match value.as_u64() {
                Some(value) => visitor.visit_u64(value),
                None => visitor.visit_i64(value.as_i64().expect("a negative integer fits i64")),
            },
            Value::F32(value) => visitor.visit_f32(*value),
            Value::F64(value) => visitor.visit_f64(*value),
            Value::String(value) => visitor.visit_borrowed_str(value),
            Value::Binary(value) => visitor.visit_borrowed_bytes(value),
            Value::Array(values) => {
                let mut access = SeqDeserializer::new(values.iter().map(Control));
                let value = visitor.visit_seq(&mut access)?;
                access.end()?;
                Ok(value)
            }
            Value::Map(values) => {
                let mut access = MapDeserializer::new(
                    values
                        .iter()
                        .map(|(key, value)| (Control(key), Control(value))),
                );
                let value = visitor.visit_map(&mut access)?;
                access.end()?;
                Ok(value)
            }
            Value::Ext(..) => Err(CodecError::Invalid(
                "an extension is not a memory control field",
            )),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        match self.0 {
            Value::String(name) => {
                visitor.visit_enum(BorrowedStrDeserializer::<CodecError>::new(name))
            }
            Value::Map(entries) if entries.len() == 1 => {
                let (name, value) = &entries[0];
                visitor.visit_enum(Variant { name, value })
            }
            _ => Err(CodecError::Invalid(
                "a variant is its name, or a one-entry map from its name",
            )),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct identifier
    }
}

struct Variant<'a> {
    name: &'a Value,
    value: &'a Value,
}

impl<'de> de::EnumAccess<'de> for Variant<'de> {
    type Error = CodecError;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self), CodecError> {
        let name = seed.deserialize(Control(self.name))?;
        Ok((name, self))
    }
}

impl<'de> de::VariantAccess<'de> for Variant<'de> {
    type Error = CodecError;

    fn unit_variant(self) -> Result<(), CodecError> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, CodecError> {
        seed.deserialize(Control(self.value))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_any(Control(self.value), visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_any(Control(self.value), visitor)
    }
}
