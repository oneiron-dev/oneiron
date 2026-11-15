//! The pins of training runs and drafter versions (PLAN-UC-04 stage 6.4a): the BLAKE3 of a
//! value's sorted JSON (`llm::canonical_json_bytes`), with no tag, started through the
//! fingerprint crate's K door.
//!
//! Every pin keeps its bytes. Runs, corpora, role swaps and drafter versions store them;
//! dispatch, completion and promotion compare them; and the Python training worker
//! (`scripts/training_pack/worker.py`) takes the definition, load-set and probe pins again
//! from the same sorted JSON. A value holding a NaN or an infinity has no pin: its JSON would
//! write `null`, so it would share a pin with the value holding `null`, and the worker
//! refuses it before it hashes (`_float_text`).

use std::fmt;

use oneiron_contracts::fingerprint::{LegacyDigest, LegacyPurpose};
use serde::Serialize;
use serde::ser;

/// Why a value has no pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinRefusal {
    /// The value has no sorted JSON: its `Serialize` failed, or a map key is not a string.
    Encoding,
    /// The value holds a NaN or an infinity, which JSON cannot write.
    NonFinite,
}

impl fmt::Display for PinRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "encoding failed",
            Self::NonFinite => "holds a non-finite number, which has no JSON form",
        })
    }
}

impl std::error::Error for PinRefusal {}

impl ser::Error for PinRefusal {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        Self::Encoding
    }
}

/// The pin of `value` under `purpose` (a plain-BLAKE3, untagged legacy purpose).
///
/// The sorted JSON is taken first, so a value with none is refused as it always was; then
/// the value is walked once more for a non-finite float, which that JSON hides.
pub(crate) fn pin_digest(
    purpose: LegacyPurpose,
    value: &impl Serialize,
) -> Result<[u8; 32], PinRefusal> {
    let bytes = crate::llm::canonical_json_bytes(value).map_err(|_| PinRefusal::Encoding)?;
    value.serialize(FiniteFloats)?;
    Ok(LegacyDigest::new(purpose).raw(&bytes).finish())
}

/// Walks a value as serde writes it and refuses its first non-finite float. It accepts
/// every other part, since the sorted JSON has already taken the value.
struct FiniteFloats;

fn finite(is_finite: bool) -> Result<(), PinRefusal> {
    if is_finite {
        Ok(())
    } else {
        Err(PinRefusal::NonFinite)
    }
}

/// Accepts a scalar that is not a float.
macro_rules! accept_scalars {
    ($($method:ident($type:ty)),* $(,)?) => {
        $(fn $method(self, _value: $type) -> Result<(), PinRefusal> {
            Ok(())
        })*
    };
}

impl ser::Serializer for FiniteFloats {
    type Ok = ();
    type Error = PinRefusal;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    accept_scalars!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
        serialize_unit_struct(&'static str),
    );

    fn serialize_f32(self, value: f32) -> Result<(), PinRefusal> {
        finite(value.is_finite())
    }

    fn serialize_f64(self, value: f64) -> Result<(), PinRefusal> {
        finite(value.is_finite())
    }

    fn serialize_none(self) -> Result<(), PinRefusal> {
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), PinRefusal> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), PinRefusal> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
    ) -> Result<(), PinRefusal> {
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), PinRefusal> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<(), PinRefusal> {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self, PinRefusal> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self, PinRefusal> {
        Ok(self)
    }
}

/// Walks each element or field of a sequence, tuple or tuple-like variant.
macro_rules! walk_elements {
    ($($kind:ident::$method:ident),* $(,)?) => {$(
        impl ser::$kind for FiniteFloats {
            type Ok = ();
            type Error = PinRefusal;

            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), PinRefusal> {
                value.serialize(FiniteFloats)
            }

            fn end(self) -> Result<(), PinRefusal> {
                Ok(())
            }
        }
    )*};
}

walk_elements!(
    SerializeSeq::serialize_element,
    SerializeTuple::serialize_element,
    SerializeTupleStruct::serialize_field,
    SerializeTupleVariant::serialize_field,
);

/// Walks each named field of a struct or struct-like variant.
macro_rules! walk_fields {
    ($($kind:ident),* $(,)?) => {$(
        impl ser::$kind for FiniteFloats {
            type Ok = ();
            type Error = PinRefusal;

            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                _key: &'static str,
                value: &T,
            ) -> Result<(), PinRefusal> {
                value.serialize(FiniteFloats)
            }

            fn end(self) -> Result<(), PinRefusal> {
                Ok(())
            }
        }
    )*};
}

walk_fields!(SerializeStruct, SerializeStructVariant);

impl ser::SerializeMap for FiniteFloats {
    type Ok = ();
    type Error = PinRefusal;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), PinRefusal> {
        key.serialize(FiniteFloats)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), PinRefusal> {
        value.serialize(FiniteFloats)
    }

    fn end(self) -> Result<(), PinRefusal> {
        Ok(())
    }
}
