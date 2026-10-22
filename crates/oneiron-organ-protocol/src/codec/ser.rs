//! The encoder: serde's data model onto MessagePack with named fields. A
//! [`crate::Value`] inside a message is written by its own walk, which does
//! not recurse ([`VALUE_TOKEN`]).

use serde::ser::{self, Serialize};

use super::{CodecError, Head, Sink};
use crate::value::VALUE_TOKEN;

pub(crate) struct Serializer<'w, W: Sink> {
    out: &'w mut W,
}

impl<'w, W: Sink> Serializer<'w, W> {
    pub(crate) fn new(out: &'w mut W) -> Self {
        Self { out }
    }

    fn head(&mut self, head: &Head) {
        self.out.put(head.as_slice());
    }

    fn text(&mut self, text: &str) {
        self.head(&Head::str(text.len() as u64));
        self.out.put(text.as_bytes());
    }

    /// The head of a variant with content: a one-entry map from its name.
    fn variant(&mut self, variant: &str) {
        self.head(&Head::map(1));
        self.text(variant);
    }
}

fn unknown_length() -> CodecError {
    CodecError::Invalid("a sequence or map of unknown length")
}

impl<'a, 'w, W: Sink> ser::Serializer for &'a mut Serializer<'w, W> {
    type Ok = ();
    type Error = CodecError;
    type SerializeSeq = Compound<'a, 'w, W>;
    type SerializeTuple = Compound<'a, 'w, W>;
    type SerializeTupleStruct = Compound<'a, 'w, W>;
    type SerializeTupleVariant = Compound<'a, 'w, W>;
    type SerializeMap = Compound<'a, 'w, W>;
    type SerializeStruct = Compound<'a, 'w, W>;
    type SerializeStructVariant = Compound<'a, 'w, W>;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, value: bool) -> Result<(), CodecError> {
        self.head(&Head::bool(value));
        Ok(())
    }

    fn serialize_i8(self, value: i8) -> Result<(), CodecError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i16(self, value: i16) -> Result<(), CodecError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i32(self, value: i32) -> Result<(), CodecError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i64(self, value: i64) -> Result<(), CodecError> {
        self.head(&Head::integer(i128::from(value)));
        Ok(())
    }

    fn serialize_u8(self, value: u8) -> Result<(), CodecError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u16(self, value: u16) -> Result<(), CodecError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<(), CodecError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u64(self, value: u64) -> Result<(), CodecError> {
        self.head(&Head::uint(value));
        Ok(())
    }

    fn serialize_f32(self, value: f32) -> Result<(), CodecError> {
        self.head(&Head::f32(value));
        Ok(())
    }

    fn serialize_f64(self, value: f64) -> Result<(), CodecError> {
        self.head(&Head::f64(value));
        Ok(())
    }

    fn serialize_char(self, value: char) -> Result<(), CodecError> {
        self.serialize_str(value.encode_utf8(&mut [0; 4]))
    }

    fn serialize_str(self, value: &str) -> Result<(), CodecError> {
        self.text(value);
        Ok(())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), CodecError> {
        self.head(&Head::bin(value.len() as u64));
        self.out.put(value);
        Ok(())
    }

    fn serialize_none(self) -> Result<(), CodecError> {
        self.serialize_unit()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), CodecError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), CodecError> {
        self.head(&Head::nil());
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), CodecError> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), CodecError> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<(), CodecError> {
        if name == VALUE_TOKEN {
            // The value's own pieces, written where it stands.
            value.serialize(Raw {
                out: &mut *self.out,
            })
        } else {
            value.serialize(self)
        }
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), CodecError> {
        self.variant(variant);
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Compound<'a, 'w, W>, CodecError> {
        let len = len.ok_or_else(unknown_length)?;
        self.head(&Head::array(len as u64));
        Ok(Compound { ser: self })
    }

    fn serialize_tuple(self, len: usize) -> Result<Compound<'a, 'w, W>, CodecError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Compound<'a, 'w, W>, CodecError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Compound<'a, 'w, W>, CodecError> {
        self.variant(variant);
        self.serialize_seq(Some(len))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Compound<'a, 'w, W>, CodecError> {
        let len = len.ok_or_else(unknown_length)?;
        self.head(&Head::map(len as u64));
        Ok(Compound { ser: self })
    }

    fn serialize_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Compound<'a, 'w, W>, CodecError> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Compound<'a, 'w, W>, CodecError> {
        self.variant(variant);
        self.serialize_map(Some(len))
    }
}

/// A sequence, map or struct being written: its header is out, its
/// elements follow.
pub(crate) struct Compound<'a, 'w, W: Sink> {
    ser: &'a mut Serializer<'w, W>,
}

impl<W: Sink> ser::SerializeSeq for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeTuple for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeTupleStruct for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeTupleVariant for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeMap for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CodecError> {
        key.serialize(&mut *self.ser)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeStruct for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CodecError> {
        self.ser.text(key);
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

impl<W: Sink> ser::SerializeStructVariant for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CodecError> {
        self.ser.text(key);
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}

/// Where a value's pieces go ([`VALUE_TOKEN`]): each binary it is handed is
/// a piece of the value's own encoding, written as it is.
struct Raw<'w, W: Sink> {
    out: &'w mut W,
}

fn not_pieces() -> CodecError {
    CodecError::Invalid("a value's encoding is only its pieces")
}

impl<'w, W: Sink> ser::Serializer for Raw<'w, W> {
    type Ok = ();
    type Error = CodecError;
    type SerializeSeq = RawSeq<'w, W>;
    type SerializeTuple = ser::Impossible<(), CodecError>;
    type SerializeTupleStruct = ser::Impossible<(), CodecError>;
    type SerializeTupleVariant = ser::Impossible<(), CodecError>;
    type SerializeMap = ser::Impossible<(), CodecError>;
    type SerializeStruct = ser::Impossible<(), CodecError>;
    type SerializeStructVariant = ser::Impossible<(), CodecError>;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<RawSeq<'w, W>, CodecError> {
        Ok(RawSeq { out: self.out })
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), CodecError> {
        self.out.put(value);
        Ok(())
    }

    fn serialize_bool(self, _: bool) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_i8(self, _: i8) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_i16(self, _: i16) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_i32(self, _: i32) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_i64(self, _: i64) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_u8(self, _: u8) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_u16(self, _: u16) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_u32(self, _: u32) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_u64(self, _: u64) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_f32(self, _: f32) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_f64(self, _: f64) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_char(self, _: char) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_str(self, _: &str) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_none(self) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_unit(self) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), CodecError> {
        Err(not_pieces())
    }

    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, CodecError> {
        Err(not_pieces())
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, CodecError> {
        Err(not_pieces())
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, CodecError> {
        Err(not_pieces())
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, CodecError> {
        Err(not_pieces())
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, CodecError> {
        Err(not_pieces())
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, CodecError> {
        Err(not_pieces())
    }
}

/// A value's pieces in order.
pub(crate) struct RawSeq<'w, W: Sink> {
    out: &'w mut W,
}

impl<W: Sink> ser::SerializeSeq for RawSeq<'_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, piece: &T) -> Result<(), CodecError> {
        piece.serialize(Raw {
            out: &mut *self.out,
        })
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}
