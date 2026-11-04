//! rmp-serde's typed MessagePack extension contract.

use serde::ser::{self, Serialize};

use super::{CodecError, Head, Serializer, Sink};

/// An extension as serde sees it ([`MSGPACK_EXT_STRUCT_NAME`]): a tuple
/// of a tag and its bytes. The tag comes first; the head goes out with
/// the bytes, with nothing buffered past them.
pub(super) struct ExtSerializer<'a, 'w, W: Sink> {
    ser: &'a mut Serializer<'w, W>,
    tuple: bool,
    tag: Option<i8>,
    done: bool,
}

impl<'a, 'w, W: Sink> ExtSerializer<'a, 'w, W> {
    pub(super) fn new(ser: &'a mut Serializer<'w, W>) -> Self {
        Self {
            ser,
            tuple: false,
            tag: None,
            done: false,
        }
    }

    pub(super) fn end(self) -> Result<(), CodecError> {
        if self.tuple && self.done {
            Ok(())
        } else {
            Err(not_ext())
        }
    }
}

fn not_ext() -> CodecError {
    CodecError::Invalid("an extension is a tag and its bytes")
}

impl<W: Sink> ser::Serializer for &mut ExtSerializer<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;
    type SerializeSeq = ser::Impossible<(), CodecError>;
    type SerializeTuple = Self;
    type SerializeTupleStruct = ser::Impossible<(), CodecError>;
    type SerializeTupleVariant = ser::Impossible<(), CodecError>;
    type SerializeMap = ser::Impossible<(), CodecError>;
    type SerializeStruct = ser::Impossible<(), CodecError>;
    type SerializeStructVariant = ser::Impossible<(), CodecError>;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_i8(self, value: i8) -> Result<(), CodecError> {
        if self.tag.is_some() {
            return Err(not_ext());
        }
        self.tag = Some(value);
        Ok(())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), CodecError> {
        match self.tag.take() {
            Some(tag) => {
                self.ser.head(&Head::ext(tag, value.len() as u64));
                self.ser.out.put(value);
                self.done = true;
                Ok(())
            }
            None => Err(not_ext()),
        }
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, CodecError> {
        self.tuple = true;
        Ok(self)
    }

    fn serialize_bool(self, _: bool) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_i16(self, _: i16) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_i32(self, _: i32) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_i64(self, _: i64) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_u8(self, _: u8) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_u16(self, _: u16) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_u32(self, _: u32) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_u64(self, _: u64) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_f32(self, _: f32) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_f64(self, _: f64) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_char(self, _: char) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_str(self, _: &str) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_none(self) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_unit(self) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), CodecError> {
        Err(not_ext())
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, CodecError> {
        Err(not_ext())
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, CodecError> {
        Err(not_ext())
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, CodecError> {
        Err(not_ext())
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, CodecError> {
        Err(not_ext())
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, CodecError> {
        Err(not_ext())
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, CodecError> {
        Err(not_ext())
    }
}

impl<W: Sink> ser::SerializeTuple for &mut ExtSerializer<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), CodecError> {
        Ok(())
    }
}
