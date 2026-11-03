//! The encoder: serde's data model onto MessagePack with named fields. A
//! [`crate::Value`] inside a message is written by its own walk, which does
//! not recurse ([`VALUE_TOKEN`]). A sequence or map whose length serde does
//! not know is buffered, then written with its counted head.

use rmp_serde::MSGPACK_EXT_STRUCT_NAME;
use serde::ser::{self, Serialize};

use super::{CodecError, Head, Reader, Sink, Token};
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
        } else if name == MSGPACK_EXT_STRUCT_NAME {
            let mut ext = ExtSerializer::new(self);
            value.serialize(&mut ext)?;
            ext.end()
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
        match len {
            Some(len) => {
                self.head(&Head::array(len as u64));
                Ok(Compound::stream(self))
            }
            None => Ok(Compound::buffered(self, false)),
        }
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
        match len {
            Some(len) => {
                self.head(&Head::map(len as u64));
                Ok(Compound::stream(self))
            }
            None => Ok(Compound::buffered(self, true)),
        }
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

/// A sequence, map or struct being written: a known length puts its
/// header out and streams what follows; an unknown one buffers it, then
/// puts the counted header and the buffered bytes out at its end.
pub(crate) struct Compound<'a, 'w, W: Sink> {
    inner: Inner<'a, 'w, W>,
}

enum Inner<'a, 'w, W: Sink> {
    /// Its header is out; items go straight to the sink.
    Stream { ser: &'a mut Serializer<'w, W> },
    /// Items gather in `buf`; `count` numbers each key and value, so a
    /// map holds half as many entries; `map` says which head the end
    /// writes.
    Buffered {
        ser: &'a mut Serializer<'w, W>,
        buf: Vec<u8>,
        count: u64,
        map: bool,
    },
}

impl<'a, 'w, W: Sink> Compound<'a, 'w, W> {
    fn stream(ser: &'a mut Serializer<'w, W>) -> Self {
        Self {
            inner: Inner::Stream { ser },
        }
    }

    fn buffered(ser: &'a mut Serializer<'w, W>, map: bool) -> Self {
        Self {
            inner: Inner::Buffered {
                ser,
                buf: Vec::new(),
                count: 0,
                map,
            },
        }
    }

    /// One element, or one key or value, where this compound puts it.
    fn item<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        match &mut self.inner {
            Inner::Stream { ser } => value.serialize(&mut **ser),
            Inner::Buffered { buf, count, .. } => {
                value.serialize(&mut Serializer::new(&mut *buf))?;
                *count += 1;
                Ok(())
            }
        }
    }

    /// One struct field: its name, then its value. A struct always
    /// knows its length, so it streams; the buffered arm keeps the same
    /// shape without a new path.
    fn field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CodecError> {
        match &mut self.inner {
            Inner::Stream { ser } => {
                ser.text(key);
                value.serialize(&mut **ser)
            }
            Inner::Buffered { buf, count, .. } => {
                let mut ser = Serializer::new(&mut *buf);
                ser.text(key);
                value.serialize(&mut ser)?;
                *count += 2;
                Ok(())
            }
        }
    }

    fn end_inner(self) -> Result<(), CodecError> {
        match self.inner {
            Inner::Stream { .. } => Ok(()),
            Inner::Buffered {
                ser,
                buf,
                count,
                map,
            } => {
                let head = if map {
                    Head::map(count / 2)
                } else {
                    Head::array(count)
                };
                ser.head(&head);
                replay(&mut *ser.out, &buf)
            }
        }
    }
}

/// Puts buffered items to `out` header by header, as streaming them
/// would have, so a measuring sink reads the same shape.
fn replay<W: Sink>(out: &mut W, buf: &[u8]) -> Result<(), CodecError> {
    let mut reader = Reader::new(buf);
    while !reader.is_empty() {
        let from = reader.at();
        let carried = match reader.token()? {
            Token::Str(bytes) | Token::Bin(bytes) | Token::Ext(_, bytes) => bytes.len(),
            Token::Nil
            | Token::Bool(_)
            | Token::Uint(_)
            | Token::Int(_)
            | Token::F32(_)
            | Token::F64(_)
            | Token::Array(_)
            | Token::Map(_) => 0,
        };
        let split = from + (reader.at() - from - carried);
        out.put(&buf[from..split]);
        if carried > 0 {
            out.put(&buf[split..reader.at()]);
        }
    }
    Ok(())
}

impl<W: Sink> ser::SerializeSeq for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        self.item(value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
    }
}

impl<W: Sink> ser::SerializeTuple for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        self.item(value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
    }
}

impl<W: Sink> ser::SerializeTupleStruct for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        self.item(value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
    }
}

impl<W: Sink> ser::SerializeTupleVariant for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        self.item(value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
    }
}

impl<W: Sink> ser::SerializeMap for Compound<'_, '_, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CodecError> {
        self.item(key)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        self.item(value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
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
        self.field(key, value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
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
        self.field(key, value)
    }

    fn end(self) -> Result<(), CodecError> {
        self.end_inner()
    }
}

/// An extension as serde sees it ([`MSGPACK_EXT_STRUCT_NAME`]): a tuple
/// of a tag and its bytes. The tag comes first; the head goes out with
/// the bytes, with nothing buffered past them.
struct ExtSerializer<'a, 'w, W: Sink> {
    ser: &'a mut Serializer<'w, W>,
    tuple: bool,
    tag: Option<i8>,
    done: bool,
}

impl<'a, 'w, W: Sink> ExtSerializer<'a, 'w, W> {
    fn new(ser: &'a mut Serializer<'w, W>) -> Self {
        Self {
            ser,
            tuple: false,
            tag: None,
            done: false,
        }
    }

    fn end(self) -> Result<(), CodecError> {
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

impl<'a, 'w, W: Sink> ser::Serializer for &mut ExtSerializer<'a, 'w, W> {
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

impl<'a, 'w, W: Sink> ser::SerializeTuple for &mut ExtSerializer<'a, 'w, W> {
    type Ok = ();
    type Error = CodecError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut **self)
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
