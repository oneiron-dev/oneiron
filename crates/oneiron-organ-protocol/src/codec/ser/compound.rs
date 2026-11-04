//! Sequence, map and struct output, including unknown-length compounds.

use serde::ser::{self, Serialize};

use super::{CodecError, Head, Serializer, Sink};
use crate::codec::{Reader, Token};

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
    pub(super) fn stream(ser: &'a mut Serializer<'w, W>) -> Self {
        Self {
            inner: Inner::Stream { ser },
        }
    }

    pub(super) fn buffered(ser: &'a mut Serializer<'w, W>, map: bool) -> Self {
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
