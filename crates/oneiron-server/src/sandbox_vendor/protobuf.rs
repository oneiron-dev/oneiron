//! The protobuf wire format of the few messages a vendor's gRPC API takes
//! and answers (L8-43). [`ProtoWriter`] writes a message field by field;
//! [`ProtoMessage`] reads the field a caller names and skips every other.
//! Only the kinds those messages use are written: varints (enums, bools and
//! integers), 32-bit floats, and length-delimited strings, bytes and
//! messages. A reader skips any kind but a group, which no proto3 message
//! has.

/// The wire types this module writes or skips.
const VARINT: u64 = 0;
const FIXED64: u64 = 1;
const DELIMITED: u64 = 2;
const FIXED32: u64 = 5;

/// A message that does not parse as protobuf, or a field of the wrong kind.
#[derive(Debug)]
pub(super) struct MalformedProto;

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// One message being written, field by field.
#[derive(Default)]
pub(super) struct ProtoWriter(Vec<u8>);

impl ProtoWriter {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn key(&mut self, field: u32, wire: u64) {
        put_varint(&mut self.0, (u64::from(field) << 3) | wire);
    }

    /// An unsigned integer, an enum or a bool field.
    pub(super) fn uint(mut self, field: u32, value: u64) -> Self {
        self.key(field, VARINT);
        put_varint(&mut self.0, value);
        self
    }

    pub(super) fn bool(self, field: u32, value: bool) -> Self {
        self.uint(field, u64::from(value))
    }

    /// A `float` field.
    pub(super) fn float(mut self, field: u32, value: f32) -> Self {
        self.key(field, FIXED32);
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// A `bytes` field.
    pub(super) fn bytes(mut self, field: u32, value: &[u8]) -> Self {
        self.key(field, DELIMITED);
        put_varint(&mut self.0, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }

    pub(super) fn string(self, field: u32, value: &str) -> Self {
        self.bytes(field, value.as_bytes())
    }

    /// One `string` field for each of `values`, in order: a repeated field.
    pub(super) fn strings(self, field: u32, values: &[&str]) -> Self {
        values
            .iter()
            .fold(self, |writer, value| writer.string(field, value))
    }

    /// An embedded message field.
    pub(super) fn message(self, field: u32, value: Self) -> Self {
        self.bytes(field, &value.0)
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// One field's value as it lies on the wire.
#[derive(Clone, Copy)]
enum ProtoValue<'a> {
    Varint(u64),
    Delimited(&'a [u8]),
    /// A fixed-width value, which no reader of this module asks for.
    Fixed,
}

fn read_varint(rest: &mut &[u8]) -> Result<u64, MalformedProto> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let (&byte, tail) = rest.split_first().ok_or(MalformedProto)?;
        *rest = tail;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(MalformedProto)
}

fn skip(rest: &mut &[u8], width: usize) -> Result<(), MalformedProto> {
    *rest = rest.get(width..).ok_or(MalformedProto)?;
    Ok(())
}

fn next_field<'a>(rest: &mut &'a [u8]) -> Result<(u64, ProtoValue<'a>), MalformedProto> {
    let key = read_varint(rest)?;
    let value = match key & 0x07 {
        VARINT => ProtoValue::Varint(read_varint(rest)?),
        FIXED64 => {
            skip(rest, 8)?;
            ProtoValue::Fixed
        }
        DELIMITED => {
            let length = usize::try_from(read_varint(rest)?).map_err(|_| MalformedProto)?;
            let value = rest.get(..length).ok_or(MalformedProto)?;
            *rest = &rest[length..];
            ProtoValue::Delimited(value)
        }
        FIXED32 => {
            skip(rest, 4)?;
            ProtoValue::Fixed
        }
        _ => return Err(MalformedProto),
    };
    Ok((key >> 3, value))
}

/// One message as read off the wire. Each reader answers the field's last
/// value, as protobuf's own readers keep for a scalar field, and `None` for
/// a field the message does not carry.
#[derive(Clone, Copy)]
pub(super) struct ProtoMessage<'a>(pub(super) &'a [u8]);

impl<'a> ProtoMessage<'a> {
    fn last(self, field: u32) -> Result<Option<ProtoValue<'a>>, MalformedProto> {
        let mut rest = self.0;
        let mut found = None;
        while !rest.is_empty() {
            let (number, value) = next_field(&mut rest)?;
            if number == u64::from(field) {
                found = Some(value);
            }
        }
        Ok(found)
    }

    /// An unsigned integer, an enum or a bool field.
    pub(super) fn uint(self, field: u32) -> Result<Option<u64>, MalformedProto> {
        match self.last(field)? {
            None => Ok(None),
            Some(ProtoValue::Varint(value)) => Ok(Some(value)),
            Some(_) => Err(MalformedProto),
        }
    }

    /// An `int32` field: a negative value lies on the wire sign-extended to
    /// 64 bits.
    pub(super) fn int32(self, field: u32) -> Result<Option<i32>, MalformedProto> {
        self.uint(field)?
            .map(|value| i32::try_from(value.cast_signed()).map_err(|_| MalformedProto))
            .transpose()
    }

    /// A `bytes` field.
    pub(super) fn bytes(self, field: u32) -> Result<Option<&'a [u8]>, MalformedProto> {
        match self.last(field)? {
            None => Ok(None),
            Some(ProtoValue::Delimited(value)) => Ok(Some(value)),
            Some(_) => Err(MalformedProto),
        }
    }

    /// A `string` field.
    pub(super) fn string(self, field: u32) -> Result<Option<&'a str>, MalformedProto> {
        self.bytes(field)?
            .map(|value| std::str::from_utf8(value).map_err(|_| MalformedProto))
            .transpose()
    }

    /// An embedded message field.
    pub(super) fn message(self, field: u32) -> Result<Option<Self>, MalformedProto> {
        Ok(self.bytes(field)?.map(ProtoMessage))
    }

    /// The `string` field the last of `fields` names, in the message the
    /// fields before it name in turn, each inside the one before.
    pub(super) fn string_at(self, fields: &[u32]) -> Result<Option<&'a str>, MalformedProto> {
        let Some((last, outer)) = fields.split_last() else {
            return Ok(None);
        };
        let mut message = self;
        for field in outer {
            match message.message(*field)? {
                Some(inner) => message = inner,
                None => return Ok(None),
            }
        }
        message.string(*last)
    }
}
