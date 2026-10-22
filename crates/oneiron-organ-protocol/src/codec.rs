//! The protocol's own MessagePack codec (protocol 2.0, FIX 6191). Every
//! message, and every value inside one, encodes and decodes with no
//! recursion over the value's depth, so no depth or count of values holds a
//! message back; what bounds one is the memory its receiver books for it.
//!
//! The encoding is MessagePack with named fields: a struct is a map from
//! its field names, a unit variant is its name as a string, and any other
//! variant is a one-entry map from its name to its content. A string that
//! is not UTF-8 reads as a binary.
//!
//! One marker MessagePack leaves unused, `0xc1`, carries a length past
//! `u32`: `0xc1 | kind: u8 | len: u64 BE`, then the content as the shorter
//! forms carry it. Kind 0 is a string, 1 a binary, 2 an array, 3 a map, and
//! 4 an extension, whose type byte follows the length. An encoder writes it
//! only for such a length, so a value under 4 GiB a field is plain
//! MessagePack.
//!
//! A typed field's own decode recurses only as deep as its type does. A type
//! that buffers its input to read it (an internally tagged or untagged
//! enum) nests as deep as that input, so the typed decoder stops past
//! [`TYPED_DEPTH`] nested containers with a typed refusal rather than
//! overrunning its thread's stack. A [`crate::Value`] never counts toward
//! it: values carry any depth.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::value::{Open, Value};

mod de;
mod ser;

/// How deep a typed field's own containers nest before the typed decoder
/// refuses it: the decoder's stack floor. A [`crate::Value`] never counts.
pub const TYPED_DEPTH: usize = 256;

/// Why bytes did not encode or decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("the encoding is cut short")]
    Eof,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Message(String),
}

impl serde::ser::Error for CodecError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

impl serde::de::Error for CodecError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

/// `value`'s encoding.
///
/// # Errors
/// The value does not encode (a sequence or map of unknown length, or a
/// serializer's own refusal).
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CodecError> {
    let len = encoded_len(value)?;
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    write_into(&mut out, value)?;
    Ok(out)
}

/// The bytes `value` encodes to, counted with nothing allocated for them.
///
/// # Errors
/// As [`to_vec`].
pub fn encoded_len<T: Serialize + ?Sized>(value: &T) -> Result<u64, CodecError> {
    let mut count = Count(0);
    value.serialize(&mut ser::Serializer::new(&mut count))?;
    Ok(count.0)
}

/// Appends `value`'s encoding to `out`.
///
/// # Errors
/// As [`to_vec`].
pub(crate) fn write_into<T: Serialize + ?Sized>(
    out: &mut Vec<u8>,
    value: &T,
) -> Result<(), CodecError> {
    value.serialize(&mut ser::Serializer::new(out))
}

/// One `T` read from `bytes`, which must hold nothing after it.
///
/// # Errors
/// The bytes are not one encoded `T`.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let mut deserializer = de::Deserializer::new(bytes);
    let value = T::deserialize(&mut deserializer)?;
    if deserializer.finished() {
        Ok(value)
    } else {
        Err(CodecError::Invalid("bytes after the value"))
    }
}

/// `value` as a [`Value`], by its field names.
///
/// # Errors
/// As [`to_vec`].
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, CodecError> {
    crate::value::decode_value(&to_vec(value)?)
}

/// `value` read as a `T`, by its field names.
///
/// # Errors
/// The value is not a `T`.
pub fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T, CodecError> {
    from_slice(&to_vec(value)?)
}

/// Where an encoder writes.
pub(crate) trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// A sink that only counts.
struct Count(u64);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 = self.0.saturating_add(bytes.len() as u64);
    }
}

/// What a length marker heads.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Str = 0,
    Bin = 1,
    Array = 2,
    Map = 3,
    Ext = 4,
}

/// One header as the encoder writes it: a marker and its length or scalar.
pub(crate) struct Head {
    bytes: [u8; 11],
    len: usize,
}

impl Head {
    fn of(bytes: &[u8]) -> Self {
        let mut head = Self {
            bytes: [0; 11],
            len: 0,
        };
        head.push(bytes);
        head
    }

    fn push(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub(crate) fn nil() -> Self {
        Self::of(&[0xc0])
    }

    pub(crate) fn bool(flag: bool) -> Self {
        Self::of(&[if flag { 0xc3 } else { 0xc2 }])
    }

    /// An integer in its shortest form: an unsigned one for any value at
    /// or above zero, a signed one below.
    pub(crate) fn integer(value: i128) -> Self {
        if let Ok(unsigned) = u64::try_from(value) {
            return Self::uint(unsigned);
        }
        let signed = i64::try_from(value).unwrap_or(i64::MIN);
        if signed >= -32 {
            Self::of(&[signed as u8])
        } else if let Ok(small) = i8::try_from(signed) {
            Self::marked(0xd0, &small.to_be_bytes())
        } else if let Ok(small) = i16::try_from(signed) {
            Self::marked(0xd1, &small.to_be_bytes())
        } else if let Ok(small) = i32::try_from(signed) {
            Self::marked(0xd2, &small.to_be_bytes())
        } else {
            Self::marked(0xd3, &signed.to_be_bytes())
        }
    }

    pub(crate) fn uint(value: u64) -> Self {
        if value < 0x80 {
            Self::of(&[value as u8])
        } else if let Ok(small) = u8::try_from(value) {
            Self::marked(0xcc, &[small])
        } else if let Ok(small) = u16::try_from(value) {
            Self::marked(0xcd, &small.to_be_bytes())
        } else if let Ok(small) = u32::try_from(value) {
            Self::marked(0xce, &small.to_be_bytes())
        } else {
            Self::marked(0xcf, &value.to_be_bytes())
        }
    }

    pub(crate) fn f32(value: f32) -> Self {
        Self::marked(0xca, &value.to_bits().to_be_bytes())
    }

    pub(crate) fn f64(value: f64) -> Self {
        Self::marked(0xcb, &value.to_bits().to_be_bytes())
    }

    pub(crate) fn str(len: u64) -> Self {
        if len < 32 {
            Self::of(&[0xa0 | len as u8])
        } else {
            Self::sized(Kind::Str, len, [Some(0xd9), Some(0xda), Some(0xdb)])
        }
    }

    pub(crate) fn bin(len: u64) -> Self {
        Self::sized(Kind::Bin, len, [Some(0xc4), Some(0xc5), Some(0xc6)])
    }

    pub(crate) fn array(len: u64) -> Self {
        if len < 16 {
            Self::of(&[0x90 | len as u8])
        } else {
            Self::sized(Kind::Array, len, [None, Some(0xdc), Some(0xdd)])
        }
    }

    pub(crate) fn map(len: u64) -> Self {
        if len < 16 {
            Self::of(&[0x80 | len as u8])
        } else {
            Self::sized(Kind::Map, len, [None, Some(0xde), Some(0xdf)])
        }
    }

    /// An extension's header: its length, then its type.
    pub(crate) fn ext(kind: i8, len: u64) -> Self {
        let fixed = match len {
            1 => Some(0xd4),
            2 => Some(0xd5),
            4 => Some(0xd6),
            8 => Some(0xd7),
            16 => Some(0xd8),
            _ => None,
        };
        let mut head = match fixed {
            Some(marker) => Self::of(&[marker]),
            None => Self::sized(Kind::Ext, len, [Some(0xc7), Some(0xc8), Some(0xc9)]),
        };
        head.push(&kind.to_be_bytes());
        head
    }

    fn marked(marker: u8, rest: &[u8]) -> Self {
        let mut head = Self::of(&[marker]);
        head.push(rest);
        head
    }

    /// A length in the shortest of the 8-, 16- and 32-bit `markers` that
    /// holds it, or past `u32` in the long form.
    fn sized(kind: Kind, len: u64, markers: [Option<u8>; 3]) -> Self {
        match markers {
            [Some(marker), ..] if len <= 0xff => Self::marked(marker, &[len as u8]),
            [_, Some(marker), _] if len <= 0xffff => {
                Self::marked(marker, &(len as u16).to_be_bytes())
            }
            [_, _, Some(marker)] if len <= u64::from(u32::MAX) => {
                Self::marked(marker, &(len as u32).to_be_bytes())
            }
            _ => {
                let mut head = Self::of(&[0xc1, kind as u8]);
                head.push(&len.to_be_bytes());
                head
            }
        }
    }
}

/// One MessagePack token: a scalar with what it carries, or a container's
/// header with the count of values it holds.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Token<'a> {
    Nil,
    Bool(bool),
    Uint(u64),
    Int(i64),
    F32(f32),
    F64(f64),
    Str(&'a [u8]),
    Bin(&'a [u8]),
    Ext(i8, &'a [u8]),
    Array(u64),
    Map(u64),
}

/// Reads tokens from bytes in order.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub(crate) fn at(&self) -> usize {
        self.at
    }

    pub(crate) fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.at == self.bytes.len()
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    pub(crate) fn since(&self, from: usize) -> &'a [u8] {
        &self.bytes[from..self.at]
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], CodecError> {
        let len = usize::try_from(len).map_err(|_| CodecError::Eof)?;
        let end = self.at.checked_add(len).ok_or(CodecError::Eof)?;
        let taken = self.bytes.get(self.at..end).ok_or(CodecError::Eof)?;
        self.at = end;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// A big-endian unsigned integer of `width` bytes.
    fn be(&mut self, width: u64) -> Result<u64, CodecError> {
        Ok(self
            .take(width)?
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    fn ext(&mut self, len: u64) -> Result<Token<'a>, CodecError> {
        let kind = self.byte()? as i8;
        Ok(Token::Ext(kind, self.take(len)?))
    }

    fn long(&mut self) -> Result<Token<'a>, CodecError> {
        let kind = self.byte()?;
        let len = self.be(8)?;
        Ok(match kind {
            0 => Token::Str(self.take(len)?),
            1 => Token::Bin(self.take(len)?),
            2 => Token::Array(len),
            3 => Token::Map(len),
            4 => self.ext(len)?,
            _ => return Err(CodecError::Invalid("an unknown kind of long length")),
        })
    }

    /// The next token.
    ///
    /// # Errors
    /// The bytes end inside it, or it is a long length of no known kind.
    pub(crate) fn token(&mut self) -> Result<Token<'a>, CodecError> {
        let marker = self.byte()?;
        Ok(match marker {
            0x00..=0x7f => Token::Uint(u64::from(marker)),
            0x80..=0x8f => Token::Map(u64::from(marker & 0x0f)),
            0x90..=0x9f => Token::Array(u64::from(marker & 0x0f)),
            0xa0..=0xbf => Token::Str(self.take(u64::from(marker & 0x1f))?),
            0xc0 => Token::Nil,
            0xc1 => self.long()?,
            0xc2 => Token::Bool(false),
            0xc3 => Token::Bool(true),
            0xc4..=0xc6 => {
                let len = self.be(1 << (marker - 0xc4))?;
                Token::Bin(self.take(len)?)
            }
            0xc7..=0xc9 => {
                let len = self.be(1 << (marker - 0xc7))?;
                self.ext(len)?
            }
            0xca => Token::F32(f32::from_bits(self.be(4)? as u32)),
            0xcb => Token::F64(f64::from_bits(self.be(8)?)),
            0xcc..=0xcf => Token::Uint(self.be(1 << (marker - 0xcc))?),
            0xd0 => Token::Int(i64::from(self.be(1)? as u8 as i8)),
            0xd1 => Token::Int(i64::from(self.be(2)? as u16 as i16)),
            0xd2 => Token::Int(i64::from(self.be(4)? as u32 as i32)),
            0xd3 => Token::Int(self.be(8)? as i64),
            0xd4..=0xd8 => self.ext(1 << (marker - 0xd4))?,
            0xd9..=0xdb => {
                let len = self.be(1 << (marker - 0xd9))?;
                Token::Str(self.take(len)?)
            }
            0xdc | 0xdd => Token::Array(self.be(2 << (marker - 0xdc))?),
            0xde | 0xdf => Token::Map(self.be(2 << (marker - 0xde))?),
            0xe0..=0xff => Token::Int(i64::from(marker as i8)),
        })
    }

    /// Steps past one whole value, however deep, with a count and no
    /// stack.
    ///
    /// # Errors
    /// The bytes end inside it.
    pub(crate) fn skip(&mut self) -> Result<(), CodecError> {
        let mut owed = 1u64;
        while owed > 0 {
            owed -= 1;
            match self.token()? {
                Token::Array(len) => owed = owed.saturating_add(len),
                Token::Map(len) => owed = owed.saturating_add(len.saturating_mul(2)),
                _ => {}
            }
            if owed > self.left() as u64 {
                return Err(CodecError::Eof);
            }
        }
        Ok(())
    }
}

/// What one message's encoding holds, read off its tokens.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Shape {
    values: u64,
    /// Arrays and maps that hold anything.
    containers: u64,
    /// The bytes of its strings, binaries and extensions.
    payload: u64,
}

impl Shape {
    /// At most what decoding the message allocates: each value one
    /// [`Value`] at most, a typed one no more; each container one more
    /// step of the decoder's own stack while it fills; and the bytes of its
    /// strings, binaries and extensions beside.
    pub(crate) fn decoded(self) -> u64 {
        let value = std::mem::size_of::<Value>() as u64;
        let open = std::mem::size_of::<Open>() as u64;
        self.values
            .saturating_mul(value)
            .saturating_add(self.containers.saturating_mul(open))
            .saturating_add(self.payload)
    }
}

/// Walks one message's encoding once, allocating nothing, and says what it
/// holds ([`Shape::decoded`]), so a receiver can make room for its value
/// before building it. Refuses only bytes that are not one MessagePack
/// value: there is no limit on its depth or on how many values it holds.
///
/// # Errors
/// The bytes are not one MessagePack value.
pub(crate) fn shape(bytes: &[u8]) -> Result<Shape, CodecError> {
    let mut reader = Reader::new(bytes);
    let mut shape = Shape::default();
    let mut owed = 1u64;
    while owed > 0 {
        owed -= 1;
        shape.values += 1;
        match reader.token()? {
            Token::Str(carried) | Token::Bin(carried) | Token::Ext(_, carried) => {
                shape.payload = shape.payload.saturating_add(carried.len() as u64);
            }
            Token::Array(len) if len > 0 => {
                shape.containers += 1;
                owed = owed.saturating_add(len);
            }
            Token::Map(len) if len > 0 => {
                shape.containers += 1;
                owed = owed.saturating_add(len.saturating_mul(2));
            }
            _ => {}
        }
        // Every value takes at least one byte.
        if owed > reader.left() as u64 {
            return Err(CodecError::Invalid(
                "a container claims more values than the bytes hold",
            ));
        }
    }
    if reader.is_empty() {
        Ok(shape)
    } else {
        Err(CodecError::Invalid("bytes after the message's value"))
    }
}
