//! FIX 3677: [`super::attaches_as_file`] read as a body streams, so an
//! archive file is classified with no file-sized buffer. The UTF-8 test
//! carries a character split between two reads; the owning adapters' tags
//! are read at the head, where each names itself; and the pack catalog's
//! marker is found as its codec finds it, at any field position, by walking
//! the first MessagePack value without holding it. Every byte is read, and
//! nothing is refused for its size or shape here: a body judged as it
//! streams is judged as the whole-slice test judges it (CALLS "FIX 3677
//! stream classifier equivalence").

use std::io::{self, Read};

use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;

/// The bytes of a body's head its owning adapters' tags are read from:
/// each tag is a prefix shorter than this.
const HEAD: usize = 64;
/// The longest marker value read to be judged: a longer one is no format
/// tag, so the decode reads no pack source either way.
const FORMAT_VALUE: usize = 1024;
/// The nesting `rmp_serde` decodes a value within; the marker's own map or
/// array spends one level of it.
const DEPTH: usize = 1024;
/// How much of a body one read takes.
const CHUNK: usize = 64 * 1024;

/// [`super::attaches_as_file`] for the body `read` yields, read to its end
/// and never held whole.
///
/// # Errors
///
/// The reader's errors.
pub(crate) fn attaches_as_file_read(entity_type: u8, read: &mut dyn Read) -> Result<bool> {
    let mut body = Stream::new(read);
    let marker = entity_type == ENTITY_TYPE_ASSET && pack_marker(&mut body)?;
    body.drain()?;
    // A tag is shorter than the head, so a codec reads the head as it reads
    // the whole body: no tagged head is untagged whole, and no other is.
    let head = &body.head[..body.head_len];
    Ok(entity_type == ENTITY_TYPE_ASSET
        && !body.utf8.text()
        && matches!(crate::skill_hub::decode_source_carrier(head), Ok(None))
        && !marker
        && !crate::receipt::is_receipt_archive_source(head))
}

/// A body read through once: each chunk passes the UTF-8 test and fills the
/// head as it is read, whatever part of the walk takes its bytes.
struct Stream<'r> {
    read: &'r mut dyn Read,
    chunk: Vec<u8>,
    at: usize,
    end: usize,
    utf8: Utf8,
    head: [u8; HEAD],
    head_len: usize,
}

impl<'r> Stream<'r> {
    fn new(read: &'r mut dyn Read) -> Self {
        Self {
            read,
            chunk: vec![0; CHUNK],
            at: 0,
            end: 0,
            utf8: Utf8::default(),
            head: [0; HEAD],
            head_len: 0,
        }
    }

    /// Whether a byte is left to take, reading the next chunk when none is.
    fn more(&mut self) -> Result<bool> {
        while self.at == self.end {
            let read = match self.read.read(&mut self.chunk) {
                Ok(0) => return Ok(false),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let bytes = &self.chunk[..read];
            self.utf8.feed(bytes);
            let room = (HEAD - self.head_len).min(read);
            self.head[self.head_len..self.head_len + room].copy_from_slice(&bytes[..room]);
            self.head_len += room;
            self.at = 0;
            self.end = read;
        }
        Ok(true)
    }

    /// The next byte; `None` at the body's end.
    fn byte(&mut self) -> Result<Option<u8>> {
        if !self.more()? {
            return Ok(None);
        }
        self.at += 1;
        Ok(Some(self.chunk[self.at - 1]))
    }

    /// Passes over `len` bytes; `false` when the body ends first.
    fn skip(&mut self, mut len: u64) -> Result<bool> {
        while len > 0 {
            if !self.more()? {
                return Ok(false);
            }
            let take = (self.end - self.at).min(usize::try_from(len).unwrap_or(usize::MAX));
            self.at += take;
            len -= take as u64;
        }
        Ok(true)
    }

    /// The next `width` bytes as a big-endian number; `None` when the body
    /// ends first.
    fn number(&mut self, width: usize) -> Result<Option<u64>> {
        let mut value = 0_u64;
        for _ in 0..width {
            let Some(byte) = self.byte()? else {
                return Ok(None);
            };
            value = (value << 8) | u64::from(byte);
        }
        Ok(Some(value))
    }

    /// The next `len` bytes; `None` when the body ends first.
    fn bytes(&mut self, len: usize) -> Result<Option<Vec<u8>>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if !self.more()? {
                return Ok(None);
            }
            let take = (self.end - self.at).min(len - out.len());
            out.extend_from_slice(&self.chunk[self.at..self.at + take]);
            self.at += take;
        }
        Ok(Some(out))
    }

    /// Reads the rest of the body.
    fn drain(&mut self) -> Result<()> {
        self.at = self.end;
        while self.more()? {
            self.at = self.end;
        }
        Ok(())
    }
}

/// UTF-8 checked across reads, a character split between two carried.
#[derive(Default)]
struct Utf8 {
    broken: bool,
    carry: [u8; 4],
    carry_len: usize,
}

impl Utf8 {
    fn feed(&mut self, mut bytes: &[u8]) {
        while self.carry_len > 0 && !self.broken {
            let Some((first, after)) = bytes.split_first() else {
                return;
            };
            self.carry[self.carry_len] = *first;
            self.carry_len += 1;
            bytes = after;
            match std::str::from_utf8(&self.carry[..self.carry_len]) {
                Ok(_) => self.carry_len = 0,
                Err(error) if error.error_len().is_some() || self.carry_len == 4 => {
                    self.broken = true;
                }
                Err(_) => {}
            }
        }
        if self.broken {
            return;
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.broken = true;
            } else {
                let tail = &bytes[error.valid_up_to()..];
                self.carry[..tail.len()].copy_from_slice(tail);
                self.carry_len = tail.len();
            }
        }
    }

    /// Whether every byte fed was UTF-8, the last character whole.
    const fn text(&self) -> bool {
        !self.broken && self.carry_len == 0
    }
}

/// A map key as the marker's field visitor reads it.
enum Field {
    /// `format`, by name (a string or binary) or by index (an unsigned 0).
    Format,
    /// Any other name or index, or a string of invalid UTF-8: skipped.
    Other,
    /// A key the visitor refuses, or one the body ends inside.
    Refused,
}

/// Whether the body opens with the pack catalog's marker, as its codec
/// reads it ([`crate::skill_hub::pack_catalog::decode_source_body`]):
/// `rmp_serde` decodes `Marker { format: String }` from the first
/// MessagePack value, a map of fields in any order with unknown fields
/// skipped, or an array of exactly its one field, and the codec takes that
/// `format` for its own. Bytes after that value are not read by the
/// decode. Whatever the decode refuses is no marker, and a format that is
/// not the codec's leaves no marker whatever follows, so the walk stops at
/// the first of either.
fn pack_marker(body: &mut Stream<'_>) -> Result<bool> {
    let Some(lead) = body.byte()? else {
        return Ok(false);
    };
    if !matches!(lead, 0x80..=0x9f | 0xdc..=0xdf) {
        return Ok(false);
    }
    let Some(len) = declared(body, lead)? else {
        return Ok(false);
    };
    if matches!(lead, 0x90..=0x9f | 0xdc | 0xdd) {
        return Ok(len == 1 && format_value(body)?);
    }
    let mut format = false;
    for _ in 0..len {
        match field(body)? {
            Field::Format if !format => {
                if !format_value(body)? {
                    return Ok(false);
                }
                format = true;
            }
            Field::Other => {
                if !skip_value(body, DEPTH - 1)? {
                    return Ok(false);
                }
            }
            // A second `format`, or a key the visitor refuses.
            Field::Format | Field::Refused => return Ok(false),
        }
    }
    Ok(format)
}

/// The length a string, binary, array or map marker `lead` declares, in it
/// or in the big-endian bytes after it; `None` for another marker, or when
/// the body ends first.
fn declared(body: &mut Stream<'_>, lead: u8) -> Result<Option<u64>> {
    match lead {
        0x80..=0x9f => Ok(Some(u64::from(lead & 0x0f))),
        0xa0..=0xbf => Ok(Some(u64::from(lead & 0x1f))),
        0xc4 | 0xd9 => body.number(1),
        0xc5 | 0xda | 0xdc | 0xde => body.number(2),
        0xc6 | 0xdb | 0xdd | 0xdf => body.number(4),
        _ => Ok(None),
    }
}

/// A map key as `Marker`'s field visitor reads it: a name compared as its
/// bytes, or an unsigned index; any other value it refuses.
fn field(body: &mut Stream<'_>) -> Result<Field> {
    const NAME: &[u8] = b"format";
    let Some(lead) = body.byte()? else {
        return Ok(Field::Refused);
    };
    let index = match lead {
        0x00..=0x7f => Some(u64::from(lead)),
        0xcc => body.number(1)?,
        0xcd => body.number(2)?,
        0xce => body.number(4)?,
        0xcf => body.number(8)?,
        0xa0..=0xbf | 0xc4..=0xc6 | 0xd9..=0xdb => {
            let Some(len) = declared(body, lead)? else {
                return Ok(Field::Refused);
            };
            let named = if len == NAME.len() as u64 {
                body.bytes(NAME.len())?.map(|name| name == NAME)
            } else {
                body.skip(len)?.then_some(false)
            };
            return Ok(match named {
                Some(true) => Field::Format,
                Some(false) => Field::Other,
                None => Field::Refused,
            });
        }
        _ => return Ok(Field::Refused),
    };
    Ok(match index {
        Some(0) => Field::Format,
        Some(_) => Field::Other,
        None => Field::Refused,
    })
}

/// Whether the `format` field's value, as the decode reads it into a
/// `String` (a string or binary of UTF-8), is the codec's own format, which
/// the pack catalog's codec judges itself from a marker holding only it.
fn format_value(body: &mut Stream<'_>) -> Result<bool> {
    let Some(lead) = body.byte()? else {
        return Ok(false);
    };
    if !matches!(lead, 0xa0..=0xbf | 0xc4..=0xc6 | 0xd9..=0xdb) {
        return Ok(false);
    }
    let Some(len) = declared(body, lead)? else {
        return Ok(false);
    };
    let Ok(len) = usize::try_from(len) else {
        return Ok(false);
    };
    if len > FORMAT_VALUE {
        return Ok(false);
    }
    let Some(value) = body.bytes(len)? else {
        return Ok(false);
    };
    let Ok(width) = u16::try_from(len) else {
        return Ok(false);
    };
    // `{"format": <value as binary>}`, the marker alone.
    let mut marker = vec![0x81, 0xa6];
    marker.extend_from_slice(b"format");
    marker.push(0xc5);
    marker.extend_from_slice(&width.to_be_bytes());
    marker.extend_from_slice(&value);
    Ok(!matches!(
        crate::skill_hub::pack_catalog::decode_source_body(&marker),
        Ok(None)
    ))
}

/// Passes over one value as the decode skips a field it does not know
/// (`IgnoredAny`): whether the value is whole and nests within `depth`, the
/// levels the decode has left. An array, a map and an extension each spend
/// one level, an empty one too.
fn skip_value(body: &mut Stream<'_>, depth: usize) -> Result<bool> {
    // The values left in each array or map the walk is inside.
    let mut open: Vec<u64> = Vec::new();
    loop {
        let Some(lead) = body.byte()? else {
            return Ok(false);
        };
        let whole = match lead {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => true,
            0xcc | 0xd0 => body.skip(1)?,
            0xcd | 0xd1 => body.skip(2)?,
            0xca | 0xce | 0xd2 => body.skip(4)?,
            0xcb | 0xcf | 0xd3 => body.skip(8)?,
            0xa0..=0xbf | 0xc4..=0xc6 | 0xd9..=0xdb => match declared(body, lead)? {
                Some(len) => body.skip(len)?,
                None => false,
            },
            0xc7..=0xc9 | 0xd4..=0xd8 => {
                let len = match lead {
                    0xc7 => body.number(1)?,
                    0xc8 => body.number(2)?,
                    0xc9 => body.number(4)?,
                    _ => Some(1_u64 << (lead - 0xd4)),
                };
                // Its type byte, then its data.
                match len {
                    Some(len) if depth > open.len() + 1 => body.skip(len + 1)?,
                    _ => false,
                }
            }
            0x80..=0x9f | 0xdc..=0xdf => {
                let Some(len) = declared(body, lead)? else {
                    return Ok(false);
                };
                if depth <= open.len() + 1 {
                    return Ok(false);
                }
                let values = if matches!(lead, 0x80..=0x8f | 0xde | 0xdf) {
                    len * 2
                } else {
                    len
                };
                if values > 0 {
                    open.push(values);
                    continue;
                }
                true
            }
            // 0xc1, which no value starts with.
            _ => false,
        };
        if !whole {
            return Ok(false);
        }
        // The value is whole: so is each container it was the last of.
        loop {
            let Some(left) = open.last_mut() else {
                return Ok(true);
            };
            *left -= 1;
            if *left > 0 {
                break;
            }
            open.pop();
        }
    }
}
