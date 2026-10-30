//! The release doors' whole read of a value: its text, and its encoding as
//! the write door reads a body's bytes.
//!
//! A re-encoding writes each number at its narrowest width, so letters that a
//! wider header kept apart in a body's stored bytes read joined in it, and a
//! body the write door accepted would be withheld for bytes it never held. A
//! door that has the stored bytes reads them instead, wherever the value is
//! still as it was decoded ([`Encoding::Stored`]).

use std::collections::HashMap;

use rmpv::Value;
use zeroize::Zeroizing;

use super::{
    Door, byte_values, credential_field, detect, detect_bytes, joined_messagepack,
    sanitize_messagepack,
};

/// The release doors' reading of a whole decoded value once its parts are
/// judged: every text it carries, one per line in order, at any depth (each
/// string and map key, binary and extension bytes, each array of byte values).
/// A walk that judges each part, and each array's items joined, can still
/// leave a secret spread over parts it keeps apart (a phrase one word per
/// nested item), as the write door reads it in a body's raw bytes; a value
/// that reads as one leaves whole-redacted. The value's own encoding is also
/// read as the write door reads a body: there a number, a length or a header
/// carries bytes as a string does.
pub(crate) fn release_reads_whole(value: &rmpv::Value) -> bool {
    release_reads_whole_in(value, Encoding::Own)
}

/// [`release_reads_whole`] over a JSON value. A JSON value can be the
/// projection of a MessagePack body, so it is also read through the
/// MessagePack it projects from: a float as either width it may have had.
pub(crate) fn release_reads_whole_json(value: &serde_json::Value) -> bool {
    if release_reads_json_text(value) {
        return true;
    }
    let mut narrows = false;
    write_door_refuses_encoding(&messagepack_form(value, false, &mut narrows))
        || (narrows && write_door_refuses_encoding(&messagepack_form(value, true, &mut narrows)))
}

/// [`release_reads_whole_json`] over the text alone, for JSON whose stored
/// encoding was already read as stored.
pub(crate) fn release_reads_json_text(value: &serde_json::Value) -> bool {
    // The joined text is wiped on drop (FIX 12047).
    let mut text = Zeroizing::new(String::new());
    json_leaves(value, &mut text);
    detect(&text, Door::Release).is_some()
}

/// The parts a release door emits from one body, read before it projects them
/// (a projection loses a float's width and a byte's type): whether one part,
/// once its parts are judged, or all of them together, still reads as a
/// secret as [`release_reads_whole`] reads it. A `verbatim` part is served as
/// it is or not at all, never with a part of it nulled, so it is read as it
/// is, alone and in the joint read.
pub(crate) fn release_parts_read_whole(verbatim: &[&rmpv::Value], parts: &[&rmpv::Value]) -> bool {
    // A part none of whose parts reads as a secret is its own judged copy:
    // it is read in place and joined by reference, never copied (speed).
    for part in verbatim {
        // The joined text is wiped on drop (FIX 12047).
        let mut leaves = Zeroizing::new(String::new());
        if part_reads_as_secret(part, &mut leaves)
            || detect(&leaves, Door::Release).is_some()
            || write_door_refuses_encoding(part)
        {
            return true;
        }
    }
    let mut copies: Vec<Option<Value>> = Vec::with_capacity(parts.len());
    for part in parts {
        let mut leaves = Zeroizing::new(String::new());
        if part_reads_as_secret(part, &mut leaves) {
            let mut copy = (*part).clone();
            sanitize_messagepack(&mut copy, true, Door::Release);
            if release_reads_whole(&copy) {
                return true;
            }
            copies.push(Some(copy));
        } else {
            if detect(&leaves, Door::Release).is_some() || write_door_refuses_encoding(part) {
                return true;
            }
            copies.push(None);
        }
    }
    let judged: Vec<&Value> = verbatim
        .iter()
        .copied()
        .chain(
            parts
                .iter()
                .zip(&copies)
                .map(|(part, copy)| copy.as_ref().unwrap_or(*part)),
        )
        .collect();
    array_reads_whole(&judged)
}

/// [`release_reads_whole`] over the array `items` make, read in place: its
/// leaves, and its encoding as `rmpv` writes an array of them.
fn array_reads_whole(items: &[&Value]) -> bool {
    // The joined text is wiped on drop (FIX 12047).
    let mut text = Zeroizing::new(String::new());
    match byte_values(items.iter().copied().map(Value::as_u64)) {
        Some(bytes) if !bytes.is_empty() => push_line(&mut text, &Zeroizing::new(bytes)),
        _ => items
            .iter()
            .for_each(|item| messagepack_leaves(item, &mut text)),
    }
    if detect(&text, Door::Release).is_some() {
        return true;
    }
    let mut bytes = Vec::new();
    write_array_len(&mut bytes, items.len());
    items
        .iter()
        .any(|item| rmpv::encode::write_value(&mut bytes, item).is_err())
        || write_door_refuses_raw(&bytes)
}

/// Whether a part of `value` reads as a secret as the release door's walk
/// judges its parts, read in place: what [`sanitize_messagepack`] returns
/// (`messagepack_has_secret`). While none does, each leaf is pushed to
/// `leaves` as [`messagepack_leaves`] pushes it, in its order, so one walk
/// gives both: a value no part of which reads as a secret is its own judged
/// copy, and `leaves` is that copy's joined text.
fn part_reads_as_secret(value: &Value, leaves: &mut Zeroizing<String>) -> bool {
    match value {
        Value::String(text) => leaf_reads_as_secret(text.as_bytes(), leaves),
        Value::Binary(bytes) | Value::Ext(_, bytes) => leaf_reads_as_secret(bytes, leaves),
        Value::Array(values) => {
            let bytes = byte_values(values.iter().map(Value::as_u64)).map(Zeroizing::new);
            if bytes
                .as_ref()
                .is_some_and(|bytes| detect_bytes(bytes, Door::Release))
                || joined_messagepack(values, Door::Release)
            {
                return true;
            }
            // An array of byte values holds no part the walk judges apart.
            match bytes {
                Some(bytes) if !bytes.is_empty() => {
                    push_line(leaves, &bytes);
                    false
                }
                _ => values
                    .iter()
                    .any(|value| part_reads_as_secret(value, leaves)),
            }
        }
        Value::Map(entries) => entries.iter().any(|(key, value)| {
            part_reads_as_secret(key, leaves)
                || key.as_str().is_some_and(|key| {
                    credential_field(key, value.is_nil(), value.as_str(), Door::Release)
                })
                || part_reads_as_secret(value, leaves)
        }),
        _ => false,
    }
}

/// [`part_reads_as_secret`] over one leaf's bytes.
fn leaf_reads_as_secret(bytes: &[u8], leaves: &mut Zeroizing<String>) -> bool {
    if detect_bytes(bytes, Door::Release) {
        return true;
    }
    push_line(leaves, bytes);
    false
}

/// The write door's text rules over bytes a release door returns as they are
/// stored: an encoding can differ from the value's own (a wider header, a
/// length that reads as a line break), and the write door reads the bytes.
pub(crate) fn write_door_refuses_raw(bytes: &[u8]) -> bool {
    detect_bytes(bytes, Door::Write)
}

/// The write door's text rules over a value's MessagePack encoding, the raw
/// bytes it reads in a body. A value that cannot be encoded reads as a secret.
fn write_door_refuses_encoding(value: &rmpv::Value) -> bool {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).is_err() || write_door_refuses_raw(&bytes)
}

/// A JSON value as MessagePack. `narrow` writes a float that a single-width
/// float holds exactly at that width; `narrows` records whether there is one.
fn messagepack_form(value: &serde_json::Value, narrow: bool, narrows: &mut bool) -> rmpv::Value {
    use serde_json::Value;
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(flag) => rmpv::Value::Boolean(*flag),
        Value::Number(number) => {
            if let Some(number) = number.as_u64() {
                return rmpv::Value::from(number);
            }
            if let Some(number) = number.as_i64() {
                return rmpv::Value::from(number);
            }
            let number = number.as_f64().unwrap_or_default();
            let single = number as f32;
            if f64::from(single) == number {
                *narrows = true;
                if narrow {
                    return rmpv::Value::F32(single);
                }
            }
            rmpv::Value::F64(number)
        }
        Value::String(text) => rmpv::Value::from(text.as_str()),
        Value::Array(values) => rmpv::Value::Array(
            values
                .iter()
                .map(|value| messagepack_form(value, narrow, narrows))
                .collect(),
        ),
        Value::Object(fields) => rmpv::Value::Map(
            fields
                .iter()
                .map(|(key, value)| {
                    (
                        rmpv::Value::from(key.as_str()),
                        messagepack_form(value, narrow, narrows),
                    )
                })
                .collect(),
        ),
    }
}

fn messagepack_leaves(value: &rmpv::Value, out: &mut Zeroizing<String>) {
    use rmpv::Value;
    match value {
        Value::String(text) => push_line(out, text.as_bytes()),
        Value::Binary(bytes) | Value::Ext(_, bytes) => push_line(out, bytes),
        Value::Array(values) => match byte_values(values.iter().map(Value::as_u64)) {
            Some(bytes) if !bytes.is_empty() => push_line(out, &Zeroizing::new(bytes)),
            _ => values
                .iter()
                .for_each(|value| messagepack_leaves(value, out)),
        },
        Value::Map(entries) => entries.iter().for_each(|(key, value)| {
            messagepack_leaves(key, out);
            messagepack_leaves(value, out);
        }),
        _ => {}
    }
}

fn json_leaves(value: &serde_json::Value, out: &mut Zeroizing<String>) {
    use serde_json::Value;
    match value {
        Value::String(text) => push_line(out, text.as_bytes()),
        Value::Array(values) => match byte_values(values.iter().map(Value::as_u64)) {
            Some(bytes) if !bytes.is_empty() => push_line(out, &Zeroizing::new(bytes)),
            _ => values.iter().for_each(|value| json_leaves(value, out)),
        },
        Value::Object(fields) => fields.iter().for_each(|(key, value)| {
            push_line(out, key.as_bytes());
            json_leaves(value, out);
        }),
        _ => {}
    }
}

fn push_line(out: &mut Zeroizing<String>, bytes: &[u8]) {
    // Borrowed valid UTF-8 copies nothing, else a lossy copy wiped on drop
    // (FIX 12047).
    match JoinedText::from_bytes(bytes) {
        JoinedText::Borrowed(text) => out.push_str(text),
        JoinedText::Owned(text) => out.push_str(&text),
    }
    out.push('\n');
}

/// Where a release door reads a decoded value's encoding from.
#[derive(Clone, Copy)]
pub(crate) enum Encoding<'a> {
    /// No stored bytes: the value's own encoding.
    Own,
    /// The MessagePack `original` was decoded from: read as stored wherever
    /// the value is as it was decoded.
    Stored {
        original: &'a Value,
        bytes: &'a [u8],
    },
    /// Text that never was MessagePack (a body stored as JSON): it has no
    /// encoding but its text.
    Text,
}

/// [`release_reads_whole`] with the value's encoding read from
/// `encoding`. An encoding that cannot be written reads as a secret.
pub(crate) fn release_reads_whole_in(value: &Value, encoding: Encoding<'_>) -> bool {
    // The joined text is wiped on drop (FIX 12047).
    let mut text = Zeroizing::new(String::new());
    messagepack_leaves(value, &mut text);
    if detect(&text, Door::Release).is_some() {
        return true;
    }
    match encoding {
        Encoding::Own => write_door_refuses_encoding(value),
        Encoding::Stored { original, bytes } => encode_as_stored(value, original, bytes)
            .is_none_or(|bytes| write_door_refuses_raw(&bytes)),
        Encoding::Text => false,
    }
}

/// [`super::sanitize_messagepack_credentials`] with the whole read taken from
/// `encoding`.
pub(crate) fn sanitize_messagepack_credentials_in(
    value: &mut Value,
    encoding: Encoding<'_>,
    null: bool,
) -> bool {
    super::sanitize_messagepack_whole(value, null, |value| release_reads_whole_in(value, encoding))
}

/// [`release_parts_read_whole`] for one body decoded from `bytes`.
pub(crate) fn release_body_reads_whole_as_stored(value: &Value, bytes: &[u8]) -> bool {
    body_reads_whole_as_stored(value, bytes, false)
}

/// [`release_body_reads_whole_as_stored`] for a body whose bytes the write
/// door's scan has read and accepted (`scan_write_payload(bytes)` is `Ok`).
/// When no part of the body reads as a secret and it is one whole value, the
/// encoding the whole read takes is `bytes` itself, whose text that door's
/// rules have read already: that read is not repeated.
pub(crate) fn release_accepted_body_reads_whole_as_stored(value: &Value, bytes: &[u8]) -> bool {
    body_reads_whole_as_stored(value, bytes, true)
}

/// One walk judges the body's parts in place and joins its text. A body
/// no part of which reads as a secret is its own judged copy, so it is not
/// copied, and as it is still as it was decoded, its encoding as stored is
/// the stored bytes of its value, read where they lie (speed). A body
/// with a part that reads as a secret is judged on a copy, as before.
fn body_reads_whole_as_stored(value: &Value, bytes: &[u8], write_accepted: bool) -> bool {
    // The joined text is wiped on drop (FIX 12047).
    let mut leaves = Zeroizing::new(String::new());
    if part_reads_as_secret(value, &mut leaves) {
        let mut judged = value.clone();
        sanitize_messagepack(&mut judged, true, Door::Release);
        return release_reads_whole_in(
            &judged,
            Encoding::Stored {
                original: value,
                bytes,
            },
        );
    }
    if detect(&leaves, Door::Release).is_some() {
        return true;
    }
    match skip(bytes, 0).and_then(|end| bytes.get(..end)) {
        Some(stored) if write_accepted && stored.len() == bytes.len() => false,
        Some(stored) => write_door_refuses_raw(stored),
        None => {
            encode_as_stored(value, value, bytes).is_none_or(|bytes| write_door_refuses_raw(&bytes))
        }
    }
}

/// `value` as MessagePack, each part of it that is as `original` decoded it
/// from `stored` written in its stored bytes, the rest at its narrowest
/// width. A map's entries are matched by key, since a walk drops some of
/// them and a projection folds a repeated key into one. `None` when `stored`
/// is not the encoding `original` was decoded from.
pub(crate) fn encode_as_stored(value: &Value, original: &Value, stored: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(stored.len());
    write_as_stored(value, original, stored, 0, &mut out)?;
    Some(out)
}

/// Writes `value` against the stored node at `at`; returns that node's end.
fn write_as_stored(
    value: &Value,
    original: &Value,
    stored: &[u8],
    at: usize,
    out: &mut Vec<u8>,
) -> Option<usize> {
    match (value, original, shape(stored.get(at..)?)?) {
        (Value::Array(values), Value::Array(was), Shape::Array { header, len })
            if values.len() == len && was.len() == len =>
        {
            out.extend_from_slice(stored.get(at..at + header)?);
            let mut cursor = at + header;
            for (value, was) in values.iter().zip(was) {
                cursor = write_as_stored(value, was, stored, cursor, out)?;
            }
            Some(cursor)
        }
        (Value::Map(entries), Value::Map(was), Shape::Map { header, len }) if was.len() == len => {
            let mut spans = Vec::with_capacity(len);
            let mut cursor = at + header;
            for _ in was {
                let value_at = skip(stored, cursor)?;
                spans.push((cursor, value_at));
                cursor = skip(stored, value_at)?;
            }
            if entries.len() == len {
                out.extend_from_slice(stored.get(at..at + header)?);
            } else {
                write_map_len(out, entries.len())?;
            }
            // The entries of one key take the last of its stored entries, in
            // order: a walk keeps or drops every entry of a key together, in
            // their order, and a projection keeps a repeated key's last value.
            let key_of = |key: &Value| {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, key).ok()?;
                Some(bytes)
            };
            let mut stored_entries: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
            for (index, (key, _)) in was.iter().enumerate() {
                stored_entries.entry(key_of(key)?).or_default().push(index);
            }
            let keys = entries
                .iter()
                .map(|(key, _)| key_of(key))
                .collect::<Option<Vec<_>>>()?;
            let mut counts: HashMap<&[u8], (usize, usize)> = HashMap::new();
            for key in &keys {
                counts.entry(key.as_slice()).or_default().0 += 1;
            }
            for ((key, value), bytes) in entries.iter().zip(&keys) {
                let (count, nth) = counts.get_mut(bytes.as_slice())?;
                let positions = stored_entries.get(bytes).map_or(&[][..], Vec::as_slice);
                let found = (*nth + positions.len())
                    .checked_sub(*count)
                    .and_then(|index| positions.get(index).copied());
                *nth += 1;
                match found {
                    Some(index) => {
                        let (key_at, value_at) = spans[index];
                        write_as_stored(key, &was[index].0, stored, key_at, out)?;
                        write_as_stored(value, &was[index].1, stored, value_at, out)?;
                    }
                    None => {
                        rmpv::encode::write_value(out, key).ok()?;
                        rmpv::encode::write_value(out, value).ok()?;
                    }
                }
            }
            Some(cursor)
        }
        _ => {
            let end = skip(stored, at)?;
            if value == original {
                out.extend_from_slice(stored.get(at..end)?);
            } else {
                rmpv::encode::write_value(out, value).ok()?;
            }
            Some(end)
        }
    }
}

/// A map header at its narrowest width.
fn write_map_len(out: &mut Vec<u8>, len: usize) -> Option<()> {
    match len {
        0..16 => out.push(0x80 | len as u8),
        16..65_536 => {
            out.push(0xde);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdf);
            out.extend_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
        }
    }
    Some(())
}

/// An array header at its narrowest width, as `rmpv` writes one: its length
/// taken as 32 bits.
fn write_array_len(out: &mut Vec<u8>, len: usize) {
    let len = len as u32;
    match len {
        0..16 => out.push(0x90 | len as u8),
        16..=0xffff => {
            out.push(0xdc);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdd);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
}

/// One stored value's leading node.
enum Shape {
    /// A scalar, with its whole length.
    Leaf(usize),
    Array {
        header: usize,
        len: usize,
    },
    Map {
        header: usize,
        len: usize,
    },
}

fn shape(bytes: &[u8]) -> Option<Shape> {
    let marker = *bytes.first()?;
    let field = |width: usize| -> Option<usize> {
        let field = bytes.get(1..1 + width)?;
        Some(
            field
                .iter()
                .fold(0, |len, byte| (len << 8) | usize::from(*byte)),
        )
    };
    let leaf = |len: usize| Some(Shape::Leaf(len));
    match marker {
        0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => leaf(1),
        0x80..=0x8f => Some(Shape::Map {
            header: 1,
            len: usize::from(marker & 0x0f),
        }),
        0x90..=0x9f => Some(Shape::Array {
            header: 1,
            len: usize::from(marker & 0x0f),
        }),
        0xa0..=0xbf => leaf(1 + usize::from(marker & 0x1f)),
        0xc1 => None,
        // bin8/16/32 and str8/16/32: a length, then the bytes.
        0xc4 | 0xd9 => leaf(2 + field(1)?),
        0xc5 | 0xda => leaf(3 + field(2)?),
        0xc6 | 0xdb => leaf(5 + field(4)?),
        // ext8/16/32: a length, a type byte, then the bytes.
        0xc7 => leaf(3 + field(1)?),
        0xc8 => leaf(4 + field(2)?),
        0xc9 => leaf(6 + field(4)?),
        0xca => leaf(5),
        0xcb => leaf(9),
        0xcc | 0xd0 => leaf(2),
        0xcd | 0xd1 => leaf(3),
        0xce | 0xd2 => leaf(5),
        0xcf | 0xd3 => leaf(9),
        0xd4 => leaf(3),
        0xd5 => leaf(4),
        0xd6 => leaf(6),
        0xd7 => leaf(10),
        0xd8 => leaf(18),
        0xdc => Some(Shape::Array {
            header: 3,
            len: field(2)?,
        }),
        0xdd => Some(Shape::Array {
            header: 5,
            len: field(4)?,
        }),
        0xde => Some(Shape::Map {
            header: 3,
            len: field(2)?,
        }),
        0xdf => Some(Shape::Map {
            header: 5,
            len: field(4)?,
        }),
    }
}

/// The end of the stored value that starts at `at`.
fn skip(stored: &[u8], at: usize) -> Option<usize> {
    let mut at = at;
    let mut pending: usize = 1;
    while pending > 0 {
        pending -= 1;
        match shape(stored.get(at..)?)? {
            Shape::Leaf(len) => at = at.checked_add(len)?,
            Shape::Array { header, len } => {
                at += header;
                pending = pending.checked_add(len)?;
            }
            Shape::Map { header, len } => {
                at += header;
                pending = pending.checked_add(len.checked_mul(2)?)?;
            }
        }
    }
    (at <= stored.len()).then_some(at)
}

/// An array item's text for the joined read: borrowed when it copies
/// nothing, else its lossy copy, held wiped (FIX 11563). The joined text
/// built from these is wiped too, so no lossy copy of an item survives the
/// read.
pub(super) enum JoinedText<'a> {
    /// Valid UTF-8 in place: no copy, nothing to wipe.
    Borrowed(&'a str),
    /// A lossy copy, wiped on drop.
    Owned(Zeroizing<String>),
}

impl std::borrow::Borrow<str> for JoinedText<'_> {
    fn borrow(&self) -> &str {
        match self {
            JoinedText::Borrowed(text) => text,
            JoinedText::Owned(text) => text.as_str(),
        }
    }
}

impl<'a> JoinedText<'a> {
    /// `bytes` as text: borrowed when it is valid UTF-8, else its lossy
    /// copy, wiped on drop.
    pub(super) fn from_bytes(bytes: &'a [u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => JoinedText::Borrowed(text),
            Err(_) => JoinedText::from_computed(bytes),
        }
    }

    /// `bytes` as text, always copied wiped: for bytes with no owner to
    /// borrow from, like an array of byte values read into a buffer.
    pub(super) fn from_computed(bytes: &[u8]) -> Self {
        JoinedText::Owned(Zeroizing::new(
            String::from_utf8_lossy(bytes).into_owned(),
        ))
    }
}
