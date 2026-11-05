//! Core half of `batch::secret_scan::whole_read`: its store-layer items live in `oneiron_store::batch::secret_scan::whole_read` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::whole_read::*;

use super::{
    Door, byte_values, credential_field, detect, detect_bytes, joined_messagepack,
    sanitize_messagepack,
};
use rmpv::Value;
use std::collections::HashMap;
use zeroize::Zeroizing;

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
