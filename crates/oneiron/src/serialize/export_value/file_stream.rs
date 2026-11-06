//! Core half of `serialize::export_value::file_stream`: its store-layer items live in `oneiron_store::serialize::export_value::file_stream` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::export_value::file_stream::*;

use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;
use std::io::{self, Read};

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
        && matches!(
            crate::store::skill_source_carrier::decode_source_carrier(head),
            Ok(None)
        )
        && !marker
        && !crate::store::receipt_identity::is_receipt_archive_source(head))
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
