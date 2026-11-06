//! Loro blocks a carrier stores, read decompressed before the census scans
//! them (OF-067). A document's snapshot or update keeps its operations in
//! blocks Loro compresses, so a scan of the stored bytes cannot see a key
//! typed into one. The carriers read here are the document family's
//! ([`LORO_CARRIERS`]); a carrier whose own module reads its documents
//! decoded is read there.
//!
//! Each block, the row itself or one a MessagePack member of the row holds,
//! is imported into a fresh document and read twice: every operation it
//! holds, as Loro's JSON export, and its state as JSON. A binary value in
//! either is read as a body too. An entity document's pending update is
//! imported on top of its snapshot and the updates before it, so its
//! operations apply and only those it adds are read.

use heed::RoTxn;
use loro::{LoroDoc, VersionVector};
use rmpv::Value;
use serde_json::Value as Json;

use oneiron_base::error::Result;

/// What every Loro export starts with.
pub const MAGIC: &[u8] = b"loro";

/// The shortest run of byte values read as a binary value.
const MIN_BINARY: usize = 8;

pub fn collect(value: &Value, found: &mut Vec<Vec<u8>>) {
    match value {
        Value::Binary(bytes) if bytes.starts_with(MAGIC) => found.push(bytes.clone()),
        Value::Array(items) => match byte_run(items.iter().map(Value::as_u64)) {
            Some(bytes) if bytes.starts_with(MAGIC) => found.push(bytes),
            Some(_) => {}
            None => {
                for item in items {
                    collect(item, found);
                }
            }
        },
        Value::Map(entries) => {
            for (key, member) in entries {
                collect(key, found);
                collect(member, found);
            }
        }
        _ => {}
    }
}

pub fn json_binaries(json: &Json, found: &mut Vec<Vec<u8>>) {
    match json {
        Json::Array(items) => match byte_run(items.iter().map(Json::as_u64)) {
            Some(bytes) => found.push(bytes),
            None => {
                for item in items {
                    json_binaries(item, found);
                }
            }
        },
        Json::Object(members) => {
            for member in members.values() {
                json_binaries(member, found);
            }
        }
        _ => {}
    }
}

/// Values that are each a byte, at least [`MIN_BINARY`] of them, as bytes.
fn byte_run(items: impl ExactSizeIterator<Item = Option<u64>>) -> Option<Vec<u8>> {
    if items.len() < MIN_BINARY {
        return None;
    }
    items
        .map(|item| item.and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}
