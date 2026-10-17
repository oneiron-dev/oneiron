//! Loro blocks a carrier stores, read decompressed before the census scans
//! them (OF-067). A document's snapshot or update keeps its operations in
//! blocks Loro compresses, so a scan of the stored bytes cannot see a key
//! typed into one. Each block, the row itself or one a MessagePack member of
//! the row holds, is imported into a fresh document and read twice: every
//! operation it holds, as Loro's JSON export, and its state as JSON. A binary
//! value in either is read as a body too. An entity document's pending
//! update is imported on top of its snapshot and the updates before it, so
//! its operations apply and only those it adds are read.

use heed::RoTxn;
use loro::{LoroDoc, VersionVector};
use rmpv::Value;
use serde_json::Value as Json;

use super::super::{decode_members, write_payload_hit};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self as t, SideTableDecl};

/// What every Loro export starts with.
const MAGIC: &[u8] = b"loro";

/// The shortest run of byte values read as a binary value.
const MIN_BINARY: usize = 8;

/// The scan's reason for a hit inside a Loro block row `key` of `decl` holds.
pub(super) fn hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    decl: &SideTableDecl,
    key: &[u8],
    row: &[u8],
) -> Result<Option<&'static str>> {
    if decl.name == t::DOCUMENT_UPDATE.name && row.starts_with(MAGIC) {
        return update_hit(vault, txn, key, row);
    }
    Ok(blocks(row)
        .iter()
        .find_map(|block| block_hit(block.as_slice())))
}

/// [`hit`] for the carrier row a census cursor names; `None` once it is gone.
pub(super) fn hit_at(
    vault: &Vault,
    txn: &RoTxn<'_>,
    cursor: &[u8],
) -> Result<Option<&'static str>> {
    let Some((decl, row)) = super::carriers::stored(vault, txn, cursor)? else {
        return Ok(None);
    };
    hit(vault, txn, decl, cursor.get(1..).unwrap_or_default(), &row)
}

/// The Loro blocks in `row`: the row itself, or each binary member of it,
/// read with or without a leading version byte.
fn blocks(row: &[u8]) -> Vec<Vec<u8>> {
    if row.starts_with(MAGIC) {
        return vec![row.to_vec()];
    }
    let mut found = Vec::new();
    if let Some(value) = decode_members(row).or_else(|| row.get(1..).and_then(decode_members)) {
        collect(&value, &mut found);
    }
    found
}

fn collect(value: &Value, found: &mut Vec<Vec<u8>>) {
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

/// An entity document's pending update `key` (`u:e:<document>:<sequence>`),
/// read on top of the document's snapshot and the updates before it: the
/// operations it adds.
fn update_hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    key: &[u8],
    row: &[u8],
) -> Result<Option<&'static str>> {
    let update_prefix = String::from_utf8_lossy(t::DOCUMENT_UPDATE.prefix);
    let Some(document) = std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.strip_prefix(&*update_prefix))
        .and_then(|rest| rest.split_once(':'))
        .map(|(document, _)| document)
    else {
        return Ok(block_hit(row));
    };
    let doc = LoroDoc::new();
    let snapshot = format!(
        "{}{document}",
        String::from_utf8_lossy(t::DOCUMENT_SNAPSHOT.prefix)
    );
    // A block that does not import adds nothing to read on top of: its own
    // row's census reads its stored bytes.
    if let Some(snapshot) = vault.store.sync_state.get(txn, &snapshot)? {
        let _ = doc.import(&snapshot);
    }
    for earlier in vault
        .store
        .sync_state
        .prefix_iter(txn, &format!("{update_prefix}{document}:"))?
    {
        let (at, bytes) = earlier?;
        if at.as_bytes() >= key {
            break;
        }
        let _ = doc.import(&bytes);
    }
    let before = doc.oplog_vv();
    if doc.import(row).is_err() {
        return Ok(None);
    }
    Ok(read_hit(&doc, &before, false))
}

/// One block on its own: every operation it holds, and its state.
fn block_hit(block: &[u8]) -> Option<&'static str> {
    let doc = LoroDoc::new();
    doc.import(block).ok()?;
    read_hit(&doc, &VersionVector::default(), true)
}

/// The scan's reason for a hit in `doc`'s operations past `from`, and in its
/// state when `state`.
fn read_hit(doc: &LoroDoc, from: &VersionVector, state: bool) -> Option<&'static str> {
    let operations = serde_json::to_value(doc.export_json_updates(from, &doc.oplog_vv())).ok();
    let state = state
        .then(|| serde_json::to_value(doc.get_deep_value()).ok())
        .flatten();
    [operations, state].iter().flatten().find_map(json_hit)
}

/// The door's reason for a hit in `json`, or in a binary value it spells as
/// an array of byte values.
fn json_hit(json: &Json) -> Option<&'static str> {
    if let Some(reason) = serde_json::to_vec(json)
        .ok()
        .and_then(|bytes| write_payload_hit(&bytes))
    {
        return Some(reason);
    }
    let mut binaries = Vec::new();
    json_binaries(json, &mut binaries);
    binaries
        .iter()
        .find_map(|bytes| write_payload_hit(bytes.as_slice()))
}

fn json_binaries(json: &Json, found: &mut Vec<Vec<u8>>) {
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
