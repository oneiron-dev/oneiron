//! An erased row out of the stored usage events' source sets (FIX 6933).
//!
//! The server keeps each usage event (`sync_state / usage:event:`) in its own
//! named encoding. The engine reads one field of it by name, `sourceRows`,
//! the rows the call's facts were read from, and leaves every other field as
//! the server wrote it: an erase takes an erased row's id out of that set,
//! and a new event's set never names a row this vault already hard-erased.
//! Its billing, origin, cost, time and idempotency facts never change here.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Named, SideTable};

/// The field of a stored usage event that names its source rows.
const SOURCE_ROWS: &str = "sourceRows";

/// The stored usage events, each as its named map. Key: the suffix after
/// `usage:event:`.
const EVENTS: SideTable<String, Value, Named> = SideTable::new(&side_table::USAGE_EVENT);

fn corrupt() -> Error {
    Error::CorruptedIndex("usage event source rows")
}

/// The stored event `raw` as its named map.
fn event_map(raw: &[u8]) -> Result<Vec<(Value, Value)>> {
    match rmpv::decode::read_value(&mut &raw[..]) {
        Ok(Value::Map(entries)) => Ok(entries),
        _ => Err(corrupt()),
    }
}

/// The source rows `entries` name; `None`, unknown, when they name none. A
/// present set that is not a list of ids is a fault, never an empty set.
fn source_rows(entries: &[(Value, Value)]) -> Result<Option<Vec<EntityId>>> {
    let Some((_, value)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(SOURCE_ROWS))
    else {
        return Ok(None);
    };
    if value.is_nil() {
        return Ok(None);
    }
    let mut raw = Vec::new();
    rmpv::encode::write_value(&mut raw, value).map_err(|_| corrupt())?;
    rmp_serde::from_slice(&raw).map(Some).map_err(|_| corrupt())
}

/// Sets the source rows `entries` name to `rows`, a set they already held.
fn set_source_rows(entries: &mut [(Value, Value)], rows: &[EntityId]) -> Result<()> {
    let raw = rmp_serde::to_vec_named(rows).map_err(|_| corrupt())?;
    let value = rmpv::decode::read_value(&mut raw.as_slice()).map_err(|_| corrupt())?;
    for (key, slot) in entries.iter_mut() {
        if key.as_str() == Some(SOURCE_ROWS) {
            *slot = value;
            return Ok(());
        }
    }
    Err(corrupt())
}

/// Drops an erased row `id` from every stored usage event's source rows (FIX
/// 6933), rewriting only the events that named it, every other field as the
/// server wrote it. An unknown set stays unknown, and one left empty stays
/// known-empty. An event that does not decode keeps its bytes for the
/// owner's repair door (FIX 6476), warned: it is never read as scrubbed, and
/// it never fails the erase. Registered on the usage event table's
/// declaration; a source may be any row, so this reads every event for each
/// erased id.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_usage_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for row in EVENTS.iter_raw_from(&vault.store, &*wtxn, &[])? {
        let (key, raw) = row?;
        let read = event_map(&raw).and_then(|entries| Ok((source_rows(&entries)?, entries)));
        let (rows, entries) = match read {
            Ok((Some(rows), entries)) => (rows, entries),
            Ok((None, _)) => continue,
            Err(_) => {
                tracing::warn!(
                    "a stored usage event does not decode: its source rows stay for the owner's \
                     repair"
                );
                continue;
            }
        };
        if rows.contains(id) {
            let key = String::from_utf8(key).map_err(|_| corrupt())?;
            named.push((key, rows, entries));
        }
    }
    for (key, mut rows, mut entries) in named {
        rows.retain(|row| row != id);
        set_source_rows(&mut entries, &rows)?;
        EVENTS.put(&vault.store, wtxn, &key, &Value::Map(entries))?;
    }
    Ok(())
}

impl Vault {
    /// `encoded`, a usage event in the server's named encoding about to be
    /// stored in `wtxn`, less each source row this vault already hard-erased
    /// (FIX 6933): a source an erase reached since the call settled does not
    /// come back. Every other field stays as encoded, an unknown set stays
    /// unknown, and one left empty stays known-empty. The event is recorded
    /// either way.
    ///
    /// # Errors
    ///
    /// Storage errors, or bytes that are not an event's named map with a set
    /// of ids.
    pub fn usage_event_with_live_sources_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        encoded: &[u8],
    ) -> Result<Vec<u8>> {
        let mut entries = event_map(encoded)?;
        let Some(rows) = source_rows(&entries)? else {
            return Ok(encoded.to_vec());
        };
        let mut live = Vec::with_capacity(rows.len());
        for row in &rows {
            if !self
                .store
                .port_deletion_marked(wtxn, DeletionMarker::HardDelete, row)?
            {
                live.push(*row);
            }
        }
        if live.len() == rows.len() {
            return Ok(encoded.to_vec());
        }
        set_source_rows(&mut entries, &live)?;
        EVENTS.encode_value(&Value::Map(entries))
    }
}
