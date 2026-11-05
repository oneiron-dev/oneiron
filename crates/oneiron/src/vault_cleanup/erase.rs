//! Core half of `vault_cleanup::erase`: its store-layer items live in `oneiron_store::vault_cleanup::erase` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::vault_cleanup::erase::*;

use super::attempt_retention::erase_task_index_in_txn;
use super::codec_receipts::{DIGEST, PROPOSAL};
use super::marks::{self, CleanupMark, Revision};
use super::person_provenance::EXTRACTION_PERSON;
use super::run_record::{KEY_REVERT, KEY_SNAPSHOT, RUN};
use super::run_snapshot::{KEY_AFTER, KEY_BEFORE, KEY_ENTRIES, KEY_REVISION};
use super::{
    CleanupKind, KEY_ARCHIVED, KEY_CANDIDATES, KEY_ENTITY, KEY_KIND, KEY_REJECTED, KEY_SKIPPED,
    encode_row, field,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Raw, SideKey, SideTable};
use crate::store::Store;
use crate::store::attempt_id::AttemptId;
use rmpv::Value;
use std::collections::BTreeMap;

/// What a walk met that does not read: rows deleted by their key, and
/// listing slots left erased.
#[derive(Default)]
struct Unreadable {
    rows: usize,
    slots: usize,
}

impl Unreadable {
    fn log(&self, walk: &'static str) {
        if self.rows > 0 || self.slots > 0 {
            tracing::warn!(
                walk,
                rows = self.rows,
                slots = self.slots,
                "vault cleanup erase: unreadable rows deleted, unreadable slots left erased"
            );
        }
    }
}

/// The registry's eraser (FIX 7517): drops the private rows cleanup keys by
/// `id`, and leaves every proposal, digest and run slot that names it
/// erased. Past reading the three listings, a no-op for an id cleanup holds
/// nothing for.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    marks::delete_in_txn(store, txn, id.as_bytes())?;
    EXTRACTION_PERSON.delete(store, txn, id)?;
    erase_task_index_in_txn(store, txn, id)?;
    let named = id.as_bytes();
    let mut unreadable = Unreadable::default();
    walk(store, txn, PROPOSAL, &mut unreadable, |row, slots| {
        erase_slots(row, KEY_CANDIDATES, named, slots)
    })?;
    walk(store, txn, DIGEST, &mut unreadable, |row, slots| {
        let mut changed = erase_slots(row, KEY_ARCHIVED, named, slots);
        changed |= erase_slots(row, KEY_SKIPPED, named, slots);
        changed |= erase_slots(row, KEY_REJECTED, named, slots);
        changed
    })?;
    walk(store, txn, RUN, &mut unreadable, |row, slots| {
        let mut changed = erase_slots(row, KEY_CANDIDATES, named, slots);
        changed |= erase_slots(row, KEY_ARCHIVED, named, slots);
        for key in [KEY_SNAPSHOT, KEY_REVERT] {
            if let Some(Value::Map(parts)) = field_mut(row, key) {
                changed |= erase_slots(parts, KEY_ENTRIES, named, slots);
            }
        }
        changed
    })?;
    unreadable.log("entity");
    Ok(())
}

/// Moves each RUN snapshot entry of an attempt the payload erase rewrote in
/// this transaction (`rewritten`: its id, and its row's bytes before and
/// after) to the rewritten bytes, as the attempt's mark moves (FIX 7076, FIX
/// 7502): an entry that bound the row as it stood takes the new revision,
/// and each of its marks that bound those bytes binds the new ones. The run
/// still reverts the attempt, and no hash of the erased text stays. Every
/// other binding of that attempt's entries, a revision or mark naming older
/// bytes, is scrubbed to nil (FIX 7615); the entry keeps its id, kind and
/// place. Every other slot stays as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_attempt_references_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    rewritten: &[(AttemptId, Vec<u8>, Vec<u8>)],
) -> Result<()> {
    if rewritten.is_empty() {
        return Ok(());
    }
    let moves: BTreeMap<[u8; 16], (Revision, Revision)> = rewritten
        .iter()
        .map(|(id, before, after)| {
            (
                *id.as_bytes(),
                (marks::revision_of(before), marks::revision_of(after)),
            )
        })
        .collect();
    let mut unreadable = Unreadable::default();
    walk(store, txn, RUN, &mut unreadable, |row, _| {
        let Some(Value::Map(snapshot)) = field_mut(row, KEY_SNAPSHOT) else {
            return false;
        };
        let Some(Value::Array(entries)) = field_mut(snapshot, KEY_ENTRIES) else {
            return false;
        };
        let mut changed = false;
        for entry in entries {
            changed |= scrub_entry(entry, &moves);
        }
        changed
    })?;
    unreadable.log("attempt");
    Ok(())
}

/// Rewrites, in place, each row of `table` that `scrub` changes. A row that
/// does not read as a map is deleted by its key and counted.
fn walk<K: SideKey>(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    table: SideTable<K, Vec<u8>, Raw>,
    unreadable: &mut Unreadable,
    mut scrub: impl FnMut(&mut [(Value, Value)], &mut usize) -> bool,
) -> Result<()> {
    for (key, raw) in table.scan(store, txn)? {
        let mut cursor = raw.as_slice();
        let Ok(Value::Map(mut row)) = rmpv::decode::read_value(&mut cursor) else {
            table.delete(store, txn, &key)?;
            unreadable.rows += 1;
            continue;
        };
        if scrub(&mut row, &mut unreadable.slots) {
            let encoded = encode_row(&Value::Map(row), ERASE_LABEL)?;
            table.put(store, txn, &key, &encoded)?;
        }
    }
    Ok(())
}
