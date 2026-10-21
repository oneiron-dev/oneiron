//! An erase reaches cleanup's own rows (FIX 7517).
//!
//! Three private rows name an entity by key and have no listing of their
//! own: a record's kept mark, a PERSON's mint evidence and a TASK's
//! archived-attempt index. Each goes by its exact key. The listings, every
//! proposal, digest and run, keep every row and every slot: a slot naming the
//! erased entity is left in its erased form, nil in its place, with no id,
//! kind, hash or mark, so each list keeps its order and its count. A later
//! accept or revert passes an erased slot by and brings nothing back. No
//! listing has an entity index, so an erase reads all three to their ends.
//!
//! An attempt the payload erase rewrote (FIX 7076, FIX 7502) is not erased:
//! its run's snapshot entry moves to the rewritten bytes, as its mark does,
//! so the run still reverts it and no hash of the erased text stays.
//!
//! A row these walks meet that does not read as a map is deleted by its key
//! and counted, and a listing slot that does not read is left erased: the
//! erase never fails on one (Engine on FIX 5736).

use std::collections::BTreeMap;

use rmpv::Value;

use super::attempt_retention::erase_task_index_in_txn;
use super::codec_receipts::{DIGEST, PROPOSAL};
use super::marks::{self, CleanupMark, Revision};
use super::person_provenance::EXTRACTION_PERSON;
use super::run_record::{KEY_REVERT, KEY_SNAPSHOT, RUN};
use super::run_snapshot::{KEY_AFTER, KEY_BEFORE, KEY_ENTRIES, KEY_REVISION};
use super::{
    CleanupKind, KEY_ARCHIVED, KEY_CANDIDATES, KEY_ENTITY, KEY_KIND, KEY_SKIPPED, encode_row, field,
};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Raw, SideKey, SideTable};
use crate::store::Store;

const ERASE_LABEL: &str = "vault cleanup erase";

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

/// What one listing slot names.
enum Slot {
    /// An erase reached it already.
    Erased,
    /// The id it names.
    Names([u8; 16]),
    /// It does not read.
    Unreadable,
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
/// still reverts the attempt, and no hash of the erased text stays. An entry
/// that bound other bytes, and every other slot, stays as it is.
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
            changed |= move_entry(entry, &moves);
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

/// The member `name` of a stored map, to rewrite.
fn field_mut<'a>(parts: &'a mut [(Value, Value)], name: &str) -> Option<&'a mut Value> {
    parts
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// The slot `value` is: nil, a hex id, or a map whose `entity` is one.
fn slot(value: &Value) -> Slot {
    let hex = match value {
        Value::Nil => return Slot::Erased,
        Value::Map(parts) => field(parts, KEY_ENTITY).and_then(Value::as_str),
        other => other.as_str(),
    };
    hex.and_then(|hex| EntityId::from_hex(hex).ok())
        .map_or(Slot::Unreadable, |id| Slot::Names(*id.as_bytes()))
}

/// Leaves each slot of the list at `key` that names `id`, or that does not
/// read, erased; `true` when one changed. A row without that list has
/// nothing there to erase.
fn erase_slots(
    parts: &mut [(Value, Value)],
    key: &str,
    id: &[u8; 16],
    unreadable: &mut usize,
) -> bool {
    let Some(Value::Array(slots)) = field_mut(parts, key) else {
        return false;
    };
    let mut changed = false;
    for value in slots {
        match slot(value) {
            Slot::Erased => continue,
            Slot::Names(named) if named != *id => continue,
            Slot::Names(_) => {}
            Slot::Unreadable => *unreadable += 1,
        }
        *value = Value::Nil;
        changed = true;
    }
    changed
}

/// Moves `entry` to the rewritten bytes of the attempt it names, when that
/// attempt is in `moves` and the entry bound its row as it stood; `true`
/// when it moved.
fn move_entry(entry: &mut Value, moves: &BTreeMap<[u8; 16], (Revision, Revision)>) -> bool {
    let Slot::Names(id) = slot(entry) else {
        return false;
    };
    let Some((bound, revision)) = moves.get(&id) else {
        return false;
    };
    let Value::Map(parts) = entry else {
        return false;
    };
    if field(parts, KEY_KIND).and_then(Value::as_str)
        != Some(CleanupKind::CompletedAttempt.as_str())
        || field(parts, KEY_REVISION).and_then(Value::as_slice) != Some(bound.as_slice())
    {
        return false;
    }
    for (key, value) in parts {
        match key.as_str() {
            Some(KEY_REVISION) => *value = Value::Binary(revision.to_vec()),
            Some(KEY_BEFORE | KEY_AFTER) => {
                if let Some(moved) = value
                    .as_slice()
                    .and_then(CleanupMark::decode)
                    .and_then(|mark| mark.moved(bound, revision))
                {
                    *value = Value::Binary(moved.encode());
                }
            }
            _ => {}
        }
    }
    true
}
