//! An erase reaches cleanup's own rows (FIX 7517).
//!
//! Three private rows name an entity by key and have no listing of their
//! own: a record's kept mark, a PERSON's mint evidence and a TASK's
//! archived-attempt index. Each goes by its exact key. The listings, every
//! proposal, digest and run, keep every row and every slot: a slot naming the
//! erased entity is left in its erased form, nil in its place, with no id,
//! kind, hash or mark, so each list keeps its order and its count. A later
//! accept or revert passes an erased slot by and brings nothing back. The
//! erase reads only the listing rows the entity index says name the id
//! (FIX 7616, [`super::entity_rows`]), never a listing to its end.
//!
//! An attempt the payload erase rewrote (FIX 7076, FIX 7502) is not erased:
//! its run's snapshot entry moves to the rewritten bytes, as its mark does,
//! so the run still reverts it and no hash of the erased text stays. A
//! binding that named other bytes, an entry already stale before the erase
//! or a stale mark it recorded, is scrubbed to nil, never rebound (FIX 7615).
//!
//! A row these walks meet that does not read as a map is deleted by its key
//! and counted, and a listing slot that does not read is left erased: the
//! erase never fails on one (Engine on FIX 5736).

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::attempt_retention::erase_task_index_in_txn;
use super::entity_rows::{self, Listing};
use super::marks::{self, CleanupMark, Revision};
use super::person_provenance::EXTRACTION_PERSON;
use super::run_record::{KEY_REVERT, KEY_SNAPSHOT};
use super::run_snapshot::{KEY_AFTER, KEY_BEFORE, KEY_ENTRIES, KEY_REVISION};
use super::{
    CleanupKind, KEY_ARCHIVED, KEY_CANDIDATES, KEY_ENTITY, KEY_KIND, KEY_REJECTED, KEY_SKIPPED,
    encode_row, field,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::attempt_id::AttemptId;

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

/// The slot lists of each listing, by path from the row: where an erase
/// scrubs an id, and where the entity index reads the ids a row names.
const PROPOSAL_LISTS: &[&[&str]] = &[&[KEY_CANDIDATES]];
const DIGEST_LISTS: &[&[&str]] = &[&[KEY_ARCHIVED], &[KEY_SKIPPED], &[KEY_REJECTED]];
const RUN_LISTS: &[&[&str]] = &[
    &[KEY_CANDIDATES],
    &[KEY_ARCHIVED],
    &[KEY_SNAPSHOT, KEY_ENTRIES],
    &[KEY_REVERT, KEY_ENTRIES],
];

const fn lists(listing: Listing) -> &'static [&'static [&'static str]] {
    match listing {
        Listing::Proposal => PROPOSAL_LISTS,
        Listing::Digest => DIGEST_LISTS,
        Listing::Run => RUN_LISTS,
    }
}

/// The list at `path` in a stored map.
fn list<'a>(parts: &'a [(Value, Value)], path: &[&str]) -> Option<&'a Vec<Value>> {
    match path {
        [last] => match field(parts, last)? {
            Value::Array(slots) => Some(slots),
            _ => None,
        },
        [first, rest @ ..] => match field(parts, first)? {
            Value::Map(inner) => list(inner, rest),
            _ => None,
        },
        [] => None,
    }
}

/// The list at `path` in a stored map, to rewrite.
fn list_mut<'a>(parts: &'a mut [(Value, Value)], path: &[&str]) -> Option<&'a mut Vec<Value>> {
    match path {
        [last] => match field_mut(parts, last)? {
            Value::Array(slots) => Some(slots),
            _ => None,
        },
        [first, rest @ ..] => match field_mut(parts, first)? {
            Value::Map(inner) => list_mut(inner, rest),
            _ => None,
        },
        [] => None,
    }
}

/// Every id a stored row of `listing` names where an erase would scrub it
/// (FIX 7616). A row that does not read names none.
pub(super) fn named_ids(listing: Listing, raw: &[u8]) -> BTreeSet<[u8; 16]> {
    let mut cursor = raw;
    let Ok(Value::Map(row)) = rmpv::decode::read_value(&mut cursor) else {
        return BTreeSet::new();
    };
    lists(listing)
        .iter()
        .filter_map(|path| list(&row, path))
        .flatten()
        .filter_map(|value| match slot(value) {
            Slot::Names(id) => Some(id),
            Slot::Erased | Slot::Unreadable => None,
        })
        .collect()
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
    for (listing, key) in entity_rows::rows_naming(store, txn, named)? {
        // Once scrubbed, the row names the id no more.
        entity_rows::forget_in_txn(store, txn, named, listing, &key)?;
        visit(store, txn, listing, &key, &mut unreadable, |row, slots| {
            let mut changed = false;
            for path in lists(listing) {
                if let Some(found) = list_mut(row, path) {
                    changed |= erase_slots(found, named, slots);
                }
            }
            changed
        })?;
    }
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
    // Only a run's snapshot names an attempt there; the index finds them.
    let mut runs = BTreeSet::new();
    for attempt in moves.keys() {
        for (listing, key) in entity_rows::rows_naming(store, txn, attempt)? {
            if listing == Listing::Run {
                runs.insert(key);
            }
        }
    }
    let mut unreadable = Unreadable::default();
    for key in runs {
        visit(store, txn, Listing::Run, &key, &mut unreadable, |row, _| {
            let Some(entries) = list_mut(row, &[KEY_SNAPSHOT, KEY_ENTRIES]) else {
                return false;
            };
            let mut changed = false;
            for entry in entries {
                changed |= scrub_entry(entry, &moves);
            }
            changed
        })?;
    }
    unreadable.log("attempt");
    Ok(())
}

/// Rewrites, in place, the row `key` of `listing` when `scrub` changes it.
/// A row that is gone is passed by; one that does not read as a map is
/// deleted by its key and counted. A rewrite only clears slots, so it names
/// no id it did not name before, and the index keeps its other rows.
fn visit(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    listing: Listing,
    key: &[u8; 16],
    unreadable: &mut Unreadable,
    scrub: impl FnOnce(&mut [(Value, Value)], &mut usize) -> bool,
) -> Result<()> {
    let Some(raw) = listing.get(store, txn, key)? else {
        return Ok(());
    };
    let mut cursor = raw.as_slice();
    let Ok(Value::Map(mut row)) = rmpv::decode::read_value(&mut cursor) else {
        listing.delete_unindexed(store, txn, key)?;
        unreadable.rows += 1;
        return Ok(());
    };
    if scrub(&mut row, &mut unreadable.slots) {
        let encoded = encode_row(&Value::Map(row), ERASE_LABEL)?;
        listing.put_unindexed(store, txn, key, &encoded)?;
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

/// Leaves each slot of `slots` that names `id`, or that does not read,
/// erased; `true` when one changed.
fn erase_slots(slots: &mut [Value], id: &[u8; 16], unreadable: &mut usize) -> bool {
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

/// Scrubs `entry` when the attempt it names is in `moves`: each binding of
/// the row as it stood (`bound`) moves to the rewritten bytes, and every
/// other revision or mark, naming bytes the row held before, goes to nil,
/// never rebound (FIX 7615). A nil binding stays nil. `true` when it changed.
fn scrub_entry(entry: &mut Value, moves: &BTreeMap<[u8; 16], (Revision, Revision)>) -> bool {
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
    {
        return false;
    }
    let mut changed = false;
    for (key, value) in parts {
        let scrubbed = match key.as_str() {
            Some(KEY_REVISION) => match value.as_slice() {
                Some(held) if held == bound.as_slice() => Value::Binary(revision.to_vec()),
                _ => Value::Nil,
            },
            Some(KEY_BEFORE | KEY_AFTER) => value
                .as_slice()
                .and_then(CleanupMark::decode)
                .and_then(|mark| mark.moved(bound, revision))
                .map_or(Value::Nil, |moved| Value::Binary(moved.encode())),
            _ => continue,
        };
        if *value != scrubbed {
            *value = scrubbed;
            changed = true;
        }
    }
    changed
}
