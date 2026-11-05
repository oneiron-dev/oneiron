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
//! so the run still reverts it and no hash of the erased text stays. A
//! binding that named other bytes, an entry already stale before the erase
//! or a stale mark it recorded, is scrubbed to nil, never rebound (FIX 7615).
//!
//! A row these walks meet that does not read as a map is deleted by its key
//! and counted, and a listing slot that does not read is left erased: the
//! erase never fails on one (Engine on FIX 5736).

use std::collections::BTreeMap;

use rmpv::Value;

use crate::attempt_archive_mark::CleanupMark;
use crate::attempt_archive_mark::Revision;
use crate::attempt_id::AttemptId;
use crate::side_table::key::SideKey;
use crate::vault_cleanup::cleanup_types::CleanupKind;
use crate::vault_cleanup::cleanup_types::KEY_ARCHIVED;
use crate::vault_cleanup::cleanup_types::KEY_CANDIDATES;
use crate::vault_cleanup::cleanup_types::KEY_ENTITY;
use crate::vault_cleanup::cleanup_types::KEY_KIND;
use crate::vault_cleanup::cleanup_types::KEY_REJECTED;
use crate::vault_cleanup::cleanup_types::KEY_SKIPPED;
use crate::vault_cleanup::codec_receipts::encode_row;
use crate::vault_cleanup::codec_receipts::field;
use crate::vault_cleanup::run_snapshot::KEY_AFTER;
use crate::vault_cleanup::run_snapshot::KEY_BEFORE;
use crate::vault_cleanup::run_snapshot::KEY_ENTRIES;
use crate::vault_cleanup::run_snapshot::KEY_REVISION;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const ERASE_LABEL: &str = "vault cleanup erase";

/// What one listing slot names.
enum Slot {
    /// An erase reached it already.
    Erased,
    /// The id it names.
    Names([u8; 16]),
    /// It does not read.
    Unreadable,
}

/// The member `name` of a stored map, to rewrite.
pub fn field_mut<'a>(parts: &'a mut [(Value, Value)], name: &str) -> Option<&'a mut Value> {
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
pub fn erase_slots(
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

/// Scrubs `entry` when the attempt it names is in `moves`: each binding of
/// the row as it stood (`bound`) moves to the rewritten bytes, and every
/// other revision or mark, naming bytes the row held before, goes to nil,
/// never rebound (FIX 7615). A nil binding stays nil. `true` when it changed.
pub fn scrub_entry(entry: &mut Value, moves: &BTreeMap<[u8; 16], (Revision, Revision)>) -> bool {
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
