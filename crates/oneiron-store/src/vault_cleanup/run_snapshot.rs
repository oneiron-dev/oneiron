//! What each cleanup run archived, kept on the run's own RUN row (OF-449).
//!
//! # What a snapshot holds, and why it is enough to revert
//!
//! An archive writes one mark and nothing else: a record's `ac:` tombstone
//! value, or an attempt's run mark (with the task index row the attempt
//! restore removes beside it). The body and its indexes stay as they were;
//! nothing is purged, swept or published. So each entry records the kind, the
//! id, the revision of the stored bytes it hid, the mark in force before, and
//! the exact mark the archive wrote. Lifting exactly that mark returns the
//! entry to where it stood. A before-image would only copy bodies the vault
//! already keeps into another place an erase must reach, and no vault backup
//! is taken.
//!
//! Each entry is read just before its mark is written, in the archive's own
//! write transaction, and the snapshot commits there too: with the marks, the
//! digest and the accepted proposal's consumption, or not at all.

use rmpv::Value;

use crate::attempt_id::AttemptId;
use crate::vault_cleanup::cleanup_types::CleanupDecision;
use crate::vault_cleanup::cleanup_types::CleanupKind;
use crate::vault_cleanup::cleanup_types::CleanupPosture;
use crate::vault_cleanup::cleanup_types::CleanupProposal;
use crate::vault_cleanup::cleanup_types::CleanupRunReport;
use crate::vault_cleanup::cleanup_types::KEY_AT;
use crate::vault_cleanup::cleanup_types::KEY_DECISION;
use crate::vault_cleanup::cleanup_types::KEY_ENTITY;
use crate::vault_cleanup::cleanup_types::KEY_KIND;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const SNAPSHOT_LABEL: &str = "cleanup run snapshot";
pub const KEY_DIGEST: &str = "digest";
pub const KEY_ENTRIES: &str = "entries";
pub const KEY_REVISION: &str = "revision";
pub const KEY_BEFORE: &str = "before";
pub const KEY_AFTER: &str = "after";

/// One entry a cleanup run archived, as it stood just before its mark was
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupSnapshotEntry {
    /// The archived record, or the completed attempt's id.
    pub entity: EntityId,
    /// The arm that archived it.
    pub kind: CleanupKind,
    /// BLAKE3 of the stored bytes it hid: the encoded record, or the
    /// attempt's queue row. The archive keeps those bytes. `None` is a
    /// binding an erase scrubbed: the attempt's row had changed since the
    /// run, so the hash named bytes the erase reached (FIX 7615).
    pub revision: Option<[u8; 32]>,
    /// The mark in force before: none for a record, whose archive door
    /// refuses a marked row; none, or a stale mark, for an attempt. `None`
    /// reads as none, or scrubbed by an erase (FIX 7615).
    pub before: Option<Vec<u8>>,
    /// The exact mark the archive wrote: a record's 25-byte `ac:` value, or
    /// an attempt's 48-byte run mark. `None` is a binding an erase scrubbed,
    /// as `revision` (FIX 7615).
    pub after: Option<Vec<u8>>,
}

/// What one cleanup run archived, taken in the transaction that archived it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunSnapshot {
    /// When the archive committed, in recorded seconds.
    pub at: u64,
    /// The decision that archived: automatic, or the owner's accept.
    pub decision: CleanupDecision,
    /// The digest that decision recorded.
    pub digest: EntityId,
    /// Each archived entry, in archive order. A skipped candidate has none.
    /// `None` is an entry an erase reached since: no id, kind, revision or
    /// mark stays, and a revert lifts nothing for it (FIX 7517).
    pub entries: Vec<Option<CleanupSnapshotEntry>>,
}

pub fn encode_snapshot(snapshot: &CleanupRunSnapshot) -> Value {
    Value::Map(vec![
        (Value::from(KEY_AT), Value::from(snapshot.at)),
        (
            Value::from(KEY_DECISION),
            Value::from(snapshot.decision.as_str()),
        ),
        (
            Value::from(KEY_DIGEST),
            Value::from(snapshot.digest.to_hex()),
        ),
        (
            Value::from(KEY_ENTRIES),
            Value::Array(
                snapshot
                    .entries
                    .iter()
                    .map(|entry| entry.as_ref().map_or(Value::Nil, encode_entry))
                    .collect(),
            ),
        ),
    ])
}

fn encode_entry(entry: &CleanupSnapshotEntry) -> Value {
    Value::Map(vec![
        (Value::from(KEY_ENTITY), Value::from(entry.entity.to_hex())),
        (Value::from(KEY_KIND), Value::from(entry.kind.as_str())),
        (
            Value::from(KEY_REVISION),
            entry
                .revision
                .map_or(Value::Nil, |revision| Value::Binary(revision.to_vec())),
        ),
        (
            Value::from(KEY_BEFORE),
            entry.before.clone().map_or(Value::Nil, Value::Binary),
        ),
        (
            Value::from(KEY_AFTER),
            entry.after.clone().map_or(Value::Nil, Value::Binary),
        ),
    ])
}
