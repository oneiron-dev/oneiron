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

use super::run_record::{self, KEY_REVERT, KEY_SNAPSHOT};
use super::run_revert::{CleanupRunRevert, decode_revert};
use super::{
    CleanupDecision, CleanupKind, CleanupPosture, CleanupProposal, CleanupRunReport, KEY_AT,
    KEY_DECISION, KEY_ENTITY, KEY_KIND, field,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const SNAPSHOT_LABEL: &str = "cleanup run snapshot";
const KEY_DIGEST: &str = "digest";
pub(super) const KEY_ENTRIES: &str = "entries";
pub(super) const KEY_REVISION: &str = "revision";
pub(super) const KEY_BEFORE: &str = "before";
pub(super) const KEY_AFTER: &str = "after";

/// One entry a cleanup run archived, as it stood just before its mark was
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupSnapshotEntry {
    /// The archived record, or the completed attempt's id.
    pub entity: EntityId,
    /// The arm that archived it.
    pub kind: CleanupKind,
    /// BLAKE3 of the stored bytes it hid: the encoded record, or the
    /// attempt's queue row. The archive keeps those bytes.
    pub revision: [u8; 32],
    /// The mark in force before: none for a record, whose archive door
    /// refuses a marked row; none, or a stale mark, for an attempt.
    pub before: Option<Vec<u8>>,
    /// The exact mark the archive wrote: a record's 25-byte `ac:` value, or
    /// an attempt's 48-byte run mark.
    pub after: Vec<u8>,
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

/// One run that archived something: its snapshot, and its revert once there
/// is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunRecord {
    /// The run's attempt id, the name a revert takes.
    pub attempt: AttemptId,
    /// What it archived.
    pub snapshot: CleanupRunSnapshot,
    /// The stored answer of its revert, once the owner reverted it.
    pub revert: Option<CleanupRunRevert>,
}

/// Every run that archived something, and the runs whose row does not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupRuns {
    /// Runs with a snapshot, in attempt order.
    pub runs: Vec<CleanupRunRecord>,
    /// Runs whose RUN row does not read; the others still answer.
    pub unreadable: Vec<AttemptId>,
}

/// Every cleanup run that archived something, in attempt order, each with
/// its revert if the owner reverted it.
///
/// A run that archived nothing, or ran before runs kept snapshots, is not
/// listed. A RUN row that does not read is named in
/// [`CleanupRuns::unreadable`], and the rest still answer.
///
/// # Errors
///
/// Storage errors.
pub fn cleanup_runs(vault: &Vault) -> Result<CleanupRuns> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = CleanupRuns::default();
    for (key, raw) in run_record::rows_in_txn(vault, &rtxn)? {
        let attempt = AttemptId::from_bytes(&key)?;
        match decode_run(attempt, &raw) {
            Ok(Some(run)) => out.runs.push(run),
            Ok(None) => {}
            Err(_) => out.unreadable.push(attempt),
        }
    }
    Ok(out)
}

fn decode_run(attempt: AttemptId, raw: &[u8]) -> Result<Option<CleanupRunRecord>> {
    let fields = run_record::decode_fields(raw)?;
    let Some(snapshot) = field(&fields, KEY_SNAPSHOT)
        .map(decode_snapshot)
        .transpose()?
        .flatten()
    else {
        return Ok(None);
    };
    let revert = match field(&fields, KEY_REVERT) {
        None | Some(Value::Nil) => None,
        Some(value) => Some(decode_revert(attempt, value)?),
    };
    Ok(Some(CleanupRunRecord {
        attempt,
        snapshot,
        revert,
    }))
}

/// Records `snapshot` on `run`'s RUN row in the archive's own transaction.
/// The row's report keys stay as the run wrote them.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &AttemptId,
    snapshot: &CleanupRunSnapshot,
) -> Result<()> {
    run_record::set_field_in_txn(vault, txn, run, KEY_SNAPSHOT, encode_snapshot(snapshot))?;
    Ok(())
}

/// Records an accepted proposal's snapshot on the RUN row of the run that
/// opened it. A run that left no row gets the propose-first report it would
/// have written. A row that does not read stays as it is and the archive
/// still stands; the review names that run as unreadable.
pub(super) fn record_accept_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &CleanupProposal,
    snapshot: &CleanupRunSnapshot,
) -> Result<()> {
    if !run_record::exists_in_txn(vault, txn, &proposal.attempt)? {
        run_record::put_in_txn(
            vault,
            txn,
            &CleanupRunReport {
                attempt: proposal.attempt,
                posture: CleanupPosture::ProposeFirst,
                candidates: proposal.candidates.clone(),
                proposal: Some(proposal.id),
                archived: Vec::new(),
                digest: None,
            },
        )?;
    }
    record_in_txn(vault, txn, &proposal.attempt, snapshot)
}

fn encode_snapshot(snapshot: &CleanupRunSnapshot) -> Value {
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
            Value::Binary(entry.revision.to_vec()),
        ),
        (
            Value::from(KEY_BEFORE),
            entry.before.clone().map_or(Value::Nil, Value::Binary),
        ),
        (Value::from(KEY_AFTER), Value::Binary(entry.after.clone())),
    ])
}

/// A RUN row's `snapshot` value; Nil is a run that archived nothing yet.
pub(super) fn decode_snapshot(value: &Value) -> Result<Option<CleanupRunSnapshot>> {
    let corrupt = || Error::CorruptedIndex(SNAPSHOT_LABEL);
    let parts = match value {
        Value::Nil => return Ok(None),
        Value::Map(parts) => parts,
        _ => return Err(corrupt()),
    };
    let Some(Value::Array(rows)) = field(parts, KEY_ENTRIES) else {
        return Err(corrupt());
    };
    Ok(Some(CleanupRunSnapshot {
        at: field(parts, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or_else(corrupt)?,
        decision: field(parts, KEY_DECISION)
            .and_then(Value::as_str)
            .and_then(CleanupDecision::parse)
            .ok_or_else(corrupt)?,
        digest: entity_at(parts, KEY_DIGEST).ok_or_else(corrupt)?,
        entries: rows
            .iter()
            .map(|row| match row {
                Value::Nil => Some(None),
                row => decode_entry(row).map(Some),
            })
            .collect::<Option<_>>()
            .ok_or_else(corrupt)?,
    }))
}

fn decode_entry(row: &Value) -> Option<CleanupSnapshotEntry> {
    let Value::Map(parts) = row else {
        return None;
    };
    Some(CleanupSnapshotEntry {
        entity: entity_at(parts, KEY_ENTITY)?,
        kind: field(parts, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)?,
        revision: field(parts, KEY_REVISION)
            .and_then(Value::as_slice)?
            .try_into()
            .ok()?,
        before: match field(parts, KEY_BEFORE)? {
            Value::Nil => None,
            value => Some(value.as_slice()?.to_vec()),
        },
        after: field(parts, KEY_AFTER).and_then(Value::as_slice)?.to_vec(),
    })
}

/// The entity id a row holds as hex under `key`.
pub(super) fn entity_at(parts: &[(Value, Value)], key: &str) -> Option<EntityId> {
    field(parts, key)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
}
