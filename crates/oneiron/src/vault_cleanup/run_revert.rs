//! The owner reverts one whole cleanup run (OF-449).
//!
//! The revert reads the run's snapshot and lifts only the marks that run
//! wrote: a record through the record restore, an attempt through the
//! attempt restore. Each entry answers for itself. An entry whose mark a
//! later archive replaced, or that a delete or an erase reached since, is a
//! finding and stays as it is: it never refuses the whole run, and a revert
//! never undoes a delete or an erase. Each restored entry is kept at its
//! revision, so no arm archives it again until it changes.
//!
//! The first answer is stored on the RUN row in the revert's own write, and a
//! repeated revert returns it as stored.

use rmpv::Value;

use super::attempt_retention::{keep_attempt_in_txn, restore_archived_attempt_in_txn};
use super::codec_receipts::PROPOSAL;
use super::marks::{self, CleanupMark};
use super::run_record::{self, KEY_REVERT, KEY_SNAPSHOT};
use super::run_snapshot::{CleanupSnapshotEntry, KEY_ENTRIES, decode_snapshot, entity_at};
use super::{CleanupKind, KEY_AT, KEY_ENTITY, KEY_KIND, field};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::batch::EntityMetadataHeader;
use crate::deletion::{TombstoneReason, decode_tombstone_value};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{EntityStoreRead, JobQueueRead};

const REVERT_LABEL: &str = "cleanup run revert";
const KEY_OUTCOME: &str = "outcome";
const KEY_REASON: &str = "reason";
const KEY_EDITED: &str = "edited";

/// Why a reverted entry was left as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupRevertReason {
    /// A later archive's mark hides it now; reverting that run brings it
    /// back.
    ArchivedAgain,
    /// Its record or its archive mark does not read as cleanup left it.
    Unreadable,
    /// A delete or an erase reached it after the run; a revert never undoes
    /// one.
    Deleted,
    /// It is no longer in the vault, or no longer on the queue.
    Gone,
}

impl CleanupRevertReason {
    /// The pinned wire string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArchivedAgain => "archived_again",
            Self::Unreadable => "unreadable",
            Self::Deleted => "deleted",
            Self::Gone => "gone",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "archived_again" => Some(Self::ArchivedAgain),
            "unreadable" => Some(Self::Unreadable),
            "deleted" => Some(Self::Deleted),
            "gone" => Some(Self::Gone),
            _ => None,
        }
    }
}

/// What reverting a run did to one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupRevertOutcome {
    /// This run's mark still hid it, and the revert lifted that mark.
    Restored,
    /// Nothing hides it any more: a restore or a re-mention brought it back
    /// first.
    AlreadyRestored,
    /// Something else marks it now; it is left as it is.
    Changed(CleanupRevertReason),
    /// A delete, an erase or its departure came after the run; it is left as
    /// it is.
    Unavailable(CleanupRevertReason),
}

impl CleanupRevertOutcome {
    /// The pinned wire string: `restored`, `already_restored`, `changed` or
    /// `unavailable`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restored => "restored",
            Self::AlreadyRestored => "already_restored",
            Self::Changed(_) => "changed",
            Self::Unavailable(_) => "unavailable",
        }
    }

    /// Why the entry was left as it is, for `changed` and `unavailable`.
    #[must_use]
    pub const fn reason(self) -> Option<CleanupRevertReason> {
        match self {
            Self::Restored | Self::AlreadyRestored => None,
            Self::Changed(reason) | Self::Unavailable(reason) => Some(reason),
        }
    }

    fn parse(outcome: &str, reason: Option<&str>) -> Option<Self> {
        match (outcome, reason.map(CleanupRevertReason::parse)) {
            ("restored", None) => Some(Self::Restored),
            ("already_restored", None) => Some(Self::AlreadyRestored),
            ("changed", Some(Some(reason))) => Some(Self::Changed(reason)),
            ("unavailable", Some(Some(reason))) => Some(Self::Unavailable(reason)),
            _ => None,
        }
    }
}

/// One entry of a run's revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupRevertEntry {
    /// The record, or the completed attempt's id.
    pub entity: EntityId,
    /// The arm that archived it.
    pub kind: CleanupKind,
    /// What the revert did.
    pub outcome: CleanupRevertOutcome,
    /// Its stored bytes changed after the run archived them: the snapshot's
    /// revision no longer matches. The mark decides the outcome, never this.
    pub edited: bool,
}

/// What reverting one cleanup run did, entry by entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunRevert {
    /// The run's attempt id.
    pub attempt: AttemptId,
    /// When the first revert committed, in recorded seconds.
    pub reverted_at: u64,
    /// One answer per snapshot entry, in snapshot order. `None` answers an
    /// entry an erase reached: it names no one, and the revert lifted nothing
    /// for it (FIX 7517).
    pub entries: Vec<Option<CleanupRevertEntry>>,
    /// An earlier revert stored this answer; this call changed nothing.
    pub repeated: bool,
}

/// The answer to a whole-run revert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupRunRevertAnswer {
    /// The run is reverted; a repeat returns the stored answer.
    Reverted(CleanupRunRevert),
    /// No cleanup run has this attempt id.
    NoSuchRun,
    /// The run archived nothing yet and its proposal waits for review;
    /// nothing was stored.
    ProposalOpen(EntityId),
    /// The run ran before runs kept snapshots; its entries restore one by
    /// one.
    Unrecorded,
}

/// Reverts cleanup run `run` in the caller's write transaction.
///
/// Storage errors fail the whole revert and store nothing; an entry that
/// changed since the run never does.
pub(super) fn revert_cleanup_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: AttemptId,
) -> Result<CleanupRunRevertAnswer> {
    let Some(fields) = run_record::fields_in_txn(vault, txn, &run)? else {
        return Ok(CleanupRunRevertAnswer::NoSuchRun);
    };
    if let Some(stored) = field(&fields, KEY_REVERT).filter(|value| !value.is_nil()) {
        let mut answer = decode_revert(run, stored)?;
        answer.repeated = true;
        return Ok(CleanupRunRevertAnswer::Reverted(answer));
    }
    let Some(snapshot) = field(&fields, KEY_SNAPSHOT) else {
        return Ok(CleanupRunRevertAnswer::Unrecorded);
    };
    let snapshot = decode_snapshot(snapshot)?;
    if snapshot.is_none()
        && let Some(proposal) = run_record::proposal_of(&fields)?
        && PROPOSAL.contains(&vault.store, txn, &proposal)?
    {
        return Ok(CleanupRunRevertAnswer::ProposalOpen(proposal));
    }
    let reverted_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut entries = Vec::new();
    let mut records_restored = false;
    for entry in snapshot.map_or_else(Vec::new, |snapshot| snapshot.entries) {
        // An erased entry names no one, so nothing is looked up, restored or
        // kept for it: no revert brings an erased entity back (FIX 7517).
        let Some(entry) = entry else {
            entries.push(None);
            continue;
        };
        let record = entry.kind != CleanupKind::CompletedAttempt;
        let (outcome, edited) = if record {
            revert_record(vault, txn, &entry)?
        } else {
            revert_attempt(vault, txn, run, &entry)?
        };
        records_restored |= record && outcome == CleanupRevertOutcome::Restored;
        entries.push(Some(CleanupRevertEntry {
            entity: entry.entity,
            kind: entry.kind,
            outcome,
            edited,
        }));
    }
    if records_restored {
        // FIX 6058, once for the whole run: a restored grant or actor may
        // stand a held program's authority again. Best-effort, as the record
        // restore does it.
        vault.resume_turn_programs_after_authority_change_in_txn(txn);
    }
    let answer = CleanupRunRevert {
        attempt: run,
        reverted_at,
        entries,
        repeated: false,
    };
    run_record::set_field_in_txn(vault, txn, &run, KEY_REVERT, encode_revert(&answer))?;
    Ok(CleanupRunRevertAnswer::Reverted(answer))
}

/// One record of the run. It is lifted only while this run's exact `ac:`
/// mark still hides it and no delete or erase came after the run.
fn revert_record(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entry: &CleanupSnapshotEntry,
) -> Result<(CleanupRevertOutcome, bool)> {
    let id = &entry.entity;
    if vault.local_hard_delete_marker_exists_in_txn(txn, id)? {
        return Ok((
            CleanupRevertOutcome::Unavailable(CleanupRevertReason::Deleted),
            true,
        ));
    }
    let Some(raw) = vault.store.port_entity_raw(txn, id)? else {
        return Ok((
            CleanupRevertOutcome::Unavailable(CleanupRevertReason::Gone),
            true,
        ));
    };
    // A scrubbed binding names no bytes: the entry reads as edited (FIX 7615).
    let edited = entry.revision.is_none()
        || marks::record_revision_in_txn(vault, txn, id)? != entry.revision;
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok((
            CleanupRevertOutcome::Changed(CleanupRevertReason::Unreadable),
            edited,
        ));
    };
    if vault
        .store
        .entity_deletion_present_in_txn(txn, id, header.learned_at)?
    {
        return Ok((
            CleanupRevertOutcome::Unavailable(CleanupRevertReason::Deleted),
            edited,
        ));
    }
    let outcome = match vault.archive_tombstone_in_txn(txn, id)? {
        None => CleanupRevertOutcome::AlreadyRestored,
        Some(mark)
            if mark.reason == Some(TombstoneReason::ArchivedByCleanup)
                && entry
                    .after
                    .as_deref()
                    .is_some_and(|after| mark == decode_tombstone_value(after)) =>
        {
            lift(
                vault,
                txn,
                CleanupRevertOutcome::Unavailable(CleanupRevertReason::Deleted),
                |savepoint| {
                    vault.restore_archived_record_in_txn(savepoint, id)?;
                    marks::keep_record_in_txn(vault, savepoint, id)
                },
            )?
        }
        Some(mark) if mark.reason == Some(TombstoneReason::ArchivedByCleanup) => {
            CleanupRevertOutcome::Changed(CleanupRevertReason::ArchivedAgain)
        }
        Some(_) => CleanupRevertOutcome::Changed(CleanupRevertReason::Unreadable),
    };
    Ok((outcome, edited))
}

/// One completed attempt of the run. It is lifted only while this run's
/// mark still binds the row's exact bytes.
fn revert_attempt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: AttemptId,
    entry: &CleanupSnapshotEntry,
) -> Result<(CleanupRevertOutcome, bool)> {
    let id = AttemptId::from_bytes(entry.entity.as_bytes())?;
    let Some(raw) = JobQueueRead::port_job_row(&vault.store, txn, &id)? else {
        return Ok((
            CleanupRevertOutcome::Unavailable(CleanupRevertReason::Gone),
            true,
        ));
    };
    let revision = marks::revision_of(&raw);
    let outcome = match marks::mark_in_txn(&vault.store, txn, id.as_bytes())? {
        Some(CleanupMark::Archived {
            revision: archived,
            run: by,
        }) if archived == revision => {
            if by == run {
                lift(
                    vault,
                    txn,
                    CleanupRevertOutcome::Changed(CleanupRevertReason::Unreadable),
                    |savepoint| {
                        restore_archived_attempt_in_txn(vault, savepoint, id)?;
                        keep_attempt_in_txn(vault, savepoint, id)
                    },
                )?
            } else {
                CleanupRevertOutcome::Changed(CleanupRevertReason::ArchivedAgain)
            }
        }
        // Absent, kept, stale or unreadable: nothing hides the row now.
        _ => CleanupRevertOutcome::AlreadyRestored,
    };
    // The current mark and run decide the lift; a scrubbed binding only
    // reads as edited (FIX 7615).
    Ok((outcome, entry.revision != Some(revision)))
}

/// Runs one entry's restore in a savepoint of the revert's write. A restore
/// the engine refuses rolls back alone and answers `refused`; any other
/// error fails the revert.
fn lift(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    refused: CleanupRevertOutcome,
    restore: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) -> Result<CleanupRevertOutcome> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match restore(&mut savepoint) {
        Ok(()) => {
            savepoint.commit()?;
            Ok(CleanupRevertOutcome::Restored)
        }
        Err(
            Error::Maintenance(_) | Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_)),
        ) => Ok(refused),
        Err(error) => Err(error),
    }
}

fn encode_revert(answer: &CleanupRunRevert) -> Value {
    Value::Map(vec![
        (Value::from(KEY_AT), Value::from(answer.reverted_at)),
        (
            Value::from(KEY_ENTRIES),
            Value::Array(
                answer
                    .entries
                    .iter()
                    .map(|entry| entry.as_ref().map_or(Value::Nil, encode_entry))
                    .collect(),
            ),
        ),
    ])
}

fn encode_entry(entry: &CleanupRevertEntry) -> Value {
    Value::Map(vec![
        (Value::from(KEY_ENTITY), Value::from(entry.entity.to_hex())),
        (Value::from(KEY_KIND), Value::from(entry.kind.as_str())),
        (
            Value::from(KEY_OUTCOME),
            Value::from(entry.outcome.as_str()),
        ),
        (
            Value::from(KEY_REASON),
            entry
                .outcome
                .reason()
                .map_or(Value::Nil, |reason| Value::from(reason.as_str())),
        ),
        (Value::from(KEY_EDITED), Value::from(entry.edited)),
    ])
}

/// A RUN row's stored `revert` value, read back as the answer it was.
pub(super) fn decode_revert(attempt: AttemptId, value: &Value) -> Result<CleanupRunRevert> {
    let corrupt = || Error::CorruptedIndex(REVERT_LABEL);
    let Value::Map(parts) = value else {
        return Err(corrupt());
    };
    let Some(Value::Array(rows)) = field(parts, KEY_ENTRIES) else {
        return Err(corrupt());
    };
    Ok(CleanupRunRevert {
        attempt,
        reverted_at: field(parts, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or_else(corrupt)?,
        entries: rows
            .iter()
            .map(|row| match row {
                Value::Nil => Some(None),
                row => decode_entry(row).map(Some),
            })
            .collect::<Option<_>>()
            .ok_or_else(corrupt)?,
        repeated: false,
    })
}

fn decode_entry(row: &Value) -> Option<CleanupRevertEntry> {
    let Value::Map(parts) = row else {
        return None;
    };
    let reason = match field(parts, KEY_REASON)? {
        Value::Nil => None,
        value => Some(value.as_str()?),
    };
    Some(CleanupRevertEntry {
        entity: entity_at(parts, KEY_ENTITY)?,
        kind: field(parts, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)?,
        outcome: CleanupRevertOutcome::parse(
            field(parts, KEY_OUTCOME).and_then(Value::as_str)?,
            reason,
        )?,
        edited: field(parts, KEY_EDITED).and_then(Value::as_bool)?,
    })
}
