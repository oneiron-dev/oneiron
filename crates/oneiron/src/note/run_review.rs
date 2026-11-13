//! Transaction-composable review and compensation over the existing NOTE door.

use super::documents::{live_doc, load_head};
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_RECEIPT, land};
use super::{NoteFork, NoteLandingReceipt, NoteVerdict, NoteVersion};
use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// What restores a NOTE to the revision before a fork landed on it: the head
/// it stood on and its version there, and the version the landing left.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RunNoteUndo {
    pub note: String,
    pub(super) before_head: String,
    pub(super) before: NoteVersion,
    pub(super) after: NoteVersion,
}

/// Where a NOTE fork stands, for a run review and a run journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoteForkState {
    /// No fork has that ref on that NOTE: an erase of its opener took a
    /// pending fork, or none was opened.
    Absent,
    /// Pending: no one decided it.
    Waiting,
    /// Decided, under the verdict its landing receipt names; `None` when
    /// that receipt is gone.
    Decided(Option<NoteVerdict>),
}

/// `fork` of `note`'s record, when it has one.
fn fork_record_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> MemoryResult<Option<NoteFork>> {
    Ok(NOTE_FORK
        .get(&vault.store, txn, &fork)?
        .filter(|record| record.note == note))
}

/// The receipt that decided `fork`, read by fork as the version tree reads it.
fn landing_receipt_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    fork: EntityId,
) -> MemoryResult<Option<NoteLandingReceipt>> {
    Ok(NOTE_RECEIPT
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, receipt)| receipt)
        .find(|receipt| receipt.fork == fork))
}

/// Where `fork` of `note` stands now, for a run journal's NOTE row.
///
/// # Errors
/// A store failure.
pub(crate) fn note_fork_state_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> MemoryResult<NoteForkState> {
    Ok(match fork_record_in_txn(vault, txn, note, fork)? {
        None => NoteForkState::Absent,
        Some(record) if !record.decided => NoteForkState::Waiting,
        Some(_) => NoteForkState::Decided(
            landing_receipt_in_txn(vault, txn, fork)?.map(|receipt| receipt.verdict),
        ),
    })
}

/// The bytes a run review binds for `fork` of `note`, and where the fork
/// stands. A pending fork binds its record, the live version and its own; a
/// decided fork binds its record, the live version and the receipt that
/// decided it, so a review reads its verdict and does not refuse it.
///
/// # Errors
/// `not_found` when no fork has that ref on that NOTE; a store failure.
pub(crate) fn run_note_review_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> MemoryResult<(Vec<u8>, NoteForkState)> {
    let record = fork_record_in_txn(vault, txn, note, fork)?
        .ok_or_else(|| MemoryError::not_found("no NOTE fork has that ref"))?;
    let live = live_doc(vault, txn, note)?.version();
    let (binding, state) = if record.decided {
        let receipt = landing_receipt_in_txn(vault, txn, fork)?;
        let state = NoteForkState::Decided(receipt.as_ref().map(|receipt| receipt.verdict));
        (serde_json::to_vec(&(&record, live, receipt)), state)
    } else {
        let proposed = load_head(vault, txn, note, fork)?.version();
        (
            serde_json::to_vec(&(&record, live, proposed)),
            NoteForkState::Waiting,
        )
    };
    let binding = binding.map_err(|_| MemoryError::bad_request("NOTE review cannot be encoded"))?;
    Ok((binding, state))
}

pub(crate) fn settle_run_note_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    fork: EntityId,
    approve: bool,
) -> MemoryResult<Option<(String, Option<RunNoteUndo>)>> {
    let vault = memory.vault();
    let mut record = fork_record_in_txn(vault, txn, note, fork)?
        .filter(|record| !record.decided)
        .ok_or_else(|| MemoryError::not_found("no pending NOTE fork has that ref"))?;
    let actor = memory.write_actor();
    if record.actor.is(actor.entity_ref()) {
        return Err(MemoryError::bad_request(
            "a proposal's opener never settles it",
        ));
    }
    if !super::proposals::grant_allows(vault, txn, note, actor)? {
        return Err(MemoryError::bad_request(
            "no grant to settle this NOTE fork",
        ));
    }
    let verdict = if !approve {
        NoteVerdict::Reject
    } else if record.rewrite {
        NoteVerdict::Switch
    } else {
        NoteVerdict::Merge
    };
    if approve {
        super::lifecycle::refuse_sealed_note_in_txn(&vault.store, txn, note)?;
    }
    // The landing takes the undo: a switch keeps the head it left.
    let Some((receipt, undo)) = land(vault, txn, &mut record, verdict, actor, true)? else {
        return Ok(None);
    };
    if let Some(proposal) = record.proposal {
        let mut bundle = NOTE_PROPOSAL_BUNDLE
            .get(&vault.store, txn, &proposal)?
            .ok_or_else(|| MemoryError::not_found("NOTE proposal is absent"))?;
        bundle.waiting.retain(|row| row.fork != fork);
        bundle.landed.push(receipt.clone());
        NOTE_PROPOSAL_BUNDLE.put(&vault.store, txn, &proposal, &bundle)?;
    }
    Ok(Some((receipt.id.to_hex(), undo)))
}

/// Currency and the inverse's content gate are checked in the same writer.
/// A later edit that changed the text is not overwritten: it returns no
/// compensation.
pub(crate) fn revert_run_note_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    undo: &RunNoteUndo,
) -> MemoryResult<Option<String>> {
    let vault = memory.vault();
    let note = EntityId::from_hex(&undo.note)?;
    let current = live_doc(vault, txn, note)?;
    if current.version() != undo.after {
        // Composition across the run's own compensations (FIX 9964): undoing
        // a later same-note change first lands a compensating edit, so the
        // note then stands at a new version holding exactly the `after`
        // text. That state still compensates; any other later text does
        // not, so no unrelated edit is overwritten.
        let Ok(after) = current.at_version(&undo.after) else {
            return Ok(None);
        };
        if after.text() != current.text() {
            return Ok(None);
        }
    }
    super::lifecycle::refuse_sealed_note_in_txn(&vault.store, txn, note)?;
    let before = load_head(vault, txn, note, EntityId::from_hex(&undo.before_head)?)?
        .at_version(&undo.before)?;
    let operation = super::NoteOperation {
        request_id: vault.store.clock.entity_id()?,
        change: super::NoteChange::Edit {
            base: current.doc.oplog_frontiers().encode(),
            edits: vec![super::documents::text_change(
                &current.text(),
                &before.text(),
            )],
        },
    };
    let receipt = memory.apply_note_operation_in_txn(txn, note, &operation, None)?;
    if matches!(receipt.outcome, super::NoteScalarEditOutcome::Proposed(_)) {
        return Err(MemoryError::bad_request("NOTE compensation did not land"));
    }
    Ok(Some(operation.request_id.to_hex()))
}
