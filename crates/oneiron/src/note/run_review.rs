//! Transaction-composable review and compensation over the existing NOTE door.

use super::documents::{NOTE_PROPOSAL_DOC, live_doc, load_head};
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE, land};
use super::side_keys::HexPair;
use super::{NoteFork, NoteVerdict, NoteVersion};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::HexId;
use crate::{EntityId, WriteActor};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RunNoteUndo {
    pub note: String,
    before_head: String,
    before: NoteVersion,
    after: NoteVersion,
}

pub(crate) fn run_note_review_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> MemoryResult<(NoteFork, Vec<u8>)> {
    let record = NOTE_FORK
        .get(&vault.store, txn, &fork)?
        .filter(|record| record.note == note && !record.decided)
        .ok_or_else(|| MemoryError::not_found("no pending NOTE fork has that ref"))?;
    let live = live_doc(vault, txn, note)?;
    let proposed = load_head(vault, txn, note, fork)?;
    let binding = serde_json::to_vec(&(&record, live.version(), proposed.version()))
        .map_err(|_| MemoryError::bad_request("NOTE review cannot be encoded"))?;
    Ok((record, binding))
}

pub(crate) fn settle_run_note_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    fork: EntityId,
    approve: bool,
) -> MemoryResult<Option<(String, RunNoteUndo)>> {
    let vault = memory.vault();
    let (mut record, _) = run_note_review_in_txn(vault, txn, note, fork)?;
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
    let before = live_doc(vault, txn, note)?;
    let before_head = before.head().to_hex();
    if approve && record.rewrite {
        NOTE_PROPOSAL_DOC.put(
            &vault.store,
            txn,
            &HexPair(HexId(note), HexId(before.head())),
            &super::documents::snapshot(&before.doc)?,
        )?;
    }
    let before = before.version();
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
    let Some(receipt) = land(vault, txn, &mut record, verdict, actor)? else {
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
    let after = live_doc(vault, txn, note)?.version();
    Ok(Some((
        receipt.id.to_hex(),
        RunNoteUndo {
            note: note.to_hex(),
            before_head,
            before,
            after,
        },
    )))
}

/// Currency and the inverse's content gate are checked in the same writer.
/// A later edit is not overwritten: it returns no compensation.
pub(crate) fn revert_run_note_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    undo: &RunNoteUndo,
) -> MemoryResult<Option<String>> {
    let vault = memory.vault();
    let note = EntityId::from_hex(&undo.note)?;
    let current = live_doc(vault, txn, note)?;
    if current.version() != undo.after {
        return Ok(None);
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
    if matches!(receipt.outcome, super::NoteEditOutcome::Proposed(_)) {
        return Err(MemoryError::bad_request("NOTE compensation did not land"));
    }
    Ok(Some(operation.request_id.to_hex()))
}
