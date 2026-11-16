//! Explicit cleanup-archived Completed attempt deletion (FIX 9059).
//! Preview describes one row; confirm checks its exact row and archive mark,
//! current authority and all deletion effects in a single write transaction.
//!
//! Check-in (ROLES-CHECKIN P2.5 2k5e; ARCH-0082 #act-table "Delete items";
//! Engine ruling P25-SHAPE Q1 = A) judges the confirm in that writer, after
//! its authority, and its receipt records the decision: the Owner deletes on
//! their own proof, an Admin's confirm never asks, a Deputy's goes on their
//! own judgment (`sure`). No role that reaches this door waits, so it takes
//! no `check_in_ref`.

use super::attempt_delete_authority::{DeleteAuthority, require_delete_in_txn};
use super::attempt_delete_receipts::stamp_in_txn;
use super::marks::{self, CleanupMark};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState, decode_record};
use crate::check_in::{
    self, ActClass, CheckInDecision, CheckInScope, DoorAct, DoorCheckIn, RolePreset,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::ports::JobQueueRead;
use crate::{Error, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::vault_cleanup::attempt_delete_wire::{
    AttemptArchiveDeleteConfirmRequest, AttemptArchiveDeleteExpectation,
    AttemptArchiveDeletePreviewRequest, AttemptArchiveDeletePreviewView,
    AttemptArchiveDeleteReceiptView,
};

/// Previews only the selected cleanup-archived Completed row, without its payload.
pub fn preview_attempt_archive_delete_wire(
    memory: &Memory<'_>,
    request: &AttemptArchiveDeletePreviewRequest,
) -> MemoryResult<AttemptArchiveDeletePreviewView> {
    let id = attempt_id(&request.attempt)?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    require_delete_in_txn(memory, &txn)?;
    selected_in_txn(vault, &txn, id)
}

/// Revalidates authority and the preview in the same writer that deletes the row,
/// its marks and indexes and commits the truthful deletion receipt.
pub fn confirm_attempt_archive_delete_wire(
    memory: &Memory<'_>,
    request: &AttemptArchiveDeleteConfirmRequest,
) -> MemoryResult<AttemptArchiveDeleteReceiptView> {
    let id = attempt_id(&request.attempt)?;
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|txn| {
        let authority = require_delete_in_txn(memory, txn)?;
        let current = selected_in_txn(vault, txn, id)?;
        if current.expected != request.expected {
            return Err(MemoryError::bad_request(
                "attempt archive changed; preview again",
            ));
        }
        let check_in = attempt_delete_check_in_in_txn(vault, txn, &authority, id)?;
        let record = AttemptQueue::new(vault).delete_archived_completed_in_txn(txn, id)?;
        let at = vault.now_recorded_at();
        let receipt_ref = stamp_in_txn(
            vault,
            txn,
            id,
            authority.actor,
            at,
            record.run_id.as_deref(),
        )?;
        Ok(AttemptArchiveDeleteReceiptView {
            attempt: bytes_to_hex_lower(id.as_bytes()),
            deleted_by: authority.actor.to_hex(),
            deleted_at: at,
            run_id: record.run_id,
            receipt_ref,
            role: authority.role.to_owned(),
            grant_ref: authority.grant.map(|(grant, _)| grant.to_hex()),
            check_in: Some(check_in),
        })
    })
}

/// The check-in decision of the confirm `authority` admitted for attempt
/// `id`, judged in `txn`, its writer (module docs). The Owner acts on their
/// own proof. An Admin or a Deputy is judged under the membership role of
/// the grant that admitted them, over the attempt's delete digest.
///
/// # Errors
///
/// `InvariantViolation` if the judge would make the confirm wait, which no
/// admin role's cell does; as [`check_in::person_door_check_in_in_txn`].
fn attempt_delete_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    authority: &DeleteAuthority,
    id: AttemptId,
) -> crate::Result<CheckInDecision> {
    let Some((grant, role)) = authority.grant else {
        return Ok(check_in::owner_own_proof_decision(ActClass::Delete));
    };
    let act = DoorAct {
        person: authority.actor,
        role: RolePreset::of_grant_role(role),
        grant,
        verb: "vault.archive.attempt.delete.confirm",
        act: ActClass::Delete,
        scope: CheckInScope::default(),
        effect_digest: check_in::attempt_archive_delete_effect_digest(id.as_bytes()),
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    match check_in::person_door_check_in_in_txn(vault, txn, &act, None, now)? {
        DoorCheckIn::Go(decision) => Ok(decision),
        DoorCheckIn::Wait(_) => Err(Error::InvariantViolation(
            "an attempt archive delete by an Admin or a Deputy never waits",
        )),
    }
}

fn selected_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> MemoryResult<AttemptArchiveDeletePreviewView> {
    let raw = JobQueueRead::port_job_row(&vault.store, txn, &id)?.ok_or_else(not_archived)?;
    let record = decode_record(&raw, id)?;
    let marker = marks::raw_in_txn(&vault.store, txn, id.as_bytes())?.ok_or_else(not_archived)?;
    let revision = marks::revision_of(&raw);
    if record.state != AttemptState::Completed
        || !matches!(CleanupMark::decode(&marker), Some(CleanupMark::Archived { revision: held, .. }) if held == revision)
    {
        return Err(not_archived());
    }
    Ok(AttemptArchiveDeletePreviewView {
        attempt: bytes_to_hex_lower(id.as_bytes()),
        record_bytes: raw.len() as u64,
        expected: AttemptArchiveDeleteExpectation {
            record_hash: bytes_to_hex_lower(&revision),
            archive_marker: bytes_to_hex_lower(&marker),
        },
    })
}

fn attempt_id(text: &str) -> MemoryResult<AttemptId> {
    let invalid = || MemoryError::bad_request("attempt must be 32 hex digits");
    if text.len() != 32 || !text.is_ascii() {
        return Err(invalid());
    }
    let mut raw = [0_u8; 16];
    for (byte, pair) in raw.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| invalid())?, 16)
            .map_err(|_| invalid())?;
    }
    AttemptId::from_bytes(&raw).map_err(|_| invalid())
}

fn not_archived() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "attempt is not a cleanup-archived Completed row",
        &["Preview a current cleanup-archived completed attempt."],
    )
}
