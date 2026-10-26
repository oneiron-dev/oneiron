//! The sends one attempt has not settled (DOOR-141 PR3b): what a held turn
//! program's resume waits on, read over the attempt's own index rows, and
//! their abandon when the owner stops that try (FIX 7188).

use super::super::types::{
    IntentEscalationReason, IntentId, IntentLedgerError, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use super::transition::transition_record_in_txn;
use super::{
    INTENT_ATTEMPT_INDEX, LEDGER, check_intent_attempt_format, read_stored_intent_record_in_txn,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;

/// Whether `attempt_id` holds an intent still Pending, or one whose row does
/// not read: a send whose delivery is not settled. A turn program's resume
/// holds on one rather than letting it go out again (DOOR-141 PR3b). Only
/// the attempt's own index rows are read.
pub(crate) fn attempt_has_pending_intent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
) -> IntentLedgerResult<bool> {
    check_intent_attempt_format(vault, txn)?;
    for row in INTENT_ATTEMPT_INDEX.iter_raw_from(&vault.store, txn, attempt_id.as_bytes())? {
        let (_, raw) = row?;
        let Ok(id) = IntentId::try_from(raw.as_slice()) else {
            return Ok(true);
        };
        match read_stored_intent_record_in_txn(vault, txn, &id) {
            Ok(Some(record)) if record.state != IntentState::Pending => {}
            _ => return Ok(true),
        }
    }
    Ok(false)
}

/// Marks each of `attempt_id`'s sends still Pending Abandoned for `reason`,
/// in the caller's writer, which commits them with its own change (FIX 7188:
/// the owner's Stop of that try). Each keeps its row, payload, binding and
/// accounting. An outcome-free one may have crossed the wire, so that stays
/// recorded as possible delivery, as a replay records it before its abandon:
/// nothing reads it as undelivered. A send already Done or Abandoned is left
/// as it is. Only the attempt's own index rows are read, and one that does
/// not read fails the whole walk, so the caller's savepoint keeps none of
/// it. Opens no writer. Returns how many it abandoned.
///
/// # Errors
///
/// An attempt index that does not read, or a row it names that does not;
/// storage errors.
pub(crate) fn abandon_attempt_pending_intents_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    reason: IntentEscalationReason,
    now_ms: u64,
) -> IntentLedgerResult<usize> {
    check_intent_attempt_format(vault, &*wtxn)?;
    let mut ids = Vec::new();
    for row in INTENT_ATTEMPT_INDEX.iter_raw_from(&vault.store, &*wtxn, attempt_id.as_bytes())? {
        let (_, raw) = row?;
        let id = IntentId::try_from(raw.as_slice()).map_err(|_| {
            IntentLedgerError::InvalidRecord("invalid outbound attempt index target")
        })?;
        ids.push(id);
    }
    let mut abandoned = 0_usize;
    for id in ids {
        let Some(mut record) = read_stored_intent_record_in_txn(vault, &*wtxn, &id)? else {
            return Err(IntentLedgerError::InvalidRecord(
                "outbound attempt index target is missing",
            ));
        };
        if record.state != IntentState::Pending {
            continue;
        }
        if record.recorded_outcome.is_none() && !record.delivery_uncertain {
            record.delivery_uncertain = true;
            LEDGER.put(&vault.store, wtxn, &id, &record)?;
        }
        transition_record_in_txn(
            vault,
            wtxn,
            id,
            IntentState::Abandoned,
            RecordedOutboundOutcome::Abandoned(reason),
            now_ms,
        )?;
        abandoned += 1;
    }
    Ok(abandoned)
}
