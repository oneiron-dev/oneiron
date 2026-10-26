//! One ledger row's transition in the caller's writer (FIX 7188): the body
//! the ledger's own transition doors commit in a writer of their own, and a
//! writer that composes it with other work (an owner's Stop) commits with
//! that work. It opens no writer.

use super::super::types::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use super::{LEDGER, get_ledger_record};
use crate::Vault;

/// What one transition did in the caller's writer.
pub(super) enum Transitioned {
    /// The row moved to the next state with the outcome: the writer owes
    /// its commit.
    Moved(IntentLedgerRecord),
    /// The row already stood in that state with the same outcome: nothing
    /// was written.
    Replayed(IntentLedgerRecord),
}

/// Moves row `id` to `next` with `outcome` in `wtxn`: Pending moves to Done,
/// Abandoned or Deferred, and Deferred to Done or Abandoned; a row already in
/// `next` replays when its outcome matches. A Done, a Deferred or an
/// Abandoned row, but one whose dedupe reservation another attempt replaced,
/// anchors its dedupe floor to this transition in the same writer, and the
/// row's reserved budget settles by its new state (FIX 7964).
///
/// # Errors
///
/// A row that is missing, does not read, or may not move to `next`; a replay
/// whose outcome differs; storage errors.
pub(super) fn transition_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
) -> IntentLedgerResult<Transitioned> {
    let mut record = get_ledger_record(vault, &*wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("transition target is missing"),
    )?;
    if record.state == next {
        if record.recorded_outcome != Some(outcome) {
            return Err(IntentLedgerError::InvalidRecord(
                "terminal replay outcome does not match persisted outcome",
            ));
        }
        return Ok(Transitioned::Replayed(record));
    }
    if !record.state.may_transition_to(next) {
        return Err(IntentLedgerError::InvalidTransition {
            from: record.state,
            to: next,
        });
    }
    record.state = next;
    record.recorded_outcome = Some(outcome);
    record.updated_ms = now_ms.max(record.created_ms);
    LEDGER.put(&vault.store, wtxn, &id, &record)?;
    if matches!(next, IntentState::Done | IntentState::Deferred)
        || (next == IntentState::Abandoned
            && outcome
                != RecordedOutboundOutcome::Abandoned(
                    IntentEscalationReason::DedupeReservationReplaced,
                ))
    {
        // Abandonment may follow a wire-started attempt whose delivery is
        // unknown. Keep its conservative floor anchored to this transition.
        crate::outbound_chokepoint::dedupe::delivered_in_txn(vault, wtxn, &id)?;
    }
    super::super::settlement::settle_reservation_in_txn(vault, wtxn, &record)?;
    Ok(Transitioned::Moved(record))
}
