//! One ledger row's transition and completion commit (FIX 7188).
//! The transaction form opens no writer: a caller can compose it with an
//! owner's Stop. The completion wrapper commits and syncs its own writer
//! before returning the record and any newly fired budget events.

use super::super::types::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use super::{LEDGER, force_sync, get_ledger_record, open_payload_in_txn};
use crate::Vault;
use crate::error::Error;

/// What one transition did in the caller's writer.
pub(super) enum Transitioned {
    /// The row moved to the next state with the outcome: the writer owes
    /// its commit.
    Moved(
        IntentLedgerRecord,
        Vec<crate::connector_key::EffectorBudgetSettlementEvents>,
    ),
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
    let budget_events = super::super::settlement::settle_reservation_in_txn(vault, wtxn, &record)?;
    // FIX 4747 slice 7: an agent run's effect mark settles in this writer.
    crate::agent_dispatch::settle_agent_run_effect_mark_in_txn(vault, wtxn, &record);
    Ok(Transitioned::Moved(record, budget_events))
}

pub(crate) struct IntentCompletion {
    pub(crate) record: IntentLedgerRecord,
    pub(crate) budget_events: Vec<crate::connector_key::EffectorBudgetSettlementEvents>,
}

pub(super) fn transition_record_with_outcome_and(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
    also: impl FnOnce(&mut heed::RwTxn<'_>, &IntentLedgerRecord),
) -> IntentLedgerResult<IntentCompletion> {
    let mut wtxn = vault.store.env.write_txn()?;
    let (mut record, budget_events) =
        match transition_record_in_txn(vault, &mut wtxn, id, next, outcome, now_ms)? {
            Transitioned::Moved(record, budget_events) => (record, budget_events),
            Transitioned::Replayed(mut record) => {
                drop(wtxn);
                // No state write to keep: the replay only re-reads, so the
                // open runs on a snapshot past the dropped writer (FIX 12497),
                // as in `record_possible_delivery`'s no-op arm.
                let rtxn = vault.store.custody_snapshot()?;
                open_payload_in_txn(vault, &rtxn, &mut record)?;
                return Ok(IntentCompletion {
                    record,
                    budget_events: Vec::new(),
                });
            }
        };
    // `also` runs on the unopened record: the bridge reads header fields
    // only, and the open below must not fail the commit (FIX 12497).
    also(&mut wtxn, &record);
    wtxn.commit().map_err(Error::from)?;
    let synced = force_sync(vault);
    // The terminal row is committed: the owner's waiting shed looks again (FIX 10157).
    vault.wake_owner_shed();
    // Open only after the state write is durable (FIX 12497), as in
    // `record_possible_delivery`: a sealed row whose key will not open must
    // not lose the transition.
    let rtxn = vault.store.custody_snapshot()?;
    open_payload_in_txn(vault, &rtxn, &mut record)?;
    synced?;
    Ok(IntentCompletion {
        record,
        budget_events,
    })
}
