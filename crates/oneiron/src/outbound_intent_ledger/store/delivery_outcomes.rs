//! The sends' terminal delivery outcomes: completion, abandon, and the
//! possible- and definite-non-delivery marks.

use super::*;

/// A send's terminal Done, with `bridge` writing in the same transaction
/// (DOOR-141 PR2): a turn program's step settles with the send's result
/// there. The bridge returns nothing, so it cannot fail the transition;
/// Pending, Done and replay are the plain transition's. A row already Done
/// runs no bridge.
pub(crate) fn complete_record_bridged(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
    bridge: impl FnOnce(&mut heed::RwTxn<'_>, &IntentLedgerRecord),
) -> IntentLedgerResult<IntentCompletion> {
    transition_record_with_outcome_and(
        vault,
        id,
        IntentState::Done,
        RecordedOutboundOutcome::Acked,
        now_ms,
        bridge,
    )
}

pub(crate) fn abandon_record(
    vault: &Vault,
    id: [u8; 32],
    reason: IntentEscalationReason,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome(
        vault,
        id,
        IntentState::Abandoned,
        RecordedOutboundOutcome::Abandoned(reason),
        now_ms,
    )
}

/// Persist positive uncertainty before a later attempt can replace the
/// current attempt's outcome with definite non-delivery. Never reset this bit
/// on retry; only confirmed Done or an explicit reconciliation can resolve it.
///
/// The bit pays for no admission, so the row's timestamp stays where its
/// admission, renewal or last outcome put it: an aged retry marked here,
/// even one a full ceiling then holds, still meets today's ceiling next time.
pub(crate) fn record_possible_delivery(
    vault: &Vault,
    id: [u8; 32],
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("possible delivery target is missing"),
    )?;
    if record.state != IntentState::Pending || record.recorded_outcome.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "possible delivery requires outcome-free Pending",
        ));
    }
    let marked = !record.delivery_uncertain;
    if marked {
        record.delivery_uncertain = true;
        LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
        wtxn.commit().map_err(Error::from)?;
    } else {
        drop(wtxn);
    }
    force_sync(vault)?;
    // Open only after the state write is durable (FIX 10959): a sealed row
    // whose key will not open must not lose the mark. On an open error the
    // caller re-reads the row, as after a post-commit sync error.
    let rtxn = vault.store.custody_snapshot()?;
    open_payload_in_txn(vault, &rtxn, &mut record)?;
    Ok(record)
}

pub(crate) fn record_definite_non_delivery(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        None,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        now_ms,
        |wtxn, record| {
            super::super::settlement::release_non_delivery_reservation_in_txn(vault, wtxn, record)?;
            Ok(BudgetBlock::Open)
        },
    )
    .map(|(record, _)| record)
}

/// A provider lookup answered that no earlier call of this outcome-free
/// Pending row reached it (FIX 4747): the explicit reconciliation that
/// resolves its possible-delivery mark. The row becomes a definite
/// non-delivery with the mark cleared, so its resend retries as one, and a
/// definite refusal of that resend reads as one.
pub(crate) fn record_looked_up_non_delivery(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("looked-up non-delivery target is missing"),
    )?;
    if record.state != IntentState::Pending || record.recorded_outcome.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "looked-up non-delivery requires outcome-free Pending",
        ));
    }
    record.recorded_outcome = Some(RecordedOutboundOutcome::DefiniteNonDelivery);
    record.delivery_uncertain = false;
    record.updated_ms = now_ms.max(record.created_ms);
    LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    // Open only after the state write is durable (FIX 10959), as in
    // `record_possible_delivery`.
    let rtxn = vault.store.custody_snapshot()?;
    open_payload_in_txn(vault, &rtxn, &mut record)?;
    Ok(record)
}
