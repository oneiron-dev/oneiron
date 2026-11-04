//! Cancel-receipt shape table, landing validators, and receipt/event append mutators.

use crate::attempt_queue::cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptResumePoint,
    CancelStanding, ForceCancelGrounds, LandingTrigger,
};
use crate::attempt_queue::types::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, MAX_ATTEMPT_EVENTS_PER_RECORD,
};
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};

use super::field_validators::{validate_intervention_actor, validate_optional_intervention_note};
pub(super) use crate::store::attempt_record_codec::cancel_validators::validate_cancel_receipt_fields;
pub(in crate::attempt_queue) use crate::store::attempt_record_codec::cancel_validators::validate_cancel_state;

/// One append-only cancel receipt row, never drained and never refused on a
/// count.
#[derive(Debug, Default)]
pub(in crate::attempt_queue) struct CancelReceiptDraft {
    pub(in crate::attempt_queue) standing: Option<CancelStanding>,
    pub(in crate::attempt_queue) trigger: Option<LandingTrigger>,
    pub(in crate::attempt_queue) grounds: Option<ForceCancelGrounds>,
    pub(in crate::attempt_queue) status: Option<String>,
    pub(in crate::attempt_queue) reason: Option<String>,
    pub(in crate::attempt_queue) resume_point: Option<AttemptResumePoint>,
    pub(in crate::attempt_queue) reserve_units: u64,
    pub(in crate::attempt_queue) request_sequence: Option<u64>,
}

/// Appends one protocol row. Never drains and never refuses on a count, so
/// `Landed` / `ForceCancelled` — including the runtime's lease-expiry cleanup
/// — always have room: landing finish and the hard rung settle atomically and
/// never silently omit their evidence.
///
/// Past the `[limits]` `attempt_cancel_receipts` row the append asks through
/// `watch` whether everything is okay and lands (Rule 5); only storage
/// capacity (LMDB's value ceiling, a full map) refuses the record write.
pub(in crate::attempt_queue) fn append_cancel_receipt(
    watch: &LimitWatch,
    record: &mut AttemptRecord,
    kind: AttemptCancelReceiptKind,
    actor: String,
    draft: CancelReceiptDraft,
    now: u64,
) -> Result<()> {
    let sequence = match record.cancel_state.receipts.last() {
        Some(receipt) => receipt
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt cancel receipt sequence"))?,
        None => 1,
    };
    let receipt = AttemptCancelReceipt {
        sequence,
        at: now,
        actor,
        kind,
        standing: draft.standing,
        trigger: draft.trigger,
        grounds: draft.grounds,
        status: draft.status,
        reason: draft.reason,
        resume_point: draft.resume_point,
        reserve_units: draft.reserve_units,
        request_sequence: draft.request_sequence,
    };
    // The SAME per-kind contract `decode_record` enforces, applied before the
    // row exists: a writer cannot persist a shape the reader would then refuse,
    // and a malformed draft leaves the record — and storage — untouched.
    validate_cancel_receipt_fields(&receipt)?;
    record.cancel_state.receipts.push(receipt);
    watch.measure(
        EngineLimit::AttemptCancelReceipts,
        record.cancel_state.receipts.len() as u64,
    );
    Ok(())
}

/// Counts one refused soft request. Saturating: the pathology signal is "many",
/// and an overflow must not reset it to "none". One refusal answers one
/// outstanding request; duplicate asks remain pending until answered.
pub(in crate::attempt_queue) fn count_cancel_rejection(pressure: &mut AttemptCancelPressure) {
    pressure.rejections = pressure.rejections.saturating_add(1);
    pressure.pending = pressure.pending.saturating_sub(1);
}

pub(in crate::attempt_queue) fn count_cancel_request(pressure: &mut AttemptCancelPressure) {
    pressure.requests = pressure.requests.saturating_add(1);
    pressure.pending = pressure.pending.saturating_add(1);
}

pub(in crate::attempt_queue) fn append_attempt_event(
    record: &mut AttemptRecord,
    kind: AttemptInterventionKind,
    actor: String,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    // Checked as the decoder checks it, so no appended event poisons the row
    // it is appended to (FIX 9580).
    validate_intervention_actor(&actor)?;
    validate_optional_intervention_note(note.as_deref())?;
    let sequence = match record.events.last() {
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt event sequence"))?,
        None => 1,
    };
    record.events.push(AttemptEvent {
        sequence,
        at: now,
        actor,
        kind,
        note,
    });
    if record.events.len() > MAX_ATTEMPT_EVENTS_PER_RECORD {
        let excess = record.events.len() - MAX_ATTEMPT_EVENTS_PER_RECORD;
        record.events.drain(0..excess);
    }
    Ok(())
}
