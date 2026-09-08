//! Cancel-receipt shape table, landing validators, and receipt/event append mutators.

use crate::attempt_queue::cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptCancelState,
    AttemptLanding, AttemptResumePoint, CancelStanding, ForceCancelGrounds, LandingTrigger,
    MAX_ATTEMPT_CANCEL_RECEIPTS, MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS,
};
use crate::attempt_queue::types::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, MAX_ATTEMPT_EVENTS_PER_RECORD,
};
use crate::error::{Error, Result};

use super::field_validators::{
    ERR_CANCEL_NO_STANDING, ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN, ERR_CANCEL_RECEIPT_FIELD_MISSING,
    ERR_CANCEL_RECEIPT_MISSING_GROUNDS, ERR_CANCEL_RECEIPT_MISSING_REASON,
    ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF, ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT,
    ERR_CANCEL_RECEIPT_MISSING_TRIGGER, ERR_CANCEL_RECEIPT_REQUEST_REF,
    ERR_CANCEL_RECEIPT_RESERVE_UNITS, ERR_CANCEL_RECEIPT_SEQUENCE,
    ERR_CANCEL_RECEIPT_TERMINAL_ORDER, ERR_CANCEL_RECEIPTS_FULL, ERR_CANCELLATION_MALFORMED,
    ERR_RESERVE_OVERSPENT, validate_intervention_actor, validate_optional_cancel_status,
    validate_optional_failure_reason, validate_optional_resume_point,
};

/// Whether one optional receipt field is REQUIRED by, merely ALLOWED on, or
/// FORBIDDEN to a given [`AttemptCancelReceiptKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldRule {
    Required,
    Allowed,
    Forbidden,
}

/// The per-kind field contract of one cancel receipt.
///
/// Declared once and enforced on BOTH sides — [`append_cancel_receipt`] before
/// a row is ever pushed, and [`validate_cancel_state`] on every decode — so a
/// writer and a reader can never disagree about what a kind means. Without it
/// a persisted row could contradict its own kind (a refusal with no reason, a
/// resume-point row with no point, a reserve spend of zero units, a force with
/// no grounds) and every projection downstream would faithfully report the
/// contradiction.
#[derive(Debug, Clone, Copy)]
struct CancelReceiptShape {
    standing: FieldRule,
    trigger: FieldRule,
    grounds: FieldRule,
    status: FieldRule,
    reason: FieldRule,
    resume_point: FieldRule,
    request_sequence: FieldRule,
    /// `Required` means strictly positive, `Forbidden` means exactly zero.
    reserve_units: FieldRule,
}

const fn cancel_receipt_shape(kind: AttemptCancelReceiptKind) -> CancelReceiptShape {
    use FieldRule::{Allowed, Forbidden, Required};
    let base = CancelReceiptShape {
        standing: Forbidden,
        trigger: Allowed,
        grounds: Forbidden,
        status: Forbidden,
        reason: Forbidden,
        resume_point: Forbidden,
        request_sequence: Forbidden,
        reserve_units: Forbidden,
    };
    match kind {
        // An ASK: it names why it is asking, may say who asked with what
        // standing, and moves nothing.
        AttemptCancelReceiptKind::SoftRequested => CancelReceiptShape {
            standing: Allowed,
            trigger: Required,
            reason: Allowed,
            ..base
        },
        // An ANSWER that stops: it carries the trigger of the ask it took, the
        // worker's status, and the resume point as it stood. A self-triggered
        // landing answers no recorded request, so the reference is optional.
        AttemptCancelReceiptKind::LandingAccepted => CancelReceiptShape {
            trigger: Required,
            status: Allowed,
            resume_point: Allowed,
            request_sequence: Allowed,
            ..base
        },
        // An ANSWER that refuses: the reason is the evidence and the request
        // reference is what keeps the OTHER requesters still owed an answer.
        AttemptCancelReceiptKind::SoftRejected => CancelReceiptShape {
            status: Allowed,
            reason: Required,
            request_sequence: Required,
            ..base
        },
        AttemptCancelReceiptKind::ResumePointRecorded => CancelReceiptShape {
            resume_point: Required,
            ..base
        },
        AttemptCancelReceiptKind::ReserveSpent => CancelReceiptShape {
            reserve_units: Required,
            ..base
        },
        // The two TERMINAL rows report settled accounting, which may legitimately
        // be zero, so their units are unconstrained.
        AttemptCancelReceiptKind::Landed => CancelReceiptShape {
            resume_point: Allowed,
            reserve_units: Allowed,
            ..base
        },
        AttemptCancelReceiptKind::ForceCancelled => CancelReceiptShape {
            grounds: Required,
            reason: Allowed,
            resume_point: Allowed,
            reserve_units: Allowed,
            ..base
        },
    }
}

fn check_field(rule: FieldRule, present: bool, missing: &'static str) -> Result<()> {
    match (rule, present) {
        (FieldRule::Required, false) => Err(Error::InvalidAttemptQueueRecord(missing)),
        (FieldRule::Forbidden, true) => Err(Error::InvalidAttemptQueueRecord(
            ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN,
        )),
        _ => Ok(()),
    }
}

/// Enforces one receipt's per-kind field contract.
///
/// `standing` and `status` are never `Required`, so their "missing" message is
/// the generic one and is unreachable; they are here to be FORBIDDEN on the
/// kinds that must not carry them (a runtime warning claiming actor standing,
/// a reserve spend carrying a worker status line).
pub(super) fn validate_cancel_receipt_fields(receipt: &AttemptCancelReceipt) -> Result<()> {
    let shape = cancel_receipt_shape(receipt.kind);
    check_field(
        shape.standing,
        receipt.standing.is_some(),
        ERR_CANCEL_RECEIPT_FIELD_MISSING,
    )?;
    check_field(
        shape.trigger,
        receipt.trigger.is_some(),
        ERR_CANCEL_RECEIPT_MISSING_TRIGGER,
    )?;
    check_field(
        shape.grounds,
        receipt.grounds.is_some(),
        ERR_CANCEL_RECEIPT_MISSING_GROUNDS,
    )?;
    check_field(
        shape.status,
        receipt.status.is_some(),
        ERR_CANCEL_RECEIPT_FIELD_MISSING,
    )?;
    check_field(
        shape.reason,
        receipt.reason.is_some(),
        ERR_CANCEL_RECEIPT_MISSING_REASON,
    )?;
    check_field(
        shape.resume_point,
        receipt.resume_point.is_some(),
        ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT,
    )?;
    check_field(
        shape.request_sequence,
        receipt.request_sequence.is_some(),
        ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF,
    )?;
    check_reserve_units(shape.reserve_units, receipt.reserve_units)?;
    // A recorded standing is a claim someone HAD standing; the "none" token is
    // the refusal verdict and can never be what a durable ask carries.
    if let Some(standing) = receipt.standing
        && !standing.may_request()
    {
        return Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_NO_STANDING));
    }
    Ok(())
}

fn check_reserve_units(rule: FieldRule, units: u64) -> Result<()> {
    match (rule, units) {
        (FieldRule::Required, 0) | (FieldRule::Forbidden, 1..) => Err(
            Error::InvalidAttemptQueueRecord(ERR_CANCEL_RECEIPT_RESERVE_UNITS),
        ),
        _ => Ok(()),
    }
}

fn validate_landing(landing: &AttemptLanding) -> Result<()> {
    validate_intervention_actor(&landing.requested_by)?;
    validate_optional_cancel_status(landing.status.as_deref())
}

/// Validates the whole ONE-1896 sub-record read back off a row.
pub(in crate::attempt_queue) fn validate_cancel_state(state: &AttemptCancelState) -> Result<()> {
    if state.receipts.len() > MAX_ATTEMPT_CANCEL_RECEIPTS {
        return Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_RECEIPTS_FULL));
    }
    let mut previous_sequence = 0;
    let last_index = state.receipts.len().saturating_sub(1);
    for (index, receipt) in state.receipts.iter().enumerate() {
        if receipt.sequence == 0 || receipt.sequence <= previous_sequence {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_CANCEL_RECEIPT_SEQUENCE,
            ));
        }
        // The reserved terminal slot is spendable exactly once and only at the
        // end: a settled row that carried a terminal receipt in the middle
        // would be a row that kept writing history after it stopped, and two
        // of them would mean one terminal receipt had been overwritten.
        if receipt.kind.is_terminal() && index != last_index {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_CANCEL_RECEIPT_TERMINAL_ORDER,
            ));
        }
        match receipt.request_sequence {
            // An answer names a request that is strictly OLDER than itself;
            // anything else is a receipt pointing forward or at nothing.
            Some(request_sequence)
                if !receipt.kind.answers_request()
                    || request_sequence == 0
                    || request_sequence >= receipt.sequence =>
            {
                return Err(Error::InvalidAttemptQueueRecord(
                    ERR_CANCEL_RECEIPT_REQUEST_REF,
                ));
            }
            _ => {}
        }
        validate_intervention_actor(&receipt.actor)?;
        validate_optional_cancel_status(receipt.status.as_deref())?;
        validate_optional_failure_reason(receipt.reason.as_deref())?;
        validate_optional_resume_point(receipt.resume_point.as_ref())?;
        // A row must agree with its own kind before any surface projects it.
        validate_cancel_receipt_fields(receipt)?;
        previous_sequence = receipt.sequence;
    }
    if let Some(landing) = state.landing.as_ref() {
        validate_landing(landing)?;
    }
    validate_optional_resume_point(state.resume_point.as_ref())?;
    if let Some(cancellation) = state.cancellation.as_ref() {
        if !cancellation.is_well_formed() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_CANCELLATION_MALFORMED));
        }
        validate_intervention_actor(&cancellation.actor)?;
        validate_optional_failure_reason(cancellation.reason.as_deref())?;
        // The terminal receipt reports the reserve AS SETTLED, so its own two
        // numbers must be consistent even if the live sub-record were lost.
        if cancellation.reserve_spent_units > cancellation.reserve_units {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RESERVE_OVERSPENT));
        }
    }
    if state.reserve.spent_units > state.reserve.reserve_units {
        return Err(Error::InvalidAttemptQueueRecord(ERR_RESERVE_OVERSPENT));
    }
    Ok(())
}

/// One append-only cancel receipt row, refusing at the cap instead of draining.
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

/// Appends one protocol row, refusing at the cap instead of draining — with the
/// last slot held for the terminal receipt.
///
/// A full history must not make an attempt unsettleable. Non-terminal rows
/// refuse at [`MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS`], leaving the reserved
/// slot; `Landed` / `ForceCancelled` — including the runtime's lease-expiry
/// cleanup — may spend it, so landing finish and the hard rung always settle
/// atomically and never silently omit their evidence.
pub(in crate::attempt_queue) fn append_cancel_receipt(
    record: &mut AttemptRecord,
    kind: AttemptCancelReceiptKind,
    actor: String,
    draft: CancelReceiptDraft,
    now: u64,
) -> Result<()> {
    let cap = if kind.is_terminal() {
        MAX_ATTEMPT_CANCEL_RECEIPTS
    } else {
        MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS
    };
    if record.cancel_state.receipts.len() >= cap {
        return Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_RECEIPTS_FULL));
    }
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
