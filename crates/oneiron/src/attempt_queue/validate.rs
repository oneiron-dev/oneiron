//! Input validators and in-place record mutators guarding the attempt-queue
//! doors.
//!
//! Every refusal message is a stable `&'static str` const declared here, so a
//! caller can assert on the exact reason. Storage-shape validation that reads
//! or writes index keys lives in [`super::encoding`] instead.

use crate::error::{Error, Result};

use super::cancel::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind,
    AttemptCancelState, AttemptLanding, AttemptResumePoint, CancelStanding, ForceCancelGrounds,
    LandingTrigger, MAX_ATTEMPT_CANCEL_RECEIPTS, MAX_LANDING_RESERVE_PERCENT,
    MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS,
};
use super::telemetry::invalid_transition;
use super::types::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, AttemptState, CleanupAttemptLeases,
    MAX_ATTEMPT_EVENTS_PER_RECORD, MAX_ATTEMPT_MANIFEST_ENTRIES, ManifestEntry,
};

const MAX_KIND_LEN: usize = 128;
const MAX_DEDUPE_KEY_LEN: usize = 512;
pub(super) const MAX_FAILURE_REASON_LEN: usize = 2048;
const MAX_LEASE_OWNER_LEN: usize = 128;
/// Longest run id the queue admits, and deliberately not a round number.
///
/// A run id is not only a queue key: `skill_optimize::proven_cycle` turns it
/// into the Dreamer CYCLE label the per-cycle skill-edit accept cap is counted
/// against, by writing `skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX` in front
/// of it. So the budget is the cycle bound MINUS that prefix, DERIVED from both
/// rather than restated — a run id this door accepted but no cycle could name
/// was a run whose every drafted proposal died at the gate, after the author
/// had already been paid for it.
pub(super) const MAX_RUN_ID_LEN: usize = crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES
    - crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len();
const MAX_INTERVENTION_ACTOR_LEN: usize = 128;
const MAX_INTERVENTION_NOTE_LEN: usize = 2048;
pub(super) const MAX_MANIFEST_REFERENCE_LEN: usize = 512;
pub(super) const MAX_MANIFEST_VERSION_LEN: usize = 128;
const ERR_EMPTY_KIND: &str = "kind must not be empty";
const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";
const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";
const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";
pub(super) const ERR_FAILURE_REASON_EMPTY: &str = "failure reason must not be empty";
const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";
const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";
const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";
const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";
pub(super) const ERR_RUN_ID_TOO_LONG: &str =
    "run id exceeds 124 bytes; the cycle label needs the rest";
const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";
const ERR_INTERVENTION_ACTOR_TOO_LONG: &str = "intervention actor exceeds 128 bytes";
const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";
const ERR_INTERVENTION_NOTE_TOO_LONG: &str = "intervention note exceeds 2048 bytes";
pub(super) const ERR_MANIFEST_REFERENCE_EMPTY: &str = "manifest reference must not be empty";
pub(super) const ERR_MANIFEST_REFERENCE_TOO_LONG: &str = "manifest reference exceeds 512 bytes";
pub(super) const ERR_MANIFEST_REFERENCE_HAS_AT: &str = "manifest reference must not contain '@'";
pub(super) const ERR_MANIFEST_VERSION_EMPTY: &str = "manifest version must not be empty";
pub(super) const ERR_MANIFEST_VERSION_TOO_LONG: &str = "manifest version exceeds 128 bytes";
pub(super) const ERR_MANIFEST_FULL: &str = "attempt manifest is full; entries are never dropped";
pub(super) const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";
pub(super) const MAX_CANCEL_STATUS_LEN: usize = 2048;
pub(super) const MAX_RESUME_MARKER_LEN: usize = 2048;
pub(super) const MAX_RESUME_ARTIFACT_REF_LEN: usize = 512;
pub(super) const ERR_CANCEL_ACTOR_IS_RUNTIME: &str =
    "cancel actor must not claim the reserved runtime identity";
pub(super) const ERR_CANCEL_NO_STANDING: &str = "cancel request requires standing";
pub(super) const ERR_CANCEL_STATUS_EMPTY: &str = "cancel status must not be empty";
pub(super) const ERR_CANCEL_STATUS_TOO_LONG: &str = "cancel status exceeds 2048 bytes";
pub(super) const ERR_RESUME_MARKER_EMPTY: &str = "resume marker must not be empty";
pub(super) const ERR_RESUME_MARKER_TOO_LONG: &str = "resume marker exceeds 2048 bytes";
pub(super) const ERR_RESUME_ARTIFACT_REF_EMPTY: &str = "resume artifact ref must not be empty";
pub(super) const ERR_RESUME_ARTIFACT_REF_TOO_LONG: &str = "resume artifact ref exceeds 512 bytes";
pub(super) const ERR_CANCEL_RECEIPTS_FULL: &str =
    "attempt cancel receipts are full; refusal evidence is never dropped";
pub(super) const ERR_CANCEL_RECEIPT_SEQUENCE: &str =
    "attempt cancel receipt sequence must be strictly increasing";
pub(super) const ERR_CANCEL_RECEIPT_TERMINAL_ORDER: &str =
    "a terminal cancel receipt must be the last row, and there may be only one";
pub(super) const ERR_CANCEL_RECEIPT_REQUEST_REF: &str =
    "a cancel receipt may only answer an earlier request receipt";
pub(super) const ERR_RESERVE_PERCENT_RANGE: &str = "landing reserve percent must be in 1..=50";
pub(super) const ERR_RESERVE_SPEND_ZERO: &str = "landing reserve spend must be > 0";
pub(super) const ERR_RESERVE_OVERSPENT: &str = "landing reserve spent exceeds the dialed reserve";
pub(super) const ERR_LANDING_WITHOUT_RECORD: &str = "landing attempt must have a landing record";
pub(super) const ERR_LANDING_WITHOUT_LEASE: &str = "landing attempt must have a lease owner";
pub(super) const ERR_LANDING_WITH_BACKOFF: &str = "landing attempt must not have backoff state";
pub(super) const ERR_LANDING_RECORD_MISPLACED: &str =
    "only a landing or cancelled attempt may carry a landing record";
pub(super) const ERR_CANCELLATION_MISPLACED: &str =
    "only a cancelled attempt may carry a cancellation receipt";
pub(super) const ERR_CANCELLATION_MALFORMED: &str =
    "cancellation grounds must be set exactly for a forced stop";
pub(super) const ERR_HANDOFF_WITHOUT_RESUME_POINT: &str =
    "landing handoff requires a recorded resume point";
pub(super) const ERR_CANCEL_RECEIPT_FIELD_MISSING: &str =
    "cancel receipt is missing a field its kind requires";
pub(super) const ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN: &str =
    "cancel receipt carries a field its kind forbids";
pub(super) const ERR_CANCEL_RECEIPT_MISSING_TRIGGER: &str =
    "a cancel request or landing receipt must name its trigger";
pub(super) const ERR_CANCEL_RECEIPT_MISSING_REASON: &str =
    "a refusal receipt must carry the worker's reason";
pub(super) const ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF: &str =
    "a refusal receipt must name the request it answered";
pub(super) const ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT: &str =
    "a resume-point receipt must carry the resume point it recorded";
pub(super) const ERR_CANCEL_RECEIPT_MISSING_GROUNDS: &str =
    "a force-cancel receipt must carry its authorized grounds";
pub(super) const ERR_CANCEL_RECEIPT_RESERVE_UNITS: &str =
    "cancel receipt reserve units contradict its kind";

pub(super) fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_EMPTY_KIND));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_KIND_TOO_LONG));
    }
    Ok(())
}

pub(super) fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_EMPTY));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_TOO_LONG));
        }
    }
    Ok(())
}

pub(super) fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

pub(super) fn validate_optional_failure_reason(reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        if reason.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_FAILURE_REASON_EMPTY));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_FAILURE_REASON_TOO_LONG,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_EMPTY));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_TOO_LONG));
        }
    }
    Ok(())
}

pub(super) fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_EMPTY,
        ));
    }
    if actor.len() > MAX_INTERVENTION_ACTOR_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_TOO_LONG,
        ));
    }
    Ok(())
}

pub(super) fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if let Some(note) = note {
        if note.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_EMPTY,
            ));
        }
        if note.len() > MAX_INTERVENTION_NOTE_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_TOO_LONG,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_EMPTY));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_TOO_LONG));
    }
    Ok(())
}

pub(super) fn validate_cleanup_leases_input(input: &CleanupAttemptLeases) -> Result<()> {
    if input.lease_timeout_secs == 0 {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
    }
    Ok(())
}

/// Leases an admitted ready row in place. The readiness instant is consumed by
/// the lease, so both spellings clear; `attempt_count` advances as this row's
/// lease-generation fence.
pub(super) fn lease_claimed_record(
    record: &mut AttemptRecord,
    lease_owner: &str,
    now: u64,
) -> Result<()> {
    record.state = AttemptState::Leased;
    record.lease_owner = Some(lease_owner.to_owned());
    record.attempt_count = record
        .attempt_count
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
    if record.claimed_at.is_none() {
        record.claimed_at = Some(now);
    }
    record.scheduled_at = None;
    record.backoff_until = None;
    record.updated_at = now;
    Ok(())
}

pub(super) fn validate_transition_lease(
    record: &AttemptRecord,
    lease_owner: &str,
    attempt_count: u32,
    action: &'static str,
) -> Result<()> {
    if record.lease_owner.as_deref() != Some(lease_owner) {
        return Err(invalid_transition(action, "leased_by_other"));
    }
    if record.attempt_count != attempt_count {
        return Err(invalid_transition(action, "stale_attempt"));
    }
    Ok(())
}

pub(super) fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
    let mut previous_sequence = 0;
    for event in events {
        if event.sequence == 0 || event.sequence <= previous_sequence {
            return Err(Error::InvalidAttemptQueueRecord(
                "attempt event sequence must be strictly increasing",
            ));
        }
        validate_intervention_actor(&event.actor)?;
        validate_optional_intervention_note(event.note.as_deref())?;
        previous_sequence = event.sequence;
    }
    Ok(())
}

/// Refuses a row the `reference@version` wire form could not carry back.
///
/// `@` in a REFERENCE is rejected here (owner ruling R-20260807-04): it is the
/// delimiter, so a reference holding one makes [`ManifestEntry::parse_wire_form`]
/// ambiguous and lets a row name a skill the pack never loaded. A VERSION may
/// hold `@` freely — everything after the first delimiter is the version.
pub(super) fn validate_manifest_entry(entry: &ManifestEntry) -> Result<()> {
    if entry.reference.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_EMPTY,
        ));
    }
    if entry.reference.contains('@') {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_HAS_AT,
        ));
    }
    if entry.reference.len() > MAX_MANIFEST_REFERENCE_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        ));
    }
    if entry.version.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_VERSION_EMPTY));
    }
    if entry.version.len() > MAX_MANIFEST_VERSION_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_VERSION_TOO_LONG,
        ));
    }
    Ok(())
}

pub(super) fn validate_attempt_manifest(manifest: &[ManifestEntry]) -> Result<()> {
    if manifest.len() > MAX_ATTEMPT_MANIFEST_ENTRIES {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL));
    }
    for entry in manifest {
        validate_manifest_entry(entry)?;
    }
    Ok(())
}

/// Refuses an actor that claims the runtime's own identity.
///
/// Structural forgery is already impossible — a hard receipt can only be
/// written by the [`super::types::ForceCancelAuthority`] path — but a soft row
/// whose actor reads `runtime` would still MISLEAD every reviewer, so the door
/// refuses it outright.
pub(super) fn validate_cancel_actor(actor: &str) -> Result<()> {
    validate_intervention_actor(actor)?;
    if actor == ATTEMPT_RUNTIME_ACTOR {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_CANCEL_ACTOR_IS_RUNTIME,
        ));
    }
    Ok(())
}

pub(super) fn validate_cancel_standing(standing: CancelStanding) -> Result<()> {
    if standing.may_request() {
        Ok(())
    } else {
        Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_NO_STANDING))
    }
}

pub(super) fn validate_optional_cancel_status(status: Option<&str>) -> Result<()> {
    if let Some(status) = status {
        if status.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_STATUS_EMPTY));
        }
        if status.len() > MAX_CANCEL_STATUS_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_CANCEL_STATUS_TOO_LONG));
        }
    }
    Ok(())
}

pub(super) fn validate_resume_point(resume_point: &AttemptResumePoint) -> Result<()> {
    if resume_point.marker.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_RESUME_MARKER_EMPTY));
    }
    if resume_point.marker.len() > MAX_RESUME_MARKER_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_RESUME_MARKER_TOO_LONG));
    }
    if let Some(artifact_ref) = resume_point.artifact_ref.as_deref() {
        if artifact_ref.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_RESUME_ARTIFACT_REF_EMPTY,
            ));
        }
        if artifact_ref.len() > MAX_RESUME_ARTIFACT_REF_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_RESUME_ARTIFACT_REF_TOO_LONG,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_optional_resume_point(
    resume_point: Option<&AttemptResumePoint>,
) -> Result<()> {
    match resume_point {
        Some(resume_point) => validate_resume_point(resume_point),
        None => Ok(()),
    }
}

pub(super) fn validate_reserve_percent(reserve_percent: u64) -> Result<()> {
    if reserve_percent == 0 || reserve_percent > MAX_LANDING_RESERVE_PERCENT {
        return Err(Error::InvalidAttemptQueueRecord(ERR_RESERVE_PERCENT_RANGE));
    }
    Ok(())
}

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
pub(super) fn validate_cancel_state(state: &AttemptCancelState) -> Result<()> {
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
pub(super) struct CancelReceiptDraft {
    pub(super) standing: Option<CancelStanding>,
    pub(super) trigger: Option<LandingTrigger>,
    pub(super) grounds: Option<ForceCancelGrounds>,
    pub(super) status: Option<String>,
    pub(super) reason: Option<String>,
    pub(super) resume_point: Option<AttemptResumePoint>,
    pub(super) reserve_units: u64,
    pub(super) request_sequence: Option<u64>,
}

/// Appends one protocol row, refusing at the cap instead of draining — with the
/// last slot held for the terminal receipt.
///
/// A full history must not make an attempt unsettleable. Non-terminal rows
/// refuse at [`MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS`], leaving the reserved
/// slot; `Landed` / `ForceCancelled` — including the runtime's lease-expiry
/// cleanup — may spend it, so landing finish and the hard rung always settle
/// atomically and never silently omit their evidence.
pub(super) fn append_cancel_receipt(
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
pub(super) fn count_cancel_rejection(pressure: &mut AttemptCancelPressure) {
    pressure.rejections = pressure.rejections.saturating_add(1);
    pressure.pending = pressure.pending.saturating_sub(1);
}

pub(super) fn count_cancel_request(pressure: &mut AttemptCancelPressure) {
    pressure.requests = pressure.requests.saturating_add(1);
    pressure.pending = pressure.pending.saturating_add(1);
}

pub(super) fn append_attempt_event(
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
