//! The cancel-receipt shape table and the landing and cancel-state
//! validators the strict reader runs on a stored row's graceful-cancel
//! state. The attempt queue's cancel protocol (`attempt_queue::validate`)
//! keeps the receipt and event append mutators and the pressure counters.
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::attempt_record_codec::field_validators::ERR_CANCEL_NO_STANDING;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_FIELD_MISSING;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_MISSING_GROUNDS;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_MISSING_REASON;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_MISSING_TRIGGER;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_REQUEST_REF;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_RESERVE_UNITS;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_SEQUENCE;
use crate::attempt_record_codec::field_validators::ERR_CANCEL_RECEIPT_TERMINAL_ORDER;
use crate::attempt_record_codec::field_validators::ERR_CANCELLATION_MALFORMED;
use crate::attempt_record_codec::field_validators::ERR_RESERVE_OVERSPENT;
use crate::attempt_record_codec::field_validators::validate_intervention_actor;
use crate::attempt_record_codec::field_validators::validate_optional_cancel_status;
use crate::attempt_record_codec::field_validators::validate_optional_failure_reason;

/// Whether one optional receipt field is REQUIRED by, merely ALLOWED on, or
/// FORBIDDEN to a given [`AttemptCancelReceiptKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRule {
    Required,
    Allowed,
    Forbidden,
}

/// The per-kind field contract of one cancel receipt.
///
/// Declared once and enforced on BOTH sides — the queue's `append_cancel_receipt` before
/// a row is ever pushed, and [`validate_cancel_state`] on every decode — so a
/// writer and a reader can never disagree about what a kind means. Without it
/// a persisted row could contradict its own kind (a refusal with no reason, a
/// resume-point row with no point, a reserve spend of zero units, a force with
/// no grounds) and every projection downstream would faithfully report the
/// contradiction.
#[derive(Debug, Clone, Copy)]
pub struct CancelReceiptShape {
    pub standing: FieldRule,
    pub trigger: FieldRule,
    pub grounds: FieldRule,
    pub status: FieldRule,
    pub reason: FieldRule,
    pub resume_point: FieldRule,
    pub request_sequence: FieldRule,
    /// `Required` means strictly positive, `Forbidden` means exactly zero.
    pub reserve_units: FieldRule,
}

pub fn check_field(rule: FieldRule, present: bool, missing: &'static str) -> Result<()> {
    match (rule, present) {
        (FieldRule::Required, false) => Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(missing),
        )),
        (FieldRule::Forbidden, true) => Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN),
        )),
        _ => Ok(()),
    }
}

pub fn check_reserve_units(rule: FieldRule, units: u64) -> Result<()> {
    match (rule, units) {
        (FieldRule::Required, 0) | (FieldRule::Forbidden, 1..) => Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(ERR_CANCEL_RECEIPT_RESERVE_UNITS),
        )),
        _ => Ok(()),
    }
}

