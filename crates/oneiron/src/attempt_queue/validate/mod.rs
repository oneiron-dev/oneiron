//! Input validators and in-place record mutators guarding the attempt-queue
//! doors.
//!
//! Every refusal message is a stable `&'static str` const declared here, so a
//! caller can assert on the exact reason. Storage-shape validation that reads
//! or writes index keys lives in [`super::encoding`] instead.

mod cancel_receipt_landing;
mod field_validators;

// Anchor for the `super::types::` paths the moved items were written with:
// from a child, `super::types` resolves through this module, so the alias
// keeps those paths pointing at `attempt_queue::types` verbatim.
use super::types;

pub(super) use self::cancel_receipt_landing::{
    CancelReceiptDraft, append_attempt_event, append_cancel_receipt, count_cancel_rejection,
    count_cancel_request, validate_cancel_state,
};
pub(super) use self::field_validators::{
    ERR_ABANDONED_WITHOUT_REASON, ERR_ABANDONED_WITHOUT_RESULT, ERR_CANCELLATION_MISPLACED,
    ERR_DEDUPE_ACTOR_WITHOUT_KEY, ERR_HANDOFF_WITHOUT_RESUME_POINT, ERR_LANDING_RECORD_MISPLACED,
    ERR_LANDING_WITH_BACKOFF, ERR_LANDING_WITHOUT_LEASE, ERR_LANDING_WITHOUT_RECORD,
    ERR_LEASE_TIMEOUT_ZERO, ERR_MANIFEST_FULL, ERR_RESERVE_SPEND_ZERO, lease_claimed_record,
    validate_attempt_events, validate_attempt_manifest, validate_cancel_actor,
    validate_cancel_standing, validate_cleanup_leases_input, validate_failure_reason,
    validate_intervention_actor, validate_kind, validate_lease_owner, validate_manifest_entry,
    validate_optional_cancel_status, validate_optional_dedupe, validate_optional_dedupe_actor_ref,
    validate_optional_failure_reason, validate_optional_intervention_note,
    validate_optional_result_ref, validate_optional_resume_point, validate_optional_run_id,
    validate_reserve_percent, validate_result_rebind, validate_result_ref, validate_resume_point,
    validate_transition_lease,
};

// Names the sibling test suite reaches through `super::validate::` in
// test builds only; a plain re-export above would be an unused import
// in non-test builds.
#[cfg(test)]
pub(super) use self::field_validators::{
    ERR_CANCEL_ACTOR_IS_RUNTIME, ERR_CANCEL_NO_STANDING, ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN,
    ERR_CANCEL_RECEIPT_MISSING_GROUNDS, ERR_CANCEL_RECEIPT_MISSING_REASON,
    ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF, ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT,
    ERR_CANCEL_RECEIPT_MISSING_TRIGGER, ERR_CANCEL_RECEIPT_RESERVE_UNITS, ERR_CANCEL_RECEIPTS_FULL,
    ERR_FAILURE_REASON_EMPTY, ERR_MANIFEST_REFERENCE_EMPTY, ERR_MANIFEST_REFERENCE_HAS_AT,
    ERR_MANIFEST_REFERENCE_TOO_LONG, ERR_MANIFEST_VERSION_EMPTY, ERR_MANIFEST_VERSION_TOO_LONG,
    ERR_RESULT_REF_REBOUND, ERR_RUN_ID_TOO_LONG, MAX_FAILURE_REASON_LEN,
    MAX_MANIFEST_REFERENCE_LEN, MAX_MANIFEST_VERSION_LEN, MAX_RESULT_REF_LEN, MAX_RUN_ID_LEN,
};
