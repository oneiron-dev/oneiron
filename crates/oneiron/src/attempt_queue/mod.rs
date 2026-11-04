//! Generic LMDB-backed background attempt queue.
//!
//! This is intentionally mechanical storage state only: enqueue, claim,
//! complete, fail, retry, and lease cleanup transition LMDB rows atomically,
//! while execution policy stays outside this module.
//!
//! Layout: `types` holds the durable wire, verb-input, and outcome types;
//! `engine` holds the [`AttemptQueue`] handle and its lease state machine;
//! `cancel` holds the ONE-1896 two-rung graceful-cancel/landing concern — its
//! own durable rows, verbs, and doors — as inherent methods on that same
//! handle; `validate` holds the door validators; `encoding` holds storage key
//! derivation and row encode/decode; `telemetry` holds the per-vault cleanup
//! counters and span emission.

mod annotation_hold;
mod borrowed_lease;
pub mod browser_admission;
mod budget_hold;
mod cancel;
mod completion;
pub mod dispatch_payload;
mod encoding;
mod engine;
mod executor;
mod fanout_hold;
mod index;
mod kind_payload_erase;
pub mod maintenance_predicate;
mod observe;
mod payload_erase;
mod payload_rebind;
mod ports;
mod read_set;
mod result;
pub mod run_signal;
mod settlement;
pub mod skill_edit_cycle;
pub mod source_rows;
mod telemetry;
pub mod turn_action_kind;
mod types;
mod validate;
#[cfg(test)]
pub(crate) use validate::validate_lease_owner;

#[cfg(test)]
mod tests;

pub use annotation_hold::{ANNOTATION_HOLD_ACTOR, AnnotationHold, AnnotationHoldSweep};
pub use borrowed_lease::BorrowedAttemptLease;
pub use budget_hold::{BUDGET_HOLD_ACTOR, HoldAttemptForBudget};
pub use cancel::{
    ATTEMPT_RUNTIME_ACTOR, AcceptAttemptLanding, AttemptCancelPressure, AttemptCancelReceipt,
    AttemptCancelReceiptKind, AttemptCancelState, AttemptCancellation, AttemptLanding,
    AttemptLandingReserve, AttemptLeaseWarningReport, AttemptResumePoint, CancelMode,
    CancelRejectionOutcome, CancelRequestOutcome, CancelStanding, DialLandingReserve,
    FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel, ForceCancelAuthority,
    ForceCancelGrounds, ForceCancelOutcome, LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT,
    LandingOutcome, LandingReserveSpendOutcome, LandingTrigger, LandingWarningOutcome,
    LeaseWarningOutcome, MAX_LANDING_RESERVE_PERCENT, RecordAttemptResumePoint,
    RejectAttemptCancel, RequestAttemptCancel, SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
    SpendAttemptLandingReserve, WarnAttemptBudgetPressure, WarnAttemptLeaseExpiry,
    WarnExpiringAttemptLeases,
};
pub use engine::{AttemptQueue, RequeueAttempt, RequeuedFailure};
pub use fanout_hold::{FANOUT_HOLD_ACTOR, HoldAttemptForFanout};
pub use read_set::{AttemptReadSet, ReadSetProducer};
pub(crate) use telemetry::AttemptQueueCleanupMetrics;
pub use telemetry::AttemptQueueCleanupMetricsSnapshot;
pub use types::AttemptTerminalExhaust;
pub use types::{
    AbandonAttempt, AbandonOutcome, AttemptEvent, AttemptId, AttemptInterventionEffect,
    AttemptInterventionKind, AttemptPlacement, AttemptQueueCleanupReport, AttemptQueueRetryReason,
    AttemptQueueRetryReasonCount, AttemptRecord, AttemptResultRef, AttemptState, ClaimAttempt,
    ClaimOutcome, CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome, InterveneAttempt, InterveneOutcome, ManifestEntry,
    ManifestKind, PlannedBinding, PlannedExactness, RetryAttempt, RetryOutcome, SetAttemptResult,
};

pub(crate) use encoding::{decode_record, rebuild_checkpoint_indexes};
pub(crate) use kind_payload_erase::erase_kind_payloads_in_txn;
pub(crate) use payload_erase::{
    attempt_payload_owners, attempt_payload_scan, attempt_row_opaque,
    erase_attempt_payload_actor_in_txn, erase_attempt_payload_actors_in_txn,
    erase_model_step_failure_reasons_in_txn,
};
#[cfg(test)]
pub(crate) fn encode_signal_record(record: &AttemptRecord) -> crate::Result<Vec<u8>> {
    encoding::encode_record(record)
}
/// A signal row's bytes, read once by the side-row wall in the writer's
/// transaction ([`encoding::encode_admitted_record`]). An erased dispatch
/// target's text leaves the row first, as on every queue write (FIX 7076).
pub(crate) fn encode_admitted_signal_record(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &mut AttemptRecord,
) -> crate::Result<Vec<u8>> {
    payload_erase::scrub_hard_erased_payload_in_txn(&vault.store, wtxn, record);
    encoding::encode_admitted_record(vault, wtxn, record)
}

pub(crate) use crate::store::attempt_record_codec::signal_validators::validate_signal_cancel;
/// Storage-ABI pin re-exported for `crate::store`; its only consumer outside
/// this module is `store`'s row-header test.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use types::ATTEMPT_RECORD_VERSION;
pub(crate) use types::attempt_record_order;

/// Where `record` stands in the order queued work is admitted in: its
/// readiness instant, then its id. `None` for a row admission never hands
/// out.
pub(crate) fn admission_order(record: &AttemptRecord) -> Option<(u64, [u8; 16])> {
    record
        .state
        .is_ready_indexed()
        .then(|| (encoding::ready_at(record), *record.id.as_bytes()))
}

pub(crate) use crate::store::attempt_retention::{
    OWNER_RETAINED_ID_PREFIX, OWNER_RETAINED_RANGE_START, owner_retained_id, owner_retained_kind,
};

/// Whether a stored job row of another kind lies in the owner-retained
/// range, where that kind's scans never read it: what a restore refuses. An
/// owner-retained row below the range (one an earlier build wrote) stays
/// readable; a row that does not decode is the decoder's to refuse.
pub(crate) fn foreign_row_in_owner_retained_range(key: &[u8], value: &[u8]) -> bool {
    let Ok(id) = AttemptId::from_bytes(key) else {
        return false;
    };
    owner_retained_id(&id)
        && decode_record(value, id).is_ok_and(|record| !owner_retained_kind(&record.kind))
}

/// Refuses a new row whose id lies in the other kinds' range: an
/// owner-retained row outside its own, or any other row inside it.
pub(crate) fn check_owner_retained_range(kind: &str, id: &AttemptId) -> crate::Result<()> {
    if owner_retained_kind(kind) == owner_retained_id(id) {
        Ok(())
    } else {
        Err(crate::Error::InvariantViolation(
            "attempt id outside its kind's key range",
        ))
    }
}

pub mod companion_task;

pub mod run_tree_view;
