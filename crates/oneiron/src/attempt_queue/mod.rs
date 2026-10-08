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

mod cancel;
mod completion;
mod encoding;
mod engine;
mod executor;
mod observe;
mod ports;
mod result;
mod settlement;
mod telemetry;
mod types;
mod validate;
#[cfg(test)]
pub(crate) use validate::validate_lease_owner;

#[cfg(test)]
mod tests;

pub use cancel::{
    ATTEMPT_RUNTIME_ACTOR, AcceptAttemptLanding, AttemptCancelPressure, AttemptCancelReceipt,
    AttemptCancelReceiptKind, AttemptCancelState, AttemptCancellation, AttemptLanding,
    AttemptLandingReserve, AttemptLeaseWarningReport, AttemptResumePoint, CancelMode,
    CancelRejectionOutcome, CancelRequestOutcome, CancelStanding, DialLandingReserve,
    FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel, ForceCancelAuthority,
    ForceCancelGrounds, ForceCancelOutcome, LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT,
    LandingOutcome, LandingReserveSpendOutcome, LandingTrigger, LandingWarningOutcome,
    LeaseWarningOutcome, MAX_ATTEMPT_CANCEL_RECEIPTS, MAX_LANDING_RESERVE_PERCENT,
    MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS, RecordAttemptResumePoint, RejectAttemptCancel,
    RequestAttemptCancel, SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD, SpendAttemptLandingReserve,
    TERMINAL_CANCEL_RECEIPT_RESERVE, WarnAttemptBudgetPressure, WarnAttemptLeaseExpiry,
    WarnExpiringAttemptLeases,
};
pub use engine::AttemptQueue;
pub(crate) use telemetry::AttemptQueueCleanupMetrics;
pub use telemetry::AttemptQueueCleanupMetricsSnapshot;
pub use types::{
    AbandonAttempt, AbandonOutcome, AttemptEvent, AttemptId, AttemptInterventionEffect,
    AttemptInterventionKind, AttemptPlacement, AttemptQueueCleanupReport, AttemptQueueRetryReason,
    AttemptQueueRetryReasonCount, AttemptRecord, AttemptResultRef, AttemptState, ClaimAttempt,
    ClaimOutcome, CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome, InterveneAttempt, InterveneOutcome,
    MAX_ATTEMPT_MANIFEST_ENTRIES, ManifestEntry, ManifestKind, RetryAttempt, RetryOutcome,
    SetAttemptResult,
};

pub(crate) use encoding::{decode_record, rebuild_checkpoint_indexes};
pub(crate) fn encode_signal_record(record: &AttemptRecord) -> crate::Result<Vec<u8>> {
    encoding::encode_record(record)
}
pub(crate) fn validate_signal_cancel(actor: &str, reason: Option<&str>) -> crate::Result<()> {
    validate::validate_cancel_actor(actor)?;
    validate::validate_optional_failure_reason(reason)
}

pub(crate) fn signal_cancel_headroom(receipts: usize, pending: usize) -> bool {
    receipts.saturating_add(pending) < cancel::MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS
}

pub(crate) fn signal_cancel_receipts_full(error: &crate::Error) -> bool {
    matches!(error, crate::Error::Artifact(crate::error::ArtifactError::InvalidAttemptQueueRecord(reason))
        if *reason == validate::ERR_CANCEL_RECEIPTS_FULL)
}
pub(crate) use engine::dreamer_run_root_id_in_txn;
/// Storage-ABI pin re-exported for `crate::store`; its only consumer outside
/// this module is `store`'s row-header test.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use types::ATTEMPT_RECORD_VERSION;
pub(crate) use types::attempt_record_order;

/// Whether rows of `kind` are job state whose owner settles, prunes and
/// bounds them itself (the tagging marker: its settled tries leave the ledger
/// for a bounded trace history). No content-side cleanup proposes such a row,
/// and no scan of another kind reads one.
pub(crate) fn owner_retained_kind(kind: &str) -> bool {
    kind == crate::tagging::TAGGING_MARKER_KIND
}

/// The first byte of every owner-retained row's id: those rows sit at the
/// top of the ledger's key order, apart from every other kind's. A minted id
/// starts with the top byte of its 48-bit millisecond clock, below this until
/// the year 10889, and only an owner-retained kind derives its ids itself; a
/// new row in the wrong range is refused. A scan of another kind stops before
/// the range, so owner-retained rows cost it nothing.
pub(crate) const OWNER_RETAINED_ID_PREFIX: u8 = 0xFF;

/// Whether `id` lies in the owner-retained range.
pub(crate) fn owner_retained_id(id: &AttemptId) -> bool {
    id.as_bytes()[0] == OWNER_RETAINED_ID_PREFIX
}

/// The first key of the owner-retained range, as a ledger scan bound.
pub(crate) const OWNER_RETAINED_RANGE_START: [u8; 1] = [OWNER_RETAINED_ID_PREFIX];

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
