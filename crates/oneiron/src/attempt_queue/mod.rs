//! Generic LMDB-backed background attempt queue.
//!
//! This is intentionally mechanical storage state only: enqueue, claim,
//! complete, fail, retry, and lease cleanup transition LMDB rows atomically,
//! while execution policy stays outside this module.
//!
//! Layout: `types` holds the durable wire, verb-input, and outcome types;
//! `engine` holds the [`AttemptQueue`] handle and its lease state machine;
//! `validate` holds the door validators; `encoding` holds storage key
//! derivation and row encode/decode; `telemetry` holds the process-local
//! cleanup counters and span emission.

mod encoding;
mod engine;
mod telemetry;
mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use engine::AttemptQueue;
pub use telemetry::{AttemptQueueCleanupMetricsSnapshot, attempt_queue_cleanup_metrics_snapshot};
pub use types::{
    ATTEMPT_RUNTIME_ACTOR, AcceptAttemptLanding, AttemptCancelPressure, AttemptCancelReceipt,
    AttemptCancelReceiptKind, AttemptCancelState, AttemptCancellation, AttemptEvent, AttemptId,
    AttemptInterventionEffect, AttemptInterventionKind, AttemptLanding, AttemptLandingReserve,
    AttemptLeaseWarningReport, AttemptQueueCleanupReport, AttemptQueueRetryReason,
    AttemptQueueRetryReasonCount, AttemptRecord, AttemptResumePoint, AttemptState, CancelMode,
    CancelRejectionOutcome, CancelRequestOutcome, CancelStanding, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, DialLandingReserve, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome, FinishAttemptLanding, FinishLandingOutcome,
    ForceAttemptCancel, ForceCancelAuthority, ForceCancelGrounds, ForceCancelOutcome,
    InterveneAttempt, InterveneOutcome, LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT,
    LandingOutcome, LandingReserveSpendOutcome, LandingTrigger, LandingWarningOutcome,
    LeaseWarningOutcome, MAX_ATTEMPT_CANCEL_RECEIPTS, MAX_ATTEMPT_MANIFEST_ENTRIES,
    MAX_LANDING_RESERVE_PERCENT, MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS, ManifestEntry,
    ManifestKind, RecordAttemptResumePoint, RejectAttemptCancel, RequestAttemptCancel,
    RetryAttempt, RetryOutcome, SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
    SpendAttemptLandingReserve, TERMINAL_CANCEL_RECEIPT_RESERVE, WarnAttemptBudgetPressure,
    WarnAttemptLeaseExpiry, WarnExpiringAttemptLeases,
};

pub(crate) use encoding::decode_record;
pub(crate) use engine::dreamer_run_root_id_in_txn;
/// Storage-ABI pin re-exported for `crate::store`; its only consumer outside
/// this module is `store`'s row-header test.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use types::ATTEMPT_RECORD_VERSION;
pub(crate) use types::attempt_record_order;
