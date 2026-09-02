//! ONE-1896 two-rung graceful-cancel and LANDING protocol.
//!
//! One coherent concern, held apart from the lease state machine in
//! [`super::engine`] because it is its own vocabulary: an ASK a worker may
//! refuse, a LANDING it may accept, an integer reserve the landing spends, and
//! exactly one runtime-authored terminal receipt.
//!
//! Layout: [`types`] holds the durable wire rows persisted inside
//! [`AttemptCancelState`]; [`verbs`] holds the door inputs and typed outcomes;
//! [`ops`] holds RUNG 1 and the reserve dial; [`terminal`] holds landing
//! completion, RUNG 2, and the runtime's warning doors.
//!
//! Doors are inherent `AttemptQueue` methods, so this split moves code without
//! moving a single public path: every name below is re-exported unchanged from
//! [`crate::attempt_queue`].

mod ops;
mod terminal;
mod types;
mod verbs;

pub(super) use terminal::{force_cancel_record, validate_force_authority};
pub use types::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind,
    AttemptCancelState, AttemptCancellation, AttemptLanding, AttemptLandingReserve,
    AttemptResumePoint, CancelMode, CancelStanding, ForceCancelAuthority, ForceCancelGrounds,
    LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT, LandingTrigger,
    MAX_ATTEMPT_CANCEL_RECEIPTS, MAX_LANDING_RESERVE_PERCENT,
    MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS, SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
    TERMINAL_CANCEL_RECEIPT_RESERVE,
};
pub use verbs::{
    AcceptAttemptLanding, AttemptLeaseWarningReport, CancelRejectionOutcome, CancelRequestOutcome,
    DialLandingReserve, FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel,
    ForceCancelOutcome, LandingOutcome, LandingReserveSpendOutcome, LandingWarningOutcome,
    LeaseWarningOutcome, RecordAttemptResumePoint, RejectAttemptCancel, RequestAttemptCancel,
    SpendAttemptLandingReserve, WarnAttemptBudgetPressure, WarnAttemptLeaseExpiry,
    WarnExpiringAttemptLeases,
};
