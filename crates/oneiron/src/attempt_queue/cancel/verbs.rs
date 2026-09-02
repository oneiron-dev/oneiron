//! Verb inputs and typed outcomes for the ONE-1896 graceful-cancel doors.
//!
//! The durable rows these doors write live in [`super::types`]; the doors
//! themselves in [`super::ops`] and [`super::terminal`].

use crate::attempt_queue::types::{AttemptId, AttemptRecord};

use super::types::{
    AttemptCancelPressure, AttemptResumePoint, CancelStanding, ForceCancelAuthority, LandingTrigger,
};

/// Input for the SOFT rung: asking a running attempt to stop.
///
/// Soft is a request, never a mutation to terminal: the worker answers by
/// landing or by refusing with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAttemptCancel {
    pub id: AttemptId,
    /// The asking actor. [`ATTEMPT_RUNTIME_ACTOR`](crate::attempt_queue::ATTEMPT_RUNTIME_ACTOR)
    /// is refused here: only the runtime's own warning doors may author runtime
    /// rows.
    pub actor: String,
    /// Standing the CALLER resolved. [`CancelStanding::None`] is refused.
    pub standing: CancelStanding,
    pub trigger: LandingTrigger,
    pub reason: Option<String>,
    pub now: u64,
}

/// Typed soft-request outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelRequestOutcome {
    /// Durably recorded against a running attempt; the worker owes an answer.
    Requested {
        record: AttemptRecord,
        pressure: AttemptCancelPressure,
    },
    /// The worker already accepted a stop. Asking again is idempotent.
    AlreadyLanding(AttemptRecord),
    /// The attempt is already terminal; there is nothing to ask.
    AlreadySettled(AttemptRecord),
    /// The caller established no standing. The attempt is UNCHANGED and the
    /// caller must fall back to its own proposal path.
    NoStanding(AttemptRecord),
    /// No worker holds this row's lease, so nobody can answer: a pre-lease
    /// attempt has no response door at all (`accept_landing` and
    /// `reject_cancel` both require a claimed lease). The attempt is UNCHANGED
    /// and NOTHING is recorded — a pending request against a queued row would
    /// be an ask addressed to no one, which the pathology counters would then
    /// read as a worker refusing to answer. Pre-lease work is stopped by
    /// `tasks.cancel`'s queue cancellation, not by asking.
    NotRunning(AttemptRecord),
}

/// Input for a worker ACCEPTING a stop and entering
/// [`AttemptState::Landing`](crate::attempt_queue::AttemptState::Landing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptAttemptLanding {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub trigger: LandingTrigger,
    /// The worker's own status — a complete "green + pushed + packet-only"
    /// answer is a valid landing.
    pub status: Option<String>,
    /// The resume point, when the worker already knows it. It may also be
    /// recorded later, inside the landing.
    pub resume_point: Option<AttemptResumePoint>,
    /// Which outstanding request this landing answers, by its receipt
    /// `sequence`. `None` answers the OLDEST outstanding one, which is the only
    /// order in which "the ask that has waited longest" is a stable meaning.
    /// An unknown or already-answered sequence is refused.
    pub request_sequence: Option<u64>,
    pub now: u64,
}

/// Typed landing-acceptance outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingOutcome {
    Landing(AttemptRecord),
    AlreadyLanding(AttemptRecord),
}

/// Input for a worker REFUSING a soft request while staying at work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectAttemptCancel {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Why the worker will not stop yet. Required: a refusal without a reason
    /// is indistinguishable from a worker that ignored the request.
    pub reason: String,
    pub status: Option<String>,
    /// Which outstanding request this refusal answers, by its receipt
    /// `sequence`. `None` answers the OLDEST outstanding one. Exactly one
    /// request is consumed, so the others keep their provenance and stay owed
    /// an answer.
    pub request_sequence: Option<u64>,
    pub now: u64,
}

/// Typed refusal outcome. The attempt stays
/// [`AttemptState::Leased`](crate::attempt_queue::AttemptState::Leased).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRejectionOutcome {
    pub record: AttemptRecord,
    pub pressure: AttemptCancelPressure,
    /// Repeated refusal has crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`](crate::attempt_queue::SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD).
    pub pathology: bool,
    /// The `sequence` of the request this refusal actually answered.
    pub answered_request_sequence: u64,
}

/// Input for recording the exact resume point inside a landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAttemptResumePoint {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

/// Input for spending landing reserve units under a lease fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendAttemptLandingReserve {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub units: u64,
    pub now: u64,
}

/// Typed reserve-spend outcome. Both arms are exact: nothing is ever partially
/// spent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingReserveSpendOutcome {
    Spent {
        record: AttemptRecord,
        remaining_units: u64,
    },
    /// The request does not fit the remaining reserve, so NOTHING was spent.
    Exhausted {
        record: AttemptRecord,
        requested_units: u64,
        remaining_units: u64,
    },
}

/// Input for dialing an attempt's budget and its landing reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialLandingReserve {
    pub id: AttemptId,
    /// Total budget units for the attempt.
    pub limit_units: u64,
    /// Percent held back for landing. `None` uses
    /// [`LANDING_RESERVE_PERCENT`](crate::attempt_queue::LANDING_RESERVE_PERCENT).
    pub reserve_percent: Option<u64>,
    pub now: u64,
}

/// Input for finishing a landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishAttemptLanding {
    pub id: AttemptId,
    /// The lease still held by the landing worker. Fenced exactly like
    /// `complete`: a stranger may not end someone else's landing early and
    /// strand the work it had not finished.
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Mint a successor row that resumes from the recorded resume point.
    /// Refused when no resume point was recorded.
    pub hand_off: bool,
    /// Instant the successor becomes claimable. `None` means immediately.
    pub scheduled_at: Option<u64>,
    pub now: u64,
}

/// Typed landing-completion outcome. Neither arm is `Completed`: a landing is
/// an honest stop, and the successor — not the landed row — carries the work.
///
/// Both rows ride the outcome by value, exactly as
/// [`ClaimOutcome`](crate::attempt_queue::ClaimOutcome) carries its claimed
/// record: a handoff caller needs the landed row's accounting AND the
/// successor's resume point, and boxing either would trade a real invariant for
/// a stack byte count.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum FinishLandingOutcome {
    Landed(AttemptRecord),
    HandedOff {
        landed: AttemptRecord,
        successor: AttemptRecord,
    },
}

/// Input for the HARD rung. The authority token is the authorization; there is
/// no actor string to forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceAttemptCancel {
    pub id: AttemptId,
    pub authority: ForceCancelAuthority,
    pub reason: Option<String>,
    pub now: u64,
}

/// Typed hard-cancel outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForceCancelOutcome {
    /// Terminal, unrefusable, runtime-authored.
    Cancelled(AttemptRecord),
    /// Idempotent replay of an already-forced stop.
    AlreadyCancelled(AttemptRecord),
    /// Already terminal in another disposition; live state is unchanged.
    AlreadySettled(AttemptRecord),
}

/// Input for the runtime's lease-expiry WARNING — distinct from expiry itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnAttemptLeaseExpiry {
    pub id: AttemptId,
    /// The same timeout
    /// [`CleanupAttemptLeases`](crate::attempt_queue::CleanupAttemptLeases)
    /// reclaims against.
    pub lease_timeout_secs: u64,
    pub now: u64,
}

/// Typed lease-warning outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseWarningOutcome {
    /// Inside the lease, before the warning window. Nothing recorded.
    NotDue(AttemptRecord),
    /// A runtime-authored landing request was recorded.
    LandingRequested(AttemptRecord),
    /// A request is already outstanding, or the worker is already landing.
    AlreadyRequested(AttemptRecord),
    /// The lease already expired: that is cleanup's force path, not a warning.
    Expired(AttemptRecord),
}

/// Input for the runtime's QUOTA/BUDGET warning: the pass counter this attempt
/// draws on is inside its land window, so the runtime asks the worker to land
/// before it starts work the budget cannot finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnAttemptBudgetPressure {
    pub id: AttemptId,
    pub now: u64,
}

/// Typed outcome of a runtime-authored landing warning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingWarningOutcome {
    /// A runtime-authored landing request was recorded against a leased row.
    LandingRequested(AttemptRecord),
    /// A request is already outstanding, or the worker is already landing.
    /// Warning again would inflate the pressure counters that make repeated
    /// refusal legible.
    AlreadyRequested(AttemptRecord),
    /// No worker holds the lease, so there is nobody to warn.
    NotRunning(AttemptRecord),
}

/// Input for the runtime's lease-expiry warning SWEEP over live leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnExpiringAttemptLeases {
    pub now: u64,
    /// The same timeout
    /// [`CleanupAttemptLeases`](crate::attempt_queue::CleanupAttemptLeases)
    /// reclaims against, so the warning window is derived from the very
    /// deadline that would otherwise take the work away.
    pub lease_timeout_secs: u64,
}

/// What one lease-warning sweep observed. Deliberately separate from
/// [`AttemptQueueCleanupReport`](crate::attempt_queue::AttemptQueueCleanupReport):
/// warning and expiry are different rungs, and a warned lease is still live
/// work, not reclaimed work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttemptLeaseWarningReport {
    /// Leased rows inspected.
    pub scanned: u64,
    /// Rows that got a fresh runtime landing request.
    pub warned: u64,
    /// Rows already carrying an unanswered ask, or already landing.
    pub already_requested: u64,
    /// Rows still inside their lease and before the warning window.
    pub not_due: u64,
    /// Rows already past expiry: cleanup's hard rung, never a warning.
    pub expired: u64,
}
