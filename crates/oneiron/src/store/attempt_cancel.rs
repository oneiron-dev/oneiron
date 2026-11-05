//! The graceful-cancel vocabulary an attempt row carries (ONE-1896): the
//! landing and its trigger, the resume point, the cancellation and its mode,
//! the standing and force grounds, the cancel receipts, the cancel pressure,
//! the landing reserve and the state that holds them. The attempt queue's
//! cancel protocol (`attempt_queue::cancel`) decides, constructs and
//! accounts them; the attempt row stores them.
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::attempt_queue::ForceCancelAuthority;

/// Actor token reserved for runtime-authored rows.
///
/// Worker- and peer-facing cancel doors refuse it, so a worker cannot author a
/// row that reads as if the runtime wrote it. It matches the run-tree
/// projection's runtime actor so both surfaces name the runtime identically.
pub const ATTEMPT_RUNTIME_ACTOR: &str = "runtime";

/// Why an attempt was asked to LAND (ONE-1896 §5).
///
/// Typed provenance, never a bare "cancelling" boolean: a landing forced by a
/// budget ceiling and a landing a peer asked for produce the same state but
/// call for different successor work, and the receipt has to say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LandingTrigger {
    /// A soft `cancel.request` from an actor with standing.
    CancelRequest,
    /// Budget or quota depletion is approaching (the `budget.land.95` rung).
    BudgetWarning,
    /// The lease is inside its expiry warning window.
    LeaseWarning,
}

/// Standing to ASK a running attempt to stop — the soft rung, and only the
/// soft rung.
///
/// The queue does not authenticate actors; the calling adapter RESOLVES
/// standing from its own authority evidence (a spawner link, a task owner
/// record, the runtime's own clock) exactly as `cancel` resolves
/// ownership, and passes the resolved verdict here. Fail closed: an adapter
/// that cannot establish standing passes [`Self::None`] and the attempt is
/// left untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CancelStanding {
    /// A peer agent — typically the spawner of a sticky child.
    PeerAgent,
    /// A healer or self-repair loop.
    Healer,
    /// Scheduled automation, including the runtime's own warnings.
    Automation,
    /// The owner/authority. The ONLY standing that can also reach the hard rung.
    Authority,
    /// No standing established. Nothing may be asked.
    None,
}

/// Grounds on which a hard, unrefusable `cancel.force` was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ForceCancelGrounds {
    /// The owner/authority ruled.
    Owner,
    /// The lease this attempt held expired.
    LeaseExpiry,
    /// A criticality stop.
    Criticality,
}

/// The exact point a successor resumes from after a designed landing.
///
/// A landing that cannot say where to pick up is a kill with extra steps, so
/// the handoff door refuses to mint a successor without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptResumePoint {
    /// Worker-authored cursor: the smallest thing a successor needs to continue.
    pub marker: String,
    /// Durable artifact/receipt the successor should read first, when one exists.
    #[serde(default)]
    pub artifact_ref: Option<String>,
    pub recorded_at: u64,
}

/// Durable LANDING record: why the attempt is landing, who asked, and what the
/// worker reported when it accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptLanding {
    pub trigger: LandingTrigger,
    /// The actor whose request was accepted, or the runtime for a warning.
    pub requested_by: String,
    pub entered_at: u64,
    /// The worker's own status at acceptance — "green + pushed + packet-only"
    /// is a complete and valid landing answer.
    #[serde(default)]
    pub status: Option<String>,
}

/// Whether a terminal cancellation was a designed landing or a hard stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CancelMode {
    /// The worker landed: it chose to stop and left a resume point.
    Landed,
    /// The hard rung fired: unrefusable and runtime-authored.
    Forced,
}

/// Durable terminal cancellation receipt, authored by the runtime.
///
/// `actor` is copied from the landing lease owner or from
/// [`ForceCancelAuthority`], never from free request text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptCancellation {
    pub mode: CancelMode,
    /// Set exactly on [`CancelMode::Forced`].
    #[serde(default)]
    pub grounds: Option<ForceCancelGrounds>,
    pub actor: String,
    pub at: u64,
    #[serde(default)]
    pub reason: Option<String>,
    /// The trigger of the landing that led here, when there was one.
    #[serde(default)]
    pub trigger: Option<LandingTrigger>,
    /// Landing reserve accounting AS SETTLED at the terminal instant.
    pub reserve_units: u64,
    pub reserve_spent_units: u64,
}

/// What one [`AttemptCancelReceipt`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttemptCancelReceiptKind {
    /// Rung 1: an actor with standing asked the worker to stop.
    SoftRequested,
    /// Rung 1 answered by LANDING.
    LandingAccepted,
    /// Rung 1 answered by REFUSAL. The attempt keeps running.
    SoftRejected,
    /// The landing recorded its exact resume point.
    ResumePointRecorded,
    /// Reserve units were spent inside the landing.
    ReserveSpent,
    /// The landing finished; a successor may carry the resume point.
    Landed,
    /// Rung 2: an authorized hard force terminated the attempt.
    ForceCancelled,
}

/// One append-only row of the two-rung graceful-cancel protocol.
///
/// Deliberately NOT folded into [`AttemptEvent`](crate::attempt_queue::AttemptEvent),
/// for the same reason the pack manifest is not: `AttemptEvent` is the closed
/// four-variant operator intervention record, and flattening a structured
/// refusal into an operator note would erase the trigger, the status, and the
/// resume point that make a landing reviewable.
///
/// Which optional fields a row may carry is NOT free-form: every kind declares
/// its required/forbidden shape and both the write door and `decode_record`
/// enforce it (`validate::validate_cancel_receipt_fields`), so a persisted row
/// can never contradict its own kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptCancelReceipt {
    pub sequence: u64,
    pub at: u64,
    /// Who authored the row. Runtime rows carry [`ATTEMPT_RUNTIME_ACTOR`].
    pub actor: String,
    pub kind: AttemptCancelReceiptKind,
    #[serde(default)]
    pub standing: Option<CancelStanding>,
    #[serde(default)]
    pub trigger: Option<LandingTrigger>,
    #[serde(default)]
    pub grounds: Option<ForceCancelGrounds>,
    /// The worker's status line, when it gave one.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// The resume point as it stood when this row was written.
    #[serde(default)]
    pub resume_point: Option<AttemptResumePoint>,
    /// Reserve units this row moved (`ReserveSpent`), or 0.
    #[serde(default)]
    pub reserve_units: u64,
    /// The `sequence` of the SoftRequested row this one ANSWERS, on the two
    /// answering kinds ([`AttemptCancelReceiptKind::answers_request`]).
    ///
    /// Requests are identified by their own receipt sequence rather than by
    /// recency: with two asks outstanding, "the last request" is not the one a
    /// refusal answered, and pairing by recency reported the refusal against a
    /// requester who is still waiting while the answered ask stayed pending
    /// forever.
    #[serde(default)]
    pub request_sequence: Option<u64>,
}

/// Two-rung cancel pressure counters carried on the row.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct AttemptCancelPressure {
    /// Soft requests recorded against this attempt, ever.
    #[serde(default)]
    pub requests: u32,
    /// Soft requests the worker refused. The pathology signal.
    #[serde(default)]
    pub rejections: u32,
    /// Recorded requests the worker has not yet answered.
    #[serde(default)]
    pub pending: u32,
}

/// Durable landing reserve accounting, in the same integer budget units as
/// [`crate::llm::BudgetRead`].
///
/// This is NOT a second budget meter. It holds back a slice and records what
/// the landing spent from it; ordinary execution is metered by the existing
/// [`crate::llm::BudgetGuard`], which is constructed with
/// [`Self::ordinary_limit_units`] and therefore never contains the reserve at
/// all. "Normal execution cannot spend it" is a property of what the ordinary
/// meter was built with, not a rule the meter has to remember.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct AttemptLandingReserve {
    /// Total budget units dialed for the attempt.
    #[serde(default)]
    pub limit_units: u64,
    /// Units held back for landing work.
    #[serde(default)]
    pub reserve_units: u64,
    /// Reserve units already spent, only ever inside `AttemptState::Landing`.
    #[serde(default)]
    pub spent_units: u64,
    /// The lease generation (`AttemptRecord::attempt_count`) this reserve was
    /// dialed at, and the durable ONE-SHOT mark.
    ///
    /// Two facts one boolean could not carry. First, it distinguishes a row
    /// deliberately dialed to a ZERO reserve (a budget too small to carve a
    /// slice from) from a row nothing has dialed yet — both leave
    /// `reserve_units == 0`, and only the second may still be dialed. Second,
    /// it fences the dial to ONE application per admitted generation: a later
    /// public or in-transaction call against the SAME generation is refused,
    /// so nothing can enlarge the reserve of an attempt that is already
    /// running against its ordinary limit. A fresh claim advances the
    /// generation, so the next admission dials its own row honestly.
    #[serde(default)]
    pub dial_generation: Option<u32>,
}

/// The whole ONE-1896 graceful-cancel lifecycle carried by one attempt row.
///
/// One additive field rather than six: the protocol is a single coherent
/// sub-record, and rows written before it decode as [`Self::default`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptCancelState {
    /// Present exactly while the row is landing, and preserved afterwards on a
    /// row that landed, so a terminal receipt can still name its trigger.
    #[serde(default)]
    pub landing: Option<AttemptLanding>,
    /// Set on a landing row when the worker records it, and COPIED onto the
    /// successor row so a handoff cannot lose it.
    #[serde(default)]
    pub resume_point: Option<AttemptResumePoint>,
    /// Terminal cancellation receipt. Only a `Cancelled` row may carry one.
    #[serde(default)]
    pub cancellation: Option<AttemptCancellation>,
    #[serde(default)]
    pub pressure: AttemptCancelPressure,
    /// Append-only protocol evidence, never drained and never refused on a
    /// count: the rejection history is the pathology evidence (ONE-1896 §1),
    /// so every row is kept. Past the `[limits]` `attempt_cancel_receipts`
    /// row an append asks whether everything is okay and lands (Rule 5).
    #[serde(default)]
    pub receipts: Vec<AttemptCancelReceipt>,
    #[serde(default)]
    pub reserve: AttemptLandingReserve,
}
