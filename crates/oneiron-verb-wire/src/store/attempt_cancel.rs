//! Moved from `crates/oneiron/src/store/attempt_cancel.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
pub use oneiron_wake_contract::store::attempt_cancel::LandingTrigger;
use serde::Deserialize;
use serde::Serialize;

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
    /// An accepted hard erase or authenticated restore erased the payload's source.
    ErasedPayload,
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
/// Deliberately NOT folded into [`AttemptEvent`](oneiron_store::attempt_inputs::AttemptEvent),
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
