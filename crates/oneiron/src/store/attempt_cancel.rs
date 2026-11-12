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

#[doc(hidden)]
pub use oneiron_wake_contract::store::attempt_cancel::{AttemptResumePoint, LandingTrigger};

#[doc(hidden)]
pub use oneiron_verb_wire::store::attempt_cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptCancellation,
    AttemptLanding, CancelMode, CancelStanding, ForceCancelGrounds,
};

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
