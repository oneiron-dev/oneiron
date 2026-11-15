//! Moved from `crates/oneiron/src/code_run/contribution/admission.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a pair's stored forks do not prove it. None of these is a verdict on
/// the skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkMismatch {
    /// The runner recorded the pair unavailable.
    Unavailable,
    /// No fork receipt is kept for a side of the pair.
    MissingFork,
    /// A kept fork has another receipt than the one submitted for its side.
    OtherReceipt,
    /// A kept fork is not scored yet.
    Unscored,
    /// A kept fork was scored otherwise than submitted.
    OtherScore,
    /// The two forks were not scored against one anchor: their stored
    /// anchors differ, a stored anchor is not the candidate's anchor bound
    /// to its fork's frozen scoring identity, the forks were not scored
    /// in one evidence mode, the one their kept program runs settle, or not
    /// by the one judge the anchor takes (FIX 3609).
    AnchorDiverged,
    /// A fork did not regenerate the capsule of the step the target's check
    /// regenerates as it stands: another capsule, request, model, route
    /// prompt or seed, or the capsule's content is gone; or, in the
    /// `Executed` mode, a fork's execution did not run from that capsule's
    /// start.
    OtherCapsule,
    /// A kept fork was scored for another outcome, goal revision or axis
    /// than the candidate's.
    OtherOutcome,
}
