//! Moved from `crates/oneiron/src/critic/review/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.critic.outcome`'s input: one critique of a persisted review, and the
/// anchor that settles it. Who records it and when come from the engine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticOutcomeSubmit {
    /// The review's `review.verdict` claim, 32-hex.
    pub verdict_ref: String,
    /// The reviewed target, 32-hex: the verdict's subject.
    pub target_ref: String,
    /// One critique of that review.
    pub artifact_id: String,
    pub anchor: CriticOutcomeAnchor,
}

/// What settles a critique.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CriticOutcomeAnchor {
    /// The live owner's own verdict: whether the critique held.
    OwnerVerdict { accepted: bool },
    /// The completed directed recheck of the sealed try, 32-hex, whose result
    /// is the reviewed target. The engine reads what its findings settle.
    SealRecheck { attempt_ref: String },
}

/// `vault.critic.findings`'s input: one persisted review.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticFindingsRequest {
    /// The review's `review.verdict` claim, 32-hex.
    pub verdict_ref: String,
    /// The reviewed target, 32-hex: the verdict's subject.
    pub target_ref: String,
}
