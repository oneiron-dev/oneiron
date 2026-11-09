//! Moved from `crates/oneiron/src/store/attempt_cancel.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
