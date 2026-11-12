//! Moved from `crates/oneiron/src/embed/space_move.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A paired comparison's reading (NOT-WORSE = A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotWorse {
    /// The interval's low end is at or above minus the tolerance.
    NotWorse,
    /// The whole interval is below minus the tolerance.
    Worse,
    /// Too few families, or the interval spans the tolerance.
    Unknown,
}

/// A family-grouped mean paired difference and its two-sided 95% interval.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PairedInterval {
    pub mean: f32,
    pub low: f32,
    pub high: f32,
}

/// One probe a check ran whose date window had ended: a member of a cut cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CohortProbe {
    /// 32 hex.
    pub probe: String,
    /// Its source document.
    pub source: EntityId,
    /// Its date window, vault seconds: `from` up to, not including, `until`.
    pub from: u64,
    pub until: u64,
}

/// Where a move stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpaceMoveState {
    /// The candidate fills beside the incumbent, which serves.
    Open,
    /// The candidate serves; the incumbent stays declared for undo. `by_owner` is the owner's
    /// yes over a check that did not read not worse.
    SwappedIn { at: u64, by_owner: bool },
    /// The incumbent kept serving; the candidate's rows of the moved kinds went. `timed_out` is
    /// a move closed at [`SPACE_MOVE_FILL_DEADLINE_SECS`] with no check run, not a worse one.
    Kept { at: u64, timed_out: bool },
    /// An undo bound the incumbent again.
    Undone { at: u64 },
}
