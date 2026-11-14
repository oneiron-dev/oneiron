//! Moved from `crates/oneiron/src/snapshot_read/strength_observations.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
pub use oneiron_verb_wire::snapshot_read::strength_observations::StrengthObservationsPageRequest;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Bound;

/// One observation page and the policy and config it was read under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrengthObservationsPage {
    pub policy: ConsolidationStrengthPolicy,
    pub policy_pin: String,
    pub config: SelectionConfig,
    pub config_pin: String,
    pub claims: Vec<ObservedClaim>,
    pub next: Option<String>,
}

/// Whether all observed sources still read at their observed revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedClaimStatus {
    Current,
    Moved,
    Withheld,
}

/// An observed claim whose own row reads for this caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedClaim {
    pub claim: String,
    pub predicate: String,
    pub last_activity_ms: u64,
    pub status: ObservedClaimStatus,
    /// The readable sources in id order, then one bare entry per withheld one.
    pub sources: Vec<ObservedSource>,
    /// The full source list exceeds an otherwise empty page's byte bound.
    pub sources_omitted: bool,
    pub signals: Option<ObservedSignals>,
    pub pin: Option<String>,
    /// For a current claim, the archive fence's reason token for this
    /// caller at the page's clock, or `None` when the fence lets it through
    /// now (RULING S69C4-FENCE-NOISE = B): the strength archive skips a
    /// fenced claim, and Archive runs the same fence again in its item's
    /// savepoint. `None` for a claim that is not current.
    pub fence: Option<String>,
}

/// A source's coarse status; withheld sources disclose nothing else, and are
/// served after every readable one so their place in the id order stays unread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ObservedSource {
    Current { source: String },
    Moved { source: String },
    Withheld,
}

/// The native strength scorer's evidence inputs, without per-source detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSignals {
    pub source_count: usize,
    pub latest_learned_at_ms: u64,
    pub distinct_diversity: usize,
}
