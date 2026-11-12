//! Moved from `crates/oneiron/src/merge_queue/review_policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::critic_lens::LensCatalog;
use serde::Deserialize;
use serde::Serialize;

/// Today's distinct accepting critics a reviewed proposal needs.
pub const DEFAULT_QUEUE_REVIEW_CRITICS: u32 = 2;

/// Today's most critic votes one proposal keeps.
pub const DEFAULT_QUEUE_REVIEW_VOTES: u32 = 64;

pub const fn default_critics() -> u32 {
    DEFAULT_QUEUE_REVIEW_CRITICS
}

pub const fn default_votes() -> u32 {
    DEFAULT_QUEUE_REVIEW_VOTES
}

/// A review policy's limits: defaults the owner may override, never floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QueueReviewThresholds {
    /// Distinct accepting critics a proposal needs. Default 2.
    #[serde(default = "default_critics")]
    pub critics: u32,
    /// The most critic votes one proposal keeps under the policy. Default 64.
    #[serde(default = "default_votes")]
    pub votes: u32,
}

impl Default for QueueReviewThresholds {
    fn default() -> Self {
        Self {
            critics: DEFAULT_QUEUE_REVIEW_CRITICS,
            votes: DEFAULT_QUEUE_REVIEW_VOTES,
        }
    }
}

/// The vault's one review policy row: the lenses inherited queue work must
/// pass, its limits, and who set it when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QueueReviewPolicy {
    pub catalog: LensCatalog,
    pub thresholds: QueueReviewThresholds,
    /// The Owner or Granted agent who set it; `None` once that actor was
    /// erased (FIX 8519): the policy stands, its setter no longer named.
    pub set_by: Option<EntityId>,
    /// When it was set, Unix seconds.
    pub set_at: u64,
}
