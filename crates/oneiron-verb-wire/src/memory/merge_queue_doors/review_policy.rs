//! Moved from `crates/oneiron/src/memory/merge_queue_doors/review_policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::review_policy::QueueReviewPolicy;
use crate::merge_queue::review_policy::QueueReviewThresholds;
use oneiron_store::critic_lens::LensCatalog;
use serde::Deserialize;
use serde::Serialize;

/// The policy an Owner, or his Granted agent, sets for the whole vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueueReviewPolicyInput {
    /// The lenses inherited queue work must pass.
    pub catalog: LensCatalog,
    /// Its limits; omitted, today's defaults (2 critics, 64 votes).
    #[serde(default)]
    pub thresholds: QueueReviewThresholds,
}

/// `.set`'s input: the policy, or `null` to clear it back to the default.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueueReviewPolicySetRequest {
    pub policy: Option<QueueReviewPolicyInput>,
}

/// What the vault's policy row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueReviewPolicyState {
    /// No row: the default.
    Absent,
    Set,
    /// A row that does not read.
    Unreadable,
}

/// What queue work that inherits the vault's review gets now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueReviewMode {
    /// No critic hold: the same checked queue lands it on green.
    LandOnGreen,
    /// It waits for the policy's critics or the owner's Approve.
    Review,
    /// It holds as `review_policy_unreadable` until an Owner sets or clears
    /// the policy.
    Held,
}

/// The vault's review policy as the door read it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QueueReviewPolicyView {
    pub state: QueueReviewPolicyState,
    pub mode: QueueReviewMode,
    /// The configured policy, when it reads.
    pub policy: Option<QueueReviewPolicy>,
    /// With a row that does not read: the typed hold and its way out.
    pub hold: Option<String>,
}
