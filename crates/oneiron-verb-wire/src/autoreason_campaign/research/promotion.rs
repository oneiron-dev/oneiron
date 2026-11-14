//! Moved from `crates/oneiron/src/autoreason_campaign/research/promotion.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The held-out decision, as decided by the campaign's dominance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeldOutCall {
    Promote,
    Reject,
    EscalateTradeoff,
}

/// The one sealed confirmation of a candidate. `exposure` is empty when the
/// shot was consumed but the release never completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationReceipt {
    pub cohort: EntityId,
    pub consumed_at: u64,
    pub exposure: Option<EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDisposition {
    /// The candidate is the campaign's new incumbent.
    Promoted,
    /// The sealed referee did not see a strict win.
    LostSealed,
    /// The sufficiency card did not read not-worse.
    HeldInsufficient,
    /// The skill gate's own verdict did not accept the revision.
    HeldGate,
}
