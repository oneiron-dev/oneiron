//! Wire types of the owner's claim-refinement doors (FIX [SKILL-HUB-PROMOTION-VERBS]): the held-out reserve
//! of a claim base and the offer of one session-branch claim edit. `oneiron` re-exports each item.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

use crate::code_run::run_verbs::{JS_SAFE_INTEGER, MemoryTimeRange};

/// `vault.claims.refinements.holdouts.reserve`: the owner's own adjudicated
/// claims, kept as the hidden held-out split that scores every branch edit of
/// one active claim. A later reserve replaces the split.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefinementHoldoutRequest {
    /// The active claim the branch edits revise.
    pub base: EntityId,
    /// Approved, active, user-stated claims on the base's subject, each once.
    pub labels: Vec<EntityId>,
}

/// The held-out split as stored: every label once, in id order.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimRefinementHoldoutReserved {
    pub base: EntityId,
    pub labels: Vec<EntityId>,
}

/// Where a branch edit's proposed value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimRefinementSource {
    Inferred,
    Generated,
}

/// `vault.claims.refinements.offer`: one edit of an active claim, staged inert
/// on a resident agent's session branch. The edit keeps the base's predicate,
/// subject and scope; only the owner's merge door can make it the live claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefinementOfferRequest {
    /// The active claim the edit revises.
    pub base: EntityId,
    /// The resident agent whose session branch holds the edit; it is stamped
    /// as the edit's producer.
    pub resident: EntityId,
    /// The session branch's tag, at most 512 bytes.
    pub session_tag: String,
    /// The proposed value.
    pub value: serde_json::Value,
    /// The proposed confidence, in `[0, 1]`.
    #[schemars(range(min = 0.0, max = 1.0))]
    pub confidence: f64,
    pub source: ClaimRefinementSource,
    /// The evidence the edit rests on.
    #[serde(default)]
    pub evidence: Option<serde_json::Value>,
    /// When the proposed value held, unix seconds.
    pub occurred: MemoryTimeRange,
    /// When it was learned, unix seconds.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub learned_at: u64,
}

/// The staged edit: `candidate` is the id the owner's merge door rules on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimRefinementOffered {
    pub candidate: EntityId,
    pub base: EntityId,
    pub resident: EntityId,
    pub session_tag: String,
}
