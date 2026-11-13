//! Moved from `crates/oneiron/src/skill_attribution/late_credit.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::learning_evidence::Anchor;
use crate::receipt::pack_attribution::PackAttributionFields;
use crate::receipt::pack_attribution::UsedProvenanceEdge;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;

/// One fractional share, with its complete eligible used chain. An erase
/// redacts only the ids it names (FIX 8988): the share keeps its decay and
/// weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LateCreditShare {
    /// The credited skill; `None` once that skill is erased.
    pub subject: Option<EntityId>,
    /// The contributing skill the chain starts from; `None` for the run's
    /// output root, and once that skill is erased, which clears the chain too.
    pub origin_skill: Option<EntityId>,
    /// The used chain; `None` once an erased entity is one of its ends.
    pub chain: Option<Vec<UsedProvenanceEdge>>,
    pub decay: f64,
    pub weight: f64,
}

/// An anchored projection's receipt. Empty shares explicitly record no late
/// credit, including disabled credit, an environment verdict or an unclear one.
/// It is sealed: what later checks and late landings make of it is appended
/// beside it, with the `credit_decay` it was projected under
/// ([`super::CreditAdjustmentReceipt`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LateCreditReceipt {
    pub receipt_id: String,
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub anchor: Anchor,
    pub succeeded: bool,
    pub axis: String,
    pub at: u64,
    /// The goal revision the outcome was checked under, as the host froze it;
    /// `None` is unscoped credit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_revision: Option<String>,
    /// The run's frozen attribution; `None` once an erased entity is one it
    /// names (FIX 8988).
    pub attribution: Option<PackAttributionFields>,
    /// Each subject credited directly; `None` for one since erased.
    pub direct_subjects: Vec<Option<EntityId>>,
    pub shares: Vec<LateCreditShare>,
}
