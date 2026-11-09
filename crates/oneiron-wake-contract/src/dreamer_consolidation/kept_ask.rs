//! Moved from `crates/oneiron/src/dreamer_consolidation/kept_ask.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::AskAct;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::HolderKind;
use oneiron_store::model_decision::HostRuleRef;
use oneiron_store::model_decision::RoleRank;

/// A role on an ask's route as a write keeps it: where it sits on the chain
/// and the project whose boards it walks, never the actor it names.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeptRole {
    pub rank: RoleRank,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "oneiron_contracts::entity_id::serde_hex::optional"
    )]
    #[schemars(with = "Option<String>")]
    pub project: Option<EntityId>,
}

/// The route the Dreamer bound, as a write keeps it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeptRoute {
    /// The role asked first.
    pub role: KeptRole,
    /// The highest rank the ask may climb to.
    pub ceiling: RoleRank,
    pub act: AskAct,
}

/// A holder's answer as a write keeps it: what it answered and when, as
/// which role, person or agent, and the owner's reason and rule row, never
/// who answered.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptAnswer {
    pub answer: DecisionAnswer,
    /// Vault clock seconds when the answer landed.
    pub answered_at: u64,
    pub role: KeptRole,
    pub kind: HolderKind,
    /// Whether the answer changed the ladder's prior.
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<HostRuleRef>,
}

/// The ask a decision went up as: its arrival number, the route the Dreamer
/// bound and the holder's answer once one landed, each actor-free. Two copies
/// of one ask are equal whoever was erased since. A request never reads as a
/// grant.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptAsk {
    pub seq: u64,
    pub to: KeptRoute,
    pub answer: Option<KeptAnswer>,
}
