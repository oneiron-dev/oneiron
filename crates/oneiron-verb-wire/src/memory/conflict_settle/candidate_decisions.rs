//! Moved from `crates/oneiron/src/memory/conflict_settle/candidate_decisions.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_wake_contract::dreamer_consolidation::provenance::KeptDecision;
use serde::Deserialize;
use serde::Serialize;

/// `vault.consolidation.candidate_decisions`'s input: the Dreamer attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerCandidateDecisionsRequest {
    /// 32-hex attempt id (`job:` prefix allowed), as
    /// `vault.consolidation.status` names it.
    pub job_ref: String,
}

/// One candidate a Dreamer attempt decided a correction for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerDecidedCandidateView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// Its position in the attempt's extraction.
    pub position: u64,
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    #[schemars(with = "String")]
    pub subject: EntityId,
    /// The listed claim its decisions bound it to; none when they bound none.
    #[serde(with = "oneiron_contracts::entity_id::serde_hex::optional")]
    #[schemars(with = "Option<String>")]
    pub corrects: Option<EntityId>,
    /// Its kept decisions, each with its receipt and, when it went up the
    /// role chain, that ask.
    pub decisions: Vec<KeptDecision>,
}
