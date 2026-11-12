//! Moved from `crates/oneiron/src/workspace_roster/project/goal/proposals.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_contracts::memory::MEMORY_CODE_NOT_FOUND;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::principal_record::NoStanding;
use oneiron_store::principal_record::PACT_STANDING_LAPSED;
use serde::Deserialize;
use serde::Serialize;

/// The goal a proposal revises: the goal claim in force and the goal
/// generation it was read at. Either one moving makes the base stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalBase {
    pub goal_claim: EntityId,
    pub generation: u64,
}

/// The proposal's argument (ARCH-0053): why, its merits and demerits, and
/// the sacrifice, what is given up if the goal moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalReasons {
    pub reason: String,
    pub merits: Vec<String>,
    pub demerits: Vec<String>,
    pub sacrifice: String,
}

/// imp@k against the target over N cycles, by the receipts that show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalImprovement {
    pub k: u32,
    pub cycles: u32,
    pub receipts: Vec<String>,
}
