//! Moved from `crates/oneiron/src/skill_optimize/eval_set/doors/cohort_retire.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::cohort::EvalCohortRetirementAuthor;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::principal_record::NoStanding;
use oneiron_store::principal_record::PACT_STANDING_LAPSED;
use serde::Deserialize;
use serde::Serialize;

/// `vault.evals.cohorts.retire`'s input: the cohort and why. Who retires it,
/// the exposure it retires on and the time come from the engine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortRetireRequest {
    pub cohort: EntityId,
    /// Why the cohort retires: at most 512 bytes once trimmed.
    pub reason: String,
}
