//! Moved from `crates/oneiron/src/skill_optimize/eval_set/doors/cohort_retire.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
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
