//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring/apply.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill_optimize::eval_set::authoring::apply::CaseDecision;
pub use oneiron_verb_wire::skill_optimize::eval_set::authoring::apply::EvalAuthoringSkip;
pub use oneiron_verb_wire::skill_optimize::eval_set::authoring::apply::FamilyDecision;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Whether one cohort retires, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortDecision {
    pub cohort: EntityId,
    pub retire: bool,
    #[serde(default)]
    pub reason: String,
}
