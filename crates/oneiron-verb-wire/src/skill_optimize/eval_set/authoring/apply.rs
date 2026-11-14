//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring/apply.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::FamilyPurpose;
use serde::Deserialize;
use serde::Serialize;

/// A purpose for one new source group, given before any case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FamilyDecision {
    pub group: String,
    pub purpose: FamilyPurpose,
}

/// One candidate kept as a case, with the slice it was drawn for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseDecision {
    pub candidate: String,
    #[serde(default)]
    pub stratum: Option<String>,
}

/// One decision a door or the inventory did not let through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalAuthoringSkip {
    /// The group, candidate, cut or cohort it named.
    pub item: String,
    pub reason: String,
}
