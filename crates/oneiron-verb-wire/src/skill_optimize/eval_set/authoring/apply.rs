//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring/apply.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::DerivationKind;
use crate::skill_optimize::eval_set::EvalLabel;
use crate::skill_optimize::eval_set::FamilyPurpose;
use crate::skill_optimize::eval_set::MAX_NAME_BYTES;
use crate::skill_optimize::eval_set::cohort::EvalCohortRetirementAuthor;
use crate::skill_optimize::eval_set::cut_audit::EvalCutAuthor;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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

/// What one applied plan did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalAuthoringReport {
    pub families_assigned: usize,
    pub families_extended: usize,
    pub cases_recorded: usize,
    pub cases_reused: usize,
    pub labels_added: usize,
    pub cohorts_cut: Vec<EntityId>,
    /// Cuts whose audit could not read every compared case's text.
    pub cuts_with_coverage_gaps: usize,
    pub cohorts_retired: Vec<EntityId>,
    pub cohorts_kept: usize,
    pub skipped: Vec<EvalAuthoringSkip>,
}

impl EvalAuthoringReport {
    fn skip(&mut self, item: impl Into<String>, reason: impl Into<String>) {
        self.skipped.push(EvalAuthoringSkip {
            item: item.into(),
            reason: reason.into(),
        });
    }
}
