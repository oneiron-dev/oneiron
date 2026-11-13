//! Anchored learning evidence and retest request vocabulary.

use serde::{Deserialize, Serialize};

use crate::claim::learning_estimate::EstimateForm;
use crate::claim::learning_predicate::LearningPredicate;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};

#[doc(hidden)]
use oneiron_verb_wire::claim::learning_evidence::MAX_CATEGORY_BYTES;
#[doc(hidden)]
pub use oneiron_verb_wire::claim::learning_evidence::{Anchor, EvidenceSource, Observation};

/// One candidate piece of evidence for a cell.
#[derive(Debug, Clone, PartialEq)]
pub struct LearningEvidence {
    /// The receipt it rests on; one row per receipt per cell.
    pub receipt: String,
    /// Unix seconds of the outcome, the time the window fades from.
    pub at: u64,
    pub source: EvidenceSource,
    pub observation: Observation,
    /// The share this receipt contributes: 1 for a whole run, a fraction for
    /// an attributed defect share or a lineage-credit hop.
    pub weight: f64,
    /// The judge revision that scored it, when a judge did.
    pub judge: Option<String>,
    /// Whether the judge scored work done on its own model.
    pub on_judge_model: bool,
    /// The outcome category a mean edit-cost observation also keeps.
    pub outcome_label: Option<String>,
    /// Frozen pack execution/use context; judge and team metadata are evidence,
    /// not reliability key qualifiers.
    pub pack_attribution: Option<crate::receipt::PackLearningContext>,
    /// The effective skill-edit goal revision the outcome was measured under,
    /// frozen at measurement. Metadata, not a cell key qualifier: a goal-axis
    /// settlement accepts the row only when it equals the question's revision.
    pub goal_revision: Option<String>,
    /// The engine version a magnitude was measured under. A mean folds one
    /// measurement version: the newest measured row's (FIX 7822).
    pub measurement_version: Option<String>,
}

impl LearningEvidence {
    /// A whole-run anchored observation with no judge.
    #[must_use]
    pub fn anchored(
        receipt: impl Into<String>,
        at: u64,
        anchor: Anchor,
        observation: Observation,
    ) -> Self {
        Self {
            receipt: receipt.into(),
            at,
            source: EvidenceSource::Anchored(anchor),
            observation,
            weight: 1.0,
            judge: None,
            on_judge_model: false,
            outcome_label: None,
            pack_attribution: None,
            goal_revision: None,
            measurement_version: None,
        }
    }
}

/// A stored, admitted evidence row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceRow {
    pub at: u64,
    pub anchor: Anchor,
    pub observation: Observation,
    pub weight: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<String>,
    #[serde(default)]
    pub on_judge_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_attribution: Option<crate::receipt::PackLearningContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_version: Option<String>,
}

impl EvidenceRow {
    /// The row `evidence` stores under `anchor`.
    pub(crate) fn of(evidence: &LearningEvidence, anchor: Anchor) -> Self {
        Self {
            at: evidence.at,
            anchor,
            observation: evidence.observation.clone(),
            weight: evidence.weight,
            judge: evidence.judge.clone(),
            on_judge_model: evidence.on_judge_model,
            outcome_label: evidence.outcome_label.clone(),
            pack_attribution: evidence.pack_attribution.clone(),
            goal_revision: evidence.goal_revision.clone(),
            measurement_version: evidence.measurement_version.clone(),
        }
    }
}

/// Evidence rows. Key: cell digest + receipt reference.
pub(crate) const EVIDENCE: SideTable<([u8; 32], String), EvidenceRow, Named> =
    SideTable::new(&side_table::LEARNING_EVIDENCE);

/// One same-case retest by one scorer.
#[derive(Debug, Clone, PartialEq)]
pub struct Retest {
    /// The scorer: a judge skill, a critic lens, any scoring subject.
    pub scorer: EntityId,
    /// The scorer's executor at revision.
    pub executor: String,
    pub axis: String,
    pub type_ref: Option<TypeRef>,
    /// The retest receipt: one row per receipt.
    pub receipt: String,
    pub first: RetestScore,
    pub second: RetestScore,
    pub at: u64,
}

/// One of the two scores a retest compares.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetestScore {
    /// A pass/fail verdict.
    Pass(bool),
    /// A numeric score.
    Value(f64),
}
