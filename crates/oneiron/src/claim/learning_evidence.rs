//! Anchored learning evidence and retest request vocabulary.

use serde::{Deserialize, Serialize};

use crate::claim::learning_estimate::EstimateForm;
use crate::claim::learning_predicate::LearningPredicate;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};

/// Longest outcome category name.
const MAX_CATEGORY_BYTES: usize = 64;

/// An anchored outcome kind.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anchor {
    /// A held-out run scored against frozen cases.
    HeldOut,
    /// The owner's verdict, including an owner's edit of the output.
    OwnerVerdict,
    /// A later fact in the world that settled the question.
    WorldOutcome,
    /// A random audit; `rate` is the sampling rate in force on its receipt.
    Audit { rate: f64 },
    /// The same case scored twice by the same scorer (`learning.retest_noise`).
    Retest,
    /// A check that fits a named knob (`learning.setting`).
    FittingCheck,
}

impl Anchor {
    /// Whether this anchor may feed `predicate`.
    #[must_use]
    pub const fn feeds(self, predicate: LearningPredicate) -> bool {
        match predicate {
            LearningPredicate::Reliability | LearningPredicate::EditCost => matches!(
                self,
                Self::HeldOut | Self::OwnerVerdict | Self::WorldOutcome | Self::Audit { .. }
            ),
            LearningPredicate::RetestNoise => matches!(self, Self::Retest),
            LearningPredicate::Setting => {
                matches!(
                    self,
                    Self::FittingCheck | Self::Audit { .. } | Self::HeldOut
                )
            }
        }
    }
}

/// Where a candidate piece of evidence came from. Only [`Self::Anchored`] is
/// admitted; the rest exist so a caller holding one gets a named refusal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvidenceSource {
    Anchored(Anchor),
    /// Two agents agreeing. Never evidence.
    AgentAgreement,
    /// An agent's report about its own work. Never evidence.
    SelfReport,
    /// A confession. It triggers a recheck and never moves a score.
    Confession,
}

impl EvidenceSource {
    /// The admission door.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] for every unanchored source, and for an
    /// audit whose rate is not a probability above zero.
    pub fn admit(self) -> Result<Anchor> {
        match self {
            Self::Anchored(Anchor::Audit { rate }) if !(rate > 0.0 && rate <= 1.0) => Err(
                Error::InvalidClaimBody("an audit carries its sampling rate in (0, 1]"),
            ),
            Self::Anchored(anchor) => Ok(anchor),
            Self::AgentAgreement => Err(Error::InvalidClaimBody(
                "agreement between agents is never learning evidence",
            )),
            Self::SelfReport => Err(Error::InvalidClaimBody(
                "an agent's report on its own work is never learning evidence",
            )),
            Self::Confession => Err(Error::InvalidClaimBody(
                "a confession triggers a recheck and is never learning evidence",
            )),
        }
    }
}

/// What one anchored outcome observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "v", rename_all = "snake_case")]
pub enum Observation {
    /// The named event happened (true) or did not (false).
    Success(bool),
    /// A measured magnitude: a normalized edit distance, a score difference,
    /// a fitted knob value.
    Magnitude(f64),
    /// One outcome category, such as untouched, amended or rejected.
    Category(String),
    /// One outcome counted beside a mean with no magnitude: its category
    /// joins the cell's outcome counts and moves neither the mean nor the
    /// runs, so it charges nobody.
    CountOnly(String),
}

impl Observation {
    /// The estimate form this observation feeds.
    #[must_use]
    pub const fn form(&self) -> EstimateForm {
        match self {
            Self::Success(_) => EstimateForm::Beta,
            Self::Magnitude(_) | Self::CountOnly(_) => EstimateForm::Mean,
            Self::Category(_) => EstimateForm::Counts,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Success(_) => Ok(()),
            Self::Magnitude(x) if x.is_finite() => Ok(()),
            Self::Magnitude(_) => Err(Error::InvalidClaimBody("a magnitude is finite")),
            Self::Category(name) | Self::CountOnly(name)
                if !name.is_empty()
                    && name.len() <= MAX_CATEGORY_BYTES
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                Ok(())
            }
            Self::Category(_) | Self::CountOnly(_) => Err(Error::InvalidClaimBody(
                "an outcome category is 1..=64 bytes of [a-z0-9_]",
            )),
        }
    }
}

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
