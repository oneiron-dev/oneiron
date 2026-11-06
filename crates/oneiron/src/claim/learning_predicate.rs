//! Measured-state predicate vocabulary and its permitted estimate forms.

use serde::{Deserialize, Serialize};

use crate::claim::learning_estimate::EstimateForm;
use crate::write_envelope::learning_predicate::{
    PREDICATE_LEARNING_EDIT_COST, PREDICATE_LEARNING_RELIABILITY, PREDICATE_LEARNING_RETEST_NOISE,
    PREDICATE_LEARNING_SETTING,
};

/// The four members of the family.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LearningPredicate {
    /// How often a thing worked: any skill role, or an actor.
    Reliability,
    /// How much people had to fix, after attribution.
    EditCost,
    /// How often a judge or scorer disagrees with itself.
    RetestNoise,
    /// The fitted value of a named knob.
    Setting,
}

impl LearningPredicate {
    /// Every member, in canon order.
    pub const ALL: [Self; 4] = [
        Self::Reliability,
        Self::EditCost,
        Self::RetestNoise,
        Self::Setting,
    ];

    /// The claim predicate.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reliability => PREDICATE_LEARNING_RELIABILITY,
            Self::EditCost => PREDICATE_LEARNING_EDIT_COST,
            Self::RetestNoise => PREDICATE_LEARNING_RETEST_NOISE,
            Self::Setting => PREDICATE_LEARNING_SETTING,
        }
    }

    /// The member a claim predicate names, if any.
    #[must_use]
    pub fn from_predicate(predicate: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == predicate)
    }

    /// Whether `form` is a shape this member may carry.
    #[must_use]
    pub const fn admits_form(self, form: EstimateForm) -> bool {
        matches!(
            (self, form),
            (Self::Reliability, EstimateForm::Beta)
                | (Self::EditCost, EstimateForm::Mean | EstimateForm::Counts)
                | (Self::RetestNoise, EstimateForm::Beta | EstimateForm::Mean)
                | (Self::Setting, EstimateForm::Mean | EstimateForm::Counts)
        )
    }

    /// What counted, when the cell names nothing more specific.
    #[must_use]
    pub const fn default_of(self, form: EstimateForm) -> &'static str {
        match (self, form) {
            (Self::Reliability, _) => "won",
            (Self::EditCost, EstimateForm::Counts) => "untouched",
            (Self::EditCost, _) => "normalized edit distance",
            (Self::RetestNoise, EstimateForm::Beta) => "retest disagreement",
            (Self::RetestNoise, _) => "retest score difference",
            (Self::Setting, _) => "fitted value",
        }
    }
}

/// The four measured predicates, not the learned-setting catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum MeasuredLearningPredicate {
    #[serde(rename = "learning.reliability")]
    Reliability,
    #[serde(rename = "learning.edit_cost")]
    EditCost,
    #[serde(rename = "learning.retest_noise")]
    RetestNoise,
    #[serde(rename = "learning.setting")]
    Setting,
}

impl From<MeasuredLearningPredicate> for LearningPredicate {
    fn from(value: MeasuredLearningPredicate) -> Self {
        match value {
            MeasuredLearningPredicate::Reliability => Self::Reliability,
            MeasuredLearningPredicate::EditCost => Self::EditCost,
            MeasuredLearningPredicate::RetestNoise => Self::RetestNoise,
            MeasuredLearningPredicate::Setting => Self::Setting,
        }
    }
}

impl From<LearningPredicate> for MeasuredLearningPredicate {
    fn from(value: LearningPredicate) -> Self {
        match value {
            LearningPredicate::Reliability => Self::Reliability,
            LearningPredicate::EditCost => Self::EditCost,
            LearningPredicate::RetestNoise => Self::RetestNoise,
            LearningPredicate::Setting => Self::Setting,
        }
    }
}
