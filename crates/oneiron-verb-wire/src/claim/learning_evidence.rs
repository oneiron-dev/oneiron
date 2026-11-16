//! Moved from `crates/oneiron/src/claim/learning_evidence.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::learning_predicate::LearningPredicate;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::learning_estimate::EstimateForm;
use serde::Deserialize;
use serde::Serialize;

/// Longest outcome category name.
pub const MAX_CATEGORY_BYTES: usize = 64;

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

    pub fn validate(&self) -> Result<()> {
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
