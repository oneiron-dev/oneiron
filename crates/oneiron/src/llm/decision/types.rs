//! Closed answer contracts and engine-owned decision receipts.

use crate::EntityId;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRung {
    Rule,
    Local,
    SystemOne,
    Big,
    Human,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionClass {
    Retrieval,
    Contradiction,
    Triage,
    Judgment,
    UsefulUpstream,
    Preference,
    Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnswerContract {
    Noul,
    Choice { options: Vec<String> },
    Score { min: f64, max: f64 },
}

impl AnswerContract {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Choice { options }
                if options.is_empty()
                    || options.len() > 64
                    || options.iter().any(|s| s.is_empty() || s.len() > 256)
                    || options
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != options.len() =>
            {
                Err(invalid("invalid choice options"))
            }
            Self::Score { min, max } if !min.is_finite() || !max.is_finite() || min >= max => {
                Err(invalid("invalid score range"))
            }
            _ => Ok(()),
        }
    }

    pub fn accepts(&self, answer: &DecisionAnswer) -> bool {
        match (self, answer) {
            (_, DecisionAnswer::Abstain) | (Self::Noul, DecisionAnswer::Noul(_)) => true,
            (Self::Choice { options }, DecisionAnswer::Choice(value)) => options.contains(value),
            (Self::Score { min, max }, DecisionAnswer::Score(value)) => {
                value.is_finite() && value >= min && value <= max
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DecisionAnswer {
    Noul(bool),
    Choice(String),
    Score(f64),
    Abstain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionQuestion {
    #[serde(with = "super::codec::entity")]
    pub id: EntityId,
    pub version: u32,
    pub text: String,
    pub class: DecisionClass,
    pub contract: AnswerContract,
    /// Confident negative accept-type judgments require a second measurement.
    pub accept_type: bool,
}

impl DecisionQuestion {
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 || self.text.trim().is_empty() || self.text.len() > 16_384 {
            return Err(invalid("invalid typed question"));
        }
        if self.class == DecisionClass::Provenance {
            return Err(invalid("provenance is not model-decided"));
        }
        self.contract.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPin {
    pub rung: DecisionRung,
    pub model: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBand {
    pub low: f64,
    pub high: f64,
}

impl Default for DecisionBand {
    fn default() -> Self {
        Self {
            low: 0.35,
            high: 0.65,
        }
    }
}

impl DecisionBand {
    pub fn validate(self) -> Result<()> {
        if !self.low.is_finite()
            || !self.high.is_finite()
            || self.low < 0.0
            || self.high > 1.0
            || self.low >= self.high
        {
            return Err(invalid("invalid decision band"));
        }
        Ok(())
    }
    pub fn contains(self, probability: f64) -> bool {
        (self.low..=self.high).contains(&probability)
    }
}

/// Owner ceiling; a resident can select a cheaper rung but never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDial {
    pub first: DecisionRung,
    pub ceiling: DecisionRung,
    pub band: DecisionBand,
}

impl DecisionDial {
    pub fn narrow(self, resident: Self) -> Result<Self> {
        if resident.ceiling > self.ceiling
            || resident.first > resident.ceiling
            || resident.band != self.band
        {
            return Err(invalid("resident decision dial widens owner authority"));
        }
        resident.band.validate()?;
        Ok(resident)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    #[serde(with = "super::codec::entity")]
    pub question: EntityId,
    pub question_version: u32,
    #[serde(with = "super::codec::entity")]
    pub principal: EntityId,
    pub providers: Vec<ProviderPin>,
    pub band: DecisionBand,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    #[serde(with = "super::codec::entities")]
    pub evidence: Vec<EntityId>,
    pub in_band: bool,
    pub receipt: DecisionReceipt,
    /// Structured explanation code. Hosts render their own localized text.
    pub human_ask: Option<HumanAskReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanAskReason {
    Disagreement,
    Uncertain,
    ProviderUnavailable,
    OwnerSelected,
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
