//! Immutable definitions and typed outcome bindings.

use super::super::types::invalid;
use super::super::{DecisionAnswer, DecisionDial, DecisionQuestion, TypedDecision};
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeSource {
    Claim { predicate: String },
    Edge { relation: String },
    Stage { campaign: String },
    Event { predicate: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutcomeBinding {
    pub source: OutcomeSource,
    /// Seconds after the prediction; earlier facts are not outcomes.
    pub horizon: u64,
    pub mapping: std::collections::BTreeMap<String, bool>,
    pub noise_weight: f64,
    /// Optional link relation from the answered unit to the outcome's unit.
    pub linked_by: Option<String>,
}
impl OutcomeBinding {
    pub fn validate(&self) -> Result<()> {
        if self.horizon == 0
            || self.mapping.is_empty()
            || self.mapping.len() > 64
            || !self.noise_weight.is_finite()
            || !(0.0..=1.0).contains(&self.noise_weight)
        {
            return Err(invalid("invalid outcome binding"));
        }
        let name = match &self.source {
            OutcomeSource::Claim { predicate } | OutcomeSource::Event { predicate } => predicate,
            OutcomeSource::Edge { relation } => relation,
            OutcomeSource::Stage { campaign } => campaign,
        };
        if name.is_empty()
            || name.len() > 256
            || name.contains('\0')
            || name.starts_with("judgment.")
            || self.mapping.keys().any(|s| s.len() > 4096)
        {
            return Err(invalid("invalid outcome source"));
        }
        if let OutcomeSource::Edge { relation } = &self.source
            && crate::edge::parse_relation(relation).is_none()
        {
            return Err(invalid("unknown outcome edge relation"));
        }
        if self
            .linked_by
            .as_deref()
            .is_some_and(|r| crate::edge::parse_relation(r).is_none())
        {
            return Err(invalid("unknown outcome unit relation"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionDefinition {
    pub question: DecisionQuestion,
    pub adapter: String,
    /// Units are a narrowing set, never a grant. Each read rechecks authority.
    #[serde(with = "super::super::codec::entities")]
    pub units: Vec<EntityId>,
    pub recipe: String,
    pub profile: String,
    pub dial: DecisionDial,
    pub refresh: RefreshPolicy,
    pub delivery: String,
    pub learning: bool,
    #[serde(default)]
    pub binding: Option<OutcomeBinding>,
}
impl QuestionDefinition {
    pub fn validate(&self) -> Result<()> {
        self.question.validate()?;
        self.dial.band.validate()?;
        if self.dial.first > self.dial.ceiling
            || self.units.len() > 4096
            || [&self.adapter, &self.recipe, &self.profile, &self.delivery]
                .iter()
                .any(|s| s.is_empty() || s.len() > 256)
            || self.refresh.every_seconds == Some(0)
        {
            return Err(invalid("invalid standing question definition"));
        }
        if let Some(binding) = &self.binding {
            binding.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshPolicy {
    pub on_arrival: bool,
    pub every_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionRecord {
    pub schema_version: u32,
    #[serde(with = "super::super::codec::entity")]
    pub principal: EntityId,
    pub definition: QuestionDefinition,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Arrival(EntityId),
    Schedule,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerRecord {
    #[serde(with = "super::super::codec::entity")]
    pub claim: EntityId,
    #[serde(with = "super::super::codec::entity")]
    pub unit: EntityId,
    pub decision: TypedDecision,
    /// Parent-computed hash of the exact source body read before provider work.
    pub frontier: [u8; 32],
    pub source_kind: u8,
    pub answered_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeLabel {
    #[serde(with = "super::super::codec::entity")]
    pub answer: EntityId,
    #[serde(with = "super::super::codec::entity")]
    pub fact: EntityId,
    /// Pins the measured outcome value; mutable facts cannot silently relabel history.
    pub fact_value_hash: [u8; 32],
    pub label: bool,
    pub noise_weight: f64,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPair {
    pub prediction: DecisionAnswer,
    pub probability: f64,
    pub outcome: OutcomeLabel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuestionHead {
    pub version: u32,
    pub paused: bool,
    pub last_refresh: Option<u64>,
}
