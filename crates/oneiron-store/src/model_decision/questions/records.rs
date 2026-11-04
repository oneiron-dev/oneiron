//! Standing-question outcome, refresh, and evidence values.

use crate::model_decision::{DecisionAnswer, invalid};
use oneiron_contracts::{EntityId, Result};
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
    /// A binding with every mapping entry its author wrote: their count is
    /// no refusal (FIX 9915).
    pub fn validate(&self) -> Result<()> {
        if self.horizon == 0
            || self.mapping.is_empty()
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
            && oneiron_base::edge::EdgeKind::from_name(relation).is_none()
        {
            return Err(invalid("unknown outcome edge relation"));
        }
        if self
            .linked_by
            .as_deref()
            .is_some_and(|r| oneiron_base::edge::EdgeKind::from_name(r).is_none())
        {
            return Err(invalid("unknown outcome unit relation"));
        }
        Ok(())
    }
}

/// Who sees a question's answers. Only the asker is built: every answer
/// lands private to the question's principal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionAudience {
    #[default]
    Asker,
}

/// The media a unit's answerer is handed beside its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QuestionMedia {
    /// The images the unit's ASSET sources hold, read under the principal,
    /// for an answerer that reads images.
    pub images: bool,
    /// The audio clips the unit's ASSET sources hold, read under the
    /// principal, for an answerer that hears audio; heard as audio, never as
    /// a transcript.
    pub audio: bool,
}
impl Default for QuestionMedia {
    fn default() -> Self {
        Self {
            images: true,
            audio: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionActivation {
    OneOff,
    Standing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshPolicy {
    pub on_arrival: bool,
    pub every_seconds: Option<u64>,
}

/// A readable neighbour a graph answer left out (FIX 1711): its ref and the
/// term it could not share with the unit and the neighbours kept before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmittedNeighbor {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    pub reason: SourceConflict,
}

/// Why a source cannot share one answer with the sources before it. An
/// answer has one facet, project and world, one relationship, one value per
/// claim scope term and one asker, and rests only on sources with a single
/// position and a representable scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceConflict {
    Facet,
    Project,
    World,
    Relationship,
    ScopeTerm,
    Principal,
    Unrepresentable,
}

impl SourceConflict {
    /// The refusal of a write that must rest on every source it names.
    pub fn error(self) -> oneiron_contracts::Error {
        match self {
            Self::Principal => invalid("incompatible evidence principal"),
            Self::Unrepresentable => invalid("unrepresentable evidence scope"),
            Self::Facet | Self::Project | Self::World | Self::Relationship | Self::ScopeTerm => {
                invalid("incompatible evidence scope")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutcomeLabel {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub answer: EntityId,
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub fact: EntityId,
    /// Pins the measured outcome value; mutable facts cannot silently relabel history.
    pub fact_value_hash: [u8; 32],
    pub label: bool,
    pub noise_weight: f64,
    pub occurred_at: u64,
}

/// How a bound answer's outcome window closed (OF-516).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WindowOutcome {
    /// An admissible fact had labelled the answer by the close.
    Observed,
    /// No fact had, and the binding maps silence to this label.
    Silence(bool),
    /// No fact had and the binding maps no silence, or the answer no longer
    /// stands: nothing is learned from it.
    Unknown,
}

/// One answer's closed outcome window, written once by the question pump
/// the first second after `ends_at`. A fact in the window that lands later
/// still labels the answer and outranks a silence label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutcomeWindowClose {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub answer: EntityId,
    pub question_version: u32,
    /// The window's last second: the answer's `answered_at` plus the horizon.
    pub ends_at: u64,
    pub closed_at: u64,
    pub outcome: WindowOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPair {
    pub prediction: DecisionAnswer,
    pub probability: f64,
    pub outcome: OutcomeLabel,
    /// The rows the reader derived the pair from. A retained copy of it is
    /// released again only while each of them may leave.
    #[serde(skip)]
    pub derived_from: Vec<EntityId>,
}

/// A standing question's scheduling head, as its principal reads it: the
/// current version, whether its schedule is paused, when it last refreshed
/// and the hold a failed refresh left, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionScheduleHead {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    pub version: u32,
    pub paused: bool,
    pub last_refresh: Option<u64>,
    pub retry_at: Option<u64>,
}
