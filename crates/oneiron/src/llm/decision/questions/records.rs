//! Immutable definitions and typed outcome bindings.

use super::super::types::invalid;
use super::super::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionDial, DecisionQuestion, DecisionRung,
    PairedReading, ProviderPin, TypedDecision,
};
use crate::learning_setting::SettingSpec;
use crate::{EntityId, Result, Vault};
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
            && crate::edge::EdgeKind::from_name(relation).is_none()
        {
            return Err(invalid("unknown outcome edge relation"));
        }
        if self
            .linked_by
            .as_deref()
            .is_some_and(|r| crate::edge::EdgeKind::from_name(r).is_none())
        {
            return Err(invalid("unknown outcome unit relation"));
        }
        Ok(())
    }
}

/// The adapter of a standing question over artifact units, asked on each artifact's head
/// as it changes ([`QuestionDefinition::artifacts`]).
pub const ARTIFACT_ADAPTER: &str = "artifact";

/// One artifact a standing artifact question asks: the artifact its answers land in, and
/// which of its units are asked, as a `vault.artifacts.ask` names them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUnits {
    #[serde(with = "super::super::codec::entity")]
    pub artifact: EntityId,
    pub selection: crate::blob_artifact::ArtifactAskUnits,
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
    pub activation: QuestionActivation,
    pub refresh: RefreshPolicy,
    pub delivery: String,
    pub learning: bool,
    #[serde(default)]
    pub binding: Option<OutcomeBinding>,
    /// The lines each unit is judged by. They ride every call's state; the
    /// question's version versions them.
    #[serde(default)]
    pub criteria: QuestionCriteria,
    /// Who sees the answers.
    #[serde(default)]
    pub audience: QuestionAudience,
    /// Where the unit text may go. `None` holds the vault's own posture.
    #[serde(default)]
    pub posture: Option<crate::config::HostingPrivacyPosture>,
    /// The media each unit's answerer is handed beside its text.
    #[serde(default)]
    pub media: QuestionMedia,
    /// Each decision call's clock, in milliseconds, shared by every rung,
    /// offer and retry in it. `None` reads the vault's question call budget.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The artifacts an [`ARTIFACT_ADAPTER`] question asks, each named once, in place of
    /// `units`. Each read rechecks authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactUnits>,
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
            || self
                .deadline_ms
                .is_some_and(|ms| ms == 0 || ms > crate::memory::caps::MAX_RECALL_DEADLINE_MS)
        {
            return Err(invalid("invalid standing question definition"));
        }
        self.criteria.validate()?;
        if let Some(binding) = &self.binding {
            binding.validate()?;
        }
        self.validate_artifacts()
    }

    /// An artifact question asks artifacts alone, standing, below the person, with no
    /// outcome learning (its answers are proposals, not claims), and names each artifact
    /// once over a selection it can ask.
    fn validate_artifacts(&self) -> Result<()> {
        let artifact = self.adapter == ARTIFACT_ADAPTER;
        if artifact == self.artifacts.is_empty()
            || (artifact
                && (!self.units.is_empty()
                    || self.activation != QuestionActivation::Standing
                    || self.learning
                    || self.binding.is_some()
                    || self.dial.first == DecisionRung::Human
                    || self.question.contract.locates()))
        {
            return Err(invalid("invalid standing artifact question"));
        }
        let mut named = std::collections::BTreeSet::new();
        for units in &self.artifacts {
            if !named.insert(units.artifact) {
                return Err(invalid(
                    "a standing artifact question names an artifact twice",
                ));
            }
            super::artifact_refresh::validate_artifact_units(units)?;
        }
        Ok(())
    }

    /// One decision call's clock: the definition's own, or the vault's
    /// question call budget.
    pub fn deadline(&self, vault: &Vault) -> Result<std::time::Duration> {
        question_call_budget(vault, self.deadline_ms)
    }
}

/// The vault's question call budget (ARCH-0076): each decision call's clock,
/// in milliseconds, when neither the question nor the ask names one. It
/// ships at a graph ask's default, within the asks' own bounds.
pub const QUESTION_CALL_BUDGET_MS: SettingSpec = SettingSpec {
    key: "question_call_budget_ms",
    min: 1.0,
    max: crate::memory::caps::MAX_RECALL_DEADLINE_MS as f64,
    seed: crate::receipt::GRAPH_ASK_UNIT_DEADLINE_MS as f64,
};

/// One decision call's clock: `explicit` milliseconds when the question or
/// the ask names them, else the vault's [`QUESTION_CALL_BUDGET_MS`] row,
/// to the nearest millisecond.
pub fn question_call_budget(vault: &Vault, explicit: Option<u64>) -> Result<std::time::Duration> {
    let ms = match explicit {
        Some(ms) => ms,
        None => crate::learning_setting::setting_value(vault, &QUESTION_CALL_BUDGET_MS)?
            .round()
            .clamp(QUESTION_CALL_BUDGET_MS.min, QUESTION_CALL_BUDGET_MS.max) as u64,
    };
    Ok(std::time::Duration::from_millis(ms))
}

/// The most lines one criteria list holds.
pub const MAX_CRITERIA_LINES: usize = 16;
/// The most bytes one criteria line holds.
pub const MAX_CRITERION_BYTES: usize = 512;

/// A question's criteria (ARCH-0076 §3): every line a yes needs, any line
/// that makes a no, and the lines that are never a reason to say no. A
/// changed line is a new definition, so the question's version versions the
/// triple. Each provider maps it for its rung; it reads as `criteria` in the
/// call's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionCriteria {
    pub yes_if_all: Vec<String>,
    pub no_if_any: Vec<String>,
    pub not_a_reason_to_say_no: Vec<String>,
}
impl QuestionCriteria {
    /// No line in any of the three lists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.yes_if_all.is_empty()
            && self.no_if_any.is_empty()
            && self.not_a_reason_to_say_no.is_empty()
    }

    /// The triple a call's state carries as `criteria`. A `criteria` that is
    /// not a valid nonempty triple is the caller's own state, no rubric.
    #[must_use]
    pub fn from_state(state: &serde_json::Value) -> Option<Self> {
        let criteria = Self::deserialize(state.get("criteria")?).ok()?;
        (criteria.validate().is_ok() && !criteria.is_empty()).then_some(criteria)
    }

    /// The criteria of `call`'s question when it is a yes/no: the triple
    /// says what a yes and a no mean, so another contract reads it as state.
    #[must_use]
    pub fn for_call(call: &DecisionCall<'_>) -> Option<Self> {
        matches!(call.question.contract, AnswerContract::Noul)
            .then(|| Self::from_state(call.state))
            .flatten()
    }

    /// What a yes means, for a rung that describes each answer: every line a
    /// yes needs holds and no line that makes a no does.
    #[must_use]
    pub fn yes_means(&self) -> String {
        self.describe(
            "Every one of these holds: ",
            &self.yes_if_all,
            "None of these holds: ",
        )
    }

    /// What a no means: a line a yes needs fails, or a line that makes a no
    /// holds.
    #[must_use]
    pub fn no_means(&self) -> String {
        self.describe(
            "One of these fails: ",
            &self.yes_if_all,
            "One of these holds: ",
        )
    }

    fn describe(&self, needs: &str, yes: &[String], vetoes: &str) -> String {
        let mut parts = Vec::with_capacity(3);
        if !yes.is_empty() {
            parts.push(format!("{needs}{}.", yes.join("; ")));
        }
        if !self.no_if_any.is_empty() {
            parts.push(format!("{vetoes}{}.", self.no_if_any.join("; ")));
        }
        if !self.not_a_reason_to_say_no.is_empty() {
            parts.push(format!(
                "Never a no on its own: {}.",
                self.not_a_reason_to_say_no.join("; ")
            ));
        }
        parts.join(" ")
    }

    /// The triple as a rubric for a rung that reads prose, every line in
    /// order.
    #[must_use]
    pub fn rubric(&self) -> String {
        let mut rubric = String::from("Criteria:");
        for (head, lines) in [
            ("Yes only if all of these hold:", &self.yes_if_all),
            ("No if any of these holds:", &self.no_if_any),
            ("Not a reason to say no:", &self.not_a_reason_to_say_no),
        ] {
            if lines.is_empty() {
                continue;
            }
            rubric.push('\n');
            rubric.push_str(head);
            for line in lines {
                rubric.push_str("\n- ");
                rubric.push_str(line);
            }
        }
        rubric
    }

    /// At most [`MAX_CRITERIA_LINES`] lines a list, each a nonempty line of
    /// at most [`MAX_CRITERION_BYTES`].
    pub fn validate(&self) -> Result<()> {
        for lines in [
            &self.yes_if_all,
            &self.no_if_any,
            &self.not_a_reason_to_say_no,
        ] {
            if lines.len() > MAX_CRITERIA_LINES
                || lines.iter().any(|line| {
                    line.trim().is_empty()
                        || line.len() > MAX_CRITERION_BYTES
                        || line.contains('\0')
                })
            {
                return Err(invalid("invalid question criteria"));
            }
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

/// Provider output only. The engine owns the question, principal, evidence and version receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct AnswerProposal {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub providers: Vec<ProviderPin>,
    /// Paired readings the providers measured with this answer; none means none was taken.
    pub paired: Vec<PairedReading>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerRecord {
    #[serde(with = "super::super::codec::entity")]
    pub claim: EntityId,
    #[serde(with = "super::super::codec::entity")]
    pub unit: EntityId,
    pub decision: TypedDecision,
    /// Engine-computed hash of the live source row and its document frontier.
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
    /// The rows the reader derived the pair from. A retained copy of it is
    /// released again only while each of them may leave.
    #[serde(skip)]
    pub derived_from: Vec<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuestionHead {
    pub version: u32,
    pub paused: bool,
    pub last_refresh: Option<u64>,
    /// A failed refresh holds the question's work until then.
    pub retry_at: Option<u64>,
}
