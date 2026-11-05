//! Immutable definitions and typed outcome bindings.

use super::super::types::invalid;
use super::super::{
    DecisionAnswer, DecisionDial, DecisionQuestion, DecisionQuestionInput, DecisionRung,
    HostRuleRef, PairedReading, ProviderPin, TypedDecision,
};
use crate::learning_setting::SettingSpec;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

pub use super::criteria::{MAX_CRITERION_BYTES, QuestionCriteria};

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

/// A standing question's definition. Stored, its `question` is the
/// engine's [`DecisionQuestion`], under the id and version the engine
/// minted. As its author writes it ([`QuestionDefinitionInput`]), the
/// question names neither (FIX 1586); every other field is the same.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionDefinition<Q = DecisionQuestion> {
    pub question: Q,
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
    pub criteria: QuestionCriteria<String>,
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

/// A standing question's definition as `vault.questions.create` and `.edit`
/// take it: its question without the engine-owned id and version.
pub type QuestionDefinitionInput = QuestionDefinition<DecisionQuestionInput>;

impl QuestionDefinition<DecisionQuestionInput> {
    /// The stored definition: this one, its question under the `id` and
    /// `version` the engine minted, every other field as written. Its caller
    /// validates the result.
    #[must_use]
    pub fn with_identity(self, id: EntityId, version: u32) -> QuestionDefinition {
        QuestionDefinition {
            question: self.question.with_identity(id, version),
            adapter: self.adapter,
            units: self.units,
            recipe: self.recipe,
            profile: self.profile,
            dial: self.dial,
            activation: self.activation,
            refresh: self.refresh,
            delivery: self.delivery,
            learning: self.learning,
            binding: self.binding,
            criteria: self.criteria,
            audience: self.audience,
            posture: self.posture,
            media: self.media,
            deadline_ms: self.deadline_ms,
            artifacts: self.artifacts,
        }
    }
}

impl QuestionDefinition {
    /// A larger authored definition is not a malformed one: its unit count,
    /// criteria lines and mapping entries are no refusal (FIX 9915).
    pub fn validate(&self) -> Result<()> {
        self.question.validate()?;
        self.dial.band.validate()?;
        if self.dial.first > self.dial.ceiling
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

/// A caller's own clock, else the vault's owner or fitted question-budget
/// override, else `fallback` unchanged. This keeps a host's shipped clock
/// distinct from the question catalog's seed.
///
/// # Errors
///
/// Storage errors; an undecodable setting row.
pub fn question_call_budget_with_fallback(
    vault: &Vault,
    explicit: Option<std::time::Duration>,
    fallback: std::time::Duration,
) -> Result<std::time::Duration> {
    if let Some(explicit) = explicit {
        return Ok(explicit);
    }
    let txn = vault.store.env.read_txn()?;
    let override_ms = crate::learning_setting::setting_override_in_txn(
        &vault.store,
        &txn,
        &QUESTION_CALL_BUDGET_MS,
    )?;
    Ok(match override_ms {
        Some(ms) => std::time::Duration::from_millis(
            ms.round()
                .clamp(QUESTION_CALL_BUDGET_MS.min, QUESTION_CALL_BUDGET_MS.max) as u64,
        ),
        None => fallback,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionRecord {
    pub schema_version: u32,
    #[serde(with = "super::super::codec::entity")]
    pub principal: EntityId,
    pub definition: QuestionDefinition<DecisionQuestion>,
    pub created_at: u64,
    /// The class the principal authenticated as when it wrote this version
    /// (FIX 1588): every create and edit stores it from the writer, never
    /// from the principal's entity type. None on an internal one-off record,
    /// which keeps no authenticated asker.
    pub asker_class: Option<QuestionAskerClass>,
    /// The read lane the asker saved this version under, frozen (OF-506, FIX
    /// 1857): the engine mints it at each create and edit from the asker's
    /// own live lane, never from the definition, and every later read of the
    /// question rebuilds inside it ([`crate::claim::FrozenReadLane`]). An
    /// internal one-off record, and a question no caller's lane saved, keeps
    /// the principal's own.
    pub read_lane: crate::claim::FrozenReadLane,
}

/// An asker's authenticated actor class, as a question version keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionAskerClass {
    Human,
    Agent,
    System,
}

impl From<crate::EdgeActorClass> for QuestionAskerClass {
    fn from(class: crate::EdgeActorClass) -> Self {
        match class {
            crate::EdgeActorClass::Human => Self::Human,
            crate::EdgeActorClass::Agent => Self::Agent,
            crate::EdgeActorClass::System => Self::System,
        }
    }
}

impl From<QuestionAskerClass> for crate::EdgeActorClass {
    fn from(class: QuestionAskerClass) -> Self {
        match class {
            QuestionAskerClass::Human => Self::Human,
            QuestionAskerClass::Agent => Self::Agent,
            QuestionAskerClass::System => Self::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Arrival(EntityId),
    Schedule,
    Manual,
    /// A scheduled backfill: each covered unit with no answer at the
    /// question's current version, once.
    Backfill,
}

/// Provider output only. The engine owns the question, principal, evidence and version receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct AnswerProposal {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub providers: Vec<ProviderPin>,
    /// Paired readings the providers measured with this answer; none means none was taken.
    pub paired: Vec<PairedReading>,
    /// The host rule row the answer was read from, as id@revision (FIX 2974); none when no
    /// rule row answered.
    pub rule: Option<HostRuleRef>,
    /// Provider-reported cost at the answered rung, when known.
    pub cost_per_thousand: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnswerRecord {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub claim: EntityId,
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub unit: EntityId,
    pub decision: TypedDecision,
    /// Engine-computed hash of the live source row and its document frontier.
    pub frontier: [u8; 32],
    pub source_kind: u8,
    pub answered_at: u64,
    /// The readable neighbours this answer left out, each with why: it was
    /// answered using the sources compatible with its unit alone. Refs and
    /// reasons only, never a body; empty when none was left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<OmittedNeighbor>,
}

/// A standing question's scheduled backfill: from `due_at`, the question
/// pump answers each covered unit with no answer at `version`, once. With
/// `joins`, it answers each join whose unit has no answer at `version`,
/// shown the join's own evidence instead of the unit's neighbours (FIX 2383).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledBackfill {
    #[serde(with = "super::super::codec::entity")]
    pub question: EntityId,
    pub version: u32,
    pub due_at: u64,
    /// The explicit recipe: each unit and the exact sources its answer is
    /// shown. Empty: the default neighbourhood recipe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins: Vec<super::recipe::GraphQuestionInput>,
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

pub use crate::model_decision::questions::{
    CalibrationPair, OmittedNeighbor, OutcomeBinding, OutcomeLabel, OutcomeSource,
    OutcomeWindowClose, QuestionActivation, QuestionAudience, QuestionMedia, QuestionScheduleHead,
    RefreshPolicy, SourceConflict, WindowOutcome,
};
