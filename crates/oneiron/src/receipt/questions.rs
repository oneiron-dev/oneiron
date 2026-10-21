//! OF-506's doors (ARCH-0076): the wire shapes of a one-off graph ask and of
//! the standing-question verbs.
//!
//! The engine's own types ride inside these requests unchanged: a
//! `DecisionQuestion` or a `QuestionDefinitionInput` decodes through its own
//! serde (with its `deny_unknown_fields`) and is shown to a schema as any JSON
//! value. No principal, actor or clock is a field here: the server's door
//! takes the asker from the credential and the time from its own clock.
//!
//! A graph ask's success and failure both come back as a
//! [`GraphAskOutcome`]: a failed unit never hides the answers the units
//! before it already committed.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::decision::questions::{
    AnswerRecord, ArtifactAskRecord, CalibrationPair, GraphAskFailure, GraphAskReceipts,
    OutcomeLabel, QuestionCriteria, QuestionDefinitionInput,
};
use crate::llm::decision::{DecisionQuestion, DecisionRung, TypedDecision};
use crate::memory::{MemoryError, MemoryResult};

/// The most graph units one ask names or selects: the engine's own bound on
/// a graph ask's selection.
pub const GRAPH_ASK_MAX_UNITS: usize = 4096;

/// The shipped seed of the vault's question call budget
/// ([`crate::llm::decision::questions::QUESTION_CALL_BUDGET_MS`]): an
/// `ai.verdict` call's default.
pub const GRAPH_ASK_UNIT_DEADLINE_MS: u64 = crate::task_verb::sdk::AI_VERDICT_DEADLINE_MS;

/// `vault.graph.ask`'s input: one typed question over graph units, through
/// the host's decision ladder, asked for the caller. Name the units, or a
/// type selection the caller can read; not both.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphAskRequest {
    /// The typed question, the engine's `DecisionQuestion`:
    /// `{id, version, text, class, contract, accept_type}`. `id` (32 hex) and
    /// `version` (1 or more) name it on every receipt; `text` is 1 to 16384
    /// bytes; `class` is one of `retrieval`, `contradiction`, `triage`,
    /// `judgment`, `useful_upstream` or `preference`; `contract` is
    /// `{"kind":"noul"}`, `{"kind":"choice","options":[..]}`,
    /// `{"kind":"score","min":..,"max":..}` or `{"kind":"box"}`.
    #[schemars(with = "serde_json::Value")]
    pub question: DecisionQuestion,
    /// The graph units asked about: distinct, at most
    /// [`GRAPH_ASK_MAX_UNITS`]. Each is read under the caller's own scoped
    /// read; a unit it cannot read is passed over as a missing one is, and
    /// appears nowhere in the answer.
    #[serde(default)]
    pub units: Vec<EntityId>,
    /// Instead of `units`: the caller's readable live units of one entity
    /// type, up to `limit`.
    #[serde(default)]
    pub select: Option<GraphAskSelection>,
    /// The highest rung that may answer; `big` when absent. A graph answer
    /// never queues an owner ask, so `human` is refused.
    #[serde(default)]
    pub ceiling: Option<DecisionRung>,
    /// Each unit's own clock on the ladder, 1 to 60000 milliseconds; the
    /// vault's question call budget when absent. It is per unit, not the
    /// ask's: an ask over n units can run up to n times this.
    #[serde(default)]
    pub unit_deadline_ms: Option<u64>,
    /// Where this ask's unit text may go: `managed`, `relay` or `self-host`;
    /// the vault's own posture when absent. It only narrows, as a standing
    /// question's `posture` does: one stricter than the vault's answers
    /// without the rungs that send unit text off the host where it forbids
    /// that, and one as loose as the vault's or looser asks under the
    /// vault's.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub posture: Option<crate::config::HostingPrivacyPosture>,
    /// The lines each unit is judged by, as a standing question's
    /// `criteria`: `{yes_if_all, no_if_any, not_a_reason_to_say_no}`, each
    /// at most 16 nonempty lines of at most 512 bytes. A yes/no question's
    /// rungs read them as its rubric; another contract's call carries them
    /// in its state. None when absent.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub criteria: Option<QuestionCriteria>,
}

/// A graph ask's type selection: the engine's by-type entry
/// (`select_graph_units_by_type`), under the caller's own scoped read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphAskSelection {
    /// The entity type, by its registry number.
    pub entity_type: u8,
    /// At most this many units, 1 to [`GRAPH_ASK_MAX_UNITS`].
    pub limit: usize,
}

impl GraphAskRequest {
    /// The ask's bounds, checked before any model work: the per-unit clock,
    /// the ceiling, one selection of at most [`GRAPH_ASK_MAX_UNITS`]
    /// distinct units, and the question itself.
    pub fn validate(&self) -> MemoryResult<()> {
        crate::memory::caps::check_deadline_ms(self.unit_deadline_ms)?;
        if self.ceiling == Some(DecisionRung::Human) {
            return Err(MemoryError::bad_request_with(
                "vault.graph.ask never queues an owner ask",
                &["Name a ceiling below human; big is the highest a graph answer climbs."],
            ));
        }
        match (&self.select, self.units.is_empty()) {
            (Some(_), false) => {
                return Err(MemoryError::bad_request_with(
                    "vault.graph.ask takes units or a type selection, not both",
                    &["Send either units or select."],
                ));
            }
            (None, true) => {
                return Err(MemoryError::bad_request_with(
                    "vault.graph.ask names no units",
                    &["Send units, or select a type with a limit."],
                ));
            }
            _ => {}
        }
        if self.units.len() > GRAPH_ASK_MAX_UNITS {
            return Err(MemoryError::bad_request_with(
                format!("vault.graph.ask names more than {GRAPH_ASK_MAX_UNITS} units"),
                &["Ask over fewer units at once."],
            ));
        }
        let mut seen = HashSet::with_capacity(self.units.len());
        if !self.units.iter().all(|unit| seen.insert(*unit)) {
            return Err(MemoryError::bad_request_with(
                "vault.graph.ask names a unit twice",
                &["Name each unit once."],
            ));
        }
        if let Some(select) = self.select
            && (select.limit == 0 || select.limit > GRAPH_ASK_MAX_UNITS)
        {
            return Err(MemoryError::bad_request_with(
                format!("select.limit must be between 1 and {GRAPH_ASK_MAX_UNITS}"),
                &["Select fewer units at once."],
            ));
        }
        if self
            .criteria
            .as_ref()
            .is_some_and(|criteria| criteria.validate().is_err())
        {
            return Err(MemoryError::bad_request_with(
                "the criteria are not valid",
                &["Give each list at most 16 nonempty lines of at most 512 bytes."],
            ));
        }
        self.question.validate().map_err(|_| {
            MemoryError::bad_request_with(
                "the question is not a valid typed question",
                &[
                    "Give it a version of 1 or more, 1 to 16384 bytes of text, a class other than provenance and a valid contract.",
                ],
            )
        })
    }
}

/// `vault.graph.admit`'s input: one graph unit and the provider
/// measurement the caller already holds for it, admitted in place of the
/// host ladder's. `decision` is the engine's `TypedDecision`: its receipt
/// must name `question` at its version, the caller as its principal and
/// only the providers that measured it. The engine validates the whole
/// decision — its provider-bound paired and person readings included —
/// against the unit's sources again in the write that lands it, so a
/// measurement no listed provider took, a duplicate provider, a reading
/// of the answered question itself, a zero version or an out-of-range
/// probability is refused before any claim is minted. The receipt's
/// evidence and evidence versions are the engine's own pins of the
/// sources it re-reads; a missing paired reading stays missing, never a
/// fabricated zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphAdmitRequest {
    /// The typed question, as `vault.graph.ask` takes it.
    pub question: DecisionQuestion,
    /// The one graph unit the measurement answers, read under the
    /// caller's own scoped read; a unit it cannot read is passed over as
    /// a missing one is, as in `vault.graph.ask`.
    pub unit: EntityId,
    /// The provider measurement to admit for `unit`.
    pub decision: TypedDecision,
}

impl GraphAdmitRequest {
    /// The admission's own bounds, checked before the unit is read: the
    /// question itself, and a decision that names it at its version. The
    /// rest of the decision — principal, contract, probability, providers
    /// and their bound readings — is the engine's graph-ask validation,
    /// run by the door over the caller's principal.
    pub fn validate(&self) -> MemoryResult<()> {
        self.question.validate().map_err(|_| {
            MemoryError::bad_request_with(
                "the question is not a valid typed question",
                &[
                    "Give it a version of 1 or more, 1 to 16384 bytes of text, a class other than provenance and a valid contract.",
                ],
            )
        })?;
        if self.decision.receipt.question != self.question.id
            || self.decision.receipt.question_version != self.question.version
        {
            return Err(MemoryError::bad_request_with(
                "the admitted decision does not name the question at its version",
                &["Name the question and its version on the decision receipt."],
            ));
        }
        Ok(())
    }
}

/// A unit whose answerer declined through a full decision, with that
/// decision: its providers, clock and owner-ask reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphAskDeclined {
    pub unit: EntityId,
    pub decision: TypedDecision,
}

/// `vault.graph.ask`'s answer. Each answer is a proposed, receipt-bearing
/// claim private to the asker, waiting for Keep; none is kept on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GraphAskOutcome {
    /// Every readable unit ran.
    Done {
        answers: Vec<AnswerRecord>,
        /// Readable units with missing input or an abstaining answerer.
        abstained: Vec<EntityId>,
        /// Each abstained unit whose answerer declined through a full
        /// decision, in `abstained` order.
        declined: Vec<GraphAskDeclined>,
    },
    /// A unit failed and the ask stopped there. The answers and abstentions
    /// before it are already committed and stand. The declined receipts
    /// before it are not carried: the engine drops them on a failure.
    Failed {
        /// The unit that failed; none when the ask failed before any unit.
        failed_unit: Option<EntityId>,
        /// The failure's `MEMORY_CODE_*` code.
        code: String,
        message: String,
        answers: Vec<AnswerRecord>,
        abstained: Vec<EntityId>,
    },
}

impl From<GraphAskReceipts> for GraphAskOutcome {
    fn from(receipts: GraphAskReceipts) -> Self {
        Self::Done {
            answers: receipts.result.answers,
            abstained: receipts.result.abstained,
            declined: receipts
                .declined
                .into_iter()
                .map(|(unit, decision)| GraphAskDeclined { unit, decision })
                .collect(),
        }
    }
}

impl GraphAskOutcome {
    /// A failed run's outcome. A run that failed before any unit committed
    /// nothing, so it is the plain error; any other names the failed unit
    /// beside what had already committed.
    pub fn from_failure(failure: GraphAskFailure) -> MemoryResult<Self> {
        let error = MemoryError::from(*failure.error);
        let completed = failure.completed;
        if failure.failed_unit.is_none()
            && completed.answers.is_empty()
            && completed.abstained.is_empty()
        {
            return Err(error);
        }
        Ok(Self::Failed {
            failed_unit: failure.failed_unit,
            code: error.code,
            message: error.message,
            answers: completed.answers,
            abstained: completed.abstained,
        })
    }
}

/// `vault.questions.create`'s input: a standing question's whole record,
/// kept by the caller's agent and served by the host's pump.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCreateRequest {
    /// The engine's `QuestionDefinitionInput`: `{question, adapter, units,
    /// recipe, profile, dial, activation, refresh, delivery, learning,
    /// binding?, criteria?, audience?, posture?, media?, deadline_ms?}`.
    /// `question` is `{text, class, contract, accept_type}`, with no `id` or
    /// `version`: the engine owns both and refuses either. `criteria` is
    /// `{yes_if_all, no_if_any, not_a_reason_to_say_no}`, each at most 16
    /// lines of 512 bytes; `audience` is `asker`; `posture` is `managed`,
    /// `relay` or `self-host` (absent: the vault's); `media` is `{images,
    /// audio}` (each absent: on); `deadline_ms` is each call's clock, 1 to
    /// 60000.
    /// `activation` must be `standing`. The engine mints the question's id
    /// and sets its version to 1. `dial` (`{first, ceiling, band}`) must sit
    /// inside the host's dial: first at or above the host's first rung,
    /// ceiling at most `big`, and a valid band inside the host's band
    /// (`host.low <= low < high <= host.high`).
    #[schemars(with = "serde_json::Value")]
    pub definition: QuestionDefinitionInput,
}

/// `vault.questions.edit`'s input: a whole replacement definition, minting
/// the question's next version.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionEditRequest {
    /// The caller's standing question.
    pub id: EntityId,
    /// The version this edit replaces; a stale one is refused.
    pub expected_version: u32,
    /// The whole new definition, as `vault.questions.create` takes it, its
    /// question without an id or version. The engine pins the question's id
    /// to `id` and its version to the next version.
    #[schemars(with = "serde_json::Value")]
    pub definition: QuestionDefinitionInput,
}

/// `vault.questions.pause`'s input: pause the caller's standing question,
/// or resume it with `paused: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionPauseRequest {
    pub id: EntityId,
    pub paused: bool,
}

/// `vault.questions.pause`'s answer: the question and the state it now has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionPaused {
    pub id: EntityId,
    pub paused: bool,
}

/// `vault.questions.backfill`'s input: schedule the caller's standing
/// question's backfill. From `at` (now when absent) the question pump
/// answers, once, each covered unit with no answer at `expected_version`.
/// A later schedule replaces it and an edit retires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionBackfillRequest {
    pub id: EntityId,
    /// The version to backfill; a stale one is refused.
    pub expected_version: u32,
    /// When the backfill falls due, in unix seconds.
    #[serde(default)]
    pub at: Option<u64>,
}

/// `vault.questions.read`'s input: one of the caller's standing questions,
/// at its current version or a past one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionReadRequest {
    pub id: EntityId,
    /// A past version; the current one when absent.
    #[serde(default)]
    pub version: Option<u32>,
}

/// `vault.questions.answers`'s input: the caller's standing question whose
/// answer receipts to read, across every version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswersRequest {
    pub id: EntityId,
}

/// `vault.questions.refresh`'s input: the caller's standing question to
/// refresh by hand, now, over every unit its current version covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionRefreshRequest {
    pub id: EntityId,
}

/// `vault.questions.outcomes`'s input: the caller's standing question whose
/// bound outcome labels and calibration pairs to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionOutcomesRequest {
    pub id: EntityId,
}

/// `vault.questions.outcomes`'s answer: every stored outcome label of the
/// question, each naming its answer and fact with the mapped label, noise
/// weight, fact-value hash and time, and each calibration pair the current
/// facts still support, pairing the answer's prediction and probability
/// with its label. A silent closed window appears only as a pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QuestionOutcomes {
    pub labels: Vec<OutcomeLabel>,
    pub calibration: Vec<CalibrationPair>,
}

/// `vault.questions.outcomes.project`'s input: the caller's standing
/// question whose bound outcomes to project over the vault's current facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionOutcomesProjectRequest {
    pub id: EntityId,
}

/// `vault.questions.outcomes.project`'s answer: the question and how many
/// labels this projection newly bound. The projection is idempotent over a
/// fact's identity, so replaying it binds none again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QuestionOutcomesProjected {
    pub id: EntityId,
    pub projected: usize,
}

/// `vault.questions.schedule`'s input: the caller's standing question whose
/// scheduling head to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionScheduleRequest {
    pub id: EntityId,
}

/// One entry of `vault.questions.answers`, tagged by `kind`: a graph
/// question's answer receipt, or a standing artifact question's last ask of
/// one artifact, whose answers wait as a proposal for Keep
/// (`vault.artifacts.keep` / `vault.artifacts.discard`) rather than as
/// claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuestionAnswer {
    Graph(AnswerRecord),
    Artifact(ArtifactAskRecord),
}

impl QuestionAnswer {
    /// The answers door's one shape: every graph answer receipt in the
    /// engine's order, then every artifact ask in artifact order.
    #[must_use]
    pub fn union(graph: Vec<AnswerRecord>, asks: Vec<ArtifactAskRecord>) -> Vec<Self> {
        graph
            .into_iter()
            .map(Self::Graph)
            .chain(asks.into_iter().map(Self::Artifact))
            .collect()
    }
}
