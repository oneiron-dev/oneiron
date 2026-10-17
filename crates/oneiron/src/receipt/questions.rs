//! OF-506's doors (ARCH-0076): the wire shapes of a one-off graph ask and of
//! the standing-question verbs.
//!
//! The engine's own types ride inside these requests unchanged: a
//! `DecisionQuestion` or a `QuestionDefinition` decodes through its own serde
//! (with its `deny_unknown_fields`) and is shown to a schema as any JSON
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
    AnswerRecord, GraphAskFailure, GraphAskReceipts, QuestionDefinition,
};
use crate::llm::decision::{DecisionQuestion, DecisionRung, TypedDecision};
use crate::memory::{MemoryError, MemoryResult};

/// The most graph units one ask names or selects: the engine's own bound on
/// a graph ask's selection.
pub const GRAPH_ASK_MAX_UNITS: usize = 4096;

/// One unit's clock when a graph ask names none: an `ai.verdict` call's
/// default, the clock the standing pump gives each unit too.
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
    /// Each unit's own clock on the ladder, 1 to 60000 milliseconds;
    /// [`GRAPH_ASK_UNIT_DEADLINE_MS`] when absent. It is per unit, not the
    /// ask's: an ask over n units can run up to n times this.
    #[serde(default)]
    pub unit_deadline_ms: Option<u64>,
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

/// A unit whose answerer declined through a full decision, with that
/// decision: its providers, clock and owner-ask reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphAskDeclined {
    pub unit: EntityId,
    pub decision: TypedDecision,
}

/// `vault.graph.ask`'s answer. Each answer is a proposed, receipt-bearing
/// claim private to the asker, waiting for Keep; none is kept on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// The engine's `QuestionDefinition`: `{question, adapter, units, recipe,
    /// profile, dial, activation, refresh, delivery, learning, binding?,
    /// criteria?, audience?, posture?, media?, deadline_ms?}`. `criteria` is
    /// `{yes_if_all, no_if_any, not_a_reason_to_say_no}`, each at most 16
    /// lines of 512 bytes; `audience` is `asker`; `posture` is `managed`,
    /// `relay` or `self-host` (absent: the vault's); `media` is `{images,
    /// audio}` (each absent: on); `deadline_ms` is each call's clock, 1 to
    /// 60000.
    /// `activation` must be `standing`. The engine mints `question.id` and
    /// sets `question.version` to 1 over what the request names. `dial`
    /// (`{first, ceiling, band}`) must sit inside the host's dial: first at
    /// or above the host's first rung, ceiling at most `big`, and the host's
    /// band.
    #[schemars(with = "serde_json::Value")]
    pub definition: QuestionDefinition,
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
    /// The whole new definition, as `vault.questions.create` takes it. The
    /// engine pins `question.id` to `id` and `question.version` to the next
    /// version.
    #[schemars(with = "serde_json::Value")]
    pub definition: QuestionDefinition,
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
