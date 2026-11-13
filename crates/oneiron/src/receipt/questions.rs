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

mod standing_admit;
pub use standing_admit::{
    QuestionAdmitRequest, QuestionPrepareRequest, QuestionPrepared, QuestionPreparedSource,
};

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::decision::TypedDecision;
use crate::llm::decision::questions::{
    AnswerRecord, ArtifactAskRecord, GraphAskFailure, GraphAskReceipts, QuestionCriteria,
    QuestionDefinitionInput,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_decision::questions::{CalibrationPair, OutcomeLabel};
use crate::model_decision::{DecisionQuestion, DecisionRung};

#[doc(hidden)]
use oneiron_verb_wire::receipt::questions::declined_receipts;
#[doc(hidden)]
pub use oneiron_verb_wire::receipt::questions::{
    AI_VERDICT_DEADLINE_MS, GRAPH_ASK_UNIT_DEADLINE_MS, GraphAdmitRequest, GraphAskDeclined,
    GraphAskSelection, QuestionAnswersRequest, QuestionBackfillRequest,
    QuestionOutcomeWindowsRequest, QuestionOutcomes, QuestionOutcomesProjectRequest,
    QuestionOutcomesProjected, QuestionOutcomesRequest, QuestionPauseRequest, QuestionReadRequest,
    QuestionRefreshRequest, QuestionScheduleRequest,
};

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
    /// The graph units asked about: distinct, as many as the caller names
    /// (Rule 5). Each is read under the caller's own scoped
    /// read; a unit it cannot read is passed over as a missing one is, and
    /// appears nowhere in the answer.
    #[serde(default)]
    pub units: Vec<EntityId>,
    /// Instead of `units`: the caller's readable live units of one entity
    /// type, up to `limit`.
    #[serde(default)]
    pub select: Option<GraphAskSelection>,
    /// The highest rung that may answer; `big` when absent. `human` asks the
    /// next authorised role for a unit no model rung settles: the caller as
    /// the responsible actor, climbing to the vault's owners (OF-506).
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
    /// a list of nonempty lines of at most 512 bytes. A yes/no question's
    /// rungs read them as its rubric; another contract's call carries them
    /// in its state. None when absent.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub criteria: Option<QuestionCriteria<String>>,
}

impl GraphAskRequest {
    /// The ask's bounds, checked before any model work: the per-unit clock,
    /// one selection of distinct units, and the question itself. A ceiling
    /// of human asks the next authorised role (OF-506), never stops at big.
    pub fn validate(&self) -> MemoryResult<()> {
        crate::request_limits::check_deadline_ms(self.unit_deadline_ms)?;
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
        let mut seen = HashSet::with_capacity(self.units.len());
        if !self.units.iter().all(|unit| seen.insert(*unit)) {
            return Err(MemoryError::bad_request_with(
                "vault.graph.ask names a unit twice",
                &["Name each unit once."],
            ));
        }
        if let Some(select) = self.select
            && select.limit == 0
        {
            return Err(MemoryError::bad_request_with(
                "select.limit must be at least 1",
                &["Select one unit or more."],
            ));
        }
        if self
            .criteria
            .as_ref()
            .is_some_and(|criteria| criteria.validate().is_err())
        {
            return Err(MemoryError::bad_request_with(
                "the criteria are not valid",
                &["Give each list nonempty lines of at most 512 bytes."],
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
    /// before it are already committed and stand, and each declined receipt
    /// before it is carried as `Done` carries it (FIX 1582).
    Failed {
        /// The unit that failed; none when the ask failed before any unit.
        failed_unit: Option<EntityId>,
        /// The failure's `MEMORY_CODE_*` code.
        code: String,
        message: String,
        answers: Vec<AnswerRecord>,
        abstained: Vec<EntityId>,
        /// Each abstained unit before the failure whose answerer declined
        /// through a full decision, in `abstained` order.
        declined: Vec<GraphAskDeclined>,
    },
}

impl From<GraphAskReceipts> for GraphAskOutcome {
    fn from(receipts: GraphAskReceipts) -> Self {
        Self::Done {
            answers: receipts.result.answers,
            abstained: receipts.result.abstained,
            declined: declined_receipts(receipts.declined),
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
            && failure.declined.is_empty()
        {
            return Err(error);
        }
        Ok(Self::Failed {
            failed_unit: failure.failed_unit,
            code: error.code,
            message: error.message,
            answers: completed.answers,
            abstained: completed.abstained,
            declined: declined_receipts(failure.declined),
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
    /// `{yes_if_all, no_if_any, not_a_reason_to_say_no}`, each a list of
    /// lines of at most 512 bytes; `audience` is `asker`; `posture` is `managed`,
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

/// `vault.questions.pause`'s answer: the question and the state it now has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionPaused {
    pub id: EntityId,
    pub paused: bool,
}

/// One entry of `vault.questions.answers`, tagged by `kind`: a graph
/// question's answer receipt, or one ask a standing artifact question made of
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
    /// engine's order, then every artifact ask in the order
    /// [`crate::llm::decision::questions::artifact_ask_records`] lists them.
    #[must_use]
    pub fn union(graph: Vec<AnswerRecord>, asks: Vec<ArtifactAskRecord>) -> Vec<Self> {
        graph
            .into_iter()
            .map(Self::Graph)
            .chain(asks.into_iter().map(Self::Artifact))
            .collect()
    }
}

/// `vault.questions.answers`'s answer: without a cursor, every answer as one
/// bare list ([`QuestionAnswer::union`]); with one, a page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QuestionAnswersReply {
    All(Vec<QuestionAnswer>),
    Page(QuestionAnswersPage),
}

/// One page of `vault.questions.answers`: its entries, graph answers before
/// artifact asks, each in commit order, and the cursor of the page after it,
/// none on the last.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswersPage {
    pub answers: Vec<QuestionAnswer>,
    pub next_cursor: Option<String>,
}
