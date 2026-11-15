//! Moved from `crates/oneiron/src/receipt/questions.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::receipt::questions::standing_admit::QuestionAdmitRequest;
pub use crate::receipt::questions::standing_admit::QuestionPrepareRequest;
pub use crate::receipt::questions::standing_admit::QuestionPrepared;
pub use crate::receipt::questions::standing_admit::QuestionPreparedSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_store::model_decision::questions::CalibrationPair;
use oneiron_store::model_decision::questions::OutcomeLabel;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// `ai.verdict`'s clock, in milliseconds, when the request names none.
pub const AI_VERDICT_DEADLINE_MS: u64 = 10_000;

/// The shipped seed of the vault's question call budget
/// ([`crate::llm::decision::questions::records::QUESTION_CALL_BUDGET_MS`]): an
/// `ai.verdict` call's default.
pub const GRAPH_ASK_UNIT_DEADLINE_MS: u64 = AI_VERDICT_DEADLINE_MS;

/// A graph ask's type selection: the engine's by-type entry
/// (`select_graph_units_by_type`), under the caller's own scoped read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphAskSelection {
    /// The entity type, by its registry number.
    pub entity_type: u8,
    /// At most this many units, 1 or more.
    pub limit: usize,
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

/// Each declined unit beside its decision, in the engine's order.
pub fn declined_receipts(declined: Vec<(EntityId, TypedDecision)>) -> Vec<GraphAskDeclined> {
    declined
        .into_iter()
        .map(|(unit, decision)| GraphAskDeclined { unit, decision })
        .collect()
}

/// `vault.questions.pause`'s input: pause the caller's standing question,
/// or resume it with `paused: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionPauseRequest {
    pub id: EntityId,
    pub paused: bool,
}

/// `vault.questions.backfill`'s input: schedule the caller's standing
/// question's backfill. From `at` (now when absent) the question pump
/// answers, once, each covered unit with no answer at `expected_version`.
/// A later schedule replaces it and an edit retires it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionBackfillRequest {
    pub id: EntityId,
    /// The version to backfill; a stale one is refused.
    pub expected_version: u32,
    /// When the backfill falls due, in unix seconds.
    #[serde(default)]
    pub at: Option<u64>,
    /// An explicit recipe for a graph question: each unit and the exact
    /// sources its answer is shown, in place of the unit's neighbours
    /// (FIX 2383). Absent or empty: the default neighbourhood recipe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins: Vec<oneiron_store::model_decision::questions::GraphQuestionInput>,
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

/// `vault.questions.outcome_windows`'s input: the caller's standing question
/// whose closed outcome windows to read, across its versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionOutcomeWindowsRequest {
    pub id: EntityId,
}

/// `vault.questions.answers`'s input: the caller's standing question whose
/// answer receipts to read, across every version. Without a `cursor` the
/// answer is every one of them, as one bare list; a `cursor` opts into pages
/// (FIX 1585).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswersRequest {
    pub id: EntityId,
    /// Opts into pages: `""` reads the first page, and a page's `next_cursor`
    /// the page after it. The first page fixes what the read covers: every
    /// answer and ask committed by then, graph answers first, then artifact
    /// asks, each in commit order; later ones are not in it. The cursor is a
    /// position, not a grant: each page checks the question is the caller's
    /// again, and a cursor taken before a vault restore is refused. Absent or
    /// null: every answer, as one bare list, unpaged.
    #[serde(default)]
    pub cursor: Option<String>,
    /// With a `cursor`, at most this many entries on the page, counted across
    /// graph answers and artifact asks together; absent or 0, the whole rest.
    /// Without a `cursor` it is not read.
    #[serde(default)]
    pub page_size: Option<usize>,
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
pub mod standing_admit;
