//! The host's reads for a question head's paired held-out trial (FIX 3864,
//! ARCH-0076 tier 3).
//!
//! `Vault::open_question_head_trial` serves the run's sealed held-out rows,
//! counted. Each row is read once by the head, at its fitted temperature,
//! and twice by the typed question's current answerer: the host's ladder as
//! the graph path asks it (`ladder_decide`), at the question's own dial and
//! posture and never past the Big rung, so a trial queues no person ask and
//! sends unit text off the host only where the question's reads would. Every
//! read is a
//! reversible read. `Vault::record_question_head_trial` reduces the reads to
//! the trial's numbers. A read that fails or abstains is recorded as
//! missing, which leaves the trial unknown; it never fails the trial.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionRung, ProviderPin, Reversibility,
    TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::training_pack::{QuestionHeadTrial, QuestionTrialCase, QuestionTrialInput, SplitSide};
use oneiron::{EntityId, Error, HostingPrivacyPosture};
use serde::Deserialize;
use serde_json::Value;

use super::question_evaluation::calibration::yes_probability;
use super::question_serving::checkpoint_upload;
use crate::decision_graph::{LadderCall, ladder_decide, question_posture};
use crate::oneironer::QuestionHead;
use crate::server::SyncServer;

const ROW_FORMAT: &str = "oneiron.detector-target-row/1";
/// The longest one read of the current answerer may take.
const READ_BUDGET: Duration = Duration::from_secs(120);
/// The run label a read is recorded under.
const TRIAL_LABEL: &str = "question-head-trial";

fn invalid(detail: &str) -> Error {
    Error::InvalidConfig(format!("question head trial: {detail}"))
}

/// One held-out row, as the split wrote it.
#[derive(Deserialize)]
struct Row {
    format: String,
    row: String,
    split: SplitSide,
    source_family: String,
    label: Label,
    input: Value,
}

#[derive(Deserialize)]
struct Label {
    answer: Answer,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    No,
    Yes,
}

/// The held-out file's rows, each once, each with its source family.
fn held_out_rows(bytes: &[u8]) -> oneiron::Result<Vec<(Row, EntityId)>> {
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row: Row =
            serde_json::from_slice(line).map_err(|_| invalid("a held-out row is malformed"))?;
        let family = EntityId::from_hex(&row.source_family)
            .map_err(|_| invalid("a held-out row names no source family"))?;
        if row.format != ROW_FORMAT
            || row.split != SplitSide::HeldOut
            || row.row.trim().is_empty()
            || !ids.insert(row.row.clone())
        {
            return Err(invalid("a held-out row differs from its split"));
        }
        rows.push((row, family));
    }
    if rows.is_empty() {
        return Err(invalid("the run's held-out split is empty"));
    }
    Ok(rows)
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

/// A yes/no answer's P(yes); `None` for an abstain or any other answer.
fn yes(decision: &TypedDecision) -> Option<f64> {
    matches!(decision.answer, DecisionAnswer::Noul(_))
        .then_some(decision.probability)
        .flatten()
}

/// The pin of the rung that answered, as the graph path names it; `None`
/// for an abstain.
fn answering_pin(decision: &TypedDecision) -> Option<ProviderPin> {
    if decision.answer == DecisionAnswer::Abstain {
        return None;
    }
    let answered = decision.receipt.time.as_ref()?.answered?;
    decision
        .receipt
        .providers
        .iter()
        .rev()
        .find(|pin| pin.rung == answered)
        .cloned()
}

/// The reads one trial makes of the current answerer.
struct Incumbent<'a> {
    server: &'a SyncServer,
    input: &'a QuestionTrialInput,
    dial: DecisionDial,
    policy: DecisionBandPolicy,
    /// The question's posture where it is stricter than the vault's.
    posture: Option<HostingPrivacyPosture>,
}

impl Incumbent<'_> {
    /// One read of `state`; `None` when the ladder failed.
    fn read(&self, state: &Value) -> Option<TypedDecision> {
        let deadline = RetrievalDeadline::hard(Instant::now(), READ_BUDGET);
        ladder_decide(
            self.server,
            LadderCall {
                principal: self.input.principal,
                class: EdgeActorClass::Human,
                question: &self.input.question,
                evidence: &[],
                images: &[],
                audio: &[],
                state,
                dial: self.dial,
                policy: &self.policy,
                reversibility: Reversibility::ReversibleRead,
                deadline: &deadline,
                label: TRIAL_LABEL,
                ask_to: None,
                correlation: None,
                posture: self.posture,
            },
        )
        .inspect_err(|error| {
            tracing::warn!(%error, "a trial read of the current answerer failed");
        })
        .ok()
    }
}

/// The pin of every rung the host's decision ladder holds, in rung order:
/// the configured answerer a trial is paired with, which an evaluated bind
/// checks is still the one the host runs.
pub(crate) fn answerer_pins(server: &SyncServer) -> Vec<ProviderPin> {
    let ladder = server.decision_ladder();
    [
        &ladder.rule,
        &ladder.local,
        &ladder.system_one,
        &ladder.escalation,
        &ladder.big,
    ]
    .into_iter()
    .flatten()
    .map(|provider| provider.pin())
    .collect()
}

/// The owner's trial of question run `run`'s head against typed question
/// `question` at `question_version`: open, read every held-out row, record.
/// Answers the recorded trial.
///
/// # Errors
///
/// The engine's refusals to open or record it, a malformed held-out file, a
/// head that cannot load, or storage errors.
pub(crate) fn run_question_head_trial(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    run: &EntityId,
    question: EntityId,
    question_version: u32,
) -> oneiron::Result<QuestionHeadTrial> {
    let vault = server.vault();
    let input = vault.open_question_head_trial(
        owner,
        run,
        question,
        question_version,
        answerer_pins(server),
    )?;
    let rows = held_out_rows(&input.held_out_jsonl)?;
    let head = {
        let export = checkpoint_upload(vault, &input.checkpoint)?;
        let inputs: Vec<&Value> = rows.iter().map(|(row, _)| &row.input).collect();
        QuestionHead::load(&input.target, &export, &inputs)
            .map_err(|error| invalid(&format!("the head could not load: {error}")))?
    };
    let ceiling = input.dial.ceiling.min(DecisionRung::Big);
    let incumbent = Incumbent {
        server,
        input: &input,
        dial: DecisionDial {
            first: input.dial.first.min(ceiling),
            ceiling,
            band: input.dial.band,
        },
        policy: server.decision_host().bands(),
        posture: question_posture(server, input.posture),
    };
    let cases: Vec<QuestionTrialCase> = rows
        .iter()
        .map(|(row, family)| {
            let started = Instant::now();
            let head_yes = head
                .logits(&row.input)
                .ok()
                .map(|raw| yes_probability(raw, input.temperature))
                .filter(|yes| yes.is_finite());
            let head_ms = elapsed_ms(started);
            let started = Instant::now();
            let first = incumbent.read(&row.input);
            let incumbent_ms = elapsed_ms(started);
            let second = incumbent.read(&row.input);
            QuestionTrialCase {
                row: row.row.clone(),
                family: *family,
                label: matches!(row.label.answer, Answer::Yes),
                head: head_yes,
                head_ms,
                incumbent: first.as_ref().and_then(yes),
                retest: second.as_ref().and_then(yes),
                incumbent_ms,
                incumbent_pin: first.as_ref().and_then(answering_pin),
                incumbent_cost_per_thousand: first
                    .as_ref()
                    .and_then(|decision| decision.receipt.cost_per_thousand),
            }
        })
        .collect();
    vault.record_question_head_trial(run, &input.exposure.id, &cases)
}
