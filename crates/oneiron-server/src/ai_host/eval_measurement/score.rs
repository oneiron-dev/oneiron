//! A leg's blind score: the replay judge's `response_score` question on the
//! task, the answer, the case's anchoring labels and the judge rubric, with
//! no model, arm or receipt named. It runs on the measurement's clock and
//! the judge's own ladder, policy and journal; only an answer at the band's
//! high mark with no person asked is a score. A state past the ladder's
//! bound is never cut and scored: it reads as cut evidence, unasked.

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::catalogue::SKILL_OPTIMIZE_JUDGMENT;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, MAX_DECISION_STATE_BYTES, Reversibility, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    EvalTaskInput, HeldOutReplayNotes, JudgeRubric, MeasurementUnavailable, SkillOptimizeDecisions,
};
use serde_json::{Value, json};

use crate::replay_judge::ServeReplayJudge;

/// The judge's wording key a leg is scored under: one response on its own
/// task, by the judge rubric.
const WORDING_KEY: &str = "response_score";
/// The question's kind beside the judge's revision.
const QUESTION_KIND: &str = "eval_measurement";

/// One leg's score, or why it has none.
pub(super) enum Scored {
    Score {
        value: f64,
        /// The judge that answered, `model@version`.
        judge: Option<String>,
    },
    Unavailable(MeasurementUnavailable),
}

/// A decided score: answered at the band's high mark with no person asked.
fn decided(decision: &TypedDecision) -> Option<f64> {
    match decision.answer {
        DecisionAnswer::Score(value)
            if decision.human_ask.is_none()
                && decision
                    .probability
                    .is_some_and(|p| p >= decision.receipt.band.high) =>
        {
            Some(value)
        }
        _ => None,
    }
}

/// The question's state: the task, the answer and the case's anchoring
/// labels, whole, and the judge rubric's text and pin when one is in force.
fn state(rubric: Option<&JudgeRubric>, task: &EvalTaskInput, prompt: &str, answer: &str) -> Value {
    let labels: Vec<Value> = task
        .labels
        .iter()
        .map(|label| json!({ "kind": label.kind, "value": label.value }))
        .collect();
    let mut state = json!({
        "task": prompt,
        "response": answer,
        "labels": labels,
    });
    if let Some(rubric) = rubric {
        state["judge_rubric"] = json!(rubric.text);
        state["judge_rubric_pin"] = json!({
            "skill": rubric.skill.to_hex(),
            "version": rubric.version,
            "digest": blake3::Hash::from(rubric.digest).to_hex().as_str(),
        });
    }
    state
}

/// Scores one leg's answer blind on the measurement's clock, and journals
/// the question with the rows the case was read from.
pub(super) fn score(
    vault: &Vault,
    judge: &'static ServeReplayJudge,
    clock: &RetrievalDeadline,
    rubric: Option<&JudgeRubric>,
    task: &EvalTaskInput,
    prompt: &str,
    answer: &str,
) -> oneiron::Result<Scored> {
    // Read whole; past its `[limits]` row it asks whether all is well.
    let _ = vault.measure_limit(
        EngineLimit::JudgeReplayTextBytes,
        u64::try_from(prompt.len().saturating_add(answer.len())).unwrap_or(u64::MAX),
    );
    let state = state(rubric, task, prompt, answer);
    if !serde_json::to_vec(&state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES) {
        return Ok(Scored::Unavailable(MeasurementUnavailable::CutEvidence));
    }
    let decisions = SkillOptimizeDecisions {
        deadline: clock,
        ..judge.decisions()
    };
    let Some(text) = decisions
        .wording
        .get(WORDING_KEY)
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(Scored::Unavailable(MeasurementUnavailable::NoScorer));
    };
    let question = SKILL_OPTIMIZE_JUDGMENT.question(
        &[judge.judge_revision().as_bytes(), QUESTION_KIND.as_bytes()],
        text.clone(),
        AnswerContract::Score { min: 0.0, max: 1.0 },
    )?;
    if clock.decision_time_left().is_zero() {
        return Ok(Scored::Unavailable(MeasurementUnavailable::ClockExhausted));
    }
    let decision = match decisions.ladder.run(
        &question,
        decisions.principal,
        &[],
        &state,
        decisions.dial,
        &decisions.bands,
        Reversibility::ReversibleRead,
        clock,
    ) {
        Ok(decision) => decision,
        Err(error) => {
            tracing::debug!(%error, "an eval measurement judgment did not run");
            return Ok(Scored::Unavailable(
                if clock.decision_time_left().is_zero() {
                    MeasurementUnavailable::ClockExhausted
                } else {
                    MeasurementUnavailable::NoScorer
                },
            ));
        }
    };
    // The rows the judgment read: the case's and its labels'. The answer is
    // no row of its own.
    judge.record_decision_sourced(&question, &decision, &state, task.source_rows.clone())?;
    Ok(match decided(&decision) {
        Some(value) => Scored::Score {
            value,
            judge: decision
                .receipt
                .providers
                .last()
                .map(|pin| format!("{}@{}", pin.model, pin.version)),
        },
        None => Scored::Unavailable(MeasurementUnavailable::NoScorer),
    })
}
