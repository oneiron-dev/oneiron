//! The seat pick as typed decisions through the host's ladder, and the note seam beside it.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{SeatCandidate, SeatTask, invalid};
use crate::llm::decision::catalogue::SEAT_PICK;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionQuestion, HeldLadder,
    Reversibility, TypedDecision, cut_text, fit_state,
};
use crate::llm::{ModelId, ReasoningEffort};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};

/// The effort answer that keeps the chosen model's first rung.
const FIRST_RUNG: &str = "default";

/// The most options one Choice read takes (`AnswerContract::Choice`'s own
/// bound): a larger catalog is picked in rounds of reads this size (FIX 9925).
const PICK_ROUND: usize = 64;

/// The pick's complete typed reads (FIX 9926): every model-pick decision in
/// the order asked (one for 64 or fewer candidates; for more, each round's
/// batch reads, the final one last), and the effort decision when that pick
/// ran.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatPickReadings {
    pub model_decisions: Vec<TypedDecision>,
    pub effort_decision: Option<TypedDecision>,
}

/// Generation beside a decided seat pick: the plain-language `why` the seat's receipt
/// keeps, from the host's own model transport. The model and effort are already decided;
/// the note cannot change them. The engine refuses a blank one. `deadline` is the birth's
/// own clock, the one its pick ran on (FIX 8230): a note runs in what is left of it and
/// never starts a new one.
pub trait SeatNotes: Send + Sync {
    fn why(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        model: &ModelId,
        effort: ReasoningEffort,
        deadline: &RetrievalDeadline,
    ) -> Result<String>;
}

/// The host's typed seat pick: its ladder, the principal the pick is for, the dial and
/// learned bands, its wording of the two questions, each birth's anytime budget, and the
/// note seam for the receipt's `why`.
///
/// A provider reads the task and the eligible candidates as the call's bounded state; no
/// evidence id names them.
pub struct SeatDecisions {
    pub ladder: HeldLadder,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// Which candidate the seat pins.
    pub model_wording: String,
    /// Which of the chosen model's efforts it runs at.
    pub effort_wording: String,
    pub budget: Duration,
    pub notes: Arc<dyn SeatNotes>,
}

impl SeatDecisions {
    /// Which candidate the seat pins, then, unless the holder fixed the effort or the
    /// model has one rung, which of its allowed efforts it runs at, under `deadline`, the
    /// clock its caller already runs on (FIX 7507): both questions share it, so a birth
    /// bound by a parent's clock never starts a new one. A caller passes its own deadline
    /// cut to the seat budget it allows. An abstained pick fails the birth, as a judge's
    /// error did; an abstained effort keeps the first rung. Every read is returned whole
    /// (FIX 9926).
    ///
    /// 64 or fewer candidates are one read, as before. More are read in rounds of 64 under
    /// the same clock, each batch's choice going on to the next round until one remains
    /// (FIX 9925): no candidate is dropped and no clock is added; a batch that abstains
    /// sends none on, and its read is kept.
    pub fn pick_before(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        deadline: &RetrievalDeadline,
    ) -> Result<(usize, Option<ReasoningEffort>, SeatPickReadings)> {
        let ladder = self.ladder.ladder();
        let ask = |read: &DecisionQuestion, asked: &[SeatCandidate], chosen: Option<&ModelId>| {
            ladder.run(
                read,
                self.principal,
                &[],
                &bounded_state(task, asked, chosen),
                self.dial,
                &self.bands,
                Reversibility::ReversibleRead,
                deadline,
            )
        };
        let mut readings = SeatPickReadings::default();
        let mut pool: Vec<usize> = (0..candidates.len()).collect();
        let (index, finalists) = loop {
            let mut winners = Vec::new();
            for batch in pool.chunks(PICK_ROUND) {
                let asked: Vec<SeatCandidate> =
                    batch.iter().map(|&at| candidates[at].clone()).collect();
                let model = SEAT_PICK.question(
                    &[b"model".as_slice()],
                    self.model_wording.clone(),
                    AnswerContract::Choice {
                        options: asked
                            .iter()
                            .map(|candidate| candidate.model.to_string())
                            .collect(),
                    },
                )?;
                let decision = ask(&model, &asked, None)?;
                if let DecisionAnswer::Choice(label) = &decision.answer {
                    let at = asked
                        .iter()
                        .position(|candidate| candidate.model.as_str() == label)
                        .ok_or_else(|| invalid("seat pick selected ineligible model"))?;
                    winners.push((batch[at], asked));
                }
                readings.model_decisions.push(decision);
            }
            match winners.len() {
                0 => return Err(invalid("seat pick abstained")),
                1 => break winners.remove(0),
                _ => pool = winners.into_iter().map(|(winner, _)| winner).collect(),
            }
        };
        let candidate = &candidates[index];
        if task.override_effort.is_some() || candidate.allowed_efforts.len() < 2 {
            return Ok((index, None, readings));
        }
        let labels = candidate
            .allowed_efforts
            .iter()
            .map(|effort| effort_label(*effort))
            .collect::<Result<Vec<_>>>()?;
        let effort = SEAT_PICK.question(
            &[b"effort".as_slice(), candidate.model.as_str().as_bytes()],
            self.effort_wording.clone(),
            AnswerContract::Choice {
                options: std::iter::once(FIRST_RUNG.to_owned())
                    .chain(labels.iter().cloned())
                    .collect(),
            },
        )?;
        // The effort read sees the batch its model was chosen from: every candidate when
        // they fit one read, as before.
        let decision = ask(&effort, &finalists, Some(&candidate.model))?;
        let effort = match &decision.answer {
            DecisionAnswer::Choice(label) => labels
                .iter()
                .position(|known| known == label)
                .map(|at| candidate.allowed_efforts[at]),
            _ => None,
        };
        readings.effort_decision = Some(decision);
        Ok((index, effort, readings))
    }
}

fn effort_label(effort: ReasoningEffort) -> Result<String> {
    match serde_json::to_value(effort) {
        Ok(Value::String(label)) => Ok(label),
        _ => Err(invalid("effort has no label")),
    }
}

/// The task and every candidate, with the effort question's chosen model. The task text
/// and the description lines are cut shorter, halving, until the whole fits.
fn bounded_state(task: &SeatTask, candidates: &[SeatCandidate], chosen: Option<&ModelId>) -> Value {
    let longest = candidates
        .iter()
        .flat_map(|candidate| &candidate.description)
        .map(|line| line.text.len())
        .chain([task.task.len()])
        .max()
        .unwrap_or(0);
    fit_state(longest, |cut| {
        let candidates: Vec<Value> = candidates
            .iter()
            .map(|candidate| {
                let description: Vec<Value> = candidate
                    .description
                    .iter()
                    .map(|line| json!({"source": line.source, "text": cut_text(&line.text, cut)}))
                    .collect();
                json!({
                    "model": candidate.model,
                    "wire": candidate.wire,
                    "locality": candidate.locality,
                    "description": description,
                    "reasoning": candidate.reasoning,
                    "default_effort": candidate.default_effort,
                    "allowed_efforts": candidate.allowed_efforts,
                })
            })
            .collect();
        json!({
            "task": {
                "kind": task.kind,
                "task": cut_text(&task.task, cut),
                "purpose": task.purpose,
                "facet": task.facet,
                "required": task.required,
                "min_context_tokens": task.min_context_tokens,
                "locality": task.locality,
            },
            "candidates": candidates,
            "chosen": chosen,
            "cut_at_bytes": cut,
        })
    })
}
