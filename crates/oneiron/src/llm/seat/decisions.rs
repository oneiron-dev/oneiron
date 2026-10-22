//! The seat pick as typed decisions through the host's ladder, and the note seam beside it.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{SeatCandidate, SeatTask, invalid};
use crate::llm::decision::catalogue::SEAT_PICK;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionQuestion, HeldLadder,
    Reversibility, cut_text, fit_state,
};
use crate::llm::{ModelId, ReasoningEffort};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};

/// The effort answer that keeps the chosen model's first rung.
const FIRST_RUNG: &str = "default";

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
    /// error did; an abstained effort keeps the first rung.
    pub fn pick_before(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        deadline: &RetrievalDeadline,
    ) -> Result<(usize, Option<ReasoningEffort>)> {
        let ladder = self.ladder.ladder();
        let ask = |question: &DecisionQuestion, chosen: Option<&ModelId>| {
            ladder.run(
                question,
                self.principal,
                &[],
                &bounded_state(task, candidates, chosen),
                self.dial,
                &self.bands,
                Reversibility::ReversibleRead,
                deadline,
            )
        };
        let model = SEAT_PICK.question(
            &[b"model".as_slice()],
            self.model_wording.clone(),
            AnswerContract::Choice {
                options: candidates
                    .iter()
                    .map(|candidate| candidate.model.to_string())
                    .collect(),
            },
        )?;
        let DecisionAnswer::Choice(label) = ask(&model, None)?.answer else {
            return Err(invalid("seat pick abstained"));
        };
        let index = candidates
            .iter()
            .position(|candidate| candidate.model.as_str() == label)
            .ok_or_else(|| invalid("seat pick selected ineligible model"))?;
        let candidate = &candidates[index];
        if task.override_effort.is_some() || candidate.allowed_efforts.len() < 2 {
            return Ok((index, None));
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
        let effort = match ask(&effort, Some(&candidate.model))?.answer {
            DecisionAnswer::Choice(label) => labels
                .iter()
                .position(|known| *known == label)
                .map(|at| candidate.allowed_efforts[at]),
            _ => None,
        };
        Ok((index, effort))
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
