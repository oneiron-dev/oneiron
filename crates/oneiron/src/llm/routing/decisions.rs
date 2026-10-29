//! The route's fitness grades as typed decisions through the host's ladder, and the note
//! seam beside a routed seat.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::llm::decision::catalogue::DESCRIPTION_FIT;
use crate::llm::decision::{
    AnswerContract, DecisionBandPolicy, DecisionDial, DecisionLadder, Reversibility, cut_text,
    fit_state,
};
use crate::llm::{ModelId, ReasoningEffort};
use crate::retrieval_depth::RetrievalDeadline;
use crate::task_type::TaskTypeRef;
use crate::{EntityId, Result};

use super::readings::DescriptionFitnessReadings;

/// Generation beside a decided route: the reason a routed seat's receipt keeps, from the
/// host's own model transport. The model, its effort and its fitness are already decided;
/// the note cannot change them. The engine refuses a blank one. A schema verdict keeps no
/// reason, so it asks for none.
pub trait DescriptionNotes {
    fn reason(
        &self,
        task: &str,
        model: &ModelId,
        description: &str,
        effort: ReasoningEffort,
        fitness: f64,
    ) -> Result<String>;
}

/// One candidate the route grades: a model, its selected description line and the effort
/// it would run at.
pub(super) struct Candidate<'a> {
    pub(super) model: &'a ModelId,
    pub(super) description: &'a str,
    pub(super) effort: ReasoningEffort,
}

/// The host's typed route grades: its ladder, the principal the route is for, the dial and
/// learned bands, its wording of the fitness question, and each route's anytime budget.
///
/// A provider reads the task and every candidate's description line and effort, each
/// beside the id of the question that grades it, as the call's bounded state.
pub struct DescriptionDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub budget: Duration,
}

impl DescriptionDecisions<'_> {
    /// Every candidate's fitness for `task` as one pack: each candidate's complete typed
    /// decision, whose `[0, 1]` score is its fitness (FIX 9922). An abstained grade leaves
    /// its candidate unfit. The task's type stamp, as placed, rides in the state the
    /// grades read and in the readings (ARCH-0079).
    pub(super) fn fitness(
        &self,
        task: &str,
        type_ref: Option<&TaskTypeRef>,
        candidates: &[Candidate<'_>],
    ) -> Result<DescriptionFitnessReadings> {
        if candidates.is_empty() {
            return Ok(DescriptionFitnessReadings::of(&[], Vec::new(), type_ref));
        }
        let questions = candidates
            .iter()
            .map(|candidate| {
                DESCRIPTION_FIT.question(
                    &[candidate.model.as_str().as_bytes()],
                    self.wording.clone(),
                    AnswerContract::Score { min: 0.0, max: 1.0 },
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let longest = candidates
            .iter()
            .map(|candidate| candidate.description.len())
            .chain([task.len()])
            .max()
            .unwrap_or(0);
        let state = fit_state(longest, |cut| {
            let candidates: Vec<Value> = candidates
                .iter()
                .zip(&questions)
                .map(|(candidate, question)| {
                    json!({
                        "question": question.id.to_hex(),
                        "model": candidate.model,
                        "description": cut_text(candidate.description, cut),
                        "effort": candidate.effort,
                    })
                })
                .collect();
            json!({
                "task": cut_text(task, cut),
                "task_type": type_ref.map(TaskTypeRef::to_string),
                "candidates": candidates,
                "cut_at_bytes": cut,
            })
        });
        let decisions = self.ladder.run_pack(
            &questions.iter().collect::<Vec<_>>(),
            self.principal,
            &[],
            &state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        Ok(DescriptionFitnessReadings::of(
            candidates,
            decisions,
            type_ref,
        ))
    }
}
