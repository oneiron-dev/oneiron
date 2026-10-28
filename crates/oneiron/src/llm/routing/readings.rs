//! The route's complete typed grading, carried with each routed outcome (FIX
//! 9922): every candidate's decision, with its question and provider pins,
//! paired readings and clock, and the fitness read from that SAME decision,
//! never from a second grading pass.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::decisions::{Candidate, DescriptionDecisions};
use super::{
    CallPurpose, DescriptionPolicy, MeasuredDescription, ModelDescription, SeatSettings, invalid,
    purpose_key,
};
use crate::Result;
use crate::llm::decision::{DecisionAnswer, TypedDecision};
use crate::llm::seat::SeatPolicy;
use crate::llm::{ModelId, ReasoningEffort};
use crate::task_type::TaskTypeRef;

/// One candidate's grade: the model, the effort it was graded at, and its
/// complete typed decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionGrading {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub decision: TypedDecision,
}

impl DescriptionGrading {
    /// Its `[0, 1]` fitness, read from its own decision: an abstained or
    /// unscored grade leaves the candidate unfit.
    #[must_use]
    pub fn fitness(&self) -> Option<f64> {
        match self.decision.answer {
            DecisionAnswer::Score(fitness) => Some(fitness),
            _ => None,
        }
    }
}

/// Every candidate's complete grade, in the order the route asked them, and
/// the type stamp of the task they were graded for.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionFitnessReadings {
    pub gradings: Vec<DescriptionGrading>,
    /// The task's type stamp as placed, which the grades read (ARCH-0079,
    /// "placed once, read everywhere"); none for an untyped task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_ref: Option<TaskTypeRef>,
}

impl DescriptionFitnessReadings {
    /// Each asked candidate's grade, paired with its decision, for a task
    /// stamped `type_ref`.
    pub(super) fn of(
        candidates: &[Candidate<'_>],
        decisions: Vec<TypedDecision>,
        type_ref: Option<&TaskTypeRef>,
    ) -> Self {
        Self {
            gradings: candidates
                .iter()
                .zip(decisions)
                .map(|(candidate, decision)| DescriptionGrading {
                    model: candidate.model.clone(),
                    effort: candidate.effort,
                    decision,
                })
                .collect(),
            type_ref: type_ref.cloned(),
        }
    }
}

/// What a route chose, with the grading it chose from.
pub(super) struct Resolved<'a> {
    pub(super) chosen: &'a ModelDescription,
    pub(super) line: &'a str,
    pub(super) fitness: f64,
    pub(super) effort: ReasoningEffort,
    pub(super) grading: DescriptionFitnessReadings,
}

/// Seats and verdicts share the seat policy's composition, ceiling and
/// evidence order; this router adds no default of its own. The highest
/// positive grade wins, with its description line, grade and effort, and
/// every candidate's grade rides with it.
pub(super) fn resolve<'a>(
    policy: &'a DescriptionPolicy,
    seat_policy: &SeatPolicy,
    measurements: &'a BTreeMap<ModelId, MeasuredDescription>,
    settings: &SeatSettings,
    purpose: &CallPurpose,
    task: &str,
    type_ref: Option<&TaskTypeRef>,
    decisions: &DescriptionDecisions<'_>,
) -> Result<Resolved<'a>> {
    let composed = seat_policy.compose_defaults(&purpose_key(purpose), Some(policy))?;
    let rows: Vec<_> = policy
        .models
        .iter()
        .filter(|row| {
            settings
                .allowed_models
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&row.model))
        })
        .filter_map(|row| {
            let effort = seat_policy
                .choose(composed, settings.effort, &row.effort_ladder)
                .ok()?;
            row.line(measurements.get(&row.model), &seat_policy.evidence_order)
                .map(|line| (row, line, effort))
        })
        .collect();
    let grading = decisions.fitness(
        task,
        type_ref,
        &rows
            .iter()
            .map(|&(row, description, effort)| Candidate {
                model: &row.model,
                description,
                effort,
            })
            .collect::<Vec<_>>(),
    )?;
    let (chosen, line, fitness, effort) = rows
        .into_iter()
        .zip(grading.gradings.iter().map(DescriptionGrading::fitness))
        .filter_map(|((row, line, effort), fitness)| {
            fitness
                .filter(|fitness| *fitness > 0.0)
                .map(|fitness| (row, line, fitness, effort))
        })
        .max_by(|a, b| a.2.total_cmp(&b.2))
        .ok_or_else(|| invalid("no description candidate passed judgment"))?;
    Ok(Resolved {
        chosen,
        line,
        fitness,
        effort,
        grading,
    })
}
