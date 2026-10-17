//! The concrete CEO planner (OF-389, ARCH-0079 #planner): the leader's
//! top-shapes advice over the one live planner service, never a second
//! planner or plan format.
//!
//! [`VaultLeaderTeamPlanner`] reads the need, care, notes, pins and placed
//! type from the leader's existing typed TASK brief, and plans on the leased
//! leader's own lease with the team-shape pack the starter already loaded.
//! It returns the resolved plan and the ranked candidates, each naming its
//! pattern skill revision, payoff and cost. It neither dispatches nor
//! creates or completes a task; the CEO picks a pattern after reading it.

use serde_json::Value as JsonValue;

use crate::attempt_queue::AttemptRecord;
use crate::error::Result;
use crate::llm::ModelId;
use crate::skill::LoadedSkillPack;
use crate::task_verb::Care;

use super::AgentDispatcher;
use super::leader_starter::{LeaderTaskContext, LeaderTeamPlanner};
use super::planner::PlannerDecisions;
use super::planner_live::{LivePlanRequest, PlannerSeat, PlannerSkills};
use super::team_shape::CoordinationPattern;
use super::types::{CareLevel, SpawnNeed, SpawnOverride};
use super::widen_record::invalid;

/// The live planner as a [`LeaderTeamPlanner`]: bound to the leader's
/// acquired lease, the seats the host serves, the planner's skills and,
/// when the host installed one, its ladder.
pub struct VaultLeaderTeamPlanner<'v, 'd> {
    dispatcher: &'d AgentDispatcher<'v>,
    leased: AttemptRecord,
    skills: PlannerSkills,
    seats: Vec<PlannerSeat>,
    executor: String,
    decisions: Option<&'d PlannerDecisions<'d>>,
    top: usize,
    at: u64,
}

impl<'v, 'd> VaultLeaderTeamPlanner<'v, 'd> {
    /// A planner over the leader's lease, returning the `top` best shapes.
    #[must_use]
    pub fn new(
        dispatcher: &'d AgentDispatcher<'v>,
        leased: AttemptRecord,
        skills: PlannerSkills,
        seats: Vec<PlannerSeat>,
        executor: impl Into<String>,
        top: usize,
        at: u64,
    ) -> Self {
        Self {
            dispatcher,
            leased,
            skills,
            seats,
            executor: executor.into(),
            decisions: None,
            top,
            at,
        }
    }

    /// Engage the host's planner ladder.
    #[must_use]
    pub const fn with_decisions(mut self, decisions: &'d PlannerDecisions<'d>) -> Self {
        self.decisions = Some(decisions);
        self
    }
}

impl LeaderTeamPlanner for VaultLeaderTeamPlanner<'_, '_> {
    fn top_shapes(
        &mut self,
        task: &LeaderTaskContext,
        team_shape: &LoadedSkillPack,
    ) -> Result<JsonValue> {
        let need = leader_spawn_need(task)?;
        let request = LivePlanRequest {
            need,
            seats: &self.seats,
            skills: &self.skills,
            executor: &self.executor,
            decisions: self.decisions,
        };
        let (receipt, mut shapes) =
            self.dispatcher
                .plan_with_team_shape(&self.leased, &request, team_shape, self.at)?;
        shapes.truncate(self.top.max(1));
        let advice = serde_json::json!({
            "task_ref": task.task_ref.to_hex(),
            "project_ref": task.responsibility.project_ref.to_hex(),
            "asked": receipt.asked,
            "plan": receipt.plan,
            "why": receipt.why,
            "shapes": shapes,
            "team_shape": receipt.team_shape,
            "rung_skill": receipt.rung_skill,
            "rung_providers": receipt.rung_providers,
        });
        Ok(advice)
    }
}

/// The spawn need a leader's TASK brief states: its need (else its
/// objective, else the task label), care, notes and pins, at the type the
/// TASK was placed at. A brief pin is a pin.
fn leader_spawn_need(task: &LeaderTaskContext) -> Result<SpawnNeed> {
    let brief = task.brief.as_ref();
    let text = brief
        .map(|brief| brief.intent.need.clone())
        .filter(|need| !need.trim().is_empty())
        .or_else(|| brief.map(|brief| brief.objective.clone()))
        .filter(|need| !need.trim().is_empty())
        .or_else(|| task.label.clone())
        .ok_or_else(|| invalid("leader task names no need"))?;
    let mut need = SpawnNeed::new(text, task.type_ref.clone());
    if let Some(brief) = brief {
        need.care = brief.intent.care.map(care_level);
        let notes = brief.constraints.notes.join("; ");
        if !notes.trim().is_empty() {
            need.notes = Some(notes);
        }
        let pins = &brief.constraints.pins;
        if let Some(model) = &pins.model {
            need.model = Some(SpawnOverride::Pin {
                value: ModelId::new(model.clone())
                    .map_err(|_| invalid("task brief pins an invalid model id"))?,
            });
        }
        if let Some(width) = pins.width {
            need.width = Some(SpawnOverride::Pin {
                value: u32::from(width),
            });
        }
        if let Some(pattern) = &pins.pattern {
            need.pattern = Some(SpawnOverride::Pin {
                value: CoordinationPattern::from_token(pattern)?,
            });
        }
        if let Some(budget) = pins.budget {
            need.budget_cap_units = Some(SpawnOverride::Pin { value: budget });
        }
    }
    need.validate()?;
    Ok(need)
}

const fn care_level(care: Care) -> CareLevel {
    match care {
        Care::Light => CareLevel::Light,
        Care::Medium => CareLevel::Medium,
        Care::High => CareLevel::High,
        Care::Xhigh => CareLevel::XHigh,
        Care::Max => CareLevel::Max,
    }
}
