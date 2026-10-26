//! The spawn plan receipt: what a spawn asked, the plan it resolved to, and
//! why. Planner vocabulary stays in `planner`.

use super::*;

/// The spawn receipt: what was asked, what was resolved, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpawnPlanReceipt {
    pub asked: SpawnNeed,
    pub plan: TeamPlan,
    /// The runner-up candidates with payoff and cost, best first — the
    /// CEO's top-shapes view rides the same rows.
    pub alternatives: Vec<ShapeQuote>,
    pub why: Vec<String>,
    /// The team-shape skill revision the plan read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_shape: Option<SkillRevisionRef>,
    /// The workflow skill the answering ladder rung ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rung_skill: Option<SkillRevisionRef>,
    /// The executors that read the rung's question, at revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rung_providers: Vec<ProviderPin>,
}

impl SpawnPlanReceipt {
    /// A receipt is whole and honest: its need validates, its shape is one
    /// the pattern can run, a team names its pattern skill, its envelope
    /// counts its agents, and no pinned field was overridden.
    ///
    /// # Errors
    ///
    /// [`crate::error::ArtifactError::InvalidAgentDispatchInput`] naming the
    /// broken rule.
    pub fn validate(&self) -> Result<()> {
        self.asked.validate()?;
        let plan = &self.plan;
        if !plan.shape.pattern.admits_width(plan.shape.width) {
            return Err(invalid("plan width does not fit its pattern"));
        }
        if plan.shape.pattern.is_team() != plan.pattern_skill.is_some() {
            return Err(invalid("a team plan runs a pattern skill; solo runs none"));
        }
        if plan.envelope.agent_count != plan.shape.width {
            return Err(invalid("plan envelope must count its agents"));
        }
        if self
            .asked
            .pinned_pattern()
            .is_some_and(|pattern| pattern != plan.shape.pattern)
            || self
                .asked
                .pinned_width()
                .is_some_and(|width| width != plan.shape.width)
            || self
                .asked
                .pinned_model()
                .is_some_and(|model| *model != plan.model)
        {
            return Err(invalid("a plan never overrides a pinned spawn field"));
        }
        Ok(())
    }

    /// The candidate id the resolved plan runs.
    #[must_use]
    pub fn candidate(&self) -> String {
        candidate_token(
            &self.plan.shape,
            &self.plan.model,
            self.plan.pattern_skill.as_ref(),
        )
    }
}
