//! The `[skills]` section: how the skill-edit gate's live slice is funded at
//! this server, and the skills a project conversation runs. It holds the pull
//! budget of one live goal-axis measurement (OF-495), which the Coach and the
//! owner's measure route read, and the drafting and goal-intake skills of a
//! project conversation (OF-501).

use oneiron::EntityId;
use oneiron::agent_dispatch::ProjectConversationSkills;
use serde::Deserialize;

/// The least budget a live slice can compare two arms on.
const MIN_LIVE_PULLS: u32 = 2;

/// Resolved skill settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SkillsConfig {
    /// Live pulls per online goal axis, across both arms, that one
    /// measurement of a skill edit takes. Unset: the Coach takes no live
    /// slice, and the owner's measure must name its own budget.
    pub live_pulls_per_axis: Option<u32>,
    /// The skill the house mind drafts a project card with, by its 32-hex
    /// id. Unset: none ships, so a drafting run is refused.
    pub project_proposal_draft_skill: Option<String>,
    /// The goal-intake skill a minted project's leader interviews with, by
    /// its 32-hex id. Unset: the shipped goal-intake skill.
    pub goal_intake_skill: Option<String>,
}

impl SkillsConfig {
    pub(super) fn apply_override(&mut self, over: SkillsConfigOverride) {
        if let Some(value) = over.live_pulls_per_axis {
            self.live_pulls_per_axis = Some(value);
        }
        if let Some(value) = over.project_proposal_draft_skill {
            self.project_proposal_draft_skill = Some(value);
        }
        if let Some(value) = over.goal_intake_skill {
            self.goal_intake_skill = Some(value);
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        if self
            .live_pulls_per_axis
            .is_some_and(|pulls| pulls < MIN_LIVE_PULLS)
        {
            anyhow::bail!("skills.live_pulls_per_axis must be at least {MIN_LIVE_PULLS}");
        }
        skill_id(
            "project_proposal_draft_skill",
            &self.project_proposal_draft_skill,
        )?;
        skill_id("goal_intake_skill", &self.goal_intake_skill)?;
        Ok(())
    }

    /// The skills a project conversation runs (OF-501): this server's
    /// drafting skill, if it names one, and its goal-intake skill, or the
    /// shipped one.
    pub fn project_conversation(&self) -> anyhow::Result<ProjectConversationSkills> {
        let mut skills = ProjectConversationSkills::seeded(skill_id(
            "project_proposal_draft_skill",
            &self.project_proposal_draft_skill,
        )?)?;
        if let Some(intake) = skill_id("goal_intake_skill", &self.goal_intake_skill)? {
            skills.goal_intake = intake;
        }
        Ok(skills)
    }
}

/// The skill `key` names, read from its 32-hex id.
fn skill_id(key: &str, value: &Option<String>) -> anyhow::Result<Option<EntityId>> {
    value
        .as_deref()
        .map(|hex| {
            EntityId::from_hex(hex.trim())
                .map_err(|_| anyhow::anyhow!("skills.{key} must be a skill's 32-hex id"))
        })
        .transpose()
}

/// One layer's `[skills]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct SkillsConfigOverride {
    pub(super) live_pulls_per_axis: Option<u32>,
    pub(super) project_proposal_draft_skill: Option<String>,
    pub(super) goal_intake_skill: Option<String>,
}

pub(super) fn lookup_skills_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<SkillsConfigOverride>> {
    let live_pulls_per_axis = lookup("ONEIRON_SKILLS_LIVE_PULLS_PER_AXIS")
        .map(|value| {
            value.parse().map_err(|_| {
                anyhow::anyhow!(
                    "ONEIRON_SKILLS_LIVE_PULLS_PER_AXIS must be a whole count, not {value:?}"
                )
            })
        })
        .transpose()?;
    let project_proposal_draft_skill = lookup("ONEIRON_SKILLS_PROJECT_PROPOSAL_DRAFT_SKILL");
    let goal_intake_skill = lookup("ONEIRON_SKILLS_GOAL_INTAKE_SKILL");
    let over = SkillsConfigOverride {
        live_pulls_per_axis,
        project_proposal_draft_skill,
        goal_intake_skill,
    };
    Ok((over != SkillsConfigOverride::default()).then_some(over))
}
