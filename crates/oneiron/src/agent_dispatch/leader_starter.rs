//! CEO starter over existing TASK promises, project responsibility and skill loads.

use rmpv::Value;
use serde_json::Value as JsonValue;

use super::{AgentDispatcher, decode_agent_dispatch_input};
use crate::EntityId;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::error::{ArtifactError, Error, Result};
use crate::skill::{LoadedSkillPack, SkillRole};
use crate::workspace_roster::{ProjectBudgetShare, ProjectEffective, ProjectGoalRecord};

/// Skill references are host configuration. None selects solo work, not an
/// implicit task or a new runtime kind. Consumers may replace the starter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderStarterSkills {
    pub starter: EntityId,
    pub pattern: Option<EntityId>,
    /// The team-shape workflow the CEO's top-shapes advice reads (OF-389).
    pub team_shape: EntityId,
}

impl LeaderStarterSkills {
    /// The installed starter shipped with the team-lead agent definition,
    /// and the installed team-shape skill.
    pub fn seeded() -> Result<Self> {
        Ok(Self {
            starter: EntityId::derive(
                crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
                &[b"team-lead"],
            )?,
            pattern: None,
            team_shape: super::team_shape::team_shape_skill()?,
        })
    }
}

/// Content belongs to the responsibility space; authority comes only from
/// its current folded view, never the stored row's leader or board fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderResponsibility {
    pub project_ref: EntityId,
    pub authority: ProjectEffective,
    pub goal: Option<String>,
    pub goal_record: Option<ProjectGoalRecord>,
    pub budget: Option<String>,
    pub budget_share: Option<ProjectBudgetShare>,
    pub asks: Vec<String>,
    pub home_room: EntityId,
    pub depth_remaining: u8,
}

/// A real attempt reads the promise it already realizes. No task is created
/// or completed by preparing a starter or consulting the planner.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaderTaskContext {
    pub task_ref: EntityId,
    pub label: Option<String>,
    pub body: Value,
    /// The type the TASK was placed at, once (OF-543).
    pub type_ref: crate::task_type::TaskTypeRef,
    /// The TASK's typed brief: need, care, notes and pins the planner reads.
    pub brief: Option<crate::task_verb::QueueTaskBrief>,
    pub responsibility: LeaderResponsibility,
}

#[derive(Debug, Clone)]
pub struct LeaderStarter {
    pub context: LeaderTaskContext,
    pub starter: LoadedSkillPack,
    pub pattern: Option<LoadedSkillPack>,
}

/// The team-shape planner owns its ladder, pins, estimates and plan schema.
/// Advice is returned to the CEO; it neither launches agents nor assigns work.
/// The JSON result preserves that planner's contract without defining a
/// second team-plan format in the starter. The installed implementation is
/// [`super::VaultLeaderTeamPlanner`], over the one live planner service.
pub trait LeaderTeamPlanner {
    fn top_shapes(
        &mut self,
        task: &LeaderTaskContext,
        team_shape: &LoadedSkillPack,
    ) -> Result<JsonValue>;
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(reason))
}

impl AgentDispatcher<'_> {
    /// Start a try on an already-assigned promise in its responsibility
    /// space. The caller supplies the normal parent/context and dedupe key;
    /// the same dispatch admission enforces scope and recursive attenuation.
    /// This does not create a TASK or change the promise's done state.
    pub fn dispatch_leader_task(
        &self,
        task: EntityId,
        input: super::DispatchAgent,
        spawn: super::AgentSpawnContext,
    ) -> Result<super::AgentDispatchOutcome> {
        self.dispatch_with_task_context(input, spawn, Some(task))
    }

    pub(super) fn validate_leader_task_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        input: &super::DispatchAgent,
        spawn: &super::AgentSpawnContext,
    ) -> Result<()> {
        let (project, _) =
            self.project_depth_limit_in_txn(txn, input.parent_attempt, spawn.project_ref)?;
        let (_, authority) = self
            .vault
            .effective_project_in_txn(txn, project)?
            .ok_or(Error::EntityNotFound)?;
        let leader = EntityId::from_hex(&authority.leader)?;
        if input.target.agent_definition_ref()? != leader {
            return Err(invalid(
                "dispatch target is not the project's current leader",
            ));
        }
        crate::task_verb::leader_task_body_in(self.vault, txn, task, leader)?;
        Ok(())
    }

    pub(super) fn require_leader_task_binding(
        outcome: &super::AgentDispatchOutcome,
        task: EntityId,
    ) -> Result<()> {
        match outcome {
            super::AgentDispatchOutcome::Dispatched(status)
            | super::AgentDispatchOutcome::Existing(status)
                if status.attempt.task_ref.as_deref() == Some(task.to_hex().as_str()) =>
            {
                Ok(())
            }
            super::AgentDispatchOutcome::ProposedWiden(_) => Ok(()),
            _ => Err(invalid(
                "existing leader attempt belongs to a different task promise",
            )),
        }
    }

    /// Read the live task and project, then load the starter and the CEO's
    /// selected pattern through the ordinary lease-fenced skill manifest door.
    /// No selected pattern means solo first. Selection is not a spawn.
    pub fn prepare_leader_starter(
        &self,
        leased: &AttemptRecord,
        skills: &LeaderStarterSkills,
        executor: &str,
        at: u64,
    ) -> Result<LeaderStarter> {
        let context = self.leader_task_context(leased)?;
        let starter = self.load_leader_workflow(leased, skills.starter, executor, at)?;
        let pattern = skills
            .pattern
            .map(|skill| self.load_leader_workflow(leased, skill, executor, at))
            .transpose()?;
        Ok(LeaderStarter {
            context,
            starter,
            pattern,
        })
    }

    /// On-demand planner advice. Re-read responsibility and the promise for
    /// every call: a prior starter snapshot is not permission to use a stale
    /// leader, board or task. The CEO chooses a pattern after seeing the advice.
    pub fn leader_top_shapes(
        &self,
        leased: &AttemptRecord,
        team_shape_skill: EntityId,
        executor: &str,
        planner: &mut dyn LeaderTeamPlanner,
        at: u64,
    ) -> Result<JsonValue> {
        let context = self.leader_task_context(leased)?;
        let team_shape = self.load_leader_workflow(leased, team_shape_skill, executor, at)?;
        planner.top_shapes(&context, &team_shape)
    }

    /// The CEO's advice: [`Self::leader_top_shapes`] on the configured
    /// team-shape workflow, over the same acquired lease.
    pub fn leader_advice(
        &self,
        leased: &AttemptRecord,
        skills: &LeaderStarterSkills,
        executor: &str,
        planner: &mut dyn LeaderTeamPlanner,
        at: u64,
    ) -> Result<JsonValue> {
        self.leader_top_shapes(leased, skills.team_shape, executor, planner, at)
    }

    /// Load the pattern the CEO selected after reading the advice, through
    /// the same lease-fenced manifest door, after re-reading the live task
    /// and responsibility. Selecting a pattern is not a spawn.
    pub fn reload_leader_pattern(
        &self,
        leased: &AttemptRecord,
        pattern: EntityId,
        executor: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.leader_task_context(leased)?;
        self.load_leader_workflow(leased, pattern, executor, at)
    }

    fn load_leader_workflow(
        &self,
        leased: &AttemptRecord,
        skill: EntityId,
        executor: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let loaded = self.vault.load_attempt_skill_pack(
            leased.id,
            &skill,
            leased
                .lease_owner
                .as_deref()
                .ok_or_else(|| invalid("leader has no lease"))?,
            leased.attempt_count,
            executor,
            at,
        )?;
        if loaded.record.role != SkillRole::Workflow {
            return Err(invalid(
                "leader starter and coordination patterns must be workflow skills",
            ));
        }
        Ok(loaded)
    }

    fn leader_task_context(&self, leased: &AttemptRecord) -> Result<LeaderTaskContext> {
        let txn = self.vault.store.env.read_txn()?;
        let live = AttemptQueue::new(self.vault)
            .get_in_txn(&txn, leased.id)?
            .ok_or(Error::EntityNotFound)?;
        if leased.state != AttemptState::Leased
            || live.state != AttemptState::Leased
            || live.lease_owner.is_none()
            || live.lease_owner != leased.lease_owner
            || live.attempt_count != leased.attempt_count
        {
            return Err(invalid(
                "leader starter requires its current acquired lease",
            ));
        }
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&live.payload)?;
        if payload.attempt_type != super::AGENT_DISPATCH_ATTEMPT_TYPE {
            return Err(invalid("leader starter requires an agent dispatch"));
        }
        let input = decode_agent_dispatch_input(&payload.input)?;
        let project_ref = input
            .project_ref
            .ok_or_else(|| invalid("leader has no project"))?;
        let (project, authority) = self
            .vault
            .effective_project_in_txn(&txn, project_ref)?
            .ok_or(Error::EntityNotFound)?;
        let leader = EntityId::from_hex(&authority.leader)?;
        let definition = self.dispatchable_definition_in_txn(&txn, &input.target)?;
        if input.target.agent_definition_ref()? != leader && definition.forked_from != Some(leader)
        {
            return Err(invalid(
                "attempt does not execute the project's current leader",
            ));
        }
        if authority.slice.is_none() {
            return Err(invalid("project has no effective responsibility slice"));
        }
        let task_ref = live
            .task_ref
            .as_deref()
            .ok_or_else(|| invalid("leader attempt has no existing task promise"))?;
        let task_ref = EntityId::from_hex(task_ref)?;
        let (label, body) =
            crate::task_verb::leader_task_body_in(self.vault, &txn, task_ref, leader)?;
        let (type_ref, brief) =
            crate::task_verb::leader_task_brief_in(self.vault, &txn, task_ref, leader)?;
        let (_, spawn_view) = self
            .vault
            .project_for_spawn_in_txn(&txn, Some(project_ref))?;
        let depth_remaining = input
            .depth_remaining
            .unwrap_or(0)
            .min(spawn_view.depth)
            .min(authority.depth_remaining)
            .min(authority.depth_limit);
        Ok(LeaderTaskContext {
            task_ref,
            label,
            body,
            type_ref,
            brief,
            responsibility: LeaderResponsibility {
                project_ref,
                authority,
                goal: project.goal,
                goal_record: project.goal_record,
                budget: project.budget,
                budget_share: project.budget_share,
                asks: project.asks,
                home_room: EntityId::from_hex(&project.home_room)?,
                depth_remaining,
            },
        })
    }
}
