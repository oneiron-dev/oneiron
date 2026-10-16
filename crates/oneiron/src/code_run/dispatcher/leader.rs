//! Host entry points for the CEO starter on a leased, task-bound leader.

use super::HostSelfDispatcher;
use crate::agent_dispatch::{
    AgentDispatcher, LeaderStarter, LeaderStarterSkills, LeaderTeamPlanner, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::attempt_queue::AttemptRecord;
use crate::code_run::storage::ExecutorStorage;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{ArtifactError, Error, Result};
use crate::{EntityId, Vault};

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "leader starter requires its host-bound acquired agent lease",
    ))
}

impl HostSelfDispatcher<'_> {
    /// Load the starter and an optional CEO-selected pattern before running
    /// the leader. Host bindings supply identity and lease, not guest text.
    pub fn prepare_leader_starter(
        &self,
        skills: &LeaderStarterSkills,
        executor: &str,
        at: u64,
    ) -> Result<LeaderStarter> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).prepare_leader_starter(&leased, skills, executor, at)
    }

    /// Ask the configured team-shape ladder without starting any work. The
    /// caller may use the advice to choose its next pattern skill load.
    pub fn leader_top_shapes(
        &self,
        team_shape_skill: EntityId,
        executor: &str,
        planner: &mut dyn LeaderTeamPlanner,
        at: u64,
    ) -> Result<serde_json::Value> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).leader_top_shapes(
            &leased, team_shape_skill, executor, planner, at,
        )
    }

    fn leader_attempt(&self) -> Result<(&Vault, AttemptRecord)> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(invalid());
        };
        let parent = self.agent_parent.ok_or_else(invalid)?;
        let lease = self.agent_lease.as_ref().ok_or_else(invalid)?;
        let status = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&status.payload.input)?;
        if agent_dispatch_actor(&input)? != self.actor
            || status.attempt.lease_owner.as_deref() != Some(lease.owner.as_str())
            || status.attempt.attempt_count != lease.generation
        {
            return Err(invalid());
        }
        Ok((vault, status.attempt))
    }
}
