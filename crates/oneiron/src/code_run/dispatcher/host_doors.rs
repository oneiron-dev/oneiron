//! Typed coordination calls whose credential admission and verb hooks are
//! owned by the host's verb-table door. The dispatcher retains the acquired
//! parent lease, planner, attenuation and project-write gates.
use super::HostSelfDispatcher;
use crate::EntityId;
use crate::code_run::{
    AgentSpawnInput, AgentSpawnKind, AgentSpawnOutput, LeaderSplitInput, LeaderSplitOutput,
    SelfAgentSpawnResult, SelfDispatchOutcome,
};
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};

impl<'a> HostSelfDispatcher<'a> {
    /// Re-enters a registered live run under the sealed lease its host held.
    /// The binding cannot be decoded from a request or minted by its caller.
    pub fn for_live_run(
        vault: &'a crate::Vault,
        actor: crate::WriteActor,
        binding: &crate::task_verb::HostBinding,
    ) -> crate::Result<Self> {
        let leased = binding.leased_record(vault)?;
        Self::for_leased_agent_attempt(vault, actor, &leased)
    }

    /// The host door's `self.agents.spawn`, after its credential and hooks
    /// admitted the call. Runs the same planner and child admission as code
    /// mode, under this dispatcher's acquired parent lease.
    pub fn spawn_agent_from_host(&self, input: AgentSpawnInput) -> MemoryResult<AgentSpawnOutput> {
        // An id-only binding is not a public host call's acquired lease.
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        match self.dispatch_agents_spawn(input.into_call()?)? {
            SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued {
                attempt_ref,
                launch,
            }) => Ok(AgentSpawnOutput::Queued {
                kind: AgentSpawnKind::AgentSpawn,
                attempt: crate::entity_id::bytes_to_hex_lower(attempt_ref.as_bytes()),
                launch,
            }),
            SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::ProposedWiden {
                proposal_ref,
            }) => Ok(AgentSpawnOutput::ProposedWiden {
                kind: AgentSpawnKind::AgentSpawn,
                proposal: proposal_ref,
            }),
            SelfDispatchOutcome::Failed(failed) => {
                Err(MemoryError::new(&failed.error, &failed.error, &[]))
            }
            _ => Err(host_result_mismatch()),
        }
    }

    /// The host door's `self.leader.split`, under its admitted credential
    /// and hooks. TASK, project, actor and parent attempt come only from the
    /// run's acquired lease. The existing split signs and gates the write.
    pub fn split_leader_from_host(
        &self,
        input: LeaderSplitInput,
    ) -> MemoryResult<LeaderSplitOutput> {
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        let leader = input
            .leader
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        match self.dispatch_leader_split(leader, input.slice)? {
            SelfDispatchOutcome::Leader(output) => {
                serde_json::from_str(&output).map_err(|_| host_result_mismatch())
            }
            SelfDispatchOutcome::Failed(failed) => {
                Err(MemoryError::new(&failed.error, &failed.error, &[]))
            }
            _ => Err(host_result_mismatch()),
        }
    }

    fn live_parent(&self) -> MemoryResult<()> {
        self.task_host_binding()?.ok_or_else(|| {
            MemoryError::bad_request("a host coordination call requires its acquired parent lease")
        })?;
        Ok(())
    }
}

fn host_result_mismatch() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "the live-run door returned an unexpected result",
        &[],
    )
}
