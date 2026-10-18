//! Typed coordination calls whose credential admission and verb hooks are
//! owned by the host's verb-table door. The dispatcher retains the acquired
//! parent lease, planner, attenuation and project-write gates.
use super::HostSelfDispatcher;
use crate::EntityId;
use crate::code_run::{
    AgentSpawnInput, AgentSpawnKind, AgentSpawnOutput, LeaderSplitInput, LeaderSplitOutput,
    SelfAgentSpawnResult, SelfDispatchOutcome, TaskRefuseInput, TaskRefuseOutput,
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

    /// The attached generated writer supersedes through its existing consent,
    /// envelope and claim/edge gates. No source field comes from the request.
    pub fn supersede_claim_from_host(
        &self,
        input: crate::code_run::MemorySupersedeInput,
    ) -> MemoryResult<crate::code_run::MemoryWriteOutput> {
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        match self.dispatch_memory_supersede_claim(input.into_call()?)? {
            SelfDispatchOutcome::MemoryWrite(written) => {
                Ok(crate::code_run::MemoryWriteOutput { id: written.id })
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

    /// Applies the attached agent's refusal only to the TASK of her live
    /// attempt. The existing engine door resolves the dial and owns replay.
    pub fn refuse_task_from_host(&self, input: TaskRefuseInput) -> MemoryResult<TaskRefuseOutput> {
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        match self.dispatch_tasks_refuse(input.into_call(crate::unix_seconds_now())?)? {
            SelfDispatchOutcome::TaskRefusal(refusal) => Ok(TaskRefuseOutput {
                task: refusal.task_ref,
                level: refusal.level,
                outcome: refusal.level.outcome(),
                replay: refusal.replay,
            }),
            SelfDispatchOutcome::Failed(failed) => {
                Err(MemoryError::new(&failed.error, &failed.error, &[]))
            }
            _ => Err(host_result_mismatch()),
        }
    }

    /// A typed batch uses this same acquired parent lease, then the existing
    /// wave launch gate and child routing. No child receives a copied cap.
    pub fn spawn_fanout_from_host(
        &self,
        input: crate::task_verb::sdk::FanoutBatchInput,
        proof: &crate::authority::VerifiedSlip,
        locality: crate::claim::CallerLocality,
        decisions: Option<&crate::fanout_auto::FanoutDecisions<'_>>,
    ) -> MemoryResult<crate::task_verb::sdk::FanoutBatchView> {
        self.live_parent()?;
        let binding = self.task_host_binding()?.ok_or_else(|| {
            MemoryError::bad_request("a batch requires its caller's acquired parent lease")
        })?;
        let _run_writes = self.agent_lease.as_ref().map(crate::skill_attribution::enter_run_writes);
        let crate::code_run::storage::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(MemoryError::bad_request("a batch requires canonical live-run storage"));
        };
        vault.memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_read_proof(proof)
            .at(locality)
            .with_task_host(binding)
            .spawn_fanout_batch(input, decisions)
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
