//! Code-mode composition: host-bound agents.spawn / tasks.ask / tasks.wait.
use super::HostSelfDispatcher;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, DispatchAgent, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::attempt_queue::AttemptId;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{
    SelfAgentSpawnCall, SelfAgentSpawnResult, SelfDispatchOutcome, SelfEffect, SelfFailedResult,
};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{ArtifactError, Error, Result};
use crate::task_verb::{TaskAskHandle, TaskAskSpec, TaskAskWait};
use crate::{Vault, WriteActor};

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "code-mode spawn requires its bound parent attempt",
    ))
}

impl<'a> HostSelfDispatcher<'a> {
    /// Host entry for a running AGENT_DEF. Guest arguments cannot replace its
    /// parent, actor, or run. Live dispatch applies the existing narrowing and
    /// depth law; a widening returns the existing typed proposal, never a child.
    pub fn for_agent_attempt(
        vault: &'a Vault,
        actor: WriteActor,
        parent: AttemptId,
    ) -> Result<Self> {
        let status = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&status.payload.input)?;
        if status.payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
            || agent_dispatch_actor(&input)? != actor
        {
            return Err(invalid());
        }
        let run_ref = status.attempt.run_id.clone().unwrap_or_else(|| {
            format!(
                "agent:{}",
                crate::entity_id::bytes_to_hex_lower(parent.as_bytes())
            )
        });
        let mut dispatcher = Self::new(vault, actor, run_ref)?;
        dispatcher.agent_parent = Some(parent);
        Ok(dispatcher)
    }

    fn coordination_vault(&self) -> Result<&Vault> {
        match &self.storage {
            ExecutorStorage::Canonical(vault) => Ok(vault),
            // No durable-record shortcut around an off-record session route.
            ExecutorStorage::Session(_) => Err(invalid()),
        }
    }

    pub(super) fn dispatch_agents_spawn(
        &self,
        call: SelfAgentSpawnCall,
    ) -> Result<SelfDispatchOutcome> {
        let vault = self.coordination_vault()?;
        let parent = self.agent_parent.ok_or_else(invalid)?;
        let live = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&live.payload.input)?;
        if agent_dispatch_actor(&input)? != self.actor {
            return Err(invalid());
        }
        if call.intent_key.trim().is_empty() || call.intent_key.len() > 256 {
            return Err(invalid());
        }
        let result = AgentDispatcher::new(vault).dispatch_with_context(
            DispatchAgent {
                target: call.target,
                parent_attempt: Some(parent),
                dedupe_key: Some(format!(
                    "code:{}:{}",
                    crate::entity_id::bytes_to_hex_lower(parent.as_bytes()),
                    call.intent_key
                )),
                run_id: live.attempt.run_id,
                now: crate::unix_seconds_now(),
            },
            call.context,
        )?;
        Ok(SelfDispatchOutcome::AgentSpawn(match result {
            AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status) => {
                SelfAgentSpawnResult::Queued {
                    attempt_ref: status.attempt.id,
                }
            }
            AgentDispatchOutcome::WorkflowDispatched(status)
            | AgentDispatchOutcome::WorkflowExisting(status) => SelfAgentSpawnResult::Queued {
                attempt_ref: status.attempt.id,
            },
            AgentDispatchOutcome::ProposedWiden(proposal) => SelfAgentSpawnResult::ProposedWiden {
                proposal_ref: proposal.proposal_id,
            },
        }))
    }

    pub(super) fn dispatch_tasks_ask(&self, call: TaskAskSpec) -> Result<SelfDispatchOutcome> {
        let vault = self.coordination_vault()?;
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        Ok(match memory.tasks_ask(&call) {
            Ok(receipt) => SelfDispatchOutcome::TaskAsk(receipt),
            Err(error) => failed(SelfEffect::TasksAsk, error),
        })
    }

    pub(super) fn dispatch_tasks_wait(&self, handle: TaskAskHandle) -> Result<SelfDispatchOutcome> {
        let vault = self.coordination_vault()?;
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        Ok(match memory.tasks_wait(handle) {
            Ok(TaskAskWait::Ready(status)) => SelfDispatchOutcome::TaskAskStatus(status),
            Ok(TaskAskWait::Park(wait)) => SelfDispatchOutcome::DurableWait(wait),
            Err(error) => failed(SelfEffect::TasksWait, error),
        })
    }
}

fn failed(effect: SelfEffect, error: crate::memory::MemoryError) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect,
        error: error.code,
    })
}
