//! Code-mode composition: host-bound agents.spawn / ask / wait.
use std::sync::Arc;

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::EntityId;
use crate::agent_def::{
    AgentAuthorLease, AgentDefinition, AgentDefinitionPutDisposition, AgentScope,
};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, DispatchAgent, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{
    RunCall, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfEffect, SelfFailedResult, SelfTaskRefusalResult, SelfTaskRefuseCall,
};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{ArtifactError, Error, Result};
use crate::task_verb::{
    ConsultPayloadRef, SelfRefusalInput, TaskAskHandle, TaskAskSpec, TaskAskWait,
};
use crate::temporal::TimeRange;
use crate::{Vault, WriteActor};

/// The most bytes a spawn's intent key holds: its dedupe key's tail.
pub(super) const SPAWN_INTENT_KEY_MAX_BYTES: usize = 256;

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "code-mode spawn requires its bound parent attempt",
    ))
}

/// What a run lends one callable skill its program calls (OF-353): the vault
/// as the host holds it, and the running attempt's lease, read live.
pub(crate) struct CallableSkillLease {
    pub(crate) vault: Arc<Vault>,
    pub(crate) leased: AttemptRecord,
    /// The key the run's door admitted the call with, which the call's verb
    /// hooks read under; `None` when its host binds no door.
    pub(crate) read_as: Option<crate::claim::ScopedReadActorKey>,
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
        let run_ref = status.attempt.run_id.unwrap_or_else(|| {
            format!(
                "agent:{}",
                crate::entity_id::bytes_to_hex_lower(parent.as_bytes())
            )
        });
        let mut dispatcher = Self::new(vault, actor, run_ref)?;
        dispatcher.agent_parent = Some(parent);
        Ok(dispatcher)
    }

    /// The SDK authoring door needs the worker's actual acquired lease.
    /// A caller that only knows the attempt id may spawn, but cannot author.
    pub fn for_leased_agent_attempt(
        vault: &'a Vault,
        actor: WriteActor,
        leased: &AttemptRecord,
    ) -> Result<Self> {
        let mut dispatcher = Self::for_agent_attempt(vault, actor, leased.id)?;
        let binding = AgentAuthorLease::from_leased(leased)?;
        let current = DreamerRunnerStore::new(vault)
            .status(leased.id)?
            .ok_or_else(invalid)?;
        if current.attempt.state != AttemptState::Leased
            || current.attempt.lease_owner.as_deref() != Some(binding.owner.as_str())
            || current.attempt.attempt_count != binding.generation
        {
            return Err(invalid());
        }
        dispatcher.agent_lease = Some(binding);
        Ok(dispatcher)
    }

    /// The sealed binding a host lends this run's TASK creates (OF-532,
    /// `Memory::with_task_host`): the running agent attempt, its lease owner
    /// and generation, read live. `None` only for a canonical run bound to no
    /// agent attempt. A run bound to one whose lease no longer holds, or that
    /// never held it, is refused, never unbound; an off-record run is refused.
    pub fn task_host_binding(&self) -> Result<Option<crate::task_verb::HostBinding>> {
        let vault = self.coordination_vault()?;
        let (parent, lease) = match (self.agent_parent, &self.agent_lease) {
            (None, None) => return Ok(None),
            (Some(parent), Some(lease)) if lease.attempt == parent => (parent, lease),
            _ => return Err(invalid()),
        };
        let live = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&live.payload.input)?;
        if live.attempt.state != AttemptState::Leased
            || live.attempt.lease_owner.as_deref() != Some(lease.owner.as_str())
            || live.attempt.attempt_count != lease.generation
            || agent_dispatch_actor(&input)? != self.actor
        {
            return Err(invalid());
        }
        crate::task_verb::HostBinding::from_leased(&live.attempt, None)
            .map(Some)
            .map_err(|_| invalid())
    }

    /// Lends the run's own vault, as the host holds it, to the callable
    /// skills its program calls (`self.skills.call`, OF-353). A skill runs
    /// only under a leased agent attempt ([`Self::for_leased_agent_attempt`]);
    /// any other run's call answers a typed failure.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `vault` is not the canonical vault this
    /// dispatcher writes into: an off-record room lends no skill.
    pub fn with_callable_skills(mut self, vault: Arc<Vault>) -> Result<Self> {
        match &self.storage {
            ExecutorStorage::Canonical(bound) if std::ptr::eq(*bound, &*vault) => {}
            _ => {
                return Err(Error::InvalidConfig(
                    "callable skills need the run's own canonical vault".to_owned(),
                ));
            }
        }
        self.skill_vault = Some(vault);
        Ok(self)
    }

    fn coordination_vault(&self) -> Result<&Vault> {
        match &self.storage {
            ExecutorStorage::Canonical(vault) => Ok(vault),
            // No durable-record shortcut around an off-record session route.
            ExecutorStorage::Session(_) => Err(invalid()),
        }
    }

    /// Author `vault.agents.put` from this running agent's host-bound identity.
    /// This is an SDK host door, not a `self.spawn` bridge: no child is launched.
    pub fn put_agent_definition(
        &self,
        id: &EntityId,
        definition: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AgentDefinitionPutDisposition> {
        let vault = self.coordination_vault()?;
        let parent = self.agent_parent.ok_or_else(invalid)?;
        let live = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&live.payload.input)?;
        if live.attempt.state != AttemptState::Leased || agent_dispatch_actor(&input)? != self.actor
        {
            return Err(invalid());
        }
        let scope_widens = input
            .scope
            .as_ref()
            .and_then(|scope| scope.world)
            .is_some_and(|world| match &definition.scope {
                AgentScope::Base => false,
                AgentScope::World(id) => *id != world,
                AgentScope::All => true,
            });
        let lease = self.agent_lease.as_ref().ok_or_else(invalid)?;
        vault.put_agent_definition_for_author_with_scope(
            &self.actor.entity_ref(),
            id,
            definition,
            scope_widens,
            Some(lease),
            occurred,
            learned_at,
        )
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
        if call.intent_key.trim().is_empty() || call.intent_key.len() > SPAWN_INTENT_KEY_MAX_BYTES {
            return Err(invalid());
        }
        let now = crate::unix_seconds_now();
        // OF-541: with the host's planner and the agent's lease, an ask is
        // placed and planned; otherwise the named target runs, under the
        // carve the ask's budget narrows.
        let planned = self.planner_bound() && self.agent_lease.is_some();
        let (target, context) = match (call.ask, call.target) {
            (Some(ask), _) if planned => self.planned_spawn(call.context, ask, now)?,
            (ask, Some(target)) => {
                let mut context = call.context;
                if let Some(ask) = ask {
                    super::leader::narrow_budget(&mut context, ask.budget_cap_units.as_ref());
                    // With no planner bound, a leased agent's spawn is still
                    // placed on its need text (the rule rung reads it);
                    // dispatch keeps the stamp.
                    if self.agent_lease.is_some() {
                        context.type_ref = Some(self.place_agent_spawn_type(
                            &ask.need,
                            context.type_ref.as_ref(),
                            None,
                        )?);
                    }
                }
                (target, context)
            }
            (Some(_), None) if self.planner_bound() => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "a planned spawn requires the agent's acquired lease",
                )));
            }
            (Some(_), None) => return Ok(Self::planner_unbound(SelfEffect::AgentsSpawn)),
            (None, None) => return Err(invalid()),
        };
        let result = AgentDispatcher::new(vault).dispatch_with_context(
            DispatchAgent {
                target,
                parent_attempt: Some(parent),
                dedupe_key: Some(format!(
                    "code:{}:{}",
                    crate::entity_id::bytes_to_hex_lower(parent.as_bytes()),
                    call.intent_key
                )),
                run_id: live.attempt.run_id,
                now,
            },
            context,
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

    pub(super) fn dispatch_tasks_ask(&self, mut call: TaskAskSpec) -> Result<SelfDispatchOutcome> {
        let vault = self.coordination_vault()?;
        if let Some(parent) = self.agent_parent {
            let live = DreamerRunnerStore::new(vault)
                .status(parent)?
                .ok_or_else(invalid)?;
            if let Some(task) = live.attempt.task_ref.as_deref() {
                let task = crate::EntityId::from_hex(task)?;
                if call.task_ref.is_some_and(|requested| requested != task) {
                    return Err(invalid());
                }
                call.task_ref = Some(task);
            }
        }
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        Ok(match memory.tasks_ask(&call) {
            Ok(receipt) => SelfDispatchOutcome::TaskAsk(receipt),
            Err(error) => failed(SelfEffect::TasksAsk, error),
        })
    }

    /// `tasks.refuse`: the bound agent's own refusal of the TASK her attempt
    /// realizes, through her dial. A run bound to no TASK has nothing to
    /// refuse, and naming another TASK is refused; both answer as a typed
    /// failure the script can read.
    pub(super) fn dispatch_tasks_refuse(
        &self,
        call: SelfTaskRefuseCall,
    ) -> Result<SelfDispatchOutcome> {
        let refused = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::TasksRefuse,
                error: code.to_owned(),
            })
        };
        let vault = self.coordination_vault()?;
        let Some(parent) = self.agent_parent else {
            return Ok(refused("tasks_refuse_unbound"));
        };
        let live = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let Some(task) = live.attempt.task_ref.as_deref() else {
            return Ok(refused("tasks_refuse_unbound"));
        };
        let task = crate::EntityId::from_hex(task)?;
        if call.task_ref.is_some_and(|requested| requested != task) {
            return Ok(refused("tasks_refuse_other_task"));
        }
        let Ok(reason_ref) = ConsultPayloadRef::parse(vault, &call.reason_ref) else {
            return Ok(refused("tasks_refuse_invalid_reason"));
        };
        let input = SelfRefusalInput {
            domain: call.domain,
            reason_ref,
            at: call.at,
        };
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        Ok(match memory.land_task_refusal(task, &input) {
            Ok(receipt) => SelfDispatchOutcome::TaskRefusal(SelfTaskRefusalResult {
                task_ref: receipt.task_ref,
                level: receipt.level,
                replay: receipt.idempotent_replay,
            }),
            Err(error) => failed(SelfEffect::TasksRefuse, error),
        })
    }

    /// Admits one `self.skills.call` as every call the run serves itself is
    /// admitted (the room's participant, the off-record line, a step past a
    /// write that did not meet its receipt, the bound door), then resolves
    /// the lease its skill runs under. The skill itself runs on the
    /// executor's host, which alone holds a runtime to run it on.
    pub(crate) fn admit_skill_call_for_executor_run(
        &self,
        site: ExecutorCallSite<'_>,
        call: &SelfCall,
    ) -> Result<std::result::Result<CallableSkillLease, SelfDispatchOutcome>> {
        let effect = call.effect();
        self.storage.answered(|| {
            self.enforce_off_record_effect_policy(effect)?;
            if let Some(refused) = self.reader_child_refusal(effect) {
                return Ok(Err(refused));
            }
            if let Some(refused) = self.refusal_past_an_unmet_write(site, Some(call))? {
                return Ok(Err(SelfDispatchOutcome::Denied(SelfDeniedResult {
                    effect,
                    ..refused
                })));
            }
            let read_as = match self.admit_run_call(RunCall::Bridge(effect))? {
                Ok(read_as) => read_as,
                Err(refusal) => {
                    return Ok(Err(SelfDispatchOutcome::Denied(SelfDeniedResult {
                        effect,
                        outcome: refusal.code,
                        reason_codes: Vec::new(),
                    })));
                }
            };
            Ok(self
                .callable_skill_lease()?
                .map(|lease| CallableSkillLease { read_as, ..lease }))
        })
    }

    /// The running attempt's lease, read live: the attempt this dispatcher
    /// was bound to, still leased to the same owner in the same generation.
    /// A run with no leased attempt, or whose host lent no vault, answers a
    /// typed failure the script can read.
    fn callable_skill_lease(
        &self,
    ) -> Result<std::result::Result<CallableSkillLease, SelfDispatchOutcome>> {
        let refused = |code: &str| -> std::result::Result<CallableSkillLease, SelfDispatchOutcome> {
            Err(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::SkillsCall,
                error: code.to_owned(),
            }))
        };
        let Some(lease) = &self.agent_lease else {
            return Ok(refused("skills_call_unleased"));
        };
        let Some(vault) = &self.skill_vault else {
            return Ok(refused("skills_call_unbound"));
        };
        let live = AttemptQueue::new(vault)
            .get(lease.attempt)?
            .filter(|record| {
                record.state == AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(lease.owner.as_str())
                    && record.attempt_count == lease.generation
            });
        let Some(leased) = live else {
            return Ok(refused("skills_call_lease_lost"));
        };
        Ok(Ok(CallableSkillLease {
            vault: Arc::clone(vault),
            leased,
            read_as: None,
        }))
    }

    /// A `self.skills.call` dispatched with no runtime to run its skill on.
    /// The skill runs a step of its own, on a sibling runtime the caller's
    /// step lends the executor's host while it waits on the call; nothing
    /// that reaches the dispatcher directly holds one.
    pub(super) fn dispatch_skills_call_unhosted() -> SelfDispatchOutcome {
        SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: SelfEffect::SkillsCall,
            error: "skills_call_no_runtime".to_owned(),
        })
    }

    pub(super) fn dispatch_tasks_wait(
        &self,
        handle: TaskAskHandle,
        run_id: Option<EntityId>,
    ) -> Result<SelfDispatchOutcome> {
        let vault = self.coordination_vault()?;
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        // Only a persisted bridge result acknowledges a void. If the process
        // died after returning Changed but before replay append, it is offered
        // again; a later distinct void has a higher generation and re-wakes.
        let mut observed = 0;
        if let Some(run_id) = run_id
            && let Some(record) = vault.get_code_run_replay_record(&run_id)?
        {
            let request =
                super::super::payload::self_call_request_value(&SelfCall::TasksWait(handle))?;
            for call in &record.bridge_calls {
                if call.effect == SelfEffect::TasksWait
                    && call.request == request
                    && let SelfDispatchOutcome::TaskAskStatus(
                        crate::task_verb::TaskAskStatus::Changed { generation, .. },
                    ) = super::super::payload::decode_self_dispatch_outcome(&call.outcome)?
                {
                    observed = observed.max(generation);
                }
            }
            crate::task_verb::ack_option_void_generation(vault, handle.group_ref, observed)?;
        }
        Ok(match memory.tasks_wait_observing(handle, None, observed) {
            Ok(TaskAskWait::Ready(result)) => {
                SelfDispatchOutcome::TaskAskStatus(crate::task_verb::TaskAskStatus::Settled(result))
            }
            Ok(TaskAskWait::Park(wait)) => SelfDispatchOutcome::DurableWait(wait),
            Ok(TaskAskWait::Changed { voided, generation }) => {
                SelfDispatchOutcome::TaskAskStatus(crate::task_verb::TaskAskStatus::Changed {
                    voided,
                    generation,
                })
            }
            Ok(TaskAskWait::Pending { .. }) => failed(
                SelfEffect::TasksWait,
                crate::memory::MemoryError::bad_request("external wait on engine step"),
            ),
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
