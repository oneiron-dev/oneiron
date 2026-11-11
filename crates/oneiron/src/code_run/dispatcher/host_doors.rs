//! Typed coordination calls whose credential admission and verb hooks are
//! owned by the host's verb-table door. The dispatcher retains the acquired
//! parent lease, planner, attenuation and project-write gates.
use super::HostSelfDispatcher;
use crate::EntityId;
use crate::agent_dispatch::AgentWaitSetResult;
use crate::code_run::{
    AgentSpawnInput, AgentSpawnOutput, LeaderSplitInput, LeaderSplitOutput, ReportBlockedInput,
    ReportBlockedOutput, SelfDispatchOutcome, TaskRefuseInput, TaskRefuseOutput,
    TaskWaitAgentsRequest,
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
        let dispatcher = Self::for_leased_agent_attempt(vault, actor, &leased)?;
        let dispatcher = match binding.executor_run() {
            Some(run) => dispatcher.with_bound_run(run),
            None => dispatcher,
        };
        // A host door writes as the run: the external effects its durable
        // replay record holds, and the external replies its waits consumed,
        // stay in that write's lineage (ONE-1314), as they do in its steps.
        if let Some(run) = binding.executor_run()
            && let Some(record) = vault.get_code_run_replay_record(&run)?
        {
            dispatcher.observe_bridge_lineage(&record.bridge_calls);
            dispatcher.observe_consumed_code_replies(&record)?;
        }
        Ok(dispatcher)
    }

    /// Mints a proposal's ordinary gated provenance from a request this
    /// host actually served under the same live-run attachment. `stamp` and
    /// the change come from the admitted native proposal door, not a wire
    /// provenance assertion.
    pub fn repo_sources_from_host(
        &self,
        stamp: &crate::memory::repo_doors::RepoRunStamp,
        path: String,
        content_hash: [u8; 32],
        witness: &super::RepoRequestWitness,
    ) -> MemoryResult<crate::memory::repo_doors::RepoRunSources> {
        self.live_parent()?;
        let crate::code_run::storage::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(MemoryError::bad_request(
                "a repo proposal requires canonical live-run storage",
            ));
        };
        self.repo_run_sources_with_witness(
            vault,
            stamp,
            &super::repo_sources::RepoChange { path, content_hash },
            witness,
            crate::code_run::SelfEffect::RepoProposalSubmit,
        )
        .map_err(crate::memory::MemoryError::from)?
    }

    /// The write origin of a browser call admitted on this live run. Its
    /// envelope and parent binding come from the run, never the HTTP input.
    pub fn browser_origin_from_host(
        &self,
        verb: crate::task_verb::sdk::AgentVerb,
    ) -> MemoryResult<crate::memory::HostWriteOrigin> {
        self.live_parent()?;
        if !verb.is_browser() {
            return Err(MemoryError::bad_request("a browser verb is required"));
        }
        Ok(
            crate::memory::HostWriteOrigin::new(self.agent_verb_envelope(verb, None)?)
                .with_task_host(self.task_host_binding()?)
                .with_model_provider(self.model_provider()),
        )
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
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        match self.dispatch_agents_spawn(input.into_call()?)? {
            SelfDispatchOutcome::AgentSpawn(spawn) => Ok(spawn.into()),
            SelfDispatchOutcome::Failed(failed) => {
                Err(MemoryError::new(&failed.error, &failed.error, &[]))
            }
            _ => Err(host_result_mismatch()),
        }
    }

    /// The host door's `tasks.wait` over AGENT children (slice 6.5b), after
    /// its credential and hooks admitted the call: the wait of this
    /// dispatcher's own leased attempt over children it spawned. A host
    /// caller has no executor step to park, so a wait that is not done
    /// answers its reduction as it stands, and the caller asks again under
    /// the same step key.
    pub fn wait_agents_from_host(
        &self,
        input: TaskWaitAgentsRequest,
    ) -> MemoryResult<AgentWaitSetResult> {
        // An id-only binding is not a public host call's acquired lease.
        self.live_parent()?;
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        let call = input.into_call();
        let agents = call.agents.clone().unwrap_or_default();
        match self.dispatch_agent_wait(&call, &agents, false)? {
            SelfDispatchOutcome::AgentVerb(answer) => {
                serde_json::from_value(answer.output).map_err(|_| host_result_mismatch())
            }
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
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        // The claims it names resolve under the actor's own read (FIX 1214).
        match self.dispatch_memory_supersede_claim(input.into_call()?, None)? {
            SelfDispatchOutcome::MemoryWrite(written) => {
                Ok(crate::code_run::MemoryWriteOutput { id: written.id })
            }
            SelfDispatchOutcome::Failed(failed) => {
                Err(MemoryError::new(&failed.error, &failed.error, &[]))
            }
            _ => Err(host_result_mismatch()),
        }
    }

    /// The attached generated writer puts one claim through its existing
    /// consent, envelope and claim gates (FIX 3983). The host stamps the
    /// actor, `Generated` source, lineage and provenance; no field of the
    /// request names them. Where it lands is decided per predicate
    /// (ARCH-0040, #mcp:5, #ONE-1184-D1): a claim of a class the policy
    /// declares critical asks Proposed and parks with its pending review; any
    /// other asks Auto and lands at once when the gates allow it, and a gate
    /// that pends the Auto request (an actor ceiling, a missing source-trust
    /// permit, a checker hold) lands it Proposed with its pending review, as
    /// the Memory claim door does. The Auto request reaches the host's auto
    /// checker as a Dreamer write does; this door injects no checker, so a
    /// vault that names one holds it checker-unavailable (review 6881 P1).
    pub fn put_claim_from_host(
        &self,
        input: crate::code_run::MemoryClaimInput,
    ) -> MemoryResult<crate::code_run::MemoryWriteOutput> {
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        let crate::code_run::storage::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(MemoryError::bad_request(
                "a live-run claim put requires canonical live-run storage",
            ));
        };
        let declared_critical = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            crate::gate::resolve_policy_manifest(&vault.store, &txn)?
                .declares_predicate_critical(&input.predicate)
        };
        let call =
            crate::code_run::run_verb_call::claim_put_call(input, crate::unix_seconds_now())?;
        let outcome = if declared_critical {
            self.dispatch_memory_put_claim_requesting(
                call,
                None,
                crate::claim::ClaimApprovalStatus::Proposed,
                true,
            )?
        } else {
            match self.dispatch_memory_put_claim_requesting(
                call.clone(),
                None,
                crate::claim::ClaimApprovalStatus::Auto,
                true,
            ) {
                Err(error) if crate::gate::gate_rejection_pends(&error) => self
                    .dispatch_memory_put_claim_requesting(
                        call,
                        None,
                        crate::claim::ClaimApprovalStatus::Proposed,
                        true,
                    )?,
                outcome => outcome?,
            }
        };
        match outcome {
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
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
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
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        match self.dispatch_tasks_refuse(input.into_call(crate::unix_seconds_now())?, None)? {
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

    /// The host door's `self.report_blocked`, under its admitted credential
    /// and hooks. The report is witnessed on the attached run through the
    /// same dispatch as code mode: the host stamps the next free speech
    /// position of the executor run and the time. A standalone dispatcher
    /// without an executor binding keeps its attempt-based identity. The receipt
    /// binds this run's own attempt, and filing wakes the Coach's Issues job.
    /// The report arms nothing: no authority, scope, self-clear or task completion.
    pub fn report_blocked_from_host(
        &self,
        input: ReportBlockedInput,
    ) -> MemoryResult<ReportBlockedOutput> {
        self.live_parent()?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        let parent = self.agent_parent.ok_or_else(|| {
            MemoryError::bad_request("a blocked report requires its acquired parent lease")
        })?;
        let run_id = match self.bound_run {
            Some(run) => run,
            None => EntityId::from_bytes(*parent.as_bytes())?,
        };
        let crate::code_run::storage::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(MemoryError::bad_request(
                "a blocked report requires canonical live-run storage",
            ));
        };
        // The live-run hold serializes this call with the run's executor
        // entries, so the first free speech position stays free until the
        // witness lands.
        let mut order = 0u32;
        while vault
            .get_raw(&crate::code_run::executor_speech_message_id_in_run(
                &self.run_ref,
                run_id,
                order,
            )?)?
            .is_some()
        {
            order = order
                .checked_add(1)
                .ok_or_else(|| MemoryError::bad_request("the run's speech positions are spent"))?;
        }
        let call = input.into_call().stamped(order, crate::unix_seconds_now());
        match self.dispatch_report_blocked(call, Some(run_id))? {
            SelfDispatchOutcome::ReportBlocked { receipt } => Ok(ReportBlockedOutput {
                receipt: receipt.to_hex(),
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
        input: crate::task_verb::fanout_batch::FanoutBatchInput,
        proof: &crate::authority::VerifiedSlip,
        locality: crate::claim::CallerLocality,
        decisions: Option<&crate::fanout_auto::FanoutDecisions<'_>>,
    ) -> MemoryResult<crate::task_verb::fanout_batch::FanoutBatchView> {
        self.live_parent()?;
        let binding = self.task_host_binding()?.ok_or_else(|| {
            MemoryError::bad_request("a batch requires its caller's acquired parent lease")
        })?;
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        // The call holds its leased run's tool witness open (FIX 8521).
        let _tool = self.activity_tool();
        let crate::code_run::storage::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(MemoryError::bad_request(
                "a batch requires canonical live-run storage",
            ));
        };
        vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
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
