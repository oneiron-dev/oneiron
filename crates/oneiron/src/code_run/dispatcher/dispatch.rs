//! Routing of admitted first-party calls to existing verb leaves.
//! Entry: `HostSelfDispatcher::dispatch_effect`.
//! Call definitions belong to `code_run::types`; state stays in `code_run::dispatcher`.

use super::*;

impl HostSelfDispatcher<'_> {
    /// Dispatches one call on behalf of a durable engine-executor replay run.
    ///
    /// The ordinary [`SelfDispatcher`] implementation intentionally has no run
    /// id and preserves the standalone run-ref-only speech identity. The engine
    /// executor owns the durable id and the call's place in the run, so it
    /// enters through this crate-private door and binds them only to
    /// transcript identity and to the receipt a verb write keeps; guest
    /// payloads still cannot name or forge either.
    pub(crate) fn dispatch_for_executor_run(
        &self,
        site: ExecutorCallSite<'_>,
        call: SelfCall,
    ) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, Some(site))
    }

    pub(super) fn dispatch_effect(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let run_id = site.map(|site| site.run_id);
        let agent_verb = match &call {
            SelfCall::AgentVerb(call) => Some(call.verb),
            _ => None,
        };
        let outcome = match call {
            SelfCall::AgentsSpawn(call) => self.dispatch_agents_spawn(*call),
            SelfCall::AgentsPut(call) => {
                let disposition = self.put_agent_definition(
                    &call.id,
                    &call.definition,
                    call.occurred,
                    call.learned_at,
                )?;
                Ok(SelfDispatchOutcome::AgentDefinitionPut(
                    crate::code_run::SelfAgentDefinitionPutResult {
                        id: call.id,
                        disposition,
                    },
                ))
            }
            // A run's own ask and wait take their turn in the vault's task-work
            // line (Rule 5), as the SDK rows do, and run on it.
            SelfCall::TasksAsk(call) => {
                let turn = std::sync::Arc::new(self.task_work_turn()?);
                self.dispatch_tasks_ask(*call, turn)
            }
            SelfCall::TasksWait(call) => {
                let turn = std::sync::Arc::new(self.task_work_turn()?);
                self.dispatch_tasks_wait(call, run_id, turn)
            }
            SelfCall::TasksRefuse(call) => self.dispatch_tasks_refuse(call),
            // The landing reads its refs under the key its door admitted it with.
            SelfCall::ConsultResult(call) => self.dispatch_consult_result(call, read_as),
            SelfCall::SkillsCall(_) => Ok(Self::dispatch_skills_call_unhosted()),
            SelfCall::MemorySearch(call) => self.dispatch_memory_search(call, read_as, site),
            SelfCall::MemoryWriteFixture(call) => self.dispatch_memory_write_fixture(call),
            SelfCall::MemoryPutClaim(call) => self.dispatch_memory_put_claim(call),
            SelfCall::MemorySupersedeClaim(call) => self.dispatch_memory_supersede_claim(call),
            SelfCall::MemoryPutEdge(call) => self.dispatch_memory_put_edge(call, read_as),
            SelfCall::Ask(call) => self.dispatch_ask(call),
            SelfCall::DestructiveFixture(call) => Ok(self.durable_wait(
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
                Some(call.label),
            )),
            SelfCall::OutboundFixture(call) => Ok(self.durable_wait(
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
                Some(call.label),
            )),
            SelfCall::Context(call) => dispatch_self_context(call),
            SelfCall::Speak(call) => self.dispatch_speech(SelfEffect::Speak, call, run_id),
            SelfCall::Think(call) => self.dispatch_speech(SelfEffect::Think, call, run_id),
            SelfCall::Express(call) => self.dispatch_speech(SelfEffect::Express, call, run_id),
            SelfCall::ReportBlocked(call) => self.dispatch_report_blocked(call, run_id),
            SelfCall::InferenceDefaultsRead => self.dispatch_inference_defaults(None),
            SelfCall::InferenceDefaultsReplace(json) => {
                self.dispatch_inference_defaults(Some(&json))
            }
            SelfCall::WakePolicyWrite(call) => self.dispatch_wake_policy_write(call),
            SelfCall::AgentVerb(call) => self.dispatch_agent_verb(call, site),
            SelfCall::ConnectorAnswer(request) => self.dispatch_connector_answer(request, site),
            SelfCall::WorldPrivacySet(input) => self.dispatch_world_privacy_set(&input),
            SelfCall::Fold(call) => self.dispatch_fold(&call, site),
            SelfCall::ReaderSpawn(call) => self.dispatch_reader_spawn(*call, site),
            SelfCall::ReaderReport(call) => self.dispatch_reader_report(call),
            SelfCall::TasksWaitSet(call) => self.dispatch_task_wait_set(call, site),
            SelfCall::Summarize(call) => self.dispatch_summarize(*call, site),
            SelfCall::Leader(call) => self.dispatch_leader(call),
            SelfCall::Team(call) => self.dispatch_team(call),
            SelfCall::TeamSubmit(input) => self.dispatch_team_submit(input),
            // The binding reads its TASK and workflow under the key its door
            // admitted it with.
            SelfCall::WorkflowDispatch(call) => self.dispatch_workflow_bound(*call, read_as),
            // The run repo rows read on the lane their door admitted, under
            // the run's lease, at its executor site (FIX 6867).
            SelfCall::Repo(call) => self.dispatch_repo(call, site, read_as),
        }?;
        self.note_created_from_outcome(agent_verb, &outcome);
        Ok(outcome)
    }
}

impl SelfDispatcher for HostSelfDispatcher<'_> {
    /// Dispatch ordering on the session-bound path (ARCH-0052 §D6):
    ///
    /// 0. the run's `SessionWriteRoute` was captured at RUN ENTRY, in
    ///    [`HostSelfDispatcher::for_off_record_session`] — not here, and never
    ///    per dispatch;
    /// 1. mode-scoped effect policy, below, before anything else but the
    ///    run's participant: a session-bound run's call is answered only
    ///    while they are in the room, checked before the call and again once
    ///    it is done (`ExecutorStorage::answered`);
    /// 2. host envelope, then the write gate;
    /// 3. for on-record supersede only, ONE-1936's stale-target guard inside
    ///    its own transaction;
    /// 4. the apply, through the STORED route, which revalidates itself.
    ///
    /// Canonical dispatch keeps its existing path and captures no route.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, None)
    }
}

/// `self.context(spec)` — validate, normalize, hand the descriptor back.
///
/// Deliberately a free function, not a `HostSelfDispatcher` method: it has no
/// access to the vault, which is the strongest available statement that the
/// call performs no read.
pub(super) fn dispatch_self_context(call: SelfContextCall) -> Result<SelfDispatchOutcome> {
    let spec = crate::context_projection::normalize_context_spec(call.spec);
    crate::context_projection::validate_context_spec(&spec)?;
    Ok(SelfDispatchOutcome::Context(SelfContextResult {
        spec: crate::context_projection::context(spec),
    }))
}
