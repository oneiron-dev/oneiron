//! A scoped child's port calls (FIX 7507 PR2): the verbs its parent lent
//! it, each run by the adapter its host registered for it, on the child's
//! own route.
//!
//! Each meets the run's write protocol ([`super`]) with the adapter in the
//! door's place, after four checks in order: the exact lent verb
//! (`scoped_child_call_allowed`), a registered adapter
//! (`scoped_child_service_admission`), the scoped door's Grant check, and
//! the job still live at its claimed generation. A write keeps its receipt
//! at its place in its step on the run's route, reserved before the adapter
//! runs: the same write made again in a resumed step gets its kept answer
//! back and runs nothing; a changed one fails closed. Nothing here asks
//! where the caller, the child or the vault runs.

use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::scoped_child::{
    SCOPED_CHILD_PORT_NOT_LENT, ScopedChildCallContext, scoped_child_call_allowed,
    scoped_child_service_admission,
};
use crate::code_run::types::{
    AgentVerbRefusal, RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;
use crate::runtime_hooks::VerbHookStop;

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{
    KeptWrite, PROVIDER_UNAVAILABLE, VERB_HOOK_HIDDEN, VERB_HOOK_STOPPED, answered, never_ran_mark,
};

/// What a port call answers once the child's job settled, or was claimed
/// again since its dispatcher bound it.
const READER_TASK_SETTLED: &str = "reader_task_settled";

impl HostSelfDispatcher<'_> {
    /// `call` from a scoped child: refused unless its loan lent the verb and
    /// its host serves it, while its authority stands and its job is live;
    /// then run by its host's adapter, a write under its receipt.
    pub(super) fn dispatch_scoped_port(
        &self,
        call: SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let refused = |code: &str| {
            answered(Err(AgentVerbRefusal {
                code: code.to_owned(),
            }))
        };
        let (Some(child), Some(spec)) = (self.reader_child(), self.scoped_child_spec()) else {
            return Err(Error::InvariantViolation(
                "a port call needs a scoped child",
            ));
        };
        if !scoped_child_call_allowed(spec, call.verb) {
            return Ok(refused(SCOPED_CHILD_PORT_NOT_LENT));
        }
        let ports = match scoped_child_service_admission(self.scoped_ports.as_deref(), call.verb) {
            Ok(ports) => ports,
            Err(refusal) => return Ok(answered(Err(refusal))),
        };
        // The scoped door's Grant check, at every port call.
        if let Err(refusal) = self.admit_run_call(RunCall::Bridge(SelfEffect::AgentVerb))? {
            return Ok(answered(Err(refusal)));
        }
        if !self.reader_job_live()? {
            return Ok(refused(READER_TASK_SETTLED));
        }
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?)
                .with_model_provider(self.model_provider());
        let parked = SelfCall::AgentVerb(call.clone());
        let invocation = self.verb_invocation(&parked, site)?;
        let origin = origin.with_hook_ask(self.parked_ask(&parked, site)?);
        let ctx = ScopedChildCallContext::new(self, child, spec);
        let Some(site) = site.filter(|_| call.verb.writes()) else {
            return Ok(answered(ports.call(&ctx, &call, &origin, invocation)?));
        };
        let (_, receipt_id, kept) = self.write_receipt(site)?;
        let stopped = match kept {
            KeptWrite::Ran(receipt) => {
                return self.kept_write_answer(self.agent_verbs.as_deref(), *receipt, call);
            }
            KeptWrite::Fresh(stopped) => stopped,
        };
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self.put_write_receipt(&receipt, stopped, None, false, site.run_id)?;
        let outcome = match ports.call(&ctx, &call, &origin, invocation) {
            Ok(answer) => answered(answer),
            Err(Error::VerbHook(stop)) if matches!(*stop, VerbHookStop::Hidden { .. }) => {
                refused(VERB_HOOK_HIDDEN)
            }
            // A hook's skip or ask, or no provider answering, stopped the
            // write before it ran: the receipt keeps the mark, and the stop
            // goes to the dispatcher.
            Err(error @ (Error::VerbHook(_) | Error::ProviderUnavailable { .. })) => {
                let why = if matches!(error, Error::VerbHook(_)) {
                    VERB_HOOK_STOPPED
                } else {
                    PROVIDER_UNAVAILABLE
                };
                receipt.bridge_calls.push(CodeRunBridgeCall::record(
                    0,
                    &SelfCall::AgentVerb(call),
                    &never_ran_mark(why),
                    0,
                    0,
                )?);
                self.storage
                    .put_code_run_replay_record_if_generation_with_heal(
                        &receipt,
                        Some(generation),
                        None,
                    )?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        receipt.bridge_calls.push(CodeRunBridgeCall::record(
            0,
            &SelfCall::AgentVerb(call),
            &outcome,
            0,
            0,
        )?);
        self.put_write_receipt(&receipt, Some(generation), None, true, site.run_id)?;
        Ok(outcome)
    }
}
