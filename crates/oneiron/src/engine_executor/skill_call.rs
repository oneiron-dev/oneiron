//! One callable bridge entry between turns of an attached, leased run.
//! The host holds the same live-run guard as the model executor. Its bridge
//! rows and result bodies join that run; it creates no run or model turn.
use crate::code_run::{
    ExecutorStorage, GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfSkillCall,
};
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use crate::task_verb::HostBinding;
use crate::{EntityId, ModelId, Vault};

use super::host::RecordingJsHost;
use super::{JsCodeModeHost, JsCodeModeRuntime};

/// Executes the host projection of `self.skills.call`. The caller has already
/// admitted its credential and verb hooks; nested calls keep their normal
/// hooks and this dispatcher's credential door. The sealed binding supplies
/// the lease and run identity, never request text.
pub fn execute_live_skill_call(
    vault: &Vault,
    binding: &HostBinding,
    dispatcher: &GatedActorWrite<'_>,
    executor: &ModelId,
    input: crate::code_run::SkillCallInput,
    runtime: &mut dyn JsCodeModeRuntime,
) -> MemoryResult<serde_json::Value> {
    let leased = binding.leased_record(vault)?;
    let run = binding
        .executor_run()
        .ok_or_else(|| MemoryError::bad_request("no executor run"))?;
    let mut record = vault
        .get_code_run_replay_record(&run)?
        .ok_or_else(|| MemoryError::bad_request("no live run record"))?;
    let generation = record.generation()?;
    let seq = record.bridge_calls.len() as u64;
    let skill = EntityId::from_hex(&input.skill)?;
    let root = vault
        .attempt_cancels
        .register(leased.id, leased.attempt_count);
    let storage = ExecutorStorage::Canonical(vault);
    dispatcher.observe_bridge_history(&record.bridge_calls);
    let author = crate::agent_def::AgentAuthorLease::from_leased(&leased)?;
    let _writes = crate::skill_attribution::enter_run_writes(&author);
    let mut host = RecordingJsHost::new(dispatcher, run, seq, record.determinism, None)
        .with_recoverable_outputs(&storage, &record, Vec::new())
        .map_err(engine_error)?
        .with_skill_executor(executor)
        .with_admitted_skill_call(seq);
    let answer = host.dispatch_self_nested_cancellable(
        SelfCall::SkillsCall(SelfSkillCall {
            skill,
            args: input.args,
        }),
        runtime,
        root.token(),
    );
    // Keep all recorded nested calls even when the callable failed. Loading
    // and a callable invocation witness never settle the attempt's outcome.
    record.bridge_calls.extend(host.bridge_calls);
    record.outputs.extend(host.captured);
    for binding in host.bound {
        match record
            .bindings
            .iter_mut()
            .find(|held| held.name == binding.name)
        {
            Some(held) => *held = binding,
            None => record.bindings.push(binding),
        }
    }
    vault.put_code_run_replay_record_if_generation(&record, Some(generation))?;
    let answer = answer?;
    match answer.outcome {
        SelfDispatchOutcome::SkillCall(result) => Ok(result.output),
        SelfDispatchOutcome::Denied(denied) => Err(MemoryError::new(
            &denied.outcome,
            "the skill call was refused",
            &[],
        )),
        SelfDispatchOutcome::Failed(failed) => {
            Err(MemoryError::new(MEMORY_CODE_INTERNAL, failed.error, &[]))
        }
        _ => Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "the skill call did not return an answer",
            &[],
        )),
    }
}

fn engine_error(error: super::EngineExecutorError) -> MemoryError {
    match error {
        super::EngineExecutorError::Engine(error) => error.into(),
        error => MemoryError::new(MEMORY_CODE_INTERNAL, error.to_string(), &[]),
    }
}
