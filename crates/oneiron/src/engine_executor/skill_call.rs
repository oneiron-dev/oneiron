//! One callable bridge entry between turns of an attached, leased run.
//! The host holds the same live-run guard as the model executor. Its bridge
//! rows and result bodies join that run; it creates no run or model turn.
use crate::code_run::{
    ExecutorStorage, GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfSkillCall,
};
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use crate::task_verb::HostBinding;
use crate::{EntityId, ModelId, Vault};

use super::host::{CallableChecks, RecordingJsHost};
use super::{JsCodeModeHost, JsCodeModeRuntime, TypeFeedback};

/// Executes the host projection of `self.skills.call`. The caller has already
/// admitted its credential and verb hooks; nested calls keep their normal
/// hooks and this dispatcher's credential door. The sealed binding supplies
/// the lease and run identity, never request text. Each callable it runs is
/// type-checked on `type_feedback`, the host's service, its feedback kept
/// beside the run and never in the answer (FIX 10389).
pub fn execute_live_skill_call(
    vault: &Vault,
    binding: &HostBinding,
    dispatcher: &GatedActorWrite<'_>,
    executor: &ModelId,
    input: crate::code_run::SkillCallInput,
    (runtime, type_feedback): (&mut dyn JsCodeModeRuntime, Option<&TypeFeedback>),
) -> MemoryResult<serde_json::Value> {
    let lent = (runtime, type_feedback);
    execute_live_skill_call_listing(vault, binding, dispatcher, executor, input, lent).0
}

/// [`execute_live_skill_call`], beside the rows its answer stands on
/// (DEC-0005): each stored skill a callable in it read and loaded (the one
/// requested, the skill or proposal its load chose, and every one it
/// called), the rows of each result a read took from another run, and the
/// union of the rows the run's recorded and this call's nested verb answers
/// were served from. `None` when one of those kept no set; a refusal before
/// the call runs lists none.
pub fn execute_live_skill_call_listing(
    vault: &Vault,
    binding: &HostBinding,
    dispatcher: &GatedActorWrite<'_>,
    executor: &ModelId,
    input: crate::code_run::SkillCallInput,
    lent: (&mut dyn JsCodeModeRuntime, Option<&TypeFeedback>),
) -> (MemoryResult<serde_json::Value>, Option<Vec<EntityId>>) {
    let mut rows = Some(Vec::new());
    let answer = live_skill_call(vault, binding, dispatcher, executor, input, lent, &mut rows);
    (answer, rows)
}

fn live_skill_call(
    vault: &Vault,
    binding: &HostBinding,
    dispatcher: &GatedActorWrite<'_>,
    executor: &ModelId,
    input: crate::code_run::SkillCallInput,
    (runtime, type_feedback): (&mut dyn JsCodeModeRuntime, Option<&TypeFeedback>),
    rows: &mut Option<Vec<EntityId>>,
) -> MemoryResult<serde_json::Value> {
    let leased = binding.leased_record(vault)?;
    let run = binding
        .executor_run()
        .ok_or_else(|| MemoryError::bad_request("no executor run"))?;
    let mut record = vault
        .get_code_run_replay_record(&run)?
        .ok_or_else(|| MemoryError::bad_request("no live run record"))?;
    let determinism = record
        .determinism
        .ok_or_else(|| MemoryError::bad_request("live run has unknown determinism"))?;
    let generation = record.generation()?;
    let seq = record.bridge_calls.len() as u64;
    let skill = EntityId::from_hex(&input.skill)?;
    let root = vault
        .runtime()
        .attempt_cancels()
        .register(leased.id, leased.attempt_count);
    let storage = ExecutorStorage::Canonical(vault);
    dispatcher.observe_bridge_history(&record.bridge_calls);
    let author = crate::agent_def::AgentAuthorLease::from_leased(&leased)?;
    let _writes = crate::skill_attribution::enter_run_writes(&author);
    let mut host = RecordingJsHost::new(dispatcher, run, seq, determinism, None)
        .with_recoverable_outputs(&storage, &record, Vec::new())
        .map_err(engine_error)?
        .with_skill_executor(executor)
        .with_admitted_skill_call(seq)
        // A call between turns is checked as a call of the step the run
        // is at, under its own bridge position (FIX 10389).
        .with_callable_checks(CallableChecks::new(
            type_feedback,
            record.step_checkpoints.len() as u64,
        ));
    let answer = host.dispatch_self_nested_cancellable(
        SelfCall::SkillsCall(SelfSkillCall {
            skill,
            args: input.args,
        }),
        runtime,
        root.token(),
    );
    // The dispatch held the call's whole answer for this caller when its
    // outer post chain may still run on it: the recorded outcome below is
    // then its record-only card, and this entry returns the whole answer
    // in its place, as a small answer is returned. Taken before the
    // record takes the host's calls.
    let outer_answer = host.admitted_skill_answer.take();
    // Read before the record takes the step's calls, failed or not: the
    // run's result rows already hold the callable rows (FIX 5460).
    *rows = host.result_rows();
    record.record_callable_rows(rows.clone());
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
    let view = answer.view;
    match answer.outcome {
        SelfDispatchOutcome::SkillCall(result) => {
            Ok(shown_skill_output(result.output, view, outer_answer))
        }
        SelfDispatchOutcome::Denied(denied) => Err(MemoryError::new(
            &denied.outcome,
            "the skill call was refused",
            &[],
        )),
        SelfDispatchOutcome::Failed(failed) => Err(MemoryError::new(
            failed.code.as_deref().unwrap_or(MEMORY_CODE_INTERNAL),
            failed.error,
            &[],
        )),
        _ => Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "the skill call did not return an answer",
            &[],
        )),
    }
}

/// What this entry's caller reads for a skill call's recorded `output`:
/// a verb hook's view of it when one was served (its `output` member, as
/// the code-mode bridge frames it), else the whole answer held for the
/// outer caller's own post chain, else the recorded output itself, its
/// card for a large answer included. The run record this entry persisted
/// binds no name to the real body in the first two cases: its dispatch
/// recorded that body record-only.
fn shown_skill_output(
    output: serde_json::Value,
    view: Option<serde_json::Value>,
    outer: Option<serde_json::Value>,
) -> serde_json::Value {
    match (view, outer) {
        (Some(serde_json::Value::Object(mut fields)), _) => match fields.remove("output") {
            Some(output) => output,
            None => serde_json::Value::Object(fields),
        },
        (Some(view), _) => view,
        (None, Some(answer)) => answer,
        (None, None) => output,
    }
}

fn engine_error(error: super::EngineExecutorError) -> MemoryError {
    match error {
        super::EngineExecutorError::Engine(error) => error.into(),
        error => MemoryError::new(MEMORY_CODE_INTERNAL, error.to_string(), &[]),
    }
}
