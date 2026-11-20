//! One callable bridge entry between turns of an attached, leased run.
//! The host holds the same live-run guard as the model executor. Its bridge
//! rows and result bodies join that run; it creates no run or model turn.
use serde_json::value::RawValue;

use crate::code_run::{
    CodeRunReplayRecord, CodeRunResultBinding, ExecutorStorage, GatedActorWrite, SelfCall,
    SelfDispatchOutcome, SelfSkillCall, result_card,
};
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use crate::runtime_hooks::VerbHookPre;
use crate::store::BodySink;
use crate::task_verb::{HostBinding, verb_hook_boundary};
use crate::{EntityId, ModelId, Vault};

use super::host::{CallableChecks, RecordingJsHost, text_nests_past_whole_depth};
use super::store::{
    ByteCount, RESULT_REPLY_INLINE_BYTES, store_ordinal_base, store_result_output_path, write_json,
};
use super::{JsCodeModeHost, JsCodeModeRuntime, TypeFeedback};

/// How many times the admitted view spill re-reads the run record and
/// appends again when another writer lands first: past it the caller keeps
/// the view inline.
const ADMITTED_VIEW_SPILL_RETRIES: u8 = 8;

/// An admitted skill call's answer as its caller's post chain takes it: one
/// value, or, for an answer nesting past what a value may hold that the
/// caller's live post chain must judge whole, its JSON text, which no value
/// is built from (SKILL-ANSWER-DEEP-JSON-STACK-SAFE). The caller judges
/// that text with [`judge_admitted_skill_text`].
#[derive(Debug)]
pub enum AdmittedSkillAnswer {
    Value(serde_json::Value),
    Text(AdmittedSkillText),
}

/// A skill answer held as JSON text for the admitted call's caller, and the
/// run its call recorded it on, record-only.
pub struct AdmittedSkillText {
    run: EntityId,
    text: Box<RawValue>,
}

impl AdmittedSkillText {
    /// Answer `text` of the admitted call on run `run`.
    pub(super) fn new(run: EntityId, text: Box<RawValue>) -> Self {
        Self { run, text }
    }
}

/// Its size, never its text: the answer is the caller's to read.
impl std::fmt::Debug for AdmittedSkillText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedSkillText")
            .field("run", &self.run)
            .field("bytes", &self.text.get().len())
            .finish()
    }
}

/// Executes the host projection of `self.skills.call`. The caller has already
/// admitted its credential and verb hooks; nested calls keep their normal
/// hooks and this dispatcher's credential door. `outer_hooks_live` is that
/// caller's own pre chain's state (`!VerbHookPre::passed_through()`), which
/// its post chain's running stands on: while it stands, a large answer is
/// held whole for that chain and recorded record-only, whatever the
/// bindings read when the skill returns; one nesting past what a value may
/// hold is held as its JSON text ([`AdmittedSkillAnswer::Text`]), which the
/// caller judges with [`judge_admitted_skill_text`]. The sealed binding supplies
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
    outer_hooks_live: bool,
) -> MemoryResult<AdmittedSkillAnswer> {
    let lent = (runtime, type_feedback);
    execute_live_skill_call_listing(
        vault,
        binding,
        dispatcher,
        executor,
        input,
        lent,
        outer_hooks_live,
    )
    .0
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
    outer_hooks_live: bool,
) -> (MemoryResult<AdmittedSkillAnswer>, Option<Vec<EntityId>>) {
    let mut rows = Some(Vec::new());
    let answer = live_skill_call(
        vault,
        binding,
        dispatcher,
        executor,
        input,
        lent,
        &mut rows,
        outer_hooks_live,
    );
    (answer, rows)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the admitted call's inputs, its row listing and the outer chain's state"
)]
fn live_skill_call(
    vault: &Vault,
    binding: &HostBinding,
    dispatcher: &GatedActorWrite<'_>,
    executor: &ModelId,
    input: crate::code_run::SkillCallInput,
    (runtime, type_feedback): (&mut dyn JsCodeModeRuntime, Option<&TypeFeedback>),
    rows: &mut Option<Vec<EntityId>>,
    outer_hooks_live: bool,
) -> MemoryResult<AdmittedSkillAnswer> {
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
        .with_admitted_skill_call(seq, outer_hooks_live)
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
    // in its place, as a small answer is returned, or its JSON text when
    // it nests past what a value may hold. Taken before the record takes
    // the host's calls. An answer the row's store withheld left none to
    // hold, and no hook's view of it goes out either: the recorded output,
    // its typed unavailable content, does.
    let outer_answer = host.admitted_skill_answer.take();
    let withheld = host.admitted_skill_withheld;
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
    let view = answer.view.filter(|_| !withheld);
    match answer.outcome {
        SelfDispatchOutcome::SkillCall(result) => match outer_answer {
            // No chain of this call ran on it, so no view stands in its
            // place: the caller's own chain judges the text.
            Some(AdmittedSkillAnswer::Text(text)) => Ok(AdmittedSkillAnswer::Text(text)),
            Some(AdmittedSkillAnswer::Value(outer)) => {
                shown_skill_output(vault, run, result.output, view, Some(outer))
                    .map(AdmittedSkillAnswer::Value)
            }
            None => shown_skill_output(vault, run, result.output, view, None)
                .map(AdmittedSkillAnswer::Value),
        },
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
/// recorded that body record-only, its run-known values swept. So what
/// stands in the recorded output's place goes out masked as that sweep
/// masks a body ([`masked_in_run`]). The whole answer of a small call is
/// its recorded output itself, and goes out as recorded.
fn shown_skill_output(
    vault: &Vault,
    run: EntityId,
    output: serde_json::Value,
    view: Option<serde_json::Value>,
    outer: Option<serde_json::Value>,
) -> MemoryResult<serde_json::Value> {
    let shown = match (view, outer) {
        (Some(serde_json::Value::Object(mut fields)), _) => match fields.remove("output") {
            Some(output) => output,
            None => serde_json::Value::Object(fields),
        },
        (Some(view), _) => view,
        (None, Some(answer)) if answer != output => answer,
        (None, _) => return Ok(output),
    };
    masked_in_run(vault, run, &shown)
}

/// What an admitted skill call's caller reads of answer `answer`, held as
/// JSON text ([`AdmittedSkillAnswer::Text`]), once its post chain `pre`
/// judged it ([`verb_hook_boundary::row_post_text`]). The view is masked as
/// a value view goes out ([`masked_in_run`]), over its text. A view that
/// nests no deeper than a value may hold, as a Redact may leave it, is then
/// read into one; its caller spills it past the inline size as it spills a
/// value view ([`spill_admitted_skill_view`]). Any other view, the answer as
/// it was among them, is spilled now as a readable result of the run, bound
/// to its next free name (`rows`, the rows it was produced from, as
/// [`spill_admitted_skill_view`] takes them), and its card goes out, as a
/// deep answer no live hook judges arrives. The answer itself stays
/// record-only, as the admitted entry left it.
///
/// # Errors
///
/// A hook's stop, as the refusal the caller reads; storage errors, a spill
/// that fails (no value can hold the view inline) among them.
pub fn judge_admitted_skill_text(
    vault: &Vault,
    pre: VerbHookPre,
    answer: AdmittedSkillText,
    rows: Option<Vec<EntityId>>,
) -> MemoryResult<serde_json::Value> {
    let AdmittedSkillText { run, text } = answer;
    let view = verb_hook_boundary::row_post_text(vault, pre, text)?;
    // A flat sweep of the text: no recursion follows the view's nesting.
    let masked =
        crate::guest_error::mask_run_known_values(vault.run_known_source(run)?, view.get())?;
    if text_nests_past_whole_depth(&masked) {
        return spill_admitted_body(vault, run, rows, |sink| sink.write(masked.as_bytes()));
    }
    serde_json::from_str(&masked).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "a judged skill answer view does not read",
            &[],
        )
    })
}

/// `value` with each custody and PERSON value the run `run` knows replaced
/// by its stand-in, over the value's JSON text, as the run's output sweep
/// replaces them in a body it stores (FIX 9209). A value that cannot be
/// encoded, masked or read back fails the call: its plaintext never goes
/// out.
fn masked_in_run(
    vault: &Vault,
    run: EntityId,
    value: &serde_json::Value,
) -> MemoryResult<serde_json::Value> {
    let unmasked = |error: serde_json::Error| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("the skill answer could not be masked: {error}"),
            &[],
        )
    };
    let text = serde_json::to_string(value).map_err(unmasked)?;
    let masked = crate::guest_error::mask_run_known_values(vault.run_known_source(run)?, &text)?;
    serde_json::from_str(&masked).map_err(unmasked)
}

/// An admitted skill call's post-hook view as its caller reads it: the view
/// itself while its JSON fits one reply, else its readable card. A large
/// view spills as a body of the run through the sweeping result sink, as the
/// guest's own spill does (`store_reply`): custody-known values are replaced
/// by their handles as they stream, and the body carries the secret marks
/// its later reads are withheld by. The body binds to the run's next free
/// `r<n>` name, and the record append is generation-guarded: a writer that
/// lands first makes the spill re-read the record and allocate its name and
/// path again, so no two spills bind one name and no append loses another
/// writer's rows. Past [`ADMITTED_VIEW_SPILL_RETRIES`] conflicting appends,
/// or when the run's record is gone, the spill fails and the caller keeps
/// the view inline: the view was already judged for this caller, so a failed
/// spill never refuses it. Only the post-hook view is ever stored readable;
/// the pre-hook answer stays record-only, as the admitted entry left it.
pub fn spill_admitted_skill_view(
    vault: &Vault,
    run_id: EntityId,
    view: serde_json::Value,
    rows: Option<Vec<EntityId>>,
) -> MemoryResult<serde_json::Value> {
    let mut size = ByteCount::default();
    serde_json::to_writer(&mut size, &view).map_err(|error| {
        crate::Error::InvalidConfig(format!("skill view encoding failed: {error}"))
    })?;
    if size.0 <= RESULT_REPLY_INLINE_BYTES {
        return Ok(view);
    }
    spill_admitted_body(vault, run_id, rows, |sink| write_json(sink, &view))
}

/// A body `write` writes, spilled as a readable result of run `run_id` as
/// [`spill_admitted_skill_view`] spills a large view: through the sweeping
/// result sink, bound to the run's next free `r<n>` name, the record append
/// generation-guarded. Its card.
fn spill_admitted_body(
    vault: &Vault,
    run_id: EntityId,
    rows: Option<Vec<EntityId>>,
    write: impl Fn(&mut BodySink) -> crate::Result<()>,
) -> MemoryResult<serde_json::Value> {
    let storage = ExecutorStorage::Canonical(vault);
    for _ in 0..ADMITTED_VIEW_SPILL_RETRIES {
        let Some(mut record) = vault.get_code_run_replay_record(&run_id)? else {
            return Err(MemoryError::bad_request("no live run record"));
        };
        let generation = record.generation()?;
        let mut sink = vault.code_run_output_sink()?;
        write(&mut sink)?;
        sink.finalize_sweep()?;
        let digest = sink.digest()?;
        let ordinal = store_ordinal_base(&record) + record.outputs.len();
        let output = vault.publish_code_run_output_produced(
            store_result_output_path(&digest, ordinal),
            sink,
            true,
            Some(run_id),
            rows.clone(),
            None,
        )?;
        let name = next_spill_name(&record);
        let mut card = result_card(&storage, run_id, &output, Some(name.as_str()))?;
        // An outside caller reads the card back by its name, handle or ref;
        // the guest read path is none of its business.
        if let Some(fields) = card.as_object_mut() {
            fields.remove("read");
        }
        record.outputs.push(output.clone());
        record.bindings.push(CodeRunResultBinding::new(
            name,
            output.handle.clone(),
            output.path.clone(),
        ));
        match vault.put_code_run_replay_record_if_generation(&record, Some(generation)) {
            Ok(_) => return Ok(card),
            Err(crate::Error::ConcurrentWrite(_)) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "the run changed under its skill view spill",
        &[],
    ))
}

/// The run record's next free automatic result name: `r<n>`, counting from
/// one past its bindings, past any name taken. The spill allocates from the
/// generation it writes, recomputed on every retry, so the name it binds is
/// free in the record that keeps it.
fn next_spill_name(record: &CodeRunReplayRecord) -> String {
    (record.bindings.len() + 1..)
        .map(|n| format!("r{n}"))
        .find(|name| !record.bindings.iter().any(|binding| binding.name == *name))
        .unwrap_or_default()
}

fn engine_error(error: super::EngineExecutorError) -> MemoryError {
    match error {
        super::EngineExecutorError::Engine(error) => error.into(),
        error => MemoryError::new(MEMORY_CODE_INTERNAL, error.to_string(), &[]),
    }
}
