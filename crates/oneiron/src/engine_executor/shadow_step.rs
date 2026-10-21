//! One captured step of a shadow arm (PR-S1, FIX 1661/2144): the pinned
//! model's answer to the step's captured request, healed as a run's reply
//! is, and its program run once on a fresh runtime at the step's own
//! position, clock and sandbox boundary, against the arm's replay-only
//! bridge. A fresh store per step is how the executor runs every step: no
//! earlier program runs again, and what the program reads back is its run's
//! results and observations before the step, frozen in the arm's store.
//!
//! The step's bodies (the answer, its program, its observation and files,
//! the values it stored) and its two traces (the effects it asked for, and
//! the recorded calls it matched) stay in the arm's store. Speech its reply
//! carried after the program is a proposed intent in the effect trace, never
//! said. The arm ends after the step: its status is the step's, never a
//! whole run's.

use super::cancel::StepCancellation;
use super::host::executor_boundary_contract;
use super::store::{
    RECOVERABLE_OUTPUT_CHUNK_BYTES, executed_output_path, is_result_output_path,
    observation_output_path, recoverable_output_path, result_read_path, script_output_path,
    source_map_output_path, validate_runtime_outputs,
};
use super::types::{JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome};
use super::wire::heal_executor_reply;
use crate::code_run::shadow_runner::{
    ArmReads, PreparedShadowStep, ShadowBodyRef, ShadowBodyStore, ShadowBridgeHost,
    ShadowBridgeWindow, ShadowStatus, ShadowStepRun, ShadowTraceEntry, ShadowTraceKind,
    ShadowUnavailable, ShadowUnavailableReason,
};
use crate::code_run::{CodeRunRawOutput, CodeRunReplayRecord};
use crate::code_sandbox::source::prepare_source;
use crate::{Error, LlmResponse, Result};

/// The outputs of `prefix`, a run's row as a step starts, that the step's
/// program may read back: the run's results, and the observation of each
/// step before it.
pub(crate) fn shadow_readable_outputs(prefix: &CodeRunReplayRecord) -> Vec<CodeRunRawOutput> {
    let mut readable: Vec<CodeRunRawOutput> = prefix
        .outputs
        .iter()
        .filter(|output| is_result_output_path(&output.path))
        .cloned()
        .collect();
    for seq in 0..prefix.step_checkpoints.len() as u64 {
        let path = observation_output_path(seq);
        if let Some(output) = prefix.outputs.iter().find(|output| output.path == path) {
            readable.push(output.clone());
        }
    }
    readable
}

/// Runs `prepared`'s captured step in an arm whose bodies are in `store`,
/// on `answer`, the pinned model's answer to the step's request, with a
/// fresh `runtime` under `cancel`. A reply that does not heal fails the step
/// as it fails a run's; a call the record cannot answer leaves the arm
/// unavailable, its evidence so far kept.
///
/// # Errors
///
/// The arm's store failing, and a step the executor cannot set up.
pub fn run_shadow_step(
    prepared: &PreparedShadowStep,
    answer: &LlmResponse,
    runtime: &mut dyn JsCodeModeRuntime,
    store: &ShadowBodyStore,
    cancel: &StepCancellation,
) -> Result<ShadowStepRun> {
    let seq = prepared.step().step;
    let (start, end) = prepared.bridge_window();
    // An arm whose source an erase or actor scrub took copies nothing in
    // and runs nothing (FIX 5718).
    if let Some(withheld) = store.source_withheld() {
        let bridge = ShadowBridgeWindow {
            start,
            end,
            consumed: start,
        };
        return withheld_run(store, seq, withheld, bridge);
    }
    seed_store(prepared, store)?;
    let encoded = serde_json::to_vec(answer)
        .map_err(|error| Error::InvalidConfig(format!("shadow step answer: {error}")))?;
    let mut outputs = vec![store.put(arm_path(seq, "answer.json"), &encoded)?];
    let Ok(healed) = heal_executor_reply(answer) else {
        let status = ShadowStatus::Failed {
            kind: "reply_unhealable".to_owned(),
        };
        let bridge = ShadowBridgeWindow {
            start,
            end,
            consumed: start,
        };
        return finish_run(store, seq, status, outputs, &[], &[], bridge);
    };
    outputs.push(store.put(script_output_path(seq), healed.code.as_bytes())?);
    // Prepared once, as a run's step is (FIX 8276): a TypeScript program's
    // executed JavaScript and its preparation record stay in the arm's own
    // store beside the program.
    let prepared = prepare_source(&healed.code);
    if let Some(transpiled) = prepared.transpiled() {
        let executed = transpiled.executed_js().as_bytes();
        outputs.push(store.put(executed_output_path(seq), executed)?);
        let record = transpiled.record_json(&healed.code)?;
        outputs.push(store.put(source_map_output_path(seq), &record)?);
    }
    let boundary = executor_boundary_contract()
        .map_err(|_| Error::InvariantViolation("executor sandbox contract"))?;
    let mut host = ShadowBridgeHost::new(prepared, store, arm_reads(prepared))?;
    let step = JsCodeModeStep {
        run_id: prepared.step().run,
        seq,
        script: &healed.code,
        boundary,
        determinism: prepared.determinism,
    };
    let ran = runtime.run_prepared_step_cancellable(step, &prepared, &mut host, cancel);
    // An erase that took the source's content while the step ran leaves the
    // arm nothing to publish of it (FIX 5718).
    if let Some(withheld) = store.source_withheld() {
        let bridge = ShadowBridgeWindow {
            start,
            end,
            consumed: host.consumed(),
        };
        return withheld_run(store, seq, withheld, bridge);
    }
    let (bodies, files_named) = step_bodies(prepared, store, &mut host, &ran)?;
    let status = match step_status(&host, &ran, cancel) {
        ShadowStatus::StepComplete { .. } if !files_named => ShadowStatus::Failed {
            kind: "runtime_output_paths".to_owned(),
        },
        status => status,
    };
    outputs.extend(bodies);
    outputs.extend(host.own_results());
    let mut proposed = std::mem::take(&mut host.proposed);
    if let Some(text) = healed
        .trailing_speak
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        outputs.push(store.put(arm_path(seq, "trailing-speech.txt"), text.as_bytes())?);
        proposed.push(trailing_speech(host.consumed(), text));
    }
    let bridge = ShadowBridgeWindow {
        start,
        end,
        consumed: host.consumed(),
    };
    finish_run(
        store,
        seq,
        status,
        outputs,
        &proposed,
        &host.matched,
        bridge,
    )
}

/// The arm's store, holding each body frozen clean for the step.
fn seed_store(prepared: &PreparedShadowStep, store: &ShadowBodyStore) -> Result<()> {
    for frozen in &prepared.frozen {
        if let Some(bytes) = &frozen.bytes {
            store.import(frozen.output.output_ref(), bytes)?;
        }
    }
    Ok(())
}

/// Where the step's program reads its run's bodies back by path: each
/// earlier step's observation under its context path, a stored result under
/// its read path, a chunk at a time.
fn arm_reads(prepared: &PreparedShadowStep) -> ArmReads {
    let recoverable = (0..prepared.step().step)
        .filter_map(|seq| {
            let path = observation_output_path(seq);
            let frozen = prepared
                .frozen
                .iter()
                .find(|frozen| frozen.output.path == path)?;
            Some((
                recoverable_output_path(seq, frozen.output.output_ref()),
                frozen.output.clone(),
                frozen.bytes.is_some(),
            ))
        })
        .collect();
    ArmReads {
        recoverable,
        result_path: result_read_path,
        chunk_bytes: RECOVERABLE_OUTPUT_CHUNK_BYTES,
    }
}

/// How the step ended in the arm: unavailable once the arm stopped or was
/// cancelled, failed as a run's step fails, waiting on a recorded wait, else
/// complete (`done` when its program finished the run, or its TASK was
/// declined, which closes the run).
fn step_status(
    host: &ShadowBridgeHost<'_>,
    ran: &Result<JsCodeModeStepOutcome>,
    cancel: &StepCancellation,
) -> ShadowStatus {
    if let Some(unavailable) = &host.stopped {
        return ShadowStatus::Unavailable {
            unavailable: unavailable.clone(),
        };
    }
    if cancel.is_cancelled() {
        return ShadowStatus::Unavailable {
            unavailable: ShadowUnavailable::new(ShadowUnavailableReason::Cancelled, "step"),
        };
    }
    match ran {
        Err(error) => ShadowStatus::Failed {
            kind: format!("{:?}", error.kind()),
        },
        Ok(_) if host.hard_failure => ShadowStatus::Failed {
            kind: "host_bridge_failure".to_owned(),
        },
        Ok(outcome) => match &host.durable_wait {
            Some(wait) => ShadowStatus::Waiting {
                wait: Box::new(wait.clone()),
            },
            None => ShadowStatus::StepComplete {
                done: outcome.done || host.declined,
            },
        },
    }
}

/// The step's bodies, finished in the arm's store: its observation and its
/// files, whole once the step ran, partial when it failed. With whether the
/// files took the paths a run gives them: a step whose files cannot fails,
/// as a run's does, its files kept by their place.
fn step_bodies(
    prepared: &PreparedShadowStep,
    store: &ShadowBodyStore,
    host: &mut ShadowBridgeHost<'_>,
    ran: &Result<JsCodeModeStepOutcome>,
) -> Result<(Vec<ShadowBodyRef>, bool)> {
    let seq = prepared.step().step;
    let streams = host.take_streams();
    let (observation, files, complete) = match ran {
        Ok(outcome) => {
            let (observation, files) = streams.into_bodies(store, outcome)?;
            (Some(observation), files, true)
        }
        Err(_) => {
            let (observation, files) = streams.into_partial();
            (observation, files, false)
        }
    };
    let mut bodies = Vec::new();
    if let Some(observation) = observation {
        let (output, secret) = store.finish(observation_output_path(seq), observation, complete)?;
        bodies.push(ShadowBodyRef::of(&output, secret));
    }
    let named = validate_runtime_outputs(&prepared.prefix, seq, &files).ok();
    let files_named = named.is_some();
    let paths = named.unwrap_or_else(|| {
        (0..files.len())
            .map(|index| arm_path(seq, &format!("file-{index:03}")))
            .collect()
    });
    for ((_, sink), path) in files.into_iter().zip(paths) {
        let (output, secret) = store.finish(path, sink, complete)?;
        bodies.push(ShadowBodyRef::of(&output, secret));
    }
    Ok((bodies, files_named))
}

/// The speech an arm's reply carried after its program, as a proposed
/// intent the arm never says (CALLS "trailing speech as proposed intent"):
/// an entry of the effect trace at the bridge position after the step's
/// calls.
fn trailing_speech(seq: u64, text: &str) -> ShadowTraceEntry {
    ShadowTraceEntry {
        kind: ShadowTraceKind::TrailingSpeech,
        seq,
        effect: "speak".to_owned(),
        request: text.as_bytes().to_vec(),
        outcome: None,
    }
}

/// The run of a step whose source an erase or actor scrub took (FIX
/// 5718): unavailable for `withheld`, publishing no body and empty traces.
fn withheld_run(
    store: &ShadowBodyStore,
    seq: u64,
    withheld: ShadowUnavailable,
    bridge: ShadowBridgeWindow,
) -> Result<ShadowStepRun> {
    let status = ShadowStatus::Unavailable {
        unavailable: withheld,
    };
    finish_run(store, seq, status, Vec::new(), &[], &[], bridge)
}

/// The step's run, its two traces written to the arm's store.
fn finish_run(
    store: &ShadowBodyStore,
    seq: u64,
    status: ShadowStatus,
    outputs: Vec<ShadowBodyRef>,
    proposed: &[ShadowTraceEntry],
    matched: &[ShadowTraceEntry],
    bridge: ShadowBridgeWindow,
) -> Result<ShadowStepRun> {
    let effect_trace = store.put(arm_path(seq, "effects.msgpack"), &encode_trace(proposed)?)?;
    let bridge_trace = store.put(arm_path(seq, "bridge.msgpack"), &encode_trace(matched)?)?;
    Ok(ShadowStepRun {
        status,
        outputs,
        effect_trace,
        bridge_trace,
        bridge,
    })
}

/// A trace as its body holds it: MessagePack, named fields.
fn encode_trace(entries: &[ShadowTraceEntry]) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(entries)
        .map_err(|error| Error::InvalidConfig(format!("shadow trace: {error}")))
}

/// Where an arm keeps a body of its own for step `seq`.
fn arm_path(seq: u64, name: &str) -> String {
    format!("shadow/{seq:06}/{name}")
}
