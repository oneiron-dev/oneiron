//! Folds by kind (ARCH-0067 §2.2): the records a `repl_output`,
//! `connector_result` or `program` mark seals from the durable replay, the
//! stub a console fold shows in place of a step's console, and a parked
//! run's pending kind folds, sealed from the vault alone (L2-37).

use super::*;

/// One batch's folds by kind (ARCH-0067 §2.2, fold by kind): for a
/// `repl_output` mark, each step of its span keeps in its stub its output's
/// handle, every stored result the output names and every id it names. The
/// engine writes them from the steps' typed outputs, with no model call; the
/// program text and its say() messages stay. A `connector_result` mark keeps
/// the same for each step that took a connector's reply, and names each of
/// the step's connector calls that replied (FIX 14541). `actor` is the byline: the
/// run's own agent, whose marks they are. The executor's token feed and a
/// parked run's idle fold (L2-37) seal through this one function.
pub(super) fn kind_fold_records(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    marks: &[FoldMark],
    actor: crate::EntityId,
) -> EngineExecutorResult<Vec<FoldRecord>> {
    let mut records = Vec::new();
    for mark in marks {
        let Some(kind) = mark.kind else {
            continue;
        };
        let mut outputs = Vec::new();
        for seq in mark.from..=mark.through {
            match kind {
                FoldKind::ReplOutput => {
                    if let Some(output) = console_fold_output(storage, record, seq)? {
                        outputs.push(output);
                    }
                }
                FoldKind::ConnectorResult => {
                    // A step that took no connector's reply keeps its console.
                    let connector_calls = step_connector_calls(record, seq);
                    if connector_calls.is_empty()
                        && connector_resumed_reply(storage, record, seq)?.is_none()
                    {
                        continue;
                    }
                    if let Some(mut output) = console_fold_output(storage, record, seq)? {
                        output.connector_calls = connector_calls;
                        outputs.push(output);
                    }
                }
                FoldKind::Program => {
                    let path = script_output_path(seq);
                    if !record.outputs.iter().any(|output| output.path == path) {
                        continue;
                    }
                    let program = load_script_context(storage, record, &path, None)?;
                    outputs.push(FoldedOutput {
                        step: seq,
                        handles: Vec::new(),
                        ids: super::compaction::text_ids(&program),
                        said: step_speech(record, seq),
                        connector_calls: Vec::new(),
                    });
                }
            }
        }
        records.push(FoldRecord::of_kind(mark, kind, actor, outputs));
    }
    Ok(records)
}

/// What a console fold (`repl_output`, `connector_result`) keeps of step
/// `seq`'s console: its read handle, every stored result it names and every
/// id it names, found in the whole output, read by range. `None` for a step
/// with no console.
fn console_fold_output(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    seq: u64,
) -> EngineExecutorResult<Option<FoldedOutput>> {
    let path = observation_output_path(seq);
    let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
        return Ok(None);
    };
    let mut handles = vec![serde_json::to_string(&serde_json::json!({
        "step": seq,
        "sandbox.fs.read_file": recoverable_chunk_path(seq, output.output_ref(), 0),
        "byte_len": output.raw_len,
        "max_chunk_bytes": RECOVERABLE_OUTPUT_CHUNK_BYTES,
    }))?];
    // The whole output, by range: a ref past the first window stays in the
    // stub too.
    let mut reads = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    scan_output_windows(storage, record, output, |window| {
        super::compaction::result_reads(window, &mut reads);
        ids.extend(super::compaction::text_ids(window));
    })?;
    for read in reads {
        handles.push(super::compaction::result_read_affordance(&read)?);
    }
    Ok(Some(FoldedOutput {
        step: seq,
        handles,
        ids: ids.into_iter().collect(),
        said: Vec::new(),
        connector_calls: Vec::new(),
    }))
}

/// Each call of step `seq`'s own bridge calls that returned a connector's
/// reply into it, in order (FIX 14541): read from the step's checkpoint, as
/// its speech calls are. No connector or tool name is kept; the stub reads
/// them when it renders. A step whose checkpoint keeps no range gives none.
fn step_connector_calls(
    record: &CodeRunReplayRecord,
    seq: u64,
) -> Vec<crate::compaction::FoldedConnectorCall> {
    let Some(range) = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == seq)
        .and_then(crate::code_run::CodeRunStepCheckpoint::bridge_range)
    else {
        return Vec::new();
    };
    record
        .bridge_calls
        .get(range)
        .unwrap_or_default()
        .iter()
        .filter_map(|call| {
            Some(crate::compaction::FoldedConnectorCall {
                verb: crate::code_run::connector_reply_verb(call)?.to_owned(),
                call: call.seq,
            })
        })
        .collect()
}

/// The reply step `seq`'s parked connector call resumed with, which a
/// `connector_result` fold folds with the step's console: `None` when the
/// step did not park, its wait was not a connector call's, or no reply came.
pub(super) fn connector_resumed_reply<'r>(
    storage: &ExecutorStorage<'_>,
    record: &'r CodeRunReplayRecord,
    seq: u64,
) -> EngineExecutorResult<Option<&'r CodeRunRawOutput>> {
    let Some(reply) = record
        .outputs
        .iter()
        .find(|output| resumed_output_wait(&output.path).is_some_and(|(step, _)| step == seq))
    else {
        return Ok(None);
    };
    Ok(parked_wait_at(storage, record, seq)?
        .filter(crate::code_run::is_connector_call_wait)
        .map(|_| reply))
}

/// What step `seq` shows in place of its console under the console fold
/// `fold` (`repl_output` or `connector_result`), unmasked: a connector
/// result's stub names each connector call that replied as the run's record
/// dispatched it. `None` when `fold` did not fold the step.
pub(crate) fn console_fold_stub(
    fold: &FoldRecord,
    record: &CodeRunReplayRecord,
    seq: u64,
    with_note: bool,
) -> Option<String> {
    if fold.kind != Some(FoldKind::ConnectorResult) {
        return fold.output_stub(seq, with_note);
    }
    fold.connector_stub(seq, with_note, |connector| {
        let call = record
            .bridge_calls
            .get(usize::try_from(connector.call).ok()?)?;
        connector_call_label(call)
    })
}

/// The connector and tool a recorded `connector.call` dispatched, as a
/// `connector_result` stub names them: `name/tool`. `None` for another call,
/// and for one whose request words an erase took (FIX 6534).
fn connector_call_label(call: &crate::code_run::CodeRunBridgeCall) -> Option<String> {
    let rmpv::Value::Map(entries) = call.dispatched_request()? else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str())
    };
    if field("verb")? != crate::task_verb::sdk::AgentVerb::ConnectorCall.as_str() {
        return None;
    }
    let input: serde_json::Value = serde_json::from_str(field("input")?).ok()?;
    let name = input.get("name")?.as_str()?;
    let tool = input.get("tool")?.as_str()?;
    Some(format!("{name}/{tool}"))
}

/// A parked run's pending kind marks, sealed from the vault alone (L2-37):
/// the ledger they were read against, the records the token feed would land
/// for them at the run's next breakpoint, and the prompt tokens of the
/// bodies those stubs replace: each body once, and none a landed fold
/// already hides (an upper estimate: the stubs' own handles are not
/// subtracted).
#[derive(Debug)]
pub(crate) struct ParkedKindFolds {
    pub(crate) ledger: crate::compaction::FoldLedger,
    pub(crate) records: Vec<FoldRecord>,
    pub(crate) folded_tokens: u64,
}

/// Seals `run_id`'s kind marks that apply with no compact ask, as the token
/// feed seals them at a breakpoint (flight.rs), from durable state alone and
/// with `actor` as the byline: `None` when none applies. Nothing is written:
/// the caller lands the records in its own write, against the ledger read
/// here.
pub(crate) fn parked_kind_folds(
    vault: &crate::Vault,
    run_id: crate::EntityId,
    actor: crate::EntityId,
) -> EngineExecutorResult<Option<ParkedKindFolds>> {
    let storage = ExecutorStorage::Canonical(vault);
    let ledger = storage.code_run_folds(run_id)?;
    if ledger.marks.is_empty() {
        return Ok(None);
    }
    let Some(record) = storage.get_code_run_replay_record(&run_id)? else {
        return Ok(None);
    };
    let completed = completed_step_count(&record)?;
    let prefix_end = storage
        .code_run_compaction_coverage(run_id)?
        .iter()
        .map(|row| row.last())
        .max();
    let marks: Vec<FoldMark> = ledger
        .applicable(completed, prefix_end, false)
        .into_iter()
        .filter(|mark| mark.kind.is_some())
        .collect();
    if marks.is_empty() {
        return Ok(None);
    }
    let records = kind_fold_records(&storage, &record, &marks, actor)?;
    if records.is_empty() {
        return Ok(None);
    }
    // Two marks over one body of a step show one stub (kind_covering, and
    // console_covering for the two console kinds), and a body a landed fold
    // hides is off the prompt already: neither saves again.
    let mut counted = std::collections::BTreeSet::new();
    let mut folded_tokens = 0_u64;
    for fold in &records {
        let Some(kind) = fold.kind else {
            continue;
        };
        for step in fold.outputs.iter().map(|output| output.step) {
            if ledger.covering(step).is_some() {
                continue;
            }
            let landed = if kind.folds_console() {
                ledger.console_covering(step)
            } else {
                ledger.kind_covering(kind, step)
            };
            let mut bodies = Vec::new();
            if landed.is_none() {
                bodies.push(match kind {
                    FoldKind::Program => script_output_path(step),
                    FoldKind::ReplOutput | FoldKind::ConnectorResult => {
                        observation_output_path(step)
                    }
                });
            }
            // A connector result's stub stands in for the reply its parked
            // connector call resumed with too, unless one already does.
            if kind == FoldKind::ConnectorResult
                && ledger.kind_covering(kind, step).is_none()
                && let Some(reply) = connector_resumed_reply(&storage, &record, step)?
            {
                bodies.push(reply.path.clone());
            }
            for path in bodies {
                if !counted.insert(path.clone()) {
                    continue;
                }
                if let Some(output) = record.outputs.iter().find(|output| output.path == path) {
                    // The window's rule of thumb: four bytes to a token.
                    folded_tokens = folded_tokens.saturating_add(output.raw_len / 4);
                }
            }
        }
    }
    Ok(Some(ParkedKindFolds {
        ledger,
        records,
        folded_tokens,
    }))
}

/// Each speech call step `seq` made, in order, by its bridge call: read from
/// the step's own bridge calls, as its checkpoint records them. No text is
/// kept; the stub reads it, masked, when it renders. A `say(result)` bubble
/// has no words, so its stub line names its verb and call (L8-25). A step
/// whose checkpoint keeps no range, or a call that did not emit, gives none.
fn step_speech(record: &CodeRunReplayRecord, seq: u64) -> Vec<crate::compaction::FoldedSpeech> {
    let Some(range) = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == seq)
        .and_then(crate::code_run::CodeRunStepCheckpoint::bridge_range)
    else {
        return Vec::new();
    };
    record
        .bridge_calls
        .get(range)
        .unwrap_or_default()
        .iter()
        .filter(|call| {
            call.emitted_speech()
                && (super::compaction::speech_call_text(call).is_some()
                    || call.emitted_said_result_ref().is_some())
        })
        .map(|call| crate::compaction::FoldedSpeech {
            verb: call.effect.as_str().to_owned(),
            call: call.seq,
        })
        .collect()
}
