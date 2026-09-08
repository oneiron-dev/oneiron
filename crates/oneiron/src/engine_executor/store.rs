//! Output envelope and path helpers for the routed raw-output store.

use super::record::REPLAY_METADATA_SCHEMA_VERSION;
use super::types::{EngineExecutorResult, JsCodeModeStepOutcome};
use crate::Error;
use crate::code_run::{CodeRunRawOutput, CodeRunReplayRecord, ExecutorStorage};
use crate::entity_id::EntityId;
use serde_json::json;
use std::collections::BTreeSet;

const SCRIPT_OUTPUT_DIR: &str = "executor/repl";

const TEXT_OUTPUT_PREFIX: &[u8] = b"oneiron-engine-executor-text-output-v1\n";

pub(super) const CONFIG_OUTPUT_PATH: &str = "executor/repl/run.config.json";

const TERMINAL_OUTPUT_SUFFIX: &str = ".terminal.json";

/// ONE-1686: the trailing-plaintext fallback's durable emission marker. A
/// SIBLING suffix of the terminal marker, never the same one:
/// `is_terminal_output_path` must not read it as a terminal status.
const FALLBACK_SPEECH_MARKER_SUFFIX: &str = ".fallback-speech.json";

pub(super) fn record_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    raw: &[u8],
) -> EngineExecutorResult<()> {
    if record.outputs.iter().any(|output| output.path == path) {
        return Err(Error::InvalidClaimBody("duplicate executor output path").into());
    }
    let output = CodeRunRawOutput::from_bytes(path, raw)?;
    storage.put_code_run_raw_output(&output, raw)?;
    record.outputs.push(output);
    Ok(())
}

pub(super) fn validate_runtime_outputs(
    record: &CodeRunReplayRecord,
    seq: u64,
    outcome: &JsCodeModeStepOutcome,
) -> EngineExecutorResult<Vec<String>> {
    let mut output_paths = BTreeSet::new();
    let mut paths = Vec::with_capacity(outcome.outputs.len());
    for (index, output) in outcome.outputs.iter().enumerate() {
        let path = runtime_output_path(seq, index, &output.path);
        if record.outputs.iter().any(|existing| existing.path == path)
            || !output_paths.insert(path.clone())
        {
            return Err(Error::InvalidClaimBody("duplicate executor output path").into());
        }
        let _ = CodeRunRawOutput::from_bytes(path.clone(), &output.bytes)?;
        paths.push(path);
    }
    Ok(paths)
}

pub(super) fn record_text_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    text: &str,
) -> EngineExecutorResult<()> {
    let raw = text_output_bytes(&path, text);
    record_output(storage, record, path, &raw)
}

fn text_output_bytes(path: &str, text: &str) -> Vec<u8> {
    let mut raw = Vec::with_capacity(TEXT_OUTPUT_PREFIX.len() + path.len() + 1 + text.len());
    raw.extend_from_slice(TEXT_OUTPUT_PREFIX);
    raw.extend_from_slice(path.as_bytes());
    raw.push(b'\n');
    raw.extend_from_slice(text.as_bytes());
    raw
}

fn decode_text_output(path: &str, raw: Vec<u8>) -> EngineExecutorResult<String> {
    let Some(rest) = raw.strip_prefix(TEXT_OUTPUT_PREFIX) else {
        return Err(Error::CorruptedIndex("executor replay text output envelope").into());
    };
    let path_header = format!("{path}\n");
    let Some(text) = rest.strip_prefix(path_header.as_bytes()) else {
        return Err(Error::CorruptedIndex("executor replay text output path").into());
    };
    String::from_utf8(text.to_vec())
        .map_err(|_| Error::InvalidClaimBody("executor replay output is not utf8").into())
}

pub(super) fn load_utf8_output(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
) -> EngineExecutorResult<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    let raw = storage
        .get_code_run_raw_output(output)?
        .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    decode_text_output(path, raw)
}

/// The durable "this step already spoke its last word" marker (ONE-1686).
///
/// Content-addressed into the run's own routed raw-output store, so its
/// presence is readable WITHOUT the replay record that a crash or a
/// `ConcurrentWrite` may have prevented from landing. The bytes name the run,
/// the step and the bubble's order and nothing else — deliberately not the
/// text, because "at most one trailing bubble per completed step" must hold
/// even if a re-run's backend produced a different observation.
pub(super) fn fallback_speech_marker(
    run_id: EntityId,
    seq: u64,
    order: u32,
) -> EngineExecutorResult<(CodeRunRawOutput, Vec<u8>)> {
    let path = fallback_speech_marker_path(seq);
    let text = serde_json::to_string(&json!({
        "schema_version": REPLAY_METADATA_SCHEMA_VERSION,
        "run_id": run_id.to_hex(),
        "step_seq": seq,
        "order": order,
    }))?;
    let raw = text_output_bytes(&path, &text);
    let marker = CodeRunRawOutput::from_bytes(path, &raw)?;
    Ok((marker, raw))
}

fn fallback_speech_marker_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{FALLBACK_SPEECH_MARKER_SUFFIX}")
}

pub(super) fn script_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.generated.js")
}

pub(super) fn observation_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.observation.txt")
}

pub(super) fn implicit_speak_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.implicit-speak.txt")
}

pub(super) fn terminal_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{TERMINAL_OUTPUT_SUFFIX}")
}

pub(super) fn is_terminal_output_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(SCRIPT_OUTPUT_DIR) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    let Some(seq) = rest.strip_suffix(TERMINAL_OUTPUT_SUFFIX) else {
        return false;
    };
    !seq.is_empty() && seq.bytes().all(|byte| byte.is_ascii_digit())
}

fn runtime_output_path(seq: u64, index: usize, path: &str) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}/output/{index:03}-{path}")
}

pub(super) fn checkpoint_label(seq: u64) -> String {
    format!("executor.repl.step.{seq:06}")
}
