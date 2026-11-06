//! The pinned MessagePack codec of a step checkpoint in a code run's replay
//! record: its keys, its encoding and decoding, and the checks the record
//! runs on its checkpoints against its bridge log.

use std::collections::HashSet;

use rmpv::Value;

use crate::Result;

use super::super::replay::CodeRunStepCheckpoint;
use super::super::support::{
    fixed_binary, invalid_code_run_replay, pinned_map, required, str_value, u64_value,
    validate_label,
};

pub const CODE_RUN_STEP_CHECKPOINT_KEYS: [&str; 6] = [
    "seq",
    "label",
    "state_hash",
    "created_at_ms",
    "bridge_end",
    "bridge_calls",
];

const KEY_SEQ: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[0];
const KEY_LABEL: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[1];
const KEY_STATE_HASH: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[2];
const KEY_CREATED_AT_MS: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[3];
const KEY_BRIDGE_END: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[4];
const KEY_STEP_BRIDGE_CALLS: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[5];

pub(super) fn encode_step_checkpoint(checkpoint: &CodeRunStepCheckpoint) -> Value {
    let mut entries = vec![
        (Value::from(KEY_SEQ), Value::from(checkpoint.seq)),
        (
            Value::from(KEY_LABEL),
            Value::from(checkpoint.label.as_str()),
        ),
        (
            Value::from(KEY_STATE_HASH),
            Value::Binary(checkpoint.state_hash.to_vec()),
        ),
        (
            Value::from(KEY_CREATED_AT_MS),
            Value::from(checkpoint.created_at_ms),
        ),
        (
            Value::from(KEY_BRIDGE_END),
            Value::from(checkpoint.bridge_end),
        ),
    ];
    // Present only where the writer recorded the step's calls.
    if let Some((start, end)) = checkpoint.bridge_calls {
        entries.push((
            Value::from(KEY_STEP_BRIDGE_CALLS),
            Value::Array(vec![Value::from(start), Value::from(end)]),
        ));
    }
    Value::Map(entries)
}

pub(super) fn decode_step_checkpoint(value: &Value) -> Result<CodeRunStepCheckpoint> {
    let fields = pinned_map(
        value,
        &CODE_RUN_STEP_CHECKPOINT_KEYS,
        "code-run step checkpoint",
    )?;
    let checkpoint = CodeRunStepCheckpoint {
        seq: u64_value(required(fields[0], "missing checkpoint seq")?)?,
        label: str_value(required(fields[1], "missing checkpoint label")?)?.to_owned(),
        state_hash: fixed_binary(
            required(fields[2], "missing checkpoint state_hash")?,
            "checkpoint state_hash",
        )?,
        created_at_ms: u64_value(required(fields[3], "missing checkpoint created_at_ms")?)?,
        bridge_end: u64_value(required(fields[4], "missing checkpoint bridge_end")?)?,
        bridge_calls: fields[5].map(decode_step_bridge_calls).transpose()?,
    };
    validate_label(&checkpoint.label, "checkpoint label")?;
    Ok(checkpoint)
}

/// A step's bridge calls, `[start, end]`, a forward range.
fn decode_step_bridge_calls(value: &Value) -> Result<(u64, u64)> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay(
            "checkpoint bridge_calls must be an array",
        ));
    };
    let [start, end] = items.as_slice() else {
        return Err(invalid_code_run_replay(
            "checkpoint bridge_calls must be [start, end]",
        ));
    };
    let (start, end) = (u64_value(start)?, u64_value(end)?);
    if start > end {
        return Err(invalid_code_run_replay(
            "checkpoint bridge_calls run backward",
        ));
    }
    Ok((start, end))
}

/// Checks a record's checkpoints against its `calls` bridge calls: one
/// checkpoint per seq, each step's calls ending inside the log and never
/// before an earlier step's end (FIX 6354), and each step's own calls
/// inside the log (FIX 14541).
pub(super) fn validate_step_checkpoints(
    checkpoints: &[CodeRunStepCheckpoint],
    calls: u64,
) -> Result<()> {
    let mut checkpoint_seqs = HashSet::new();
    let mut bridge_end = 0_u64;
    for checkpoint in checkpoints {
        if !checkpoint_seqs.insert(checkpoint.seq) {
            return Err(invalid_code_run_replay("duplicate checkpoint seq"));
        }
        validate_label(&checkpoint.label, "checkpoint label")?;
        if checkpoint.bridge_end < bridge_end || checkpoint.bridge_end > calls {
            return Err(invalid_code_run_replay(
                "checkpoint bridge_end is outside the bridge log or before an earlier step's",
            ));
        }
        bridge_end = checkpoint.bridge_end;
        if checkpoint.bridge_calls.is_some_and(|(_, end)| end > calls) {
            return Err(invalid_code_run_replay(
                "checkpoint bridge_calls exceed the record's calls",
            ));
        }
    }
    Ok(())
}
