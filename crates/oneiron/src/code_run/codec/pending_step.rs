//! The pinned MessagePack codec of a code run's pending step (FIX 7703):
//! its keys, its encoding and decoding, its checks against the record's
//! bridge log, and the digest the record's generation carries.

use rmpv::Value;

use crate::{ModelId, Result};

use super::super::correction::ExecutorWireRepairs;
use super::super::replay::PendingCodeStep;
use super::super::support::{
    bool_value, decode_array, fixed_binary, invalid_code_run_replay, pinned_map, required,
    str_value, u64_value,
};
use super::{decode_determinism, encode_determinism, encode_value};

const CODE_RUN_PENDING_STEP_KEYS: [&str; 14] = [
    "step_seq",
    "bridge_start",
    "guest_calls",
    "bridge_frontier",
    "output_frontier",
    "script_blake3",
    "prepared_identity",
    "guest_abi",
    "request_hash",
    "model",
    "repairs",
    "determinism",
    "trailing_speech",
    "park_generation",
];

/// The keys of a pending step's [`ExecutorWireRepairs`].
const CODE_RUN_PENDING_REPAIRS_KEYS: [&str; 4] = [
    "trimmed_transport_whitespace",
    "stripped_code_fence",
    "stripped_exec_wrapper",
    "discarded_console_blocks",
];

const PENDING_STEP_DIGEST_DOMAIN: &[u8] = b"oneiron:code-run-pending-step:v1";

pub(super) fn encode_pending_step(step: &PendingCodeStep) -> Value {
    Value::Map(
        CODE_RUN_PENDING_STEP_KEYS
            .iter()
            .map(|key| Value::from(*key))
            .zip([
                Value::from(step.step_seq),
                Value::from(step.bridge_start),
                Value::Array(step.guest_calls.iter().copied().map(Value::from).collect()),
                Value::from(step.bridge_frontier),
                Value::from(step.output_frontier),
                Value::Binary(step.script_blake3.to_vec()),
                step.prepared_identity
                    .map_or(Value::Nil, |identity| Value::Binary(identity.to_vec())),
                Value::Binary(step.guest_abi.to_vec()),
                Value::Binary(step.request_hash.to_vec()),
                Value::from(step.model.as_str()),
                encode_repairs(step.repairs),
                encode_determinism(&step.determinism),
                Value::Boolean(step.trailing_speech),
                Value::from(step.park_generation),
            ])
            .collect(),
    )
}

/// A record's pending step; `None` when the record holds none.
pub(super) fn decode_pending_step(value: Option<&Value>) -> Result<Option<PendingCodeStep>> {
    let Some(value) = value.filter(|value| !value.is_nil()) else {
        return Ok(None);
    };
    let fields = pinned_map(value, &CODE_RUN_PENDING_STEP_KEYS, "code-run pending step")?;
    Ok(Some(PendingCodeStep {
        step_seq: u64_value(required(fields[0], "missing pending step_seq")?)?,
        bridge_start: u64_value(required(fields[1], "missing pending bridge_start")?)?,
        guest_calls: decode_array(
            required(fields[2], "missing pending guest_calls")?,
            u64_value,
        )?,
        bridge_frontier: u64_value(required(fields[3], "missing pending bridge_frontier")?)?,
        output_frontier: u64_value(required(fields[4], "missing pending output_frontier")?)?,
        script_blake3: fixed_binary(
            required(fields[5], "missing pending script_blake3")?,
            "pending script_blake3",
        )?,
        prepared_identity: match required(fields[6], "missing pending prepared_identity")? {
            Value::Nil => None,
            identity => Some(fixed_binary(identity, "pending prepared_identity")?),
        },
        guest_abi: fixed_binary(
            required(fields[7], "missing pending guest_abi")?,
            "pending guest_abi",
        )?,
        request_hash: fixed_binary(
            required(fields[8], "missing pending request_hash")?,
            "pending request_hash",
        )?,
        model: ModelId::new(str_value(required(fields[9], "missing pending model")?)?)
            .map_err(|_| invalid_code_run_replay("pending model is not a model id"))?,
        repairs: decode_repairs(required(fields[10], "missing pending repairs")?)?,
        determinism: decode_determinism(required(fields[11], "missing pending determinism")?)?,
        trailing_speech: bool_value(required(fields[12], "missing pending trailing_speech")?)?,
        park_generation: u64_value(required(fields[13], "missing pending park_generation")?)?,
    }))
}

fn encode_repairs(repairs: ExecutorWireRepairs) -> Value {
    Value::Map(
        CODE_RUN_PENDING_REPAIRS_KEYS
            .iter()
            .map(|key| Value::from(*key))
            .zip([
                Value::Boolean(repairs.trimmed_transport_whitespace),
                Value::Boolean(repairs.stripped_code_fence),
                Value::Boolean(repairs.stripped_exec_wrapper),
                Value::from(repairs.discarded_console_blocks),
            ])
            .collect(),
    )
}

fn decode_repairs(value: &Value) -> Result<ExecutorWireRepairs> {
    let fields = pinned_map(
        value,
        &CODE_RUN_PENDING_REPAIRS_KEYS,
        "code-run pending repairs",
    )?;
    Ok(ExecutorWireRepairs {
        trimmed_transport_whitespace: bool_value(required(
            fields[0],
            "missing pending trimmed_transport_whitespace",
        )?)?,
        stripped_code_fence: bool_value(required(
            fields[1],
            "missing pending stripped_code_fence",
        )?)?,
        stripped_exec_wrapper: bool_value(required(
            fields[2],
            "missing pending stripped_exec_wrapper",
        )?)?,
        discarded_console_blocks: u32::try_from(u64_value(required(
            fields[3],
            "missing pending discarded_console_blocks",
        )?)?)
        .map_err(|_| invalid_code_run_replay("pending discarded_console_blocks overflow"))?,
    })
}

/// Checks a record's pending step against its `calls` bridge calls: its rows
/// lie inside the log and run forward, and its program's own calls run in
/// order from the step's first row, so every row in its range belongs to one
/// of them.
pub(super) fn validate_pending_step(step: &PendingCodeStep, calls: u64) -> Result<()> {
    if step.bridge_start > step.bridge_frontier || step.bridge_frontier > calls {
        return Err(invalid_code_run_replay(
            "pending step rows lie outside the bridge log",
        ));
    }
    let mut next = step.bridge_start;
    for &seq in &step.guest_calls {
        if seq < next || seq >= step.bridge_frontier {
            return Err(invalid_code_run_replay(
                "pending step program calls are out of order",
            ));
        }
        next = seq.saturating_add(1);
    }
    match step.guest_calls.first() {
        Some(&first) if first != step.bridge_start => Err(invalid_code_run_replay(
            "pending step rows start before its program's first call",
        )),
        None if step.bridge_start != step.bridge_frontier => Err(invalid_code_run_replay(
            "pending step rows name no program call",
        )),
        _ => Ok(()),
    }
}

/// The digest of `step` the record's generation carries (FIX 7703), so a
/// park that adds no row still changes the generation a guarded write
/// compares.
pub(in crate::code_run) fn pending_step_digest(step: &PendingCodeStep) -> Result<[u8; 32]> {
    let bytes = encode_value(
        &encode_pending_step(step),
        "code-run pending step MessagePack encode failed",
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PENDING_STEP_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
