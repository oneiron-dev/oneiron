use std::collections::HashSet;

use rmpv::Value;

use crate::attempt_queue::AttemptId;
use crate::claim::CallerLocality;
use crate::{EdgeActorClass, Error, Result};

use super::live_run::{CodeRunLiveRunBinding, LiveRunCredential};
use super::payload::self_effect_from_str;
use super::replay::{
    CODE_RUN_REPLAY_SCHEMA_VERSION, CodeRunAbiLayoutCheck, CodeRunBridgeCall, CodeRunDeterminism,
    CodeRunOutputKind, CodeRunOutputPreview, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, CodeRunStepCheckpoint,
};
use super::support::{
    CODE_RUN_OUTPUT_HANDLE_PREFIX, CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES, bool_value,
    code_run_layout_hash, decode_array, decode_string_array, entity_value, fixed_binary,
    invalid_code_run_replay, pinned_map, required, str_value, u64_value, validate_label,
    validate_text,
};

pub const CODE_RUN_REPLAY_RECORD_KEYS: [&str; 9] = [
    "schema_version",
    "run_id",
    "determinism",
    "bridge_calls",
    "step_checkpoints",
    "outputs",
    "abi_layout_checks",
    "bindings",
    "live_run",
];
pub const CODE_RUN_DETERMINISM_KEYS: [&str; 2] = ["frozen_unix_ms", "rng_seed"];
pub const CODE_RUN_BRIDGE_CALL_KEYS: [&str; 7] = [
    "seq",
    "effect",
    "request",
    "outcome",
    "started_at_ms",
    "finished_at_ms",
    "action_digest",
];
pub const CODE_RUN_STEP_CHECKPOINT_KEYS: [&str; 4] =
    ["seq", "label", "state_hash", "created_at_ms"];
pub const CODE_RUN_RAW_OUTPUT_KEYS: [&str; 8] = [
    "handle",
    "path",
    "raw_blake3",
    "raw_len",
    "kind",
    "lines",
    "complete",
    "preview",
];
pub const CODE_RUN_OUTPUT_PREVIEW_KEYS: [&str; 3] = ["codec", "text", "truncated"];
pub const CODE_RUN_ABI_LAYOUT_CHECK_KEYS: [&str; 4] =
    ["name", "schema_version", "fields", "layout_hash"];
/// A live run's attachment (OF-181); an unattached run's is Nil.
const CODE_RUN_LIVE_RUN_KEYS: [&str; 8] = [
    "issued",
    "credential",
    "locality",
    "actor",
    "actor_class",
    "attempt",
    "lease_owner",
    "lease_generation",
];

const KEY_SCHEMA_VERSION: &str = CODE_RUN_REPLAY_RECORD_KEYS[0];
const KEY_RUN_ID: &str = CODE_RUN_REPLAY_RECORD_KEYS[1];
const KEY_DETERMINISM: &str = CODE_RUN_REPLAY_RECORD_KEYS[2];
const KEY_BRIDGE_CALLS: &str = CODE_RUN_REPLAY_RECORD_KEYS[3];
const KEY_STEP_CHECKPOINTS: &str = CODE_RUN_REPLAY_RECORD_KEYS[4];
const KEY_OUTPUTS: &str = CODE_RUN_REPLAY_RECORD_KEYS[5];
const KEY_ABI_LAYOUT_CHECKS: &str = CODE_RUN_REPLAY_RECORD_KEYS[6];
const KEY_BINDINGS: &str = CODE_RUN_REPLAY_RECORD_KEYS[7];
const KEY_LIVE_RUN: &str = CODE_RUN_REPLAY_RECORD_KEYS[8];

const KEY_FROZEN_UNIX_MS: &str = CODE_RUN_DETERMINISM_KEYS[0];
const KEY_RNG_SEED: &str = CODE_RUN_DETERMINISM_KEYS[1];

const KEY_SEQ: &str = CODE_RUN_BRIDGE_CALL_KEYS[0];
const KEY_EFFECT: &str = CODE_RUN_BRIDGE_CALL_KEYS[1];
const KEY_REQUEST: &str = CODE_RUN_BRIDGE_CALL_KEYS[2];
const KEY_OUTCOME: &str = CODE_RUN_BRIDGE_CALL_KEYS[3];
const KEY_STARTED_AT_MS: &str = CODE_RUN_BRIDGE_CALL_KEYS[4];
const KEY_FINISHED_AT_MS: &str = CODE_RUN_BRIDGE_CALL_KEYS[5];
const KEY_ACTION_DIGEST: &str = CODE_RUN_BRIDGE_CALL_KEYS[6];

const KEY_LABEL: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[1];
const KEY_STATE_HASH: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[2];
const KEY_CREATED_AT_MS: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[3];

const KEY_HANDLE: &str = CODE_RUN_RAW_OUTPUT_KEYS[0];
const KEY_PATH: &str = CODE_RUN_RAW_OUTPUT_KEYS[1];
const KEY_RAW_BLAKE3: &str = CODE_RUN_RAW_OUTPUT_KEYS[2];
const KEY_RAW_LEN: &str = CODE_RUN_RAW_OUTPUT_KEYS[3];
const KEY_KIND: &str = CODE_RUN_RAW_OUTPUT_KEYS[4];
const KEY_LINES: &str = CODE_RUN_RAW_OUTPUT_KEYS[5];
const KEY_COMPLETE: &str = CODE_RUN_RAW_OUTPUT_KEYS[6];
const KEY_PREVIEW: &str = CODE_RUN_RAW_OUTPUT_KEYS[7];

const KEY_CODEC: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[0];
const KEY_TEXT: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[1];
const KEY_TRUNCATED: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[2];

const KEY_NAME: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[0];
const KEY_FIELDS: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[2];
const KEY_LAYOUT_HASH: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[3];

/// Encodes a deterministic code-run replay record as pinned MessagePack.
pub fn encode_code_run_replay_record(record: &CodeRunReplayRecord) -> Result<Vec<u8>> {
    validate_code_run_replay_record(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CODE_RUN_REPLAY_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_RUN_ID),
            Value::Binary(record.run_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_DETERMINISM),
            encode_determinism(&record.determinism),
        ),
        (
            Value::from(KEY_BRIDGE_CALLS),
            Value::Array(record.bridge_calls.iter().map(encode_bridge_call).collect()),
        ),
        (
            Value::from(KEY_STEP_CHECKPOINTS),
            Value::Array(
                record
                    .step_checkpoints
                    .iter()
                    .map(encode_step_checkpoint)
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_OUTPUTS),
            Value::Array(record.outputs.iter().map(encode_raw_output).collect()),
        ),
        (
            Value::from(KEY_ABI_LAYOUT_CHECKS),
            Value::Array(
                record
                    .abi_layout_checks
                    .iter()
                    .map(encode_abi_layout_check)
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_BINDINGS),
            Value::Array(record.bindings.iter().map(encode_binding).collect()),
        ),
        (
            Value::from(KEY_LIVE_RUN),
            record.live_run.as_ref().map_or(Value::Nil, encode_live_run),
        ),
    ]);
    encode_value(&value, "code-run replay record MessagePack encode failed")
}

/// The replay record is its own pinned MessagePack layout: the side table
/// stores exactly the bytes [`encode_code_run_replay_record`] spells.
impl crate::side_table::RawValue for CodeRunReplayRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        Ok(encode_code_run_replay_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        Ok(decode_code_run_replay_record(bytes)?)
    }
}

/// Decodes a deterministic code-run replay record.
pub fn decode_code_run_replay_record(bytes: &[u8]) -> Result<CodeRunReplayRecord> {
    let value = decode_value(bytes)?;
    let fields = pinned_map(
        &value,
        &CODE_RUN_REPLAY_RECORD_KEYS,
        "code-run replay record",
    )?;
    let schema_version = u64_value(required(fields[0], "missing replay schema_version")?)?;
    if schema_version != CODE_RUN_REPLAY_SCHEMA_VERSION {
        return Err(invalid_code_run_replay(
            "unsupported code-run replay schema_version",
        ));
    }

    let record = CodeRunReplayRecord {
        run_id: entity_value(required(fields[1], "missing replay run_id")?)?,
        determinism: decode_determinism(required(fields[2], "missing replay determinism")?)?,
        bridge_calls: decode_array(
            required(fields[3], "missing replay bridge_calls")?,
            decode_bridge_call,
        )?,
        step_checkpoints: decode_array(
            required(fields[4], "missing replay step_checkpoints")?,
            decode_step_checkpoint,
        )?,
        outputs: decode_array(
            required(fields[5], "missing replay outputs")?,
            decode_raw_output,
        )?,
        abi_layout_checks: decode_array(
            required(fields[6], "missing replay abi_layout_checks")?,
            decode_abi_layout_check,
        )?,
        bindings: decode_array(
            required(fields[7], "missing replay bindings")?,
            decode_binding,
        )?,
        live_run: decode_live_run(required(fields[8], "missing replay live_run")?)?,
    };
    validate_code_run_replay_record(&record)?;
    Ok(record)
}

fn encode_determinism(determinism: &CodeRunDeterminism) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_FROZEN_UNIX_MS),
            Value::from(determinism.frozen_unix_ms),
        ),
        (
            Value::from(KEY_RNG_SEED),
            Value::Binary(determinism.rng_seed.to_vec()),
        ),
    ])
}

fn decode_determinism(value: &Value) -> Result<CodeRunDeterminism> {
    let fields = pinned_map(value, &CODE_RUN_DETERMINISM_KEYS, "code-run determinism")?;
    Ok(CodeRunDeterminism {
        frozen_unix_ms: u64_value(required(fields[0], "missing frozen_unix_ms")?)?,
        rng_seed: fixed_binary(required(fields[1], "missing rng_seed")?, "rng_seed")?,
    })
}

fn encode_bridge_call(call: &CodeRunBridgeCall) -> Value {
    Value::Map(vec![
        (Value::from(KEY_SEQ), Value::from(call.seq)),
        (Value::from(KEY_EFFECT), Value::from(call.effect.as_str())),
        (Value::from(KEY_REQUEST), call.request.clone()),
        (Value::from(KEY_OUTCOME), call.outcome.clone()),
        (
            Value::from(KEY_STARTED_AT_MS),
            Value::from(call.started_at_ms),
        ),
        (
            Value::from(KEY_FINISHED_AT_MS),
            Value::from(call.finished_at_ms),
        ),
        (
            Value::from(KEY_ACTION_DIGEST),
            call.action_digest
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_bridge_call(value: &Value) -> Result<CodeRunBridgeCall> {
    let fields = pinned_map(value, &CODE_RUN_BRIDGE_CALL_KEYS, "code-run bridge call")?;
    Ok(CodeRunBridgeCall {
        seq: u64_value(required(fields[0], "missing bridge seq")?)?,
        effect: self_effect_from_str(str_value(required(fields[1], "missing bridge effect")?)?)?,
        request: required(fields[2], "missing bridge request")?.clone(),
        outcome: required(fields[3], "missing bridge outcome")?.clone(),
        started_at_ms: u64_value(required(fields[4], "missing bridge started_at_ms")?)?,
        finished_at_ms: u64_value(required(fields[5], "missing bridge finished_at_ms")?)?,
        action_digest: match required(fields[6], "missing bridge action_digest")? {
            Value::Nil => None,
            digest => Some(str_value(digest)?.to_owned()),
        },
    })
}

fn encode_step_checkpoint(checkpoint: &CodeRunStepCheckpoint) -> Value {
    Value::Map(vec![
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
    ])
}

fn decode_step_checkpoint(value: &Value) -> Result<CodeRunStepCheckpoint> {
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
    };
    validate_label(&checkpoint.label, "checkpoint label")?;
    Ok(checkpoint)
}

fn encode_raw_output(output: &CodeRunRawOutput) -> Value {
    Value::Map(vec![
        (Value::from(KEY_HANDLE), Value::from(output.handle.as_str())),
        (Value::from(KEY_PATH), Value::from(output.path.as_str())),
        (
            Value::from(KEY_RAW_BLAKE3),
            Value::Binary(output.raw_blake3.to_vec()),
        ),
        (Value::from(KEY_RAW_LEN), Value::from(output.raw_len)),
        (Value::from(KEY_KIND), Value::from(output.kind.as_str())),
        (Value::from(KEY_LINES), Value::from(output.lines)),
        (Value::from(KEY_COMPLETE), Value::Boolean(output.complete)),
        (
            Value::from(KEY_PREVIEW),
            encode_output_preview(&output.preview),
        ),
    ])
}

fn decode_raw_output(value: &Value) -> Result<CodeRunRawOutput> {
    let fields = pinned_map(value, &CODE_RUN_RAW_OUTPUT_KEYS, "code-run raw output")?;
    let output = CodeRunRawOutput {
        handle: str_value(required(fields[0], "missing output handle")?)?.to_owned(),
        path: str_value(required(fields[1], "missing output path")?)?.to_owned(),
        raw_blake3: fixed_binary(
            required(fields[2], "missing output raw_blake3")?,
            "raw_blake3",
        )?,
        raw_len: u64_value(required(fields[3], "missing output raw_len")?)?,
        kind: CodeRunOutputKind::parse(str_value(required(fields[4], "missing output kind")?)?)
            .ok_or_else(|| invalid_code_run_replay("unknown output kind"))?,
        lines: u64_value(required(fields[5], "missing output lines")?)?,
        complete: bool_value(required(fields[6], "missing output complete")?)?,
        preview: decode_output_preview(required(fields[7], "missing output preview")?)?,
    };
    validate_raw_output(&output)?;
    Ok(output)
}

fn encode_output_preview(preview: &CodeRunOutputPreview) -> Value {
    Value::Map(vec![
        (Value::from(KEY_CODEC), Value::from(preview.codec.as_str())),
        (Value::from(KEY_TEXT), Value::from(preview.text.as_str())),
        (
            Value::from(KEY_TRUNCATED),
            Value::Boolean(preview.truncated),
        ),
    ])
}

fn decode_output_preview(value: &Value) -> Result<CodeRunOutputPreview> {
    let fields = pinned_map(
        value,
        &CODE_RUN_OUTPUT_PREVIEW_KEYS,
        "code-run output preview",
    )?;
    Ok(CodeRunOutputPreview {
        codec: str_value(required(fields[0], "missing preview codec")?)?.to_owned(),
        text: str_value(required(fields[1], "missing preview text")?)?.to_owned(),
        truncated: bool_value(required(fields[2], "missing preview truncated")?)?,
    })
}

fn encode_abi_layout_check(check: &CodeRunAbiLayoutCheck) -> Value {
    Value::Map(vec![
        (Value::from(KEY_NAME), Value::from(check.name.as_str())),
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(check.schema_version),
        ),
        (
            Value::from(KEY_FIELDS),
            Value::Array(
                check
                    .fields
                    .iter()
                    .map(|field| Value::from(field.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_LAYOUT_HASH),
            Value::Binary(check.layout_hash.to_vec()),
        ),
    ])
}

fn decode_abi_layout_check(value: &Value) -> Result<CodeRunAbiLayoutCheck> {
    let fields = pinned_map(
        value,
        &CODE_RUN_ABI_LAYOUT_CHECK_KEYS,
        "code-run ABI layout check",
    )?;
    let check = CodeRunAbiLayoutCheck {
        name: str_value(required(fields[0], "missing ABI layout name")?)?.to_owned(),
        schema_version: u64_value(required(fields[1], "missing ABI layout schema_version")?)?,
        fields: decode_string_array(required(fields[2], "missing ABI layout fields")?)?,
        layout_hash: fixed_binary(
            required(fields[3], "missing ABI layout hash")?,
            "layout_hash",
        )?,
    };
    validate_abi_layout_check(&check)?;
    Ok(check)
}

/// A binding is the pair `[name, handle]`.
fn encode_binding(binding: &CodeRunResultBinding) -> Value {
    Value::Array(vec![
        Value::from(binding.name.as_str()),
        Value::from(binding.handle.as_str()),
    ])
}

fn decode_binding(value: &Value) -> Result<CodeRunResultBinding> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("result binding must be an array"));
    };
    let [name, handle] = items.as_slice() else {
        return Err(invalid_code_run_replay(
            "result binding must be a [name, handle] pair",
        ));
    };
    Ok(CodeRunResultBinding::new(
        str_value(name)?,
        str_value(handle)?,
    ))
}

fn encode_live_run(binding: &CodeRunLiveRunBinding) -> Value {
    let locality = match binding.credential.locality {
        CallerLocality::OnDevice => "on_device",
        CallerLocality::OffDevice => "off_device",
    };
    Value::Map(
        CODE_RUN_LIVE_RUN_KEYS
            .iter()
            .map(|key| Value::from(*key))
            .zip([
                Value::Binary(binding.issued.to_vec()),
                Value::Binary(binding.credential.digest.to_vec()),
                Value::from(locality),
                Value::Binary(binding.actor.as_bytes().to_vec()),
                Value::from(binding.actor_class as u8),
                Value::Binary(binding.attempt.as_bytes().to_vec()),
                Value::from(binding.lease_owner.as_str()),
                Value::from(binding.lease_generation),
            ])
            .collect(),
    )
}

fn decode_live_run(value: &Value) -> Result<Option<CodeRunLiveRunBinding>> {
    if value.is_nil() {
        return Ok(None);
    }
    let fields = pinned_map(value, &CODE_RUN_LIVE_RUN_KEYS, "code-run live run")?;
    let locality = match str_value(required(fields[2], "missing live run locality")?)? {
        "on_device" => CallerLocality::OnDevice,
        "off_device" => CallerLocality::OffDevice,
        _ => return Err(invalid_code_run_replay("unknown live run locality")),
    };
    let actor_class = u8::try_from(u64_value(required(
        fields[4],
        "missing live run actor_class",
    )?)?)
    .ok()
    .and_then(EdgeActorClass::try_from_u8)
    .ok_or(invalid_code_run_replay("unknown live run actor class"))?;
    let attempt: [u8; 16] = fixed_binary(
        required(fields[5], "missing live run attempt")?,
        "live run attempt",
    )?;
    Ok(Some(CodeRunLiveRunBinding {
        issued: fixed_binary(
            required(fields[0], "missing live run issued")?,
            "live run issued",
        )?,
        credential: LiveRunCredential {
            digest: fixed_binary(
                required(fields[1], "missing live run credential")?,
                "live run credential",
            )?,
            locality,
        },
        actor: entity_value(required(fields[3], "missing live run actor")?)?,
        actor_class,
        attempt: AttemptId::from_bytes(&attempt)
            .map_err(|_| invalid_code_run_replay("live run attempt"))?,
        lease_owner: str_value(required(fields[6], "missing live run lease_owner")?)?.to_owned(),
        lease_generation: u32::try_from(u64_value(required(
            fields[7],
            "missing live run lease_generation",
        )?)?)
        .map_err(|_| invalid_code_run_replay("live run lease generation overflow"))?,
    }))
}

fn validate_code_run_replay_record(record: &CodeRunReplayRecord) -> Result<()> {
    let mut expected_seq = 0_u64;
    for call in &record.bridge_calls {
        if call.seq != expected_seq {
            return Err(invalid_code_run_replay(
                "bridge call seq must be contiguous",
            ));
        }
        validate_bridge_call(call)?;
        expected_seq = expected_seq.saturating_add(1);
    }

    let mut checkpoint_seqs = HashSet::new();
    for checkpoint in &record.step_checkpoints {
        if !checkpoint_seqs.insert(checkpoint.seq) {
            return Err(invalid_code_run_replay("duplicate checkpoint seq"));
        }
        validate_label(&checkpoint.label, "checkpoint label")?;
    }

    let mut output_paths = HashSet::new();
    for output in &record.outputs {
        validate_raw_output(output)?;
        if !output_paths.insert(output.path.as_str()) {
            return Err(invalid_code_run_replay("duplicate raw output path"));
        }
    }

    if record.abi_layout_checks.is_empty() {
        return Err(invalid_code_run_replay("missing ABI layout checks"));
    }
    for check in &record.abi_layout_checks {
        validate_abi_layout_check(check)?;
    }

    let mut names = HashSet::new();
    for binding in &record.bindings {
        if !CodeRunResultBinding::is_valid_name(&binding.name) {
            return Err(invalid_code_run_replay("invalid result binding name"));
        }
        if !names.insert(binding.name.as_str()) {
            return Err(invalid_code_run_replay("duplicate result binding name"));
        }
        if !record
            .outputs
            .iter()
            .any(|output| output.handle == binding.handle)
        {
            return Err(invalid_code_run_replay(
                "result binding names no output of this run",
            ));
        }
    }
    if let Some(live_run) = &record.live_run {
        validate_label(&live_run.lease_owner, "live run lease owner")?;
    }
    Ok(())
}

fn validate_bridge_call(call: &CodeRunBridgeCall) -> Result<()> {
    if call.finished_at_ms < call.started_at_ms {
        return Err(invalid_code_run_replay(
            "bridge call finished before it started",
        ));
    }
    call.validate_speech_coherence()?;
    Ok(())
}

pub(super) fn validate_raw_output(output: &CodeRunRawOutput) -> Result<()> {
    validate_text(
        &output.path,
        CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
        "raw output path",
    )?;
    let expected_handle = format!(
        "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
        crate::entity_id::bytes_to_hex_lower(&output.raw_blake3)
    );
    if output.handle != expected_handle {
        return Err(invalid_code_run_replay(
            "raw output handle must match raw_blake3",
        ));
    }
    if output.preview.codec != crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC {
        return Err(invalid_code_run_replay("unknown output preview codec"));
    }
    if output.preview.text.chars().count() > crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS {
        return Err(invalid_code_run_replay("output preview exceeds cap"));
    }
    Ok(())
}

fn validate_abi_layout_check(check: &CodeRunAbiLayoutCheck) -> Result<()> {
    validate_label(&check.name, "ABI layout name")?;
    if check.fields.is_empty() {
        return Err(invalid_code_run_replay(
            "ABI layout fields must not be empty",
        ));
    }
    for field in &check.fields {
        validate_label(field, "ABI layout field")?;
    }
    let expected = code_run_layout_hash(
        &check.name,
        check.schema_version,
        check.fields.iter().map(String::as_str),
    );
    if check.layout_hash != expected {
        return Err(invalid_code_run_replay("ABI layout hash mismatch"));
    }
    Ok(())
}

fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_code_run_replay("record is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(invalid_code_run_replay(
            "trailing bytes after code-run replay record",
        ));
    }
    Ok(value)
}

fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub(crate) fn encode_code_run_replay_value(
    value: &Value,
    context: &'static str,
) -> Result<Vec<u8>> {
    encode_value(value, context)
}
