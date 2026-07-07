//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

use std::{cell::Cell, collections::HashSet};

use rmpv::Value;
use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::xxh3_128;

use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeActorClass, EdgeKind, EntityId, Error, Result, ScoredEntity, TimeRange,
    Vault, WriteActor, WriteEnvelope, WriteProvenance,
};

const SELF_SURFACE_NAME: &str = "self.*";
const SELF_PROVENANCE_SURFACE_KEY: &str = "surface";
const SELF_PROVENANCE_RUN_KEY: &str = "run";
const SELF_PROVENANCE_CALL_KEY: &str = "call";
const SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN: &[u8] = b"oneiron:self-memory-edge-operation:v1";
const CODE_RUN_REPLAY_RECORD_KEY_PREFIX: &[u8] = b"code_run:replay:v1:";
const CODE_RUN_RAW_OUTPUT_KEY_PREFIX: &[u8] = b"code_run:raw_output:v1:";
const CODE_RUN_OUTPUT_HANDLE_PREFIX: &str = "code-run-output:sha256:";
const CODE_RUN_LAYOUT_HASH_DOMAIN: &[u8] = b"oneiron:code-run-replay-layout:v1";
const CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR: [u8; 16] = [0x42; 16];
const CODE_RUN_REPLAY_MAX_LABEL_BYTES: usize = 512;
const CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES: usize = 1024;

pub const CODE_RUN_REPLAY_SCHEMA_VERSION: u64 = 1;
pub const CODE_RUN_RNG_SEED_LEN: usize = 32;
pub const CODE_RUN_REPLAY_HASH_LEN: usize = 32;
pub const CODE_RUN_REPLAY_RECORD_KEYS: [&str; 7] = [
    "schema_version",
    "run_id",
    "determinism",
    "bridge_calls",
    "step_checkpoints",
    "outputs",
    "abi_layout_checks",
];
pub const CODE_RUN_DETERMINISM_KEYS: [&str; 2] = ["frozen_unix_ms", "rng_seed"];
pub const CODE_RUN_BRIDGE_CALL_KEYS: [&str; 6] = [
    "seq",
    "effect",
    "request",
    "outcome",
    "started_at_ms",
    "finished_at_ms",
];
pub const CODE_RUN_STEP_CHECKPOINT_KEYS: [&str; 4] =
    ["seq", "label", "state_hash", "created_at_ms"];
pub const CODE_RUN_RAW_OUTPUT_KEYS: [&str; 5] =
    ["handle", "path", "raw_sha256", "raw_len", "preview"];
pub const CODE_RUN_OUTPUT_PREVIEW_KEYS: [&str; 3] = ["codec", "text", "truncated"];
pub const CODE_RUN_ABI_LAYOUT_CHECK_KEYS: [&str; 4] =
    ["name", "schema_version", "fields", "layout_hash"];

const KEY_SCHEMA_VERSION: &str = CODE_RUN_REPLAY_RECORD_KEYS[0];
const KEY_RUN_ID: &str = CODE_RUN_REPLAY_RECORD_KEYS[1];
const KEY_DETERMINISM: &str = CODE_RUN_REPLAY_RECORD_KEYS[2];
const KEY_BRIDGE_CALLS: &str = CODE_RUN_REPLAY_RECORD_KEYS[3];
const KEY_STEP_CHECKPOINTS: &str = CODE_RUN_REPLAY_RECORD_KEYS[4];
const KEY_OUTPUTS: &str = CODE_RUN_REPLAY_RECORD_KEYS[5];
const KEY_ABI_LAYOUT_CHECKS: &str = CODE_RUN_REPLAY_RECORD_KEYS[6];

const KEY_FROZEN_UNIX_MS: &str = CODE_RUN_DETERMINISM_KEYS[0];
const KEY_RNG_SEED: &str = CODE_RUN_DETERMINISM_KEYS[1];

const KEY_SEQ: &str = CODE_RUN_BRIDGE_CALL_KEYS[0];
const KEY_EFFECT: &str = CODE_RUN_BRIDGE_CALL_KEYS[1];
const KEY_REQUEST: &str = CODE_RUN_BRIDGE_CALL_KEYS[2];
const KEY_OUTCOME: &str = CODE_RUN_BRIDGE_CALL_KEYS[3];
const KEY_STARTED_AT_MS: &str = CODE_RUN_BRIDGE_CALL_KEYS[4];
const KEY_FINISHED_AT_MS: &str = CODE_RUN_BRIDGE_CALL_KEYS[5];

const KEY_LABEL: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[1];
const KEY_STATE_HASH: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[2];
const KEY_CREATED_AT_MS: &str = CODE_RUN_STEP_CHECKPOINT_KEYS[3];

const KEY_HANDLE: &str = CODE_RUN_RAW_OUTPUT_KEYS[0];
const KEY_PATH: &str = CODE_RUN_RAW_OUTPUT_KEYS[1];
const KEY_RAW_SHA256: &str = CODE_RUN_RAW_OUTPUT_KEYS[2];
const KEY_RAW_LEN: &str = CODE_RUN_RAW_OUTPUT_KEYS[3];
const KEY_PREVIEW: &str = CODE_RUN_RAW_OUTPUT_KEYS[4];

const KEY_CODEC: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[0];
const KEY_TEXT: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[1];
const KEY_TRUNCATED: &str = CODE_RUN_OUTPUT_PREVIEW_KEYS[2];

const KEY_NAME: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[0];
const KEY_FIELDS: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[2];
const KEY_LAYOUT_HASH: &str = CODE_RUN_ABI_LAYOUT_CHECK_KEYS[3];

/// Frozen nondeterministic inputs for one code run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunDeterminism {
    pub frozen_unix_ms: u64,
    pub rng_seed: [u8; CODE_RUN_RNG_SEED_LEN],
}

impl CodeRunDeterminism {
    #[must_use]
    pub const fn new(frozen_unix_ms: u64, rng_seed: [u8; CODE_RUN_RNG_SEED_LEN]) -> Self {
        Self {
            frozen_unix_ms,
            rng_seed,
        }
    }
}

/// One host bridge call captured for deterministic step replay.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeRunBridgeCall {
    pub seq: u64,
    pub effect: SelfEffect,
    pub request: Value,
    pub outcome: Value,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

impl CodeRunBridgeCall {
    /// Captures one typed `self.*` call and its host outcome.
    ///
    /// Replay compares `effect` and the canonical request payload before
    /// returning this stored outcome. A changed call cannot consume an old row.
    pub fn record(
        seq: u64,
        call: &SelfCall,
        outcome: &SelfDispatchOutcome,
        started_at_ms: u64,
        finished_at_ms: u64,
    ) -> Result<Self> {
        if finished_at_ms < started_at_ms {
            return Err(invalid_code_run_replay(
                "bridge call finished before it started",
            ));
        }

        Ok(Self {
            seq,
            effect: call.effect(),
            request: self_call_request_value(call)?,
            outcome: self_dispatch_outcome_value(outcome),
            started_at_ms,
            finished_at_ms,
        })
    }
}

/// Deterministic checkpoint marker between bridge calls.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunStepCheckpoint {
    pub seq: u64,
    pub label: String,
    pub state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
    pub created_at_ms: u64,
}

impl CodeRunStepCheckpoint {
    pub fn new(
        seq: u64,
        label: impl Into<String>,
        state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
        created_at_ms: u64,
    ) -> Result<Self> {
        let checkpoint = Self {
            seq,
            label: label.into(),
            state_hash,
            created_at_ms,
        };
        validate_label(&checkpoint.label, "checkpoint label")?;
        Ok(checkpoint)
    }
}

/// Compact preview stored in a replay record beside a raw output handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunOutputPreview {
    pub codec: String,
    pub text: String,
    pub truncated: bool,
}

/// Raw code-run output metadata. Bytes are stored separately by handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunRawOutput {
    pub handle: String,
    pub path: String,
    pub raw_sha256: [u8; CODE_RUN_REPLAY_HASH_LEN],
    pub raw_len: u64,
    pub preview: CodeRunOutputPreview,
}

impl CodeRunRawOutput {
    pub fn from_bytes(path: impl Into<String>, raw: &[u8]) -> Result<Self> {
        let path = path.into();
        validate_text(
            &path,
            CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
            "raw output path",
        )?;

        let raw_sha256 = sha256_bytes(raw);
        let handle = format!(
            "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
            crate::types::bytes_to_hex_lower(&raw_sha256)
        );
        let raw_len = u64::try_from(raw.len())
            .map_err(|_| invalid_code_run_replay("raw output length overflow"))?;
        let (text, truncated) = crate::serialize::compressed_code_run_output_preview(
            raw,
            crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS,
        );

        Ok(Self {
            handle,
            path,
            raw_sha256,
            raw_len,
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text,
                truncated,
            },
        })
    }
}

/// One pinned host/guest record layout check carried by a replay record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunAbiLayoutCheck {
    pub name: String,
    pub schema_version: u64,
    pub fields: Vec<String>,
    pub layout_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
}

impl CodeRunAbiLayoutCheck {
    #[must_use]
    pub fn for_fields(name: impl Into<String>, schema_version: u64, fields: &[&str]) -> Self {
        let name = name.into();
        Self {
            layout_hash: code_run_layout_hash(&name, schema_version, fields.iter().copied()),
            name,
            schema_version,
            fields: fields.iter().map(|field| (*field).to_owned()).collect(),
        }
    }
}

/// Persisted deterministic replay record for a first-party code run.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeRunReplayRecord {
    pub run_id: EntityId,
    pub determinism: CodeRunDeterminism,
    pub bridge_calls: Vec<CodeRunBridgeCall>,
    pub step_checkpoints: Vec<CodeRunStepCheckpoint>,
    pub outputs: Vec<CodeRunRawOutput>,
    pub abi_layout_checks: Vec<CodeRunAbiLayoutCheck>,
}

impl CodeRunReplayRecord {
    #[must_use]
    pub fn new(run_id: EntityId, determinism: CodeRunDeterminism) -> Self {
        Self {
            run_id,
            determinism,
            bridge_calls: Vec::new(),
            step_checkpoints: Vec::new(),
            outputs: Vec::new(),
            abi_layout_checks: code_run_replay_abi_layout_checks(),
        }
    }

    #[must_use]
    pub fn replay_cursor(&self) -> CodeRunReplayCursor<'_> {
        CodeRunReplayCursor::new(self)
    }
}

/// Returns the default ABI/layout checks recorded with v1 replay records.
#[must_use]
pub fn code_run_replay_abi_layout_checks() -> Vec<CodeRunAbiLayoutCheck> {
    vec![
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.replay_record",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_REPLAY_RECORD_KEYS,
        ),
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.determinism",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_DETERMINISM_KEYS,
        ),
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.bridge_call",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_BRIDGE_CALL_KEYS,
        ),
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.step_checkpoint",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_STEP_CHECKPOINT_KEYS,
        ),
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.raw_output",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_RAW_OUTPUT_KEYS,
        ),
        CodeRunAbiLayoutCheck::for_fields(
            "code_run.output_preview",
            CODE_RUN_REPLAY_SCHEMA_VERSION,
            &CODE_RUN_OUTPUT_PREVIEW_KEYS,
        ),
    ]
}

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
    ]);
    encode_value(&value, "code-run replay record MessagePack encode failed")
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
    };
    validate_code_run_replay_record(&record)?;
    Ok(record)
}

/// Cursor that replays bridge calls from a stored record without invoking live host effects.
pub struct CodeRunReplayCursor<'a> {
    record: &'a CodeRunReplayRecord,
    next: Cell<usize>,
}

impl<'a> CodeRunReplayCursor<'a> {
    #[must_use]
    pub const fn new(record: &'a CodeRunReplayRecord) -> Self {
        Self {
            record,
            next: Cell::new(0),
        }
    }

    #[must_use]
    pub fn consumed(&self) -> usize {
        self.next.get()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.consumed() == self.record.bridge_calls.len()
    }
}

impl SelfDispatcher for CodeRunReplayCursor<'_> {
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        let index = self.next.get();
        let stored = self
            .record
            .bridge_calls
            .get(index)
            .ok_or(invalid_code_run_replay(
                "code-run replay bridge log exhausted",
            ))?;
        if stored.seq != index as u64 {
            return Err(invalid_code_run_replay("code-run replay bridge seq drift"));
        }
        if stored.effect != call.effect() {
            return Err(invalid_code_run_replay("code-run replay effect mismatch"));
        }

        let request = self_call_request_value(&call)?;
        if stored.request != request {
            return Err(invalid_code_run_replay("code-run replay request mismatch"));
        }

        let outcome = decode_self_dispatch_outcome(&stored.outcome)?;
        self.next.set(index + 1);
        Ok(outcome)
    }
}

impl Vault {
    /// Persists the replay record for `record.run_id`.
    pub fn put_code_run_replay_record(&self, record: &CodeRunReplayRecord) -> Result<()> {
        let encoded = encode_code_run_replay_record(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.store.vault_meta.put(
            &mut wtxn,
            &code_run_replay_record_key(&record.run_id),
            &encoded,
        )?;
        wtxn.commit().map_err(Error::from)
    }

    /// Loads the replay record for `run_id`, if present.
    pub fn get_code_run_replay_record(
        &self,
        run_id: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        let rtxn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&rtxn, &code_run_replay_record_key(run_id))?
            .map(decode_code_run_replay_record)
            .transpose()
    }

    /// Stores raw output bytes under a deterministic content handle.
    pub fn put_code_run_raw_output(&self, output: &CodeRunRawOutput, raw: &[u8]) -> Result<()> {
        let expected = CodeRunRawOutput::from_bytes(output.path.clone(), raw)?;
        if expected != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }

        let mut wtxn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut wtxn, &code_run_raw_output_key(output), raw)?;
        wtxn.commit().map_err(Error::from)
    }

    /// Loads raw output bytes for `output` and verifies they still match metadata.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &code_run_raw_output_key(output))?
            .map(<[u8]>::to_vec)
        else {
            return Ok(None);
        };
        let expected = CodeRunRawOutput::from_bytes(output.path.clone(), &raw)?;
        if expected != *output {
            return Err(invalid_code_run_replay(
                "stored raw output bytes drifted from metadata",
            ));
        }
        Ok(Some(raw))
    }
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
            Value::from(KEY_RAW_SHA256),
            Value::Binary(output.raw_sha256.to_vec()),
        ),
        (Value::from(KEY_RAW_LEN), Value::from(output.raw_len)),
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
        raw_sha256: fixed_binary(
            required(fields[2], "missing output raw_sha256")?,
            "raw_sha256",
        )?,
        raw_len: u64_value(required(fields[3], "missing output raw_len")?)?,
        preview: decode_output_preview(required(fields[4], "missing output preview")?)?,
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

    let mut output_handles = HashSet::new();
    for output in &record.outputs {
        validate_raw_output(output)?;
        if !output_handles.insert(output.handle.as_str()) {
            return Err(invalid_code_run_replay("duplicate raw output handle"));
        }
    }

    if record.abi_layout_checks.is_empty() {
        return Err(invalid_code_run_replay("missing ABI layout checks"));
    }
    for check in &record.abi_layout_checks {
        validate_abi_layout_check(check)?;
    }
    Ok(())
}

fn validate_bridge_call(call: &CodeRunBridgeCall) -> Result<()> {
    if call.finished_at_ms < call.started_at_ms {
        return Err(invalid_code_run_replay(
            "bridge call finished before it started",
        ));
    }
    let _ = decode_self_dispatch_outcome(&call.outcome)?;
    Ok(())
}

fn validate_raw_output(output: &CodeRunRawOutput) -> Result<()> {
    validate_text(
        &output.path,
        CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
        "raw output path",
    )?;
    let expected_handle = format!(
        "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
        crate::types::bytes_to_hex_lower(&output.raw_sha256)
    );
    if output.handle != expected_handle {
        return Err(invalid_code_run_replay(
            "raw output handle must match raw_sha256",
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

fn self_call_request_value(call: &SelfCall) -> Result<Value> {
    Ok(match call {
        SelfCall::MemorySearch(call) => request_map(vec![
            ("query", Value::from(call.query.as_str())),
            ("limit", Value::from(call.limit as u64)),
        ]),
        SelfCall::MemoryWriteFixture(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemoryPutClaim(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemorySupersedeClaim(call) => request_map(vec![
            ("new_id", entity_id_value(call.new_id)),
            ("old_id", entity_id_value(call.old_id)),
            ("now", Value::from(call.now)),
        ]),
        SelfCall::MemoryPutEdge(call) => request_map(vec![
            ("src", entity_id_value(call.src)),
            ("kind", Value::from(call.kind as u8)),
            ("tgt", entity_id_value(call.tgt)),
            ("weight", Value::F32(call.weight)),
        ]),
        SelfCall::AskHuman(call) => {
            request_map(vec![("prompt", Value::from(call.prompt.as_str()))])
        }
        SelfCall::DestructiveFixture(call) | SelfCall::OutboundFixture(call) => {
            request_map(vec![("label", Value::from(call.label.as_str()))])
        }
    })
}

fn claim_candidate_request_value(candidate: &ClaimCandidate) -> Result<Value> {
    let envelope = canonical_replay_request_envelope()?;
    let body = (*candidate).clone().into_claim_body(&envelope);
    Ok(Value::Map(vec![
        (
            Value::from("predicate"),
            Value::from(body.predicate.as_str()),
        ),
        (Value::from("subject"), Value::Binary(body.subject.encode())),
        (Value::from("value"), body.value.clone()),
        (Value::from("confidence"), Value::F32(body.confidence)),
        (Value::from("salience"), optional_f32_value(body.salience)),
        (
            Value::from("evidence"),
            optional_value(body.evidence.clone()),
        ),
        (
            Value::from("valid_from"),
            optional_u64_value(body.valid_from),
        ),
        (Value::from("valid_to"), optional_u64_value(body.valid_to)),
        (Value::from("world"), optional_entity_value(body.world)),
        (Value::from("scope"), optional_value(body.scope.clone())),
        (Value::from("stale"), Value::Boolean(body.stale)),
    ]))
}

fn canonical_replay_request_envelope() -> Result<WriteEnvelope> {
    let actor = EntityId::from_bytes(CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR)
        .map_err(|_| invalid_code_run_replay("canonical replay actor id is invalid"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from(SELF_PROVENANCE_SURFACE_KEY),
            Value::from("code_run_replay_request"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    ))
}

fn self_dispatch_outcome_value(outcome: &SelfDispatchOutcome) -> Value {
    match outcome {
        SelfDispatchOutcome::MemorySearch(result) => request_map(vec![
            ("kind", Value::from("memory_search")),
            ("query", Value::from(result.query.as_str())),
            (
                "results",
                Value::Array(
                    result
                        .results
                        .iter()
                        .map(|hit| {
                            request_map(vec![
                                ("id", entity_id_value(hit.id)),
                                ("score", Value::F32(hit.score)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        SelfDispatchOutcome::MemoryWrite(result) => request_map(vec![
            ("kind", Value::from("memory_write")),
            ("id", entity_id_value(result.id)),
        ]),
        SelfDispatchOutcome::MemoryEdgeWrite(result) => request_map(vec![
            ("kind", Value::from("memory_edge_write")),
            ("src", entity_id_value(result.src)),
            ("edge_kind", Value::from(result.kind as u8)),
            ("tgt", entity_id_value(result.tgt)),
        ]),
        SelfDispatchOutcome::DurableWait(wait) => request_map(vec![
            ("kind", Value::from("durable_wait")),
            ("wait_id", entity_id_value(wait.wait_id)),
            ("effect", Value::from(wait.effect.as_str())),
            ("reason", Value::from(durable_wait_reason_str(wait.reason))),
            (
                "prompt",
                wait.prompt
                    .as_ref()
                    .map_or(Value::Nil, |prompt| Value::from(prompt.as_str())),
            ),
        ]),
    }
}

fn decode_self_dispatch_outcome(value: &Value) -> Result<SelfDispatchOutcome> {
    let entries = expect_map(value, "dispatch outcome must be a map")?;
    let kind = str_value(map_get(entries, "kind")?)?;
    match kind {
        "memory_search" => {
            let results = decode_array(map_get(entries, "results")?, decode_scored_entity)?;
            Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
                query: str_value(map_get(entries, "query")?)?.to_owned(),
                results,
            }))
        }
        "memory_write" => Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: entity_value(map_get(entries, "id")?)?,
        })),
        "memory_edge_write" => Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: entity_value(map_get(entries, "src")?)?,
                kind: edge_kind_value(map_get(entries, "edge_kind")?)?,
                tgt: entity_value(map_get(entries, "tgt")?)?,
            },
        )),
        "durable_wait" => {
            let prompt = match map_get(entries, "prompt")? {
                Value::Nil => None,
                value => Some(str_value(value)?.to_owned()),
            };
            Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: entity_value(map_get(entries, "wait_id")?)?,
                effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
                reason: durable_wait_reason_from_str(str_value(map_get(entries, "reason")?)?)?,
                prompt,
            }))
        }
        _ => Err(invalid_code_run_replay("unknown dispatch outcome kind")),
    }
}

fn decode_scored_entity(value: &Value) -> Result<ScoredEntity> {
    let entries = expect_map(value, "scored entity must be a map")?;
    Ok(ScoredEntity {
        id: entity_value(map_get(entries, "id")?)?,
        score: f32_value(map_get(entries, "score")?)?,
    })
}

fn request_map(entries: Vec<(&'static str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn optional_value(value: Option<Value>) -> Value {
    value.unwrap_or(Value::Nil)
}

fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn optional_f32_value(value: Option<f32>) -> Value {
    value.map_or(Value::Nil, Value::F32)
}

fn optional_entity_value(value: Option<EntityId>) -> Value {
    value.map_or(Value::Nil, entity_id_value)
}

fn entity_id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn self_effect_from_str(value: &str) -> Result<SelfEffect> {
    match value {
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "self.ask_human" => Ok(SelfEffect::AskHuman),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        _ => Err(invalid_code_run_replay("unknown self effect")),
    }
}

fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
    }
}

fn durable_wait_reason_from_str(value: &str) -> Result<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        _ => Err(invalid_code_run_replay("unknown durable wait reason")),
    }
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

fn pinned_map<'a, const N: usize>(
    value: &'a Value,
    keys: &[&str; N],
    context: &'static str,
) -> Result<[Option<&'a Value>; N]> {
    let entries = expect_map(value, context)?;
    let mut out = [None; N];
    for (key, value) in entries {
        let key = str_value(key)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_code_run_replay("map key is not pinned"));
        };
        if out[index].replace(value).is_some() {
            return Err(invalid_code_run_replay("duplicate map key"));
        }
    }
    Ok(out)
}

fn expect_map<'a>(value: &'a Value, _context: &'static str) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_code_run_replay("value must be a MessagePack map"));
    };
    Ok(entries)
}

fn map_get<'a>(entries: &'a [(Value, Value)], needle: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(needle)).then_some(value))
        .ok_or(invalid_code_run_replay("missing dispatch outcome key"))
}

fn required<'a>(value: Option<&'a Value>, message: &'static str) -> Result<&'a Value> {
    value.ok_or(invalid_code_run_replay(message))
}

fn decode_array<T>(value: &Value, decode: fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("value must be an array"));
    };
    items.iter().map(decode).collect()
}

fn decode_string_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("fields must be an array"));
    };
    items
        .iter()
        .map(|item| str_value(item).map(ToOwned::to_owned))
        .collect()
}

fn str_value(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or(invalid_code_run_replay("value must be a string"))
}

fn bool_value(value: &Value) -> Result<bool> {
    match value {
        Value::Boolean(value) => Ok(*value),
        _ => Err(invalid_code_run_replay("value must be a boolean")),
    }
}

fn u64_value(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or(invalid_code_run_replay("value must be an unsigned integer"))
}

fn f32_value(value: &Value) -> Result<f32> {
    let parsed = match value {
        Value::F32(value) => *value,
        Value::F64(value) => *value as f32,
        _ => return Err(invalid_code_run_replay("value must be a float")),
    };
    if !parsed.is_finite() {
        return Err(invalid_code_run_replay("float must be finite"));
    }
    Ok(parsed)
}

fn entity_value(value: &Value) -> Result<EntityId> {
    let bytes: [u8; 16] = fixed_binary(value, "entity id")?;
    EntityId::from_bytes(bytes).map_err(|_| invalid_code_run_replay("entity id is reserved"))
}

fn edge_kind_value(value: &Value) -> Result<EdgeKind> {
    let raw = u8::try_from(u64_value(value)?)
        .map_err(|_| invalid_code_run_replay("edge kind byte overflow"))?;
    EdgeKind::try_from_u8(raw).ok_or(invalid_code_run_replay("unknown edge kind byte"))
}

fn fixed_binary<const N: usize>(value: &Value, field: &'static str) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_code_run_replay(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_code_run_replay(field))
}

fn validate_label(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, CODE_RUN_REPLAY_MAX_LABEL_BYTES, field)
}

fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid_code_run_replay(field));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> [u8; CODE_RUN_REPLAY_HASH_LEN] {
    Sha256::digest(bytes).into()
}

fn code_run_layout_hash<I, S>(
    name: &str,
    schema_version: u64,
    fields: I,
) -> [u8; CODE_RUN_REPLAY_HASH_LEN]
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Sha256::new();
    hasher.update(CODE_RUN_LAYOUT_HASH_DOMAIN);
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(schema_version.to_be_bytes());
    for field in fields {
        hasher.update([0]);
        hasher.update(field.as_ref().as_bytes());
    }
    hasher.finalize().into()
}

fn code_run_replay_record_key(run_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_REPLAY_RECORD_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CODE_RUN_REPLAY_RECORD_KEY_PREFIX);
    key.extend_from_slice(run_id.as_bytes());
    key
}

fn code_run_raw_output_key(output: &CodeRunRawOutput) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_RAW_OUTPUT_KEY_PREFIX.len() + output.handle.len());
    key.extend_from_slice(CODE_RUN_RAW_OUTPUT_KEY_PREFIX);
    key.extend_from_slice(output.handle.as_bytes());
    key
}

fn invalid_code_run_replay(message: &'static str) -> Error {
    Error::InvalidCodeArtifactBody(message)
}

/// Dispatcher for host-side `self.*` calls emitted by a first-party runtime.
pub trait SelfDispatcher {
    /// Routes one typed call through the host-owned dispatcher.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome>;
}

/// Host-bound dispatcher for one first-party code run.
///
/// The actor and source are bound at construction time by the host. Individual
/// [`SelfCall`] values carry only operation arguments, so guest-authored code
/// cannot spoof actor, source, or approval fields through this skeleton.
pub struct HostSelfDispatcher<'a> {
    vault: &'a Vault,
    actor: WriteActor,
    run_ref: String,
}

impl<'a> HostSelfDispatcher<'a> {
    /// Creates a dispatcher for a first-party run.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn new(vault: &'a Vault, actor: WriteActor, run_ref: impl Into<String>) -> Result<Self> {
        let run_ref = run_ref.into();
        if run_ref.trim().is_empty() {
            return Err(crate::Error::InvalidClaimBody(
                "self dispatcher missing run ref",
            ));
        }

        Ok(Self {
            vault,
            actor,
            run_ref,
        })
    }

    /// Host-stamped actor for writes from this dispatcher.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Host-stamped source for first-party generated code effects.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        ClaimSource::Generated
    }

    /// Stable host run reference included in write provenance.
    #[must_use]
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }

    fn write_envelope(&self, effect: SelfEffect) -> Result<WriteEnvelope> {
        Ok(WriteEnvelope::new(
            self.actor,
            self.source(),
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from(SELF_PROVENANCE_SURFACE_KEY),
                    Value::from(SELF_SURFACE_NAME),
                ),
                (
                    Value::from(SELF_PROVENANCE_RUN_KEY),
                    Value::from(self.run_ref.clone()),
                ),
                (
                    Value::from(SELF_PROVENANCE_CALL_KEY),
                    Value::from(effect.as_str()),
                ),
            ]))?,
            ClaimApprovalStatus::Proposed,
        ))
    }

    fn dispatch_memory_search(&self, call: SelfMemorySearchCall) -> Result<SelfDispatchOutcome> {
        let results = self.vault.search_text(&call.query, call.limit)?;
        Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: call.query,
            results,
        }))
    }

    fn dispatch_memory_write_fixture(
        &self,
        call: SelfMemoryWriteFixtureCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemoryWriteFixture)?;
        self.vault
            .batch()
            .claim_candidate(
                &call.id,
                *call.candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )
            .commit()?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemoryPutClaim)?;
        let gate_body = (*call.candidate).clone().into_claim_body(&envelope);
        self.check_write_gate(call.id, &gate_body, &envelope, true)?;
        self.vault
            .put_claim_candidate_without_lexical_query_reconcile(
                &call.id,
                *call.candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim)?;
        let claim_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Entity(call.old_id),
            Value::Binary(call.new_id.as_bytes().to_vec()),
            &envelope,
        );

        let supersedes_weight =
            EdgeKind::Supersedes
                .default_weight()
                .ok_or(Error::InvariantViolation(
                    "Supersedes edge missing default weight",
                ))?;
        let edge_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Edge {
                source: call.new_id,
                kind: EdgeKind::Supersedes,
                target: call.old_id,
            },
            Value::F32(supersedes_weight),
            &envelope,
        );
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            call.new_id,
            EdgeKind::Supersedes,
            call.old_id,
        )?;
        self.vault.supersede_claim_for_code_run_trap(
            &call.new_id,
            &call.old_id,
            call.now,
            &envelope,
            call.old_id,
            &claim_gate_body,
            edge_gate_id,
            &edge_gate_body,
        )?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    fn dispatch_memory_put_edge(&self, call: SelfMemoryPutEdgeCall) -> Result<SelfDispatchOutcome> {
        ensure_public_memory_edge_kind(call.kind)?;
        let envelope = self.write_envelope(SelfEffect::MemoryPutEdge)?;
        let gate_body = self.operation_gate_body(
            SelfEffect::MemoryPutEdge,
            ClaimSubject::Edge {
                source: call.src,
                kind: call.kind,
                target: call.tgt,
            },
            Value::F32(call.weight),
            &envelope,
        );
        self.vault.put_edge_for_code_run_trap(
            &call.src,
            call.kind,
            &call.tgt,
            call.weight,
            &envelope,
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, call.src, call.kind, call.tgt)?,
            &gate_body,
        )?;

        Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: call.src,
                kind: call.kind,
                tgt: call.tgt,
            },
        ))
    }

    fn operation_gate_body(
        &self,
        effect: SelfEffect,
        subject: ClaimSubject,
        value: Value,
        envelope: &WriteEnvelope,
    ) -> ClaimBody {
        let mut body = ClaimBody::new(
            effect.as_str(),
            subject,
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(crate::types::write_envelope_evidence(envelope, None));
        body.source = Some(envelope.source());
        body
    }

    fn validate_write_actor_binding(&self, envelope: &WriteEnvelope) -> Result<()> {
        crate::gate::validate_write_envelope(envelope)?;
        let actor = envelope.actor();
        let rtxn = self.vault.store.env.read_txn()?;
        let actor_raw = self
            .vault
            .store
            .entities
            .get(&rtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = crate::batch::EntityMetadataHeader::parse(actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
    }

    fn check_write_gate(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        self.validate_write_actor_binding(envelope)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &wtxn)?;
        let gate_result = crate::gate::check_claim_policy_for_write(
            &self.vault.store,
            &mut wtxn,
            &id,
            body,
            Some(envelope),
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent,
                include_source_in_gate_input: true,
            },
        );
        wtxn.commit().map_err(Error::from)?;
        gate_result
    }

    fn durable_wait(
        &self,
        effect: SelfEffect,
        reason: SelfDurableWaitReason,
        prompt: Option<String>,
    ) -> SelfDispatchOutcome {
        SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id: EntityId::now(),
            effect,
            reason,
            prompt,
        })
    }
}

impl SelfDispatcher for HostSelfDispatcher<'_> {
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        match call {
            SelfCall::MemorySearch(call) => self.dispatch_memory_search(call),
            SelfCall::MemoryWriteFixture(call) => self.dispatch_memory_write_fixture(call),
            SelfCall::MemoryPutClaim(call) => self.dispatch_memory_put_claim(call),
            SelfCall::MemorySupersedeClaim(call) => self.dispatch_memory_supersede_claim(call),
            SelfCall::MemoryPutEdge(call) => self.dispatch_memory_put_edge(call),
            SelfCall::AskHuman(call) => Ok(self.durable_wait(
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
                Some(call.prompt),
            )),
            SelfCall::DestructiveFixture(call) => Ok(self.durable_wait(
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
                Some(call.label),
            )),
            SelfCall::OutboundFixture(call) => Ok(self.durable_wait(
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
                Some(call.label),
            )),
        }
    }
}

fn edge_operation_gate_id(
    effect: SelfEffect,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<EntityId> {
    let mut material = Vec::with_capacity(
        SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN.len()
            + effect.as_str().len()
            + src.as_bytes().len()
            + 1
            + tgt.as_bytes().len(),
    );
    material.extend_from_slice(SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN);
    material.extend_from_slice(effect.as_str().as_bytes());
    material.extend_from_slice(src.as_bytes());
    material.push(kind as u8);
    material.extend_from_slice(tgt.as_bytes());

    let bytes = xxh3_128(&material).to_le_bytes();
    for tweak in 0..=u8::MAX {
        let mut candidate = bytes;
        candidate[0] ^= tweak;
        if let Ok(id) = EntityId::from_bytes(candidate) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "edge operation gate id derivation failed",
    ))
}

fn ensure_public_memory_edge_kind(kind: EdgeKind) -> Result<()> {
    match kind {
        EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => Ok(()),
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom => Err(Error::InvalidClaimBody(
            "self.memory.put_edge rejects structural edge kinds",
        )),
    }
}

/// Typed first-party host call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfCall {
    /// Fixture for `self.memory.search(...)`.
    MemorySearch(SelfMemorySearchCall),
    /// Internal fixture proving dispatcher-stamped writes use the batch/gate path.
    ///
    /// This is not the CODE-007a public `self.memory.put_claim` trap surface.
    MemoryWriteFixture(SelfMemoryWriteFixtureCall),
    /// Public first-party `self.memory.put_claim(...)` trap.
    MemoryPutClaim(SelfMemoryPutClaimCall),
    /// Public first-party `self.memory.supersede_claim(...)` trap.
    MemorySupersedeClaim(SelfMemorySupersedeClaimCall),
    /// Public first-party `self.memory.put_edge(...)` trap.
    MemoryPutEdge(SelfMemoryPutEdgeCall),
    /// Fixture for `self.ask_human(...)`.
    AskHuman(SelfAskHumanCall),
    /// Fixture for destructive effects, which must park as durable waits.
    DestructiveFixture(SelfFixtureEffectCall),
    /// Fixture for outbound effects, which must park as durable waits.
    OutboundFixture(SelfFixtureEffectCall),
}

impl SelfCall {
    /// Returns the host effect class for this call.
    #[must_use]
    pub const fn effect(&self) -> SelfEffect {
        match self {
            Self::MemorySearch(_) => SelfEffect::MemorySearch,
            Self::MemoryWriteFixture(_) => SelfEffect::MemoryWriteFixture,
            Self::MemoryPutClaim(_) => SelfEffect::MemoryPutClaim,
            Self::MemorySupersedeClaim(_) => SelfEffect::MemorySupersedeClaim,
            Self::MemoryPutEdge(_) => SelfEffect::MemoryPutEdge,
            Self::AskHuman(_) => SelfEffect::AskHuman,
            Self::DestructiveFixture(_) => SelfEffect::DestructiveFixture,
            Self::OutboundFixture(_) => SelfEffect::OutboundFixture,
        }
    }
}

/// Host effect class routed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfEffect {
    MemorySearch,
    MemoryWriteFixture,
    MemoryPutClaim,
    MemorySupersedeClaim,
    MemoryPutEdge,
    AskHuman,
    DestructiveFixture,
    OutboundFixture,
}

impl SelfEffect {
    /// Stable effect label used in host-generated provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemorySearch => "self.memory.search",
            Self::MemoryWriteFixture => "self.memory.write_fixture",
            Self::MemoryPutClaim => "self.memory.put_claim",
            Self::MemorySupersedeClaim => "self.memory.supersede_claim",
            Self::MemoryPutEdge => "self.memory.put_edge",
            Self::AskHuman => "self.ask_human",
            Self::DestructiveFixture => "self.fixture.destructive",
            Self::OutboundFixture => "self.fixture.outbound",
        }
    }
}

/// Arguments for the `self.memory.search` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfMemorySearchCall {
    pub query: String,
    pub limit: usize,
}

impl SelfMemorySearchCall {
    #[must_use]
    pub fn new(query: impl Into<String>, limit: usize) -> Self {
        Self {
            query: query.into(),
            limit,
        }
    }
}

/// Internal fixture write routed through [`Vault::batch`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryWriteFixtureCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryWriteFixtureCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `self.memory.put_claim` trap.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryPutClaimCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryPutClaimCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `self.memory.supersede_claim` trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemorySupersedeClaimCall {
    pub new_id: EntityId,
    pub old_id: EntityId,
    pub now: u64,
}

impl SelfMemorySupersedeClaimCall {
    #[must_use]
    pub const fn new(new_id: EntityId, old_id: EntityId, now: u64) -> Self {
        Self {
            new_id,
            old_id,
            now,
        }
    }
}

/// Arguments for the public `self.memory.put_edge` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryPutEdgeCall {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
    pub weight: f32,
}

impl SelfMemoryPutEdgeCall {
    #[must_use]
    pub const fn new(src: EntityId, kind: EdgeKind, tgt: EntityId, weight: f32) -> Self {
        Self {
            src,
            kind,
            tgt,
            weight,
        }
    }
}

/// Arguments for the `self.ask_human` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAskHumanCall {
    pub prompt: String,
}

impl SelfAskHumanCall {
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
        }
    }
}

/// Arguments for destructive/outbound fixture effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFixtureEffectCall {
    pub label: String,
}

impl SelfFixtureEffectCall {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// Result of dispatching a `self.*` call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfDispatchOutcome {
    MemorySearch(SelfMemorySearchResult),
    MemoryWrite(SelfMemoryWriteResult),
    MemoryEdgeWrite(SelfMemoryEdgeWriteResult),
    DurableWait(SelfDurableWait),
}

/// Result of a `self.memory.search` fixture dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemorySearchResult {
    pub query: String,
    pub results: Vec<ScoredEntity>,
}

/// Result of an internal fixture memory write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemoryWriteResult {
    pub id: EntityId,
}

/// Result of a public `self.memory.put_edge` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryEdgeWriteResult {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
}

/// Durable wait produced for effects that need human/external resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDurableWait {
    pub wait_id: EntityId,
    pub effect: SelfEffect,
    pub reason: SelfDurableWaitReason,
    pub prompt: Option<String>,
}

/// Why a dispatched effect parked instead of committing immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfDurableWaitReason {
    HumanInput,
    DestructiveEffect,
    OutboundEffect,
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::*;
    use crate::{
        ClaimSubject, EdgeActorClass, HnswConfig, VaultConfig, WriteActor,
        receipt::{ReceiptKind, ReceiptQuery},
        types::{
            ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
            WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
            WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
        },
    };

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), test_config()).expect("open vault");
        (dir, vault)
    }

    fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn seed_person(vault: &Vault, seed: u8) -> EntityId {
        let id = EntityId::from_bytes([seed; 16]).expect("entity id");
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .expect("seed person");
        id
    }

    fn seed_machine(vault: &Vault, seed: u8) -> EntityId {
        let id = EntityId::from_bytes([seed; 16]).expect("entity id");
        vault
            .put_entity(&id, ENTITY_TYPE_MACHINE, range(1), 1, b"machine")
            .expect("seed machine");
        id
    }

    fn seed_first_party_actor(vault: &Vault) -> EntityId {
        let id = EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
            .expect("first-party actor id");
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"first-party actor")
            .expect("seed first-party actor");
        id
    }

    fn clear_policy_manifests_for_test(vault: &Vault) -> Result<()> {
        vault.with_write_txn(|wtxn| {
            let mut ids = Vec::new();
            for row in vault
                .store
                .type_index
                .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
            {
                let (key, _) = row?;
                let id = EntityId::from_bytes(
                    key[1..]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("type index key"))?,
                )
                .map_err(|_| Error::CorruptedIndex("type index key"))?;
                ids.push(id);
            }
            for id in ids {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            }
            Ok(())
        })
    }

    fn put_policy_manifest_bytes(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = EntityId::from_bytes([seed; 16])?;
        let learned_at = 2_u64;
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(data);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &payload)?;
        let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
        let temporal_key = crate::store::Store::encode_temporal_key(learned_at, &id);
        vault
            .store
            .temporal_occurred_start
            .put(&mut wtxn, &temporal_key, &[])?;
        vault
            .store
            .temporal_learned
            .put(&mut wtxn, &temporal_key, &[])?;
        wtxn.commit().map_err(Error::from)
    }

    fn put_malformed_policy_manifest(vault: &Vault, seed: u8) -> Result<()> {
        put_policy_manifest_bytes(vault, seed, b"not-msgpack")
    }

    fn install_self_memory_allow_policy(vault: &Vault, actor: EntityId) -> Result<()> {
        install_self_memory_policy_trusting_source(vault, actor, ClaimSource::Generated)
    }

    fn install_self_memory_policy_trusting_source(
        vault: &Vault,
        actor: EntityId,
        source: ClaimSource,
    ) -> Result<()> {
        clear_policy_manifests_for_test(vault)?;
        let manifest = Value::Map(vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("code-run-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (
                Value::from("rules"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("prefix"), Value::from("self.memory.")),
                    (
                        Value::from("axes"),
                        Value::Map(vec![
                            (Value::from("criticality"), Value::from("normal")),
                            (Value::from("sensitivity"), Value::from("normal")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("actor_ref"), Value::from(actor.to_hex())),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
            (
                Value::from("source_trust"),
                Value::Map(vec![(
                    Value::from(source.as_str()),
                    Value::Map(vec![
                        (Value::from("max_auto_sensitivity"), Value::from(0_u64)),
                        (Value::from("receipted"), Value::Boolean(true)),
                        (Value::from("warned"), Value::Boolean(true)),
                    ]),
                )]),
            ),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)
            .map_err(|_| Error::InvariantViolation("failed to encode policy manifest fixture"))?;
        put_policy_manifest_bytes(vault, 0xE8, &data)
    }

    fn gate_decision_count(vault: &Vault) -> Result<usize> {
        Ok(vault.store.gate_decisions(100)?.len())
    }

    fn gate_receipt_count(vault: &Vault) -> Result<usize> {
        Ok(vault
            .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?
            .len())
    }

    fn assert_latest_gate_decision(vault: &Vault, expected_id: EntityId) -> Result<()> {
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.content_kind, "claim");
        assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
        assert!(latest.actor_ref.is_some());
        assert!(
            latest
                .reason_codes
                .iter()
                .all(|code| code.starts_with("gate."))
        );
        Ok(())
    }

    fn assert_gate_receipts_for_claim(
        vault: &Vault,
        expected_id: EntityId,
        expected_actor: EntityId,
        expected_outcome: &str,
        expected_count: usize,
    ) -> Result<()> {
        let expected_trigger = format!("claim:{}", expected_id.to_hex());
        let expected_actor = expected_actor.to_hex();
        let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        let matching_receipts = receipts
            .iter()
            .filter(|receipt| {
                receipt.trigger_ref.as_deref() == Some(expected_trigger.as_str())
                    && receipt.outcome == expected_outcome
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matching_receipts.len(),
            expected_count,
            "unexpected gate receipt count for {expected_trigger}"
        );

        for receipt in matching_receipts {
            assert_eq!(receipt.receipt_kind, ReceiptKind::Gate);
            assert_eq!(receipt.actor.as_deref(), Some(expected_actor.as_str()));
            assert_eq!(
                receipt.fields.get("content_kind").map(String::as_str),
                Some("claim")
            );
            assert!(
                receipt
                    .fields
                    .get("diff_handle")
                    .is_some_and(|value| !value.is_empty())
            );
            assert!(
                receipt
                    .fields
                    .get("read_frontier_hash")
                    .is_some_and(|value| !value.is_empty())
            );
        }
        Ok(())
    }

    fn assert_latest_gate_decision_reasons(
        vault: &Vault,
        expected_id: EntityId,
        expected_outcome: &str,
        expected_reasons: &[&str],
    ) -> Result<()> {
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, expected_outcome);
        assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
        assert_eq!(
            latest.reason_codes,
            expected_reasons
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    fn assert_source_trust_gate_rejection(err: Error) {
        match err {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "pending");
                assert_eq!(reason_codes, vec!["gate.pending.source_trust"]);
            }
            other => panic!("expected source-trust gate rejection, got {other:?}"),
        }
    }

    fn assert_recent_gate_decision_ids(vault: &Vault, expected: &[EntityId]) -> Result<()> {
        let decisions = vault.store.gate_decisions(expected.len())?;
        let actual = decisions
            .iter()
            .map(|decision| decision.claim_id.expect("gate decision claim id"))
            .collect::<Vec<_>>();
        let expected = expected.iter().map(|id| *id.as_bytes()).collect::<Vec<_>>();
        assert_eq!(actual, expected);
        Ok(())
    }

    fn map_value<'a>(entries: &'a [(Value, Value)], key: &str) -> &'a Value {
        entries
            .iter()
            .find_map(|(entry_key, entry_value)| {
                (entry_key.as_str() == Some(key)).then_some(entry_value)
            })
            .expect("map entry")
    }

    #[test]
    fn code_run_replay_record_round_trips_and_replays_bridge_log_without_dispatch() -> Result<()> {
        let run_id = EntityId::from_bytes([0x91; 16]).expect("run id");
        let src = EntityId::from_bytes([0x92; 16]).expect("src id");
        let tgt = EntityId::from_bytes([0x93; 16]).expect("tgt id");
        let wait_id = EntityId::from_bytes([0x94; 16]).expect("wait id");
        let determinism = CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]);

        let edge_call = SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        ));
        let edge_outcome = SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
            src,
            kind: EdgeKind::Mentions,
            tgt,
        });
        let human_call = SelfCall::AskHuman(SelfAskHumanCall::new("continue?"));
        let human_outcome = SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id,
            effect: SelfEffect::AskHuman,
            reason: SelfDurableWaitReason::HumanInput,
            prompt: Some("continue?".to_owned()),
        });

        let mut record = CodeRunReplayRecord::new(run_id, determinism);
        record.bridge_calls.push(CodeRunBridgeCall::record(
            0,
            &edge_call,
            &edge_outcome,
            determinism.frozen_unix_ms,
            determinism.frozen_unix_ms + 1,
        )?);
        record.bridge_calls.push(CodeRunBridgeCall::record(
            1,
            &human_call,
            &human_outcome,
            determinism.frozen_unix_ms + 2,
            determinism.frozen_unix_ms + 3,
        )?);
        record.step_checkpoints.push(CodeRunStepCheckpoint::new(
            0,
            "after-edge",
            [0xCD; 32],
            determinism.frozen_unix_ms + 4,
        )?);

        let encoded = encode_code_run_replay_record(&record)?;
        let decoded = decode_code_run_replay_record(&encoded)?;
        assert_eq!(decoded, record);
        assert_eq!(encode_code_run_replay_record(&decoded)?, encoded);

        let replay = decoded.replay_cursor();
        assert_eq!(replay.dispatch(edge_call)?, edge_outcome);
        assert_eq!(replay.dispatch(human_call.clone())?, human_outcome);
        assert!(replay.is_complete());

        let reordered = decoded.replay_cursor();
        let err = reordered
            .dispatch(human_call)
            .expect_err("replay must reject out-of-order bridge calls");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
        assert_eq!(reordered.consumed(), 0);

        let changed_call = SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.8,
        ));
        let changed = decoded.replay_cursor();
        let _err = changed
            .dispatch(changed_call)
            .expect_err("replay must reject changed typed trap arguments");
        assert_eq!(changed.consumed(), 0);
        Ok(())
    }

    #[test]
    fn code_run_replay_large_output_persists_raw_bytes_and_compact_preview() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = EntityId::from_bytes([0x95; 16]).expect("run id");
        let raw = (0..1024)
            .map(|i| format!("row {i}: large output payload with whitespace\n\n"))
            .collect::<String>()
            .into_bytes();
        let output = CodeRunRawOutput::from_bytes("/mnt/outputs/large.txt", &raw)?;

        assert_eq!(output.raw_len, raw.len() as u64);
        assert!(output.preview.truncated);
        assert!(
            output.preview.text.chars().count()
                <= crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS
        );
        assert!(!output.preview.text.contains("\n\n"));

        vault.put_code_run_raw_output(&output, &raw)?;
        let mut record = CodeRunReplayRecord::new(
            run_id,
            CodeRunDeterminism::new(1_719_000_002_000, [0xBC; 32]),
        );
        record.outputs.push(output.clone());
        vault.put_code_run_replay_record(&record)?;

        let loaded = vault
            .get_code_run_replay_record(&run_id)?
            .expect("stored replay record");
        assert_eq!(loaded.outputs, vec![output.clone()]);
        let loaded_raw = vault
            .get_code_run_raw_output(&output)?
            .expect("stored raw output");
        assert_eq!(loaded_raw, raw);
        Ok(())
    }

    #[test]
    fn code_run_replay_abi_layout_keys_are_pinned_and_hash_checked() {
        assert_eq!(
            CODE_RUN_REPLAY_RECORD_KEYS,
            [
                "schema_version",
                "run_id",
                "determinism",
                "bridge_calls",
                "step_checkpoints",
                "outputs",
                "abi_layout_checks",
            ]
        );
        assert_eq!(
            CODE_RUN_BRIDGE_CALL_KEYS,
            [
                "seq",
                "effect",
                "request",
                "outcome",
                "started_at_ms",
                "finished_at_ms",
            ]
        );
        assert_eq!(
            CODE_RUN_RAW_OUTPUT_KEYS,
            ["handle", "path", "raw_sha256", "raw_len", "preview"]
        );
        assert_eq!(CODE_RUN_OUTPUT_PREVIEW_KEYS, ["codec", "text", "truncated"]);

        let checks = code_run_replay_abi_layout_checks();
        assert!(checks.iter().any(|check| {
            check.name == "code_run.bridge_call"
                && check.fields == CODE_RUN_BRIDGE_CALL_KEYS.map(str::to_owned)
        }));

        let mut record = CodeRunReplayRecord::new(
            EntityId::from_bytes([0x96; 16]).expect("run id"),
            CodeRunDeterminism::new(1_719_000_003_000, [0xDD; 32]),
        );
        record.abi_layout_checks[0]
            .fields
            .push("bulk_write".to_owned());
        let err = encode_code_run_replay_record(&record)
            .expect_err("layout field drift must fail before persistence");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
    }

    #[test]
    fn code_run_memory_search_routes_through_dispatcher() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA1);
        let memory = EntityId::from_bytes([0xB1; 16]).expect("memory id");
        vault
            .batch()
            .put(&memory, ENTITY_TYPE_PERSON, range(2), 2, b"matcha note")
            .text(&memory, &[("body", "matcha preference")])
            .commit()?;

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-search",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
            "matcha", 5,
        )))?;

        let SelfDispatchOutcome::MemorySearch(result) = outcome else {
            panic!("expected memory search outcome");
        };
        assert_eq!(result.query, "matcha");
        assert!(result.results.iter().any(|hit| hit.id == memory));
        Ok(())
    }

    #[test]
    fn code_run_fixture_write_stamps_actor_source_and_approval() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA2);
        let subject = seed_person(&vault, 0xB2);
        let claim = EntityId::from_bytes([0xC2; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("matcha"),
            0.8,
        )
        .with_evidence(Value::Map(vec![(
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::from("guest-spoof-attempt"),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-write",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemoryWriteFixture(
            SelfMemoryWriteFixtureCall::new(claim, candidate, range(3), 4),
        ))?;

        assert_eq!(
            outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
        );
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        let stamped_actor = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
            })
            .expect("stamped actor");
        assert_eq!(stamped_actor, &Value::Binary(actor.as_bytes().to_vec()));

        let provenance = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)).then_some(value)
            })
            .expect("stamped provenance");
        let Value::Map(provenance) = provenance else {
            panic!("expected provenance map");
        };
        let call = provenance
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(SELF_PROVENANCE_CALL_KEY)).then_some(value)
            })
            .expect("call provenance");
        assert_eq!(call.as_str(), Some(SelfEffect::MemoryWriteFixture.as_str()));

        let candidate_evidence = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
            })
            .expect("nested candidate evidence");
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        let spoofed_actor = candidate_evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
            })
            .expect("spoofed actor remains nested");
        assert_eq!(spoofed_actor.as_str(), Some("guest-spoof-attempt"));
        Ok(())
    }

    #[test]
    fn code_run_public_put_claim_trap_stamps_host_fields() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA4);
        let subject = seed_person(&vault, 0xB4);
        let claim = EntityId::from_bytes([0xC4; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        )
        .with_evidence(Value::Map(vec![(
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::from("guest-spoof-attempt"),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-put-claim",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemoryPutClaim(
            SelfMemoryPutClaimCall::new(claim, candidate, range(5), 6),
        ))?;

        assert_eq!(
            outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
        );
        assert_latest_gate_decision(&vault, claim)?;
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        assert_eq!(
            map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            &Value::Binary(actor.as_bytes().to_vec())
        );

        let provenance = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY);
        let Value::Map(provenance) = provenance else {
            panic!("expected provenance map");
        };
        assert_eq!(
            map_value(provenance, SELF_PROVENANCE_CALL_KEY).as_str(),
            Some(SelfEffect::MemoryPutClaim.as_str())
        );

        let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        assert_eq!(
            map_value(candidate_evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).as_str(),
            Some("guest-spoof-attempt")
        );
        Ok(())
    }

    #[test]
    fn code_run_put_claim_trap_ignores_guest_source_and_g2_sees_generated() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xAA);
        install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
        let subject = seed_person(&vault, 0xBA);
        let claim = EntityId::from_bytes([0xCA; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("gyokuro"),
            0.9,
        )
        .with_evidence(Value::Map(vec![(
            Value::from("source"),
            Value::from(ClaimSource::UserStated.as_str()),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-guest-source-spoof",
        )?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            claim,
            candidate,
            range(7),
            8,
        )))?;

        assert_latest_gate_decision_reasons(
            &vault,
            claim,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        let pending = vault.pending_gate_consents(10)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].claim_id, *claim.as_bytes());
        assert_eq!(pending[0].reason_codes, vec!["gate.pending.source_trust"]);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        assert_eq!(
            map_value(candidate_evidence, "source").as_str(),
            Some(ClaimSource::UserStated.as_str())
        );
        Ok(())
    }

    #[test]
    fn code_run_full_access_write_traps_route_per_op_through_gate_and_receipts() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_first_party_actor(&vault);
        install_self_memory_allow_policy(&vault, actor)?;
        let subject = seed_person(&vault, 0xB5);
        let edge_target = seed_person(&vault, 0xC5);
        let old = EntityId::from_bytes([0xD5; 16]).expect("old claim id");
        let new = EntityId::from_bytes([0xE5; 16]).expect("new claim id");
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-write-traps",
        )?;

        let before_old_decisions = gate_decision_count(&vault)?;
        let before_old_receipts = gate_receipt_count(&vault)?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            old,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.8,
            ),
            range(10),
            11,
        )))?;
        assert_eq!(gate_decision_count(&vault)?, before_old_decisions + 1);
        assert_eq!(gate_receipt_count(&vault)?, before_old_receipts + 1);
        assert_latest_gate_decision(&vault, old)?;
        assert_gate_receipts_for_claim(&vault, old, actor, "allow", 1)?;

        let before_new_decisions = gate_decision_count(&vault)?;
        let before_new_receipts = gate_receipt_count(&vault)?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            new,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("matcha"),
                0.9,
            ),
            range(12),
            13,
        )))?;
        assert_eq!(gate_decision_count(&vault)?, before_new_decisions + 1);
        assert_eq!(gate_receipt_count(&vault)?, before_new_receipts + 1);
        assert_latest_gate_decision(&vault, new)?;
        assert_gate_receipts_for_claim(&vault, new, actor, "allow", 1)?;

        let before_supersede_decisions = gate_decision_count(&vault)?;
        let before_supersede_receipts = gate_receipt_count(&vault)?;
        let supersedes_edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            new,
            EdgeKind::Supersedes,
            old,
        )?;
        let supersede_outcome = dispatcher.dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, 20),
        ))?;
        assert_eq!(
            supersede_outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: new })
        );
        assert_eq!(gate_decision_count(&vault)?, before_supersede_decisions + 2);
        assert_eq!(gate_receipt_count(&vault)?, before_supersede_receipts + 2);
        assert_recent_gate_decision_ids(&vault, &[supersedes_edge_gate_id, old])?;
        assert_gate_receipts_for_claim(&vault, supersedes_edge_gate_id, actor, "allow", 1)?;
        assert_gate_receipts_for_claim(&vault, old, actor, "allow", 2)?;
        let old_read = vault.get_claim(&old)?.expect("superseded claim");
        assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(old_read.valid_to, Some(20));
        assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);

        let before_edge_decisions = gate_decision_count(&vault)?;
        let before_edge_receipts = gate_receipt_count(&vault)?;
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemoryPutEdge,
            subject,
            EdgeKind::Mentions,
            edge_target,
        )?;
        let edge_outcome = dispatcher.dispatch(SelfCall::MemoryPutEdge(
            SelfMemoryPutEdgeCall::new(subject, EdgeKind::Mentions, edge_target, 0.7),
        ))?;
        assert_eq!(
            edge_outcome,
            SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
                src: subject,
                kind: EdgeKind::Mentions,
                tgt: edge_target,
            })
        );
        assert_eq!(gate_decision_count(&vault)?, before_edge_decisions + 1);
        assert_eq!(gate_receipt_count(&vault)?, before_edge_receipts + 1);
        assert_latest_gate_decision(&vault, edge_gate_id)?;
        assert_gate_receipts_for_claim(&vault, edge_gate_id, actor, "allow", 1)?;
        assert_eq!(
            vault.targets(&subject, EdgeKind::Mentions, None)?,
            vec![edge_target]
        );

        let read_after_write = vault.get_claim(&new)?.expect("new claim after traps");
        assert_eq!(read_after_write.value, Value::from("matcha"));
        assert_eq!(read_after_write.lifecycle, ClaimLifecycleStatus::Active);
        Ok(())
    }

    #[test]
    fn code_run_edge_and_supersede_traps_force_generated_source_into_g2() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xAB);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-generated-source-g2",
        )?;
        let subject = seed_person(&vault, 0xBB);
        let edge_target = seed_person(&vault, 0xCB);
        let old = EntityId::from_bytes([0xDB; 16]).expect("old claim id");
        let new = EntityId::from_bytes([0xEB; 16]).expect("new claim id");

        install_self_memory_allow_policy(&vault, actor)?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            old,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.8,
            ),
            range(10),
            11,
        )))?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            new,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("matcha"),
                0.9,
            ),
            range(12),
            13,
        )))?;

        install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemoryPutEdge,
            subject,
            EdgeKind::Mentions,
            edge_target,
        )?;
        let edge_err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                subject,
                EdgeKind::Mentions,
                edge_target,
                0.7,
            )))
            .expect_err("generated source must be evaluated by G2");
        assert_source_trust_gate_rejection(edge_err);
        assert_latest_gate_decision_reasons(
            &vault,
            edge_gate_id,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        assert!(
            vault
                .targets(&subject, EdgeKind::Mentions, None)?
                .is_empty()
        );

        let supersede_err = dispatcher
            .dispatch(SelfCall::MemorySupersedeClaim(
                SelfMemorySupersedeClaimCall::new(new, old, 20),
            ))
            .expect_err("generated source must be evaluated by G2");
        assert_source_trust_gate_rejection(supersede_err);
        assert_latest_gate_decision_reasons(
            &vault,
            old,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        let old_read = vault.get_claim(&old)?.expect("old claim remains");
        assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Active);
        assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_immediate_write_traps_reject_pending_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA6);
        let src = seed_person(&vault, 0xB6);
        let tgt = seed_person(&vault, 0xC6);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-pending-write",
        )?;
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("pending immediate write must not commit");

        assert_eq!(gate_decision_count(&vault)?, before + 1);
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, "pending");
        assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
        assert!(
            latest
                .reason_codes
                .iter()
                .any(|code| code.starts_with("gate.pending."))
        );
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_write_traps_validate_bound_actor() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_machine(&vault, 0xA8);
        let src = seed_person(&vault, 0xB8);
        let tgt = seed_person(&vault, 0xC8);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-invalid-actor",
        )?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("wrong actor class must reject before write");

        assert_eq!(gate_decision_count(&vault)?, before);
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_put_edge_rejects_structural_edge_kinds() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_first_party_actor(&vault);
        let src = seed_person(&vault, 0xB9);
        let tgt = seed_person(&vault, 0xC9);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-structural-edge",
        )?;
        let before = gate_decision_count(&vault)?;

        let err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::ClaimOf,
                tgt,
                1.0,
            )))
            .expect_err("structural edge kind must reject");
        assert!(
            matches!(
                err,
                Error::InvalidClaimBody("self.memory.put_edge rejects structural edge kinds")
            ),
            "{err:?}"
        );

        assert_eq!(gate_decision_count(&vault)?, before);
        assert!(vault.targets(&src, EdgeKind::ClaimOf, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_write_gate_denial_persists_decision() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        put_malformed_policy_manifest(&vault, 0xE7)?;
        let actor = seed_person(&vault, 0xA7);
        let src = seed_person(&vault, 0xB7);
        let tgt = seed_person(&vault, 0xC7);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-denied-write",
        )?;
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("fail-closed policy must reject write");

        assert_eq!(gate_decision_count(&vault)?, before + 1);
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, "deny");
        assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
        assert_eq!(latest.reason_codes, vec!["gate.deny.policy_fail_closed"]);
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_human_destructive_and_outbound_effects_become_durable_waits() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA3);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-waits",
        )?;

        let cases = [
            (
                SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
            ),
            (
                SelfCall::DestructiveFixture(SelfFixtureEffectCall::new("delete memory")),
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
            ),
            (
                SelfCall::OutboundFixture(SelfFixtureEffectCall::new("send message")),
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
            ),
        ];

        for (call, effect, reason) in cases {
            let outcome = dispatcher.dispatch(call)?;
            let SelfDispatchOutcome::DurableWait(wait) = outcome else {
                panic!("expected durable wait");
            };
            assert_eq!(wait.effect, effect);
            assert_eq!(wait.reason, reason);
            assert!(wait.prompt.is_some());
        }

        Ok(())
    }
}
