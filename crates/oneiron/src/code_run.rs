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
    error::{GateDenialOutcome, GateDenialReason},
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

/// Maximum results a first-party `self.memory.search` call can request.
pub const SELF_MEMORY_SEARCH_MAX_RESULTS: usize = 16;
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
            crate::entity_id::bytes_to_hex_lower(&raw_sha256)
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

/// Stable replay-row generation used for guarded executor appends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeRunReplayGeneration {
    pub bridge_call_count: u64,
    pub step_checkpoint_count: u64,
    pub output_count: u64,
    pub last_state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
}

impl CodeRunReplayGeneration {
    fn for_record(record: &CodeRunReplayRecord) -> Result<Self> {
        Ok(Self {
            bridge_call_count: u64::try_from(record.bridge_calls.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
            step_checkpoint_count: u64::try_from(record.step_checkpoints.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
            output_count: u64::try_from(record.outputs.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
            last_state_hash: record
                .step_checkpoints
                .last()
                .map_or([0; CODE_RUN_REPLAY_HASH_LEN], |checkpoint| {
                    checkpoint.state_hash
                }),
        })
    }
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

    /// Returns the current replay-row generation fingerprint.
    pub fn generation(&self) -> Result<CodeRunReplayGeneration> {
        CodeRunReplayGeneration::for_record(self)
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
        match outcome {
            SelfDispatchOutcome::Denied(result) => Err(replay_denied_trap_error(&result)),
            SelfDispatchOutcome::Failed(result) => Err(replay_failed_trap_error(&result)),
            outcome => Ok(outcome),
        }
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
        Ok(wtxn.commit()?)
    }

    /// Persists the replay record only if the stored row still matches `expected`.
    pub fn put_code_run_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<CodeRunReplayGeneration> {
        let encoded = encode_code_run_replay_record(record)?;
        let next_generation = record.generation()?;
        let key = code_run_replay_record_key(&record.run_id);
        let mut wtxn = self.store.env.write_txn()?;
        let current = self
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .map(|raw| decode_code_run_replay_record(&raw))
            .transpose()?;
        let current_generation = current
            .as_ref()
            .map(CodeRunReplayRecord::generation)
            .transpose()?;
        if current_generation != expected {
            return Err(Error::ConcurrentWrite(
                "code-run replay record changed; retry executor",
            ));
        }
        self.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(next_generation)
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
            .map(|raw| decode_code_run_replay_record(&raw))
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
        Ok(wtxn.commit()?)
    }

    /// Loads raw output bytes for `output` and verifies they still match metadata.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &code_run_raw_output_key(output))?
            .map(|value| value.to_vec())
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
        crate::entity_id::bytes_to_hex_lower(&output.raw_sha256)
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
        SelfDispatchOutcome::Denied(result) => request_map(vec![
            ("kind", Value::from("denied")),
            ("effect", Value::from(result.effect.as_str())),
            ("outcome", Value::from(result.outcome.as_str())),
            (
                "reason_codes",
                Value::Array(
                    result
                        .reason_codes
                        .iter()
                        .map(|reason| Value::from(reason.as_str()))
                        .collect(),
                ),
            ),
        ]),
        SelfDispatchOutcome::Failed(result) => request_map(vec![
            ("kind", Value::from("failed")),
            ("effect", Value::from(result.effect.as_str())),
            ("error", Value::from(result.error.as_str())),
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
        "denied" => Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
            outcome: str_value(map_get(entries, "outcome")?)?.to_owned(),
            reason_codes: str_array(map_get(entries, "reason_codes")?)?,
        })),
        "failed" => Ok(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
            error: str_value(map_get(entries, "error")?)?.to_owned(),
        })),
        _ => Err(invalid_code_run_replay("unknown dispatch outcome kind")),
    }
}

fn replay_denied_trap_error(result: &SelfDeniedResult) -> Error {
    let outcome =
        GateDenialOutcome::parse(&result.outcome).map_or("deny", GateDenialOutcome::as_str);
    let reason_codes = result
        .reason_codes
        .iter()
        .filter_map(|reason| GateDenialReason::from_code(reason))
        .map(GateDenialReason::as_str)
        .collect::<Vec<_>>();
    Error::GateWriteRejected {
        outcome,
        reason_codes,
    }
}

fn replay_failed_trap_error(_result: &SelfFailedResult) -> Error {
    invalid_code_run_replay("replayed failed self trap")
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

pub(crate) fn encode_code_run_replay_value(
    value: &Value,
    context: &'static str,
) -> Result<Vec<u8>> {
    encode_value(value, context)
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

fn str_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("value must be an array"));
    };
    items
        .iter()
        .map(|item| str_value(item).map(str::to_owned))
        .collect()
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

/// Explicit first-party GatedActorWrite trap surface for engine-native code.
///
/// This is a type alias for [`HostSelfDispatcher`], whose public `self.memory.*`
/// variants stamp host-owned actor/provenance and run per-operation gate checks
/// before any write commits.
pub type GatedActorWrite<'a> = HostSelfDispatcher<'a>;

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
        let limit = call.limit.min(SELF_MEMORY_SEARCH_MAX_RESULTS);
        let results = self.vault.search_text(&call.query, limit)?;
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
        body.evidence = Some(crate::write_envelope::write_envelope_evidence(
            envelope, None,
        ));
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
        let actor_header = crate::batch::EntityMetadataHeader::parse(&actor_raw)
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
        wtxn.commit()?;
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
        | EdgeKind::DerivedFrom
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto
        | EdgeKind::BlockedBy => Err(Error::InvalidClaimBody(
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
    Denied(SelfDeniedResult),
    Failed(SelfFailedResult),
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

/// Result of a `self.*` trap rejected after the gate recorded an audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDeniedResult {
    pub effect: SelfEffect,
    pub outcome: String,
    pub reason_codes: Vec<String>,
}

/// Result of a `self.*` trap that failed after crossing an audited write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFailedResult {
    pub effect: SelfEffect,
    pub error: String,
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
mod tests;
