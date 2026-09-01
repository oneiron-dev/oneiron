use std::cell::Cell;

use rmpv::Value;

use crate::{EntityId, Error, Result};

use super::codec::{
    CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS, CODE_RUN_OUTPUT_PREVIEW_KEYS,
    CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS, CODE_RUN_STEP_CHECKPOINT_KEYS,
};
use super::payload::{
    decode_self_dispatch_outcome, replay_denied_trap_error, replay_failed_trap_error,
    self_call_request_value, self_dispatch_outcome_value,
};
use super::support::{
    CODE_RUN_OUTPUT_HANDLE_PREFIX, CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES, code_run_layout_hash,
    expect_map, invalid_code_run_replay, map_get, sha256_bytes, str_value, validate_label,
    validate_text,
};
use super::types::{
    SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect, SelfSpeechCall, SelfSpeechResult,
};

pub const CODE_RUN_REPLAY_SCHEMA_VERSION: u64 = 1;
pub const CODE_RUN_RNG_SEED_LEN: usize = 32;
pub const CODE_RUN_REPLAY_HASH_LEN: usize = 32;

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

        let row = Self {
            seq,
            effect: call.effect(),
            request: self_call_request_value(call)?,
            outcome: self_dispatch_outcome_value(outcome),
            started_at_ms,
            finished_at_ms,
        };
        row.validate_speech_coherence()?;
        Ok(row)
    }

    /// Validates every host-owned and outcome-owned axis of a speech row.
    ///
    /// The top-level effect, canonical request, decoded result and host stamp
    /// are one fact. Keeping this check on the row lets record construction,
    /// codec encode/decode and an in-memory replay cursor all enforce the same
    /// contract rather than trusting whichever boundary happened to run first.
    pub(super) fn validate_speech_coherence(&self) -> Result<()> {
        let outcome = decode_self_dispatch_outcome(&self.outcome)?;
        let expected_order = if self.effect.is_speech() {
            let order = u32::try_from(self.seq)
                .map_err(|_| invalid_code_run_replay("speech bridge seq exceeds u32"))?;
            let entries = expect_map(&self.request, "speech request must be a map")?;
            let text = str_value(map_get(entries, "text")?)?;
            let unstamped = match self.effect {
                SelfEffect::Speak => SelfCall::Speak(SelfSpeechCall::new(text)),
                SelfEffect::Think => SelfCall::Think(SelfSpeechCall::new(text)),
                SelfEffect::Express => SelfCall::Express(SelfSpeechCall::new(text)),
                _ => unreachable!("is_speech exhaustively names the speech family"),
            };
            let expected_call = unstamped.with_bridge_stamp(self.seq, self.started_at_ms);
            if self.request != self_call_request_value(&expected_call)? {
                return Err(invalid_code_run_replay(
                    "speech request contradicts its host bridge stamp",
                ));
            }
            Some(order)
        } else {
            None
        };

        let SelfDispatchOutcome::Speech(result) = outcome else {
            return Ok(());
        };
        let Some(expected_order) = expected_order else {
            return Err(invalid_code_run_replay(
                "speech outcome belongs to a non-speech bridge effect",
            ));
        };
        validate_speech_result(self.effect, expected_order, result)
    }

    /// Whether this row is an explicit speech call that ACTUALLY emitted.
    ///
    /// The two conditions are separate on purpose. A speech row whose outcome
    /// is a durable wait or a failed trap is a call the fail-closed barrier
    /// refused: it is replay-visible, but no bubble exists for it, so it must
    /// not suppress the trailing plaintext fallback. Only a row carrying a
    /// speech OUTCOME says the run spoke — and the decoder refuses a speech
    /// outcome that claims `emitted: false`, so "decodes as speech" and
    /// "emitted" are one fact rather than two that could disagree.
    #[must_use]
    pub fn emitted_speech(&self) -> bool {
        self.effect.is_speech()
            && self.validate_speech_coherence().is_ok()
            && matches!(
                decode_self_dispatch_outcome(&self.outcome),
                Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
                    emitted: true,
                    ..
                }))
            )
    }

    /// The visible TEXT this row spoke, when it emitted an addressed bubble.
    ///
    /// Read from the row's own request payload — the same canonical value
    /// replay compares a re-dispatched call against — so what the fallback
    /// treats as "already said" is exactly what the user could already see.
    /// Hidden `self.think` text deliberately returns `None`: a private thought
    /// that matches the terminal observation must not suppress its visible
    /// trailing fallback.
    #[must_use]
    pub fn emitted_visible_speech_text(&self) -> Option<&str> {
        if self.validate_speech_coherence().is_err() {
            return None;
        }
        let Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
            is_visible: true,
            emitted: true,
            ..
        })) = decode_self_dispatch_outcome(&self.outcome)
        else {
            return None;
        };
        let Value::Map(entries) = &self.request else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("text"))
            .and_then(|(_, value)| value.as_str())
    }
}

fn validate_speech_result(
    bridge_effect: SelfEffect,
    expected_order: u32,
    result: SelfSpeechResult,
) -> Result<()> {
    if result.effect != bridge_effect {
        return Err(invalid_code_run_replay(
            "speech outcome effect contradicts its bridge effect",
        ));
    }
    if result.order != expected_order {
        return Err(invalid_code_run_replay(
            "speech outcome order contradicts its request",
        ));
    }
    let expected_visibility = bridge_effect
        .speech_utterance()
        .ok_or(invalid_code_run_replay(
            "speech outcome belongs to a non-speech effect",
        ))?
        .is_visible();
    if result.is_visible != expected_visibility {
        return Err(invalid_code_run_replay(
            "speech outcome visibility contradicts its bridge effect",
        ));
    }
    if !result.emitted {
        return Err(invalid_code_run_replay(
            "speech outcome claims no emitted bubble",
        ));
    }
    Ok(())
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

        // ONE-1686: replay re-stamps the HOST-owned bridge identity from the
        // PERSISTED row — its seq and its start clock — exactly as the live
        // bridge stamps it at dispatch. Guest code supplies neither on either
        // path, so a replayed speech call cannot claim a different position or
        // timestamp than the one its bubble was written under, and an
        // unstamped re-dispatch cannot fail the comparison below for a
        // difference the guest was never allowed to control.
        let call = call.with_bridge_stamp(stored.seq, stored.started_at_ms);
        let request = self_call_request_value(&call)?;
        if stored.request != request {
            return Err(invalid_code_run_replay("code-run replay request mismatch"));
        }
        // A cursor can be built from an in-memory record that never passed the
        // codec. Recheck speech effect/request/result coherence here before the
        // stored outcome can reach the guest.
        stored.validate_speech_coherence()?;

        let outcome = decode_self_dispatch_outcome(&stored.outcome)?;
        self.next.set(index + 1);
        match outcome {
            SelfDispatchOutcome::Denied(result) => Err(replay_denied_trap_error(&result)),
            SelfDispatchOutcome::Failed(result) => Err(replay_failed_trap_error(&result)),
            outcome => Ok(outcome),
        }
    }
}
