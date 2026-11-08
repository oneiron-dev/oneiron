use std::borrow::Cow;
use std::sync::Mutex;

use crate::{EntityId, Error, Result};

use super::codec::{
    CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS, CODE_RUN_OUTPUT_PREVIEW_KEYS,
    CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS, CODE_RUN_STEP_CHECKPOINT_KEYS,
};
use super::payload::{
    decode_self_dispatch_outcome, self_call_request_value, self_dispatch_outcome_value,
};
use super::support::{
    code_run_layout_hash, expect_map, invalid_code_run_replay, map_get, str_value, u64_value,
    validate_text,
};
use super::types::{SelfCall, SelfDispatchOutcome, SelfEffect, SelfSpeechCall, SelfSpeechResult};
// The bridge call's body names these by their `super::` paths.
use super::{SelfStoredReply, SelfStoredReplyKind, spawn_replay};
mod bridge;
mod checkpoint;
mod cursor;
mod pending_step;
mod position;
mod request_identity;

pub use self::bridge::CodeRunBridgeCall;
pub use self::checkpoint::CodeRunStepCheckpoint;
pub use self::cursor::CodeRunReplayCursor;
pub use self::pending_step::PendingCodeStep;
pub(super) use self::request_identity::ErasedRequest;

pub const CODE_RUN_REPLAY_SCHEMA_VERSION: u64 = 3;
pub const CODE_RUN_RNG_SEED_LEN: usize = 32;
pub use crate::store::result_manifest::CODE_RUN_REPLAY_HASH_LEN;

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

pub(crate) use crate::store::result_manifest::CODE_RUN_OUTPUT_PREVIEW_WITHHELD;
pub use crate::store::result_manifest::{
    CodeRunOutputKind, CodeRunOutputPreview, CodeRunRawOutput, ResultOccurrence,
};

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

/// Engine-authored open mark for a replayed executor program (ONE-1929).
pub const CODE_RUN_EXEC_OPEN: &str = "<exec>";
/// Engine-authored close mark for a replayed executor program (ONE-1929).
pub const CODE_RUN_EXEC_CLOSE: &str = "</exec>";
/// Engine-authored open mark for a replayed sandbox console (ONE-1929).
pub const CODE_RUN_CONSOLE_OPEN: &str = "<console>";
/// Engine-authored close mark for a replayed sandbox console (ONE-1929).
pub const CODE_RUN_CONSOLE_CLOSE: &str = "</console>";

/// One completed durable step, rendered back into model-facing history
/// (ONE-1929).
///
/// The two payloads come from DIFFERENT provenances and neither is provider
/// text: `code` is the healed executable interior the sandbox actually ran,
/// and `console` is the runtime's own
/// [`crate::engine_executor::JsCodeModeStepOutcome::observation`] (or the
/// runtime failure observation on the persisted failed-step path). A model
/// reply's own console bytes are discarded during healing and never reach
/// this renderer.
///
/// Framing is PRESENTATION ONLY. The bare code and the authoritative
/// observation stay untagged in raw replay storage, so checkpoint hashing and
/// execution never depend on these marks; the history builder wraps them only
/// while composing the next LLM request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunHistoryTurn {
    pub code: String,
    pub console: String,
}

impl CodeRunHistoryTurn {
    /// Renders the assistant half: engine-authored exec marks around the
    /// healed bare program.
    #[must_use]
    pub fn assistant_exec(&self) -> String {
        let escaped_code = escape_code_run_frame_marks(&self.code);
        format!("{CODE_RUN_EXEC_OPEN}\n{escaped_code}\n{CODE_RUN_EXEC_CLOSE}")
    }

    /// Renders the user half: engine-authored console marks around the
    /// authoritative sandbox observation for durable step `seq`.
    #[must_use]
    pub fn user_console(&self, seq: u64) -> String {
        let escaped_console = escape_code_run_frame_marks(&self.console);
        format!(
            "Console after durable step {seq}:\n{CODE_RUN_CONSOLE_OPEN}\n{escaped_console}\n{CODE_RUN_CONSOLE_CLOSE}"
        )
    }
}

/// Escapes ALL FOUR engine-authored frame marks in a payload.
///
/// The transform is total and deterministic: every literal `<exec>`,
/// `</exec>`, `<console>`, and `</console>` in either payload renders with its
/// opening `<` escaped, so neither a program nor an observation can forge or
/// close the frame the engine wrapped around it. Each replacement's output
/// contains no input pattern, so the four passes cannot cascade.
fn escape_code_run_frame_marks(payload: &str) -> String {
    payload
        .replace(CODE_RUN_EXEC_OPEN, r"<\exec>")
        .replace(CODE_RUN_EXEC_CLOSE, r"<\/exec>")
        .replace(CODE_RUN_CONSOLE_OPEN, r"<\console>")
        .replace(CODE_RUN_CONSOLE_CLOSE, r"<\/console>")
}

/// Transient decoded-row memos for one replay record. They are never
/// persisted: a clone starts cold and equality ignores them because the rows
/// are pure functions of `bridge_calls` (FIX 837).
#[derive(Debug, Default)]
pub(crate) struct VerbRowsCache {
    agent: Mutex<IncrementalRows>,
    resident: Mutex<IncrementalRows>,
}

impl Clone for VerbRowsCache {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PartialEq for VerbRowsCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl VerbRowsCache {
    fn invalidate(&self) {
        *lock_incremental(&self.agent) = IncrementalRows::default();
        *lock_incremental(&self.resident) = IncrementalRows::default();
    }
}

#[derive(Debug)]
struct IncrementalRows {
    decoded: usize,
    rows: Option<Vec<EntityId>>,
}

impl Default for IncrementalRows {
    fn default() -> Self {
        Self {
            decoded: 0,
            rows: Some(Vec::new()),
        }
    }
}

fn lock_incremental(cache: &Mutex<IncrementalRows>) -> std::sync::MutexGuard<'_, IncrementalRows> {
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached_rows(
    cache: &Mutex<IncrementalRows>,
    calls: &[CodeRunBridgeCall],
    decode: impl Fn(&[CodeRunBridgeCall], usize) -> Option<Vec<EntityId>>,
) -> Option<Vec<EntityId>> {
    let mut cached = lock_incremental(cache);
    if calls.len() < cached.decoded {
        *cached = IncrementalRows::default();
    }
    if cached.decoded == calls.len() {
        return cached.rows.clone();
    }
    // Unknown stays unknown: a later append cannot make an incomplete row
    // witness look complete again.
    if cached.rows.is_none() {
        return None;
    }
    match decode(calls, cached.decoded) {
        Some(rows) => {
            if let Some(kept) = cached.rows.as_mut() {
                kept.extend(rows);
                cached.decoded = calls.len();
            }
        }
        None => {
            cached.rows = None;
            cached.decoded = calls.len();
        }
    }
    cached.rows.clone()
}

/// Persisted replay record for a first-party code run. Imported result
/// outputs may have unknown frozen inputs and cannot seed deterministic execution.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeRunReplayRecord {
    pub run_id: EntityId,
    /// The host-bound birth world. Known base reality has its actual id;
    /// `None` means no accepted placement was witnessed. Not read authority.
    pub birth_world: Option<EntityId>,
    /// Frozen inputs when witnessed; imported outputs can retain unknown inputs.
    pub determinism: Option<CodeRunDeterminism>,
    pub bridge_calls: Vec<CodeRunBridgeCall>,
    pub step_checkpoints: Vec<CodeRunStepCheckpoint>,
    pub outputs: Vec<CodeRunRawOutput>,
    pub abi_layout_checks: Vec<CodeRunAbiLayoutCheck>,
    /// The run's live result names, each bound to one of `outputs`. A rebind
    /// replaces its entry in place.
    pub bindings: Vec<CodeRunResultBinding>,
    /// The credential attached to this live agent run (OF-181), as its host
    /// stored it: association metadata, never the lease proof.
    pub live_run: Option<super::live_run::CodeRunLiveRunBinding>,
    /// Skills loaded and other runs' result rows read so far (FIX 6999).
    /// `None` once any such constituent read is unknown.
    pub callable_rows: Option<Vec<EntityId>>,
    /// The step its deadline stopped before its program ended (FIX 7703):
    /// the run's next entry runs that stored program again before any new
    /// model turn. `None` while no step is pending.
    pub pending_step: Option<PendingCodeStep>,
    /// Decoded row memos, never part of the replay codec or ABI (FIX 837).
    /// Any future in-place prefix outcome rewrite must invalidate them.
    pub(crate) verb_rows_cache: VerbRowsCache,
}

/// One name a program bound to a result of its run (`r7`, or a name it gave
/// `store`). The name is the model's handle on the result across steps,
/// compaction and restart; it grants nothing by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunResultBinding {
    pub name: String,
    pub handle: String,
    /// The occurrence path the name was bound to (FIX 1393 follow-up): two
    /// stores of the same bytes are two occurrences under one handle, and a
    /// name resolves to its own occurrence, never the first with its bytes.
    /// Empty on rows bound before occurrences were recorded; those match any
    /// occurrence with their handle, as before.
    pub path: String,
}

impl CodeRunResultBinding {
    /// The longest result name, in ASCII characters.
    pub const MAX_NAME_LEN: usize = 64;

    #[must_use]
    pub fn new(
        name: impl Into<String>,
        handle: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            handle: handle.into(),
            path: path.into(),
        }
    }

    /// Whether `name` can name a result: `[A-Za-z_][A-Za-z0-9_]{0,63}`, so it
    /// reads as a JS identifier.
    #[must_use]
    pub fn is_valid_name(name: &str) -> bool {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && name.len() <= Self::MAX_NAME_LEN
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }
}

/// Stable replay-row generation used for guarded executor appends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeRunReplayGeneration {
    pub bridge_call_count: u64,
    pub step_checkpoint_count: u64,
    pub output_count: u64,
    pub last_state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The pending step's digest, zero while none is pending (FIX 7703).
    pub pending_digest: [u8; CODE_RUN_REPLAY_HASH_LEN],
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
            pending_digest: match &record.pending_step {
                Some(pending) => super::codec::pending_step_digest(pending)?,
                None => [0; CODE_RUN_REPLAY_HASH_LEN],
            },
        })
    }
}

impl CodeRunReplayRecord {
    /// Whether this exact owned output is the stored receipt of a native
    /// team start. Neither a matching digest nor caller-supplied card text
    /// alone classifies an output as a receipt.
    pub(crate) fn output_is_retained_receipt(&self, output: &CodeRunRawOutput) -> bool {
        self.bridge_calls
            .iter()
            .any(|call| self.call_retains_output(call, output))
    }

    /// The same canonical classification for one call and its actual output.
    pub(crate) fn call_retains_output(
        &self,
        call: &CodeRunBridgeCall,
        output: &CodeRunRawOutput,
    ) -> bool {
        if call.effect != SelfEffect::Team
            || call.validate_speech_coherence().is_err()
            || !self.outputs.iter().any(|held| held == output)
        {
            return false;
        }
        let Ok(occurrence) = ResultOccurrence::owned(self.run_id, &output.path) else {
            return false;
        };
        let Ok(SelfDispatchOutcome::StoredReply(stored)) =
            decode_self_dispatch_outcome(&call.outcome)
        else {
            return false;
        };
        let reference = format!("occurrence:{}", occurrence.id().to_hex());
        stored.kind == super::SelfStoredReplyKind::TeamStartReceipt
            && stored.output.get("ref").and_then(serde_json::Value::as_str)
                == Some(reference.as_str())
            && stored
                .output
                .get("handle")
                .and_then(serde_json::Value::as_str)
                == Some(output.handle.as_str())
            && stored
                .output
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                == Some(output.raw_len)
    }

    #[must_use]
    pub fn new(run_id: EntityId, determinism: CodeRunDeterminism) -> Self {
        Self::with_determinism(run_id, Some(determinism))
    }

    pub(crate) fn with_determinism(
        run_id: EntityId,
        determinism: Option<CodeRunDeterminism>,
    ) -> Self {
        Self {
            run_id,
            birth_world: None,
            determinism,
            bridge_calls: Vec::new(),
            step_checkpoints: Vec::new(),
            outputs: Vec::new(),
            abi_layout_checks: code_run_replay_abi_layout_checks(),
            bindings: Vec::new(),
            live_run: None,
            callable_rows: Some(Vec::new()),
            pending_step: None,
            verb_rows_cache: VerbRowsCache::default(),
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

    /// This record with each bridge call `held` already stores in its place,
    /// as the side-row wall admitted it (OF-067). An append rewrites the whole
    /// row, so a call an earlier append stored keeps its handles and the wall
    /// mints only for the calls this append adds.
    pub(crate) fn over_held(&self, held: Option<&Self>) -> Cow<'_, Self> {
        let Some(held) = held.filter(|held| held.run_id == self.run_id) else {
            return Cow::Borrowed(self);
        };
        let mut record = self.clone();
        record.birth_world = held.birth_world.or(record.birth_world);
        for (call, kept) in record.bridge_calls.iter_mut().zip(&held.bridge_calls) {
            if call.seq == kept.seq
                && call.effect == kept.effect
                && call.started_at_ms == kept.started_at_ms
                && call.finished_at_ms == kept.finished_at_ms
            {
                // A parked call keeps the rows its delivered reply listed
                // (FIX 5455), which the held copy has not kept yet.
                let delivered = super::wait_rows::wait_rows(&call.outcome);
                call.clone_from(kept);
                if let Some(rows) = delivered {
                    super::wait_rows::keep_wait_rows(&mut call.outcome, &rows);
                }
            }
        }
        Cow::Owned(record)
    }

    /// Unions newly witnessed callable/result rows into the record. Unknown
    /// stays unknown; known sets are sorted and deduplicated (FIX 6999).
    pub(crate) fn record_callable_rows(&mut self, rows: Option<Vec<EntityId>>) {
        self.callable_rows =
            crate::skill_optimize::union_source_rows([self.callable_rows.take(), rows]);
    }

    /// The rows this run's verb calls listed as served, kept beside each
    /// answer it recorded (DEC-0005). `None` when an answer was recorded with
    /// no row set, or does not decode: no caller off this device is released
    /// such a run's answers.
    #[must_use]
    pub fn agent_verb_rows(&self) -> Option<Vec<EntityId>> {
        cached_rows(
            &self.verb_rows_cache.agent,
            &self.bridge_calls,
            |calls, from| agent_verb_rows_of_from(calls, from),
        )
    }

    /// The second resident read-set fold, sharing the same append-only memo
    /// so each output does not re-decode the whole record (FIX 837).
    pub(crate) fn cached_resident_tool_answer_rows(&self) -> Option<Vec<EntityId>> {
        cached_rows(
            &self.verb_rows_cache.resident,
            &self.bridge_calls,
            |calls, from| super::read_set::resident_tool_answer_rows_of_from(calls, from, None),
        )
    }

    /// A delivered reply can add rows to a parked prefix call. That is the
    /// only in-loop prefix mutation; every replacement starts cold instead.
    pub(crate) fn invalidate_verb_rows(&self) {
        self.verb_rows_cache.invalidate();
    }
}

/// The served rows of the verb answers among `calls`, as
/// [`CodeRunReplayRecord::agent_verb_rows`] reads them; `None` when any answer
/// has no row set or does not decode. A consult landing's answer lists the
/// refs it read (DOOR-063), and a bound workflow run's the TASK, workflow,
/// definitions and attempts it served (FIX 5316). A board frame observed
/// beside an answer adds the rows it was derived from (FIX 2135).
pub(crate) fn agent_verb_rows_of(calls: &[CodeRunBridgeCall]) -> Option<Vec<EntityId>> {
    agent_verb_rows_of_from(calls, 0)
}

fn agent_verb_rows_of_from(calls: &[CodeRunBridgeCall], from: usize) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    let verb_calls = calls.get(from..)?.iter().filter(|call| {
        matches!(
            call.effect,
            SelfEffect::AgentVerb | SelfEffect::ConsultResult | SelfEffect::WorkflowDispatch
        ) || call.effect.is_repo()
    });
    for call in verb_calls {
        if let SelfDispatchOutcome::AgentVerb(answer) =
            decode_self_dispatch_outcome(&call.outcome).ok()?
        {
            rows.extend(answer.released_rows()?);
        }
        // An answer an erase took keeps the rows it was served from (FIX 5718).
        if let Some(kept) = super::wait_rows::erased_answer_rows(&call.outcome) {
            rows.extend(kept?);
        }
        // A parked call's delivered reply's rows, once the run resumed from
        // it (FIX 5455).
        rows.extend(
            super::wait_rows::wait_rows(&call.outcome)
                .into_iter()
                .flatten(),
        );
    }
    Some(rows)
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
