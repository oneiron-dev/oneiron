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
    expect_map, invalid_code_run_replay, map_get, str_value, validate_label, validate_text,
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
            outcome: self_dispatch_outcome_value(outcome)?,
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

        match outcome {
            SelfDispatchOutcome::WakePolicyWritten(_)
                if self.effect == SelfEffect::WakePolicyWrite =>
            {
                Ok(())
            }
            SelfDispatchOutcome::WakePolicyWritten(_) => Err(invalid_code_run_replay(
                "wake policy result belongs to another effect",
            )),
            SelfDispatchOutcome::Denied(result)
                if self.effect == SelfEffect::WakePolicyWrite && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::Failed(result)
                if self.effect == SelfEffect::WakePolicyWrite && result.effect == self.effect =>
            {
                Ok(())
            }
            _ if self.effect == SelfEffect::WakePolicyWrite => Err(invalid_code_run_replay(
                "wake policy effect carries another success outcome",
            )),
            SelfDispatchOutcome::AgentVerb(_) if self.effect != SelfEffect::AgentVerb => Err(
                invalid_code_run_replay("agent verb result belongs to another effect"),
            ),
            SelfDispatchOutcome::Fold(_) if self.effect != SelfEffect::Fold => Err(
                invalid_code_run_replay("fold answer belongs to another effect"),
            ),
            SelfDispatchOutcome::TaskRefusal(_) if self.effect != SelfEffect::TasksRefuse => Err(
                invalid_code_run_replay("task refusal belongs to another effect"),
            ),
            SelfDispatchOutcome::SkillCall(_) if self.effect != SelfEffect::SkillsCall => Err(
                invalid_code_run_replay("skill call answer belongs to another effect"),
            ),
            SelfDispatchOutcome::ReaderSpawn(_) if self.effect != SelfEffect::ReaderSpawn => Err(
                invalid_code_run_replay("reader spawn receipt belongs to another effect"),
            ),
            SelfDispatchOutcome::ReaderReport(_) if self.effect != SelfEffect::ReaderReport => Err(
                invalid_code_run_replay("reader report receipt belongs to another effect"),
            ),
            SelfDispatchOutcome::TaskWaitSet(_) if self.effect != SelfEffect::TasksWaitSet => Err(
                invalid_code_run_replay("task wait set answer belongs to another effect"),
            ),
            SelfDispatchOutcome::Speech(result) => {
                let Some(expected_order) = expected_order else {
                    return Err(invalid_code_run_replay(
                        "speech outcome belongs to a non-speech bridge effect",
                    ));
                };
                validate_speech_result(self.effect, expected_order, result)
            }
            // A speech attempt can fail at the gate or hit the fail-closed
            // barrier after an earlier durable wait. Those are replay-visible
            // outcomes, but they are not successful speech and therefore carry
            // no bubble identity to validate here. Denied/Failed still name the
            // attempted effect; a DurableWait intentionally carries the wait
            // that caused the barrier, which may be a different effect.
            SelfDispatchOutcome::Denied(result)
                if self.effect.is_speech() && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::Failed(result)
                if self.effect.is_speech() && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::DurableWait(_) if self.effect.is_speech() => Ok(()),
            // A successful non-speech result for a speech request is not a
            // weaker variant. It is an impossible cross-effect row and must
            // fail closed before a replay cursor can hand it to the guest.
            _ if self.effect.is_speech() => Err(invalid_code_run_replay(
                "speech bridge effect carries a non-speech success outcome",
            )),
            // Non-speech bridge effects retain their existing outcome family;
            // the speech-specific checks above do not narrow those rows.
            _ => Ok(()),
        }
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

    /// The bubble position this row emitted at, when it emitted one.
    pub(crate) fn emitted_speech_order(&self) -> Option<u32> {
        if !self.emitted_speech() {
            return None;
        }
        match decode_self_dispatch_outcome(&self.outcome) {
            Ok(SelfDispatchOutcome::Speech(result)) => Some(result.order),
            _ => None,
        }
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

/// The preview text of a body the secret scan marked.
pub(crate) const CODE_RUN_OUTPUT_PREVIEW_WITHHELD: &str =
    "[preview withheld: the secret scan found a secret in this result]";

/// Compact preview stored in a replay record beside a raw output handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunOutputPreview {
    pub codec: String,
    pub text: String,
    pub truncated: bool,
}

/// What a result body holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRunOutputKind {
    /// The whole body is UTF-8.
    Text,
    /// Anything else, kept byte for byte.
    Binary,
}

impl CodeRunOutputKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "binary" => Some(Self::Binary),
            _ => None,
        }
    }
}

/// One result occurrence's manifest (OF-597): what the body is, measured
/// as it was written. The body is stored once by its content handle, inline
/// in LMDB or as a file beside `data.mdb`; authority stays with the
/// occurrence, here, never with the shared bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunRawOutput {
    pub handle: String,
    pub path: String,
    pub raw_blake3: [u8; CODE_RUN_REPLAY_HASH_LEN],
    pub raw_len: u64,
    pub kind: CodeRunOutputKind,
    /// Lines in a text body: its newlines, plus one for an unterminated last
    /// line.
    pub lines: u64,
    /// Whether the producer finished the body. An incomplete one is kept as
    /// far as it got, and says so; it never reads as a success.
    pub complete: bool,
    pub preview: CodeRunOutputPreview,
}

impl CodeRunRawOutput {
    /// The manifest of a complete body held whole in memory.
    pub fn from_bytes(path: impl Into<String>, raw: &[u8]) -> Result<Self> {
        let mut meter = crate::store::BodyMeter::new();
        meter.feed(raw);
        Self::from_facts(
            path,
            &meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS),
            true,
        )
    }

    /// The manifest of a body measured as it streamed.
    pub(crate) fn from_facts(
        path: impl Into<String>,
        facts: &crate::store::BodyFacts,
        complete: bool,
    ) -> Result<Self> {
        let path = path.into();
        validate_text(
            &path,
            CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
            "raw output path",
        )?;
        Ok(Self {
            handle: format!(
                "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
                crate::entity_id::bytes_to_hex_lower(&facts.digest)
            ),
            path,
            raw_blake3: facts.digest,
            raw_len: facts.len,
            kind: if facts.text {
                CodeRunOutputKind::Text
            } else {
                CodeRunOutputKind::Binary
            },
            lines: facts.lines,
            complete,
            // A body the secret scan marked shows no preview: the view is
            // redacted, the stored body never rewritten.
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text: match facts.secret {
                    Some(_) => CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned(),
                    None => facts.preview.clone(),
                },
                truncated: facts.preview_truncated || facts.secret.is_some(),
            },
        })
    }

    /// The manifest a context reference names, for reading its body by
    /// digest and length; it carries no occurrence facts.
    pub(crate) fn of_ref(source: crate::compaction::output::OutputRef) -> Self {
        Self {
            handle: format!(
                "{CODE_RUN_OUTPUT_HANDLE_PREFIX}{}",
                crate::entity_id::bytes_to_hex_lower(&source.hash)
            ),
            path: String::new(),
            raw_blake3: source.hash,
            raw_len: source.byte_len,
            kind: CodeRunOutputKind::Binary,
            lines: 0,
            complete: true,
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text: String::new(),
                truncated: false,
            },
        }
    }

    /// The model-context reference of this body: its digest and length.
    #[must_use]
    pub fn output_ref(&self) -> crate::compaction::output::OutputRef {
        crate::compaction::output::OutputRef {
            hash: self.raw_blake3,
            byte_len: self.raw_len,
        }
    }
}

/// One result occurrence (Docs Q08): what a result's taint and secret mark
/// bind, as its authority does, never the bytes it shares with another. An
/// owned output's occurrence is its owner and path, the id its body
/// descriptor carries; an unowned body (a context output) has no occurrence
/// beyond its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultOccurrence(EntityId);

impl ResultOccurrence {
    /// The occurrence of `output` that `owner` holds, or of its bytes alone
    /// when it has no owner. The one derivation of an occurrence id.
    pub fn of(owner: Option<EntityId>, output: &CodeRunRawOutput) -> Result<Self> {
        Ok(Self(match owner {
            Some(owner) => EntityId::derive(
                b"oneiron:code-run-output-occurrence:v1",
                &[owner.as_bytes().as_slice(), output.path.as_bytes()],
            )?,
            None => EntityId::derive(
                b"oneiron:code-run-output-unowned:v1",
                &[output.raw_blake3.as_slice()],
            )?,
        }))
    }

    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.0
    }

    /// The key of this occurrence's taint and secret rows: the handle of
    /// its body, so a read naming the bytes alone and the body's collector
    /// find every occurrence of them together, then the occurrence.
    pub(crate) fn mark_key(&self, handle: &str) -> String {
        format!("{}{}", Self::marks_prefix(handle), self.0.to_hex())
    }

    /// The key prefix the marks of every occurrence of `handle`'s body
    /// share.
    pub(crate) fn marks_prefix(handle: &str) -> String {
        format!("{handle}/")
    }

    /// The body handle and the occurrence a mark row's key names.
    pub(crate) fn parse_mark_key(key: &str) -> Result<(&str, Self)> {
        let (handle, occurrence) = key
            .rsplit_once('/')
            .ok_or(Error::CorruptedIndex("code-run result mark key"))?;
        Ok((handle, Self(EntityId::from_hex(occurrence)?)))
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
    /// The run's live result names, each bound to one of `outputs`. A rebind
    /// replaces its entry in place.
    pub bindings: Vec<CodeRunResultBinding>,
}

/// One name a program bound to a result of its run (`r7`, or a name it gave
/// `store`). The name is the model's handle on the result across steps,
/// compaction and restart; it grants nothing by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunResultBinding {
    pub name: String,
    pub handle: String,
}

impl CodeRunResultBinding {
    /// The longest result name, in ASCII characters.
    pub const MAX_NAME_LEN: usize = 64;

    #[must_use]
    pub fn new(name: impl Into<String>, handle: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            handle: handle.into(),
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
            bindings: Vec::new(),
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

    /// The rows this run's verb calls listed as served, kept beside each
    /// answer it recorded (DEC-0005). `None` when an answer was recorded with
    /// no row set, or does not decode: no caller off this device is released
    /// such a run's answers.
    #[must_use]
    pub fn agent_verb_rows(&self) -> Option<Vec<EntityId>> {
        agent_verb_rows_of(&self.bridge_calls)
    }
}

/// The served rows of the verb answers among `calls`, as
/// [`CodeRunReplayRecord::agent_verb_rows`] reads them; `None` when any answer
/// has no row set or does not decode.
pub(crate) fn agent_verb_rows_of(calls: &[CodeRunBridgeCall]) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    let verb_calls = calls
        .iter()
        .filter(|call| call.effect == SelfEffect::AgentVerb);
    for call in verb_calls {
        if let SelfDispatchOutcome::AgentVerb(answer) =
            decode_self_dispatch_outcome(&call.outcome).ok()?
        {
            rows.extend(answer.rows?);
        }
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
            // A refused SDK verb reached the guest as a typed refusal it could
            // handle, so replay hands back that same refusal, not a gate trap.
            SelfDispatchOutcome::Denied(result)
                if stored.effect == SelfEffect::AgentVerb
                    && result.effect == SelfEffect::AgentVerb =>
            {
                Ok(SelfDispatchOutcome::Denied(result))
            }
            // So did a host door's refusal of a call the run serves itself. A
            // gate's denial carries the gate's own outcome word and replays as
            // the trap it was; a door's code is never one.
            SelfDispatchOutcome::Denied(result)
                if crate::error::GateDenialOutcome::parse(&result.outcome).is_none() =>
            {
                Ok(SelfDispatchOutcome::Denied(result))
            }
            SelfDispatchOutcome::Denied(result) => Err(replay_denied_trap_error(&result)),
            SelfDispatchOutcome::Failed(result) => Err(replay_failed_trap_error(&result)),
            outcome => Ok(outcome),
        }
    }
}
