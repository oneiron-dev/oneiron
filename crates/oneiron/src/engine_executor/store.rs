//! Output envelope and path helpers for the routed raw-output store.

mod reply_evidence;
mod script_context;
pub(super) use script_context::{load_script_context, mask_known_text};

use super::record::REPLAY_METADATA_SCHEMA_VERSION;
use super::types::{EngineExecutorResult, JsCodeModeStepOutcome, JsCodeModeStream};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunRawOutput, CodeRunReplayRecord, CodeRunResultBinding,
    ExecutorStorage, ResultOccurrence,
};
use crate::code_sandbox::source::PreparedSource;
use crate::compaction::output::OutputRef;
use crate::entity_id::EntityId;
use crate::store::BodySink;
use crate::{Error, Result};
use serde_json::json;
use std::collections::BTreeSet;

const SCRIPT_OUTPUT_DIR: &str = "executor/repl";

pub(super) const CONFIG_OUTPUT_PATH: &str = "executor/repl/run.config.json";

const TERMINAL_OUTPUT_SUFFIX: &str = ".terminal.json";

/// Between a resumed reply's step and the wait it names.
const RESUMED_OUTPUT_INFIX: &str = ".resumed.";

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
    let mut sink = storage.code_run_output_sink()?;
    sink.write(raw)?;
    publish_output(storage, record, path, sink).map(drop)
}

/// Publishes the body `sink` wrote as the run's output at `path`, and
/// returns its manifest. The body streamed into its store as it was
/// measured: past the inline bound it is a file beside data.mdb, whole on
/// disk before its row and this manifest are published.
pub(super) fn publish_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    sink: BodySink,
) -> EngineExecutorResult<CodeRunRawOutput> {
    if record.outputs.iter().any(|output| output.path == path) {
        return Err(Error::InvalidClaimBody("duplicate executor output path").into());
    }
    let input_rows = crate::code_run::resident_tool_answer_rows(record, None);
    let output =
        storage.publish_code_run_output_sourced(path, sink, true, record.run_id, input_rows)?;
    record.outputs.push(output.clone());
    Ok(output)
}

/// Binds the published `output` to the next free automatic `r<n>` name, one
/// past the record's live names and past any name taken: the binding joins
/// the record, and its name and handle join the step's digest bindings.
pub(super) fn bind_published_output(
    record: &mut CodeRunReplayRecord,
    digest_bindings: &mut Vec<(String, String)>,
    output: &CodeRunRawOutput,
) {
    let name = (record.bindings.len() + 1..)
        .map(|n| format!("r{n}"))
        .find(|name| !record.bindings.iter().any(|binding| binding.name == *name))
        .unwrap_or_default();
    record.bindings.push(CodeRunResultBinding::new(
        name.clone(),
        output.handle.clone(),
        output.path.clone(),
    ));
    digest_bindings.push((name, output.handle.clone()));
}

/// A step's model reply, kept apart from the program healed out of it:
/// untrusted evidence, never executed. PERSON and custody matches share the
/// original encoding, so neither substitution changes the other's context.
pub(super) fn record_reply_evidence(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    reply: &crate::LlmMessage,
) -> EngineExecutorResult<()> {
    if let Some(bytes) = reply_evidence::for_run_bytes(storage, record.run_id, reply)? {
        let mut sink = storage.code_run_script_sink()?;
        sink.write(bytes.as_slice())?;
        publish_output(storage, record, reply_output_path(seq), sink).map(drop)
    } else {
        let mut sink = storage.code_run_output_sink()?;
        write_json(&mut sink, reply)?;
        publish_output(storage, record, reply_output_path(seq), sink).map(drop)
    }
}

/// Encodes `value` as JSON straight into a body sink, never whole first.
pub(super) fn write_json(sink: &mut BodySink, value: &impl serde::Serialize) -> Result<()> {
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, SinkWriter(sink));
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| Error::InvalidConfig(format!("result body encoding failed: {error}")))?;
    std::io::Write::flush(&mut writer)?;
    Ok(())
}

/// A body sink as a byte writer.
struct SinkWriter<'s>(&'s mut BodySink);

impl std::io::Write for SinkWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .write(bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Counts the bytes an encoding would take, holding none of them.
#[derive(Default)]
pub(super) struct ByteCount(pub(super) usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A verb answer whose JSON is longer than this is stored as a body of the
/// run, and the guest and the replay row get its handle: no reply passes one
/// message, and no answer is refused for its size.
pub(crate) const RESULT_REPLY_INLINE_BYTES: usize = 512 * 1024;

/// The guest's read path for a stored result body; `<path>/chunk/<offset>`
/// reads up to [`RECOVERABLE_OUTPUT_CHUNK_BYTES`] from `offset`.
pub(super) fn result_read_path(source: OutputRef) -> String {
    format!(
        "{RESULT_READ_ROOT}{}/{}",
        crate::entity_id::bytes_to_hex_lower(&source.hash),
        source.byte_len,
    )
}

/// The guest's read path for one occurrence of a stored result body: the
/// content path plus the occurrence id, so two stores of the same bytes
/// read under different paths and select their own taint and secrets.
/// Paths without the occurrence segment keep the legacy meaning (the
/// first occurrence with those bytes).
pub(crate) fn result_read_path_for(source: OutputRef, occurrence: &ResultOccurrence) -> String {
    format!("{}/{}", result_read_path(source), occurrence.id().to_hex())
}

/// Splits a stored-result read path into its body ref, its occurrence when
/// present, and its chunk offset: `{ROOT}{hash}/{len}[/{occ}]/chunk/{off}`.
/// `None` when the shape is wrong.
pub(crate) fn parse_result_read_path(path: &str) -> Option<(OutputRef, Option<EntityId>, u64)> {
    let rest = path.strip_prefix(RESULT_READ_ROOT)?;
    let (base, offset) = rest.rsplit_once("/chunk/")?;
    let mut parts = base.split('/');
    let hash = parts.next()?;
    let len = parts.next()?;
    let occurrence = match (parts.next(), parts.next()) {
        (Some(occ), None) => Some(EntityId::from_hex(occ).ok()?),
        (None, None) => None,
        _ => return None,
    };
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (at, chunk) in hash.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        digest[at] = u8::from_str_radix(text, 16).ok()?;
    }
    let byte_len = len
        .parse::<u64>()
        .ok()
        .filter(|parsed| len == parsed.to_string())?;
    let offset = offset
        .parse::<u64>()
        .ok()
        .filter(|parsed| offset == parsed.to_string())?;
    Some((
        OutputRef {
            hash: digest,
            byte_len,
        },
        occurrence,
        offset,
    ))
}

/// Where the guest reads stored result bodies.
pub(crate) const RESULT_READ_ROOT: &str = "/mnt/outputs/.oneiron-result/";

/// What the guest gets in place of a result stored as a body: its handle,
/// size, kind, completion and preview, where to read it, and the ref that
/// names it back. The read path names the run's occurrence of the body, so
/// a same-byte result reads its own taint and secrets instead of the first
/// occurrence's. The ref names the same occurrence (`occurrence:<hex>`),
/// because the guest's `refOf` prefers `ref` over `handle`: a bare handle
/// names the first occurrence with those bytes, so a second same-byte store
/// would slice, describe and inherit as the first one and read its taint.
pub(crate) fn result_handle_json(owner: EntityId, output: &CodeRunRawOutput) -> serde_json::Value {
    let occurrence = ResultOccurrence::of(Some(owner), output).ok();
    let read = occurrence
        .as_ref()
        .map(|occurrence| result_read_path_for(output.output_ref(), occurrence))
        .unwrap_or_else(|| result_read_path(output.output_ref()));
    let mut card = json!({
        "handle": output.handle,
        "bytes": output.raw_len,
        "kind": match output.kind {
            crate::code_run::CodeRunOutputKind::Text => "text",
            crate::code_run::CodeRunOutputKind::Binary => "binary",
        },
        "lines": output.lines,
        "complete": output.complete,
        "preview": output.preview.text,
        "read": read,
    });
    if let Some(occurrence) = occurrence.as_ref() {
        card["ref"] = json!(format!("occurrence:{}", occurrence.id().to_hex()));
    }
    card
}

/// A step's streamed result as its host took it: one body sink per target,
/// written as each frame arrives, so no part of it is held whole.
#[derive(Default)]
pub(super) struct StreamedOutputs {
    console: Option<BodySink>,
    finish: Option<BodySink>,
    /// The value the program is passing to `store`, until the host takes it.
    store: Option<BodySink>,
    files: Vec<(String, BodySink)>,
}

/// A step's bodies, ready to publish: its observation, the console lines of
/// a finished step (whose observation is its answer), and its files, in the
/// order the step first wrote them.
pub(super) struct StepBodies {
    pub(super) observation: BodySink,
    pub(super) console: Option<BodySink>,
    pub(super) files: Vec<(String, BodySink)>,
}

impl StreamedOutputs {
    /// Appends one frame to its target's body. A finish frame that starts
    /// an answer drops the answer before it; a store frame that starts a
    /// value drops any value no `store` took.
    pub(super) fn write(
        &mut self,
        storage: &ExecutorStorage<'_>,
        exec_run: EntityId,
        stream: JsCodeModeStream<'_>,
        frame: &[u8],
    ) -> Result<()> {
        let sink = match stream {
            JsCodeModeStream::Console => &mut self.console,
            JsCodeModeStream::Finish { start } => {
                if start {
                    self.finish = None;
                }
                &mut self.finish
            }
            JsCodeModeStream::Store { start } => {
                if start {
                    self.store = None;
                }
                &mut self.store
            }
            JsCodeModeStream::File(path) => {
                let at = match self.files.iter().position(|(held, _)| held == path) {
                    Some(at) => at,
                    None => {
                        self.files
                            .push((path.to_owned(), storage.code_run_output_sink_for(exec_run)?));
                        self.files.len() - 1
                    }
                };
                return self.files[at].1.write(frame);
            }
        };
        if sink.is_none() {
            *sink = Some(storage.code_run_output_sink_for(exec_run)?);
        }
        match sink {
            Some(sink) => sink.write(frame),
            None => Err(Error::InvariantViolation("streamed result sink missing")),
        }
    }

    /// The value the program's last `store` streamed, taken to be stored
    /// as a result of its own.
    pub(super) fn take_store(&mut self) -> Option<BodySink> {
        self.store.take()
    }

    /// The step's bodies: the answer of a finished step, else its console
    /// lines, the console lines a finished step also wrote, and its files,
    /// with whatever a runtime returned in its outcome instead of streaming
    /// it.
    pub(super) fn into_step_bodies(
        self,
        storage: &ExecutorStorage<'_>,
        exec_run: EntityId,
        outcome: &JsCodeModeStepOutcome,
    ) -> Result<StepBodies> {
        let (observation, console) = if outcome.done {
            (self.finish, self.console)
        } else {
            (self.console, None)
        };
        let mut observation = match observation {
            Some(sink) => sink,
            None => storage.code_run_output_sink_for(exec_run)?,
        };
        observation.write(outcome.observation.as_bytes())?;
        let mut files = self.files;
        for output in &outcome.outputs {
            let mut sink = storage.code_run_output_sink_for(exec_run)?;
            sink.write(&output.bytes)?;
            files.push((output.path.clone(), sink));
        }
        Ok(StepBodies {
            observation,
            console,
            files,
        })
    }
}

pub(super) fn validate_runtime_outputs(
    record: &CodeRunReplayRecord,
    seq: u64,
    files: &[(String, BodySink)],
) -> EngineExecutorResult<Vec<String>> {
    let mut output_paths = BTreeSet::new();
    let mut paths = Vec::with_capacity(files.len());
    for (index, (file, _)) in files.iter().enumerate() {
        let path = runtime_output_path(seq, index, file);
        if record.outputs.iter().any(|existing| existing.path == path)
            || !output_paths.insert(path.clone())
        {
            return Err(Error::InvalidClaimBody("duplicate executor output path").into());
        }
        // Checks the path alone; the body is measured once, as it is stored.
        let _ = CodeRunRawOutput::from_bytes(path.clone(), &[])?;
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
    record_output(storage, record, path, text.as_bytes())
}

/// A step's program as stored: byte for byte, never swept, because a resumed
/// step runs the stored program again.
pub(super) fn record_script_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    script: &str,
) -> EngineExecutorResult<()> {
    let mut sink = storage.code_run_script_sink()?;
    sink.write(script.as_bytes())?;
    publish_output(storage, record, path, sink).map(drop)
}

/// A TypeScript step's preparation beside its program (FIX 8276): the
/// JavaScript the guest ran, byte for byte and never swept as its program
/// is, and the typed record of its position map and Oxc pin. The program at
/// [`script_output_path`] stays the author's original; a JavaScript step
/// records nothing here.
pub(super) fn record_prepared_source(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    prepared: &PreparedSource<'_>,
) -> EngineExecutorResult<()> {
    let Some(transpiled) = prepared.transpiled() else {
        return Ok(());
    };
    record_script_output(
        storage,
        record,
        executed_output_path(seq),
        transpiled.executed_js(),
    )?;
    let map = transpiled.record_json(prepared.original())?;
    record_output(storage, record, source_map_output_path(seq), &map)
}

/// The output count a step's stores count from: the run's outputs minus
/// the current step's own evidence (its reply, its script, and for a
/// transpiled program its executed JavaScript plus source map). A step's
/// stores then name the same ordinals live and in a shadow replay, which
/// seeds its base from the step-start row that holds none of this
/// evidence. Rows without current-step evidence are unchanged.
pub(crate) fn store_ordinal_base(record: &CodeRunReplayRecord) -> usize {
    let seq = record.step_checkpoints.len() as u64;
    let evidence = [
        reply_output_path(seq),
        script_output_path(seq),
        executed_output_path(seq),
        source_map_output_path(seq),
    ];
    record.outputs.len()
        - record
            .outputs
            .iter()
            .filter(|output| evidence.iter().any(|path| path == &output.path))
            .count()
}

/// Whether the occurrence of `output` that run `owner` holds may enter
/// model context as it stands: one the secret scan marked, or one under
/// live or stale taint, never does. A context output has no `owner`, and is
/// read as its bytes are.
pub(crate) fn clean_for_context(
    storage: &ExecutorStorage<'_>,
    owner: Option<EntityId>,
    output: &CodeRunRawOutput,
) -> Result<bool> {
    Ok(!storage.code_run_result_taint(owner, output)?.0.is_tainted())
}

/// A text output as model context reads it: its body, or the withheld mark
/// in its place when the body is not clean.
pub(super) fn load_context_output(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
) -> Result<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Ok(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned());
    }
    load_utf8_output(storage, record, path)
}

pub(super) fn decode_text_output(raw: Vec<u8>) -> Result<String> {
    String::from_utf8(raw)
        .map_err(|_| Error::InvalidClaimBody("executor replay output is not utf8"))
}

/// What model context needs of one committed observation: its reference and
/// overview, never its body.
#[derive(Debug, Clone)]
pub(super) struct ObservationRef {
    pub(super) source: OutputRef,
    pub(super) overview: String,
}

/// An observation's reference, from its manifest alone: the body's digest
/// and length are the reference, and its preview the overview. No body byte
/// is read.
pub(super) fn observation_ref(output: &CodeRunRawOutput) -> ObservationRef {
    ObservationRef {
        source: output.output_ref(),
        overview: output.preview.text.chars().take(128).collect(),
    }
}

pub(super) fn load_utf8_output(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
) -> Result<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    let raw = storage
        .get_code_run_raw_output(output)?
        .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    decode_text_output(raw)
}

/// Bytes of one observation a compaction window carries. Past it, the window
/// carries the observation's head and the reference to its whole body, so a
/// summary never claims to cover bytes it was not given.
pub(super) const COMPACTION_OBSERVATION_WINDOW_BYTES: usize = 256 * 1024;

/// An observation for a compaction window: whole within `cap` bytes, else
/// its first `cap` bytes, read by range, and the reference to the rest. A
/// body that is not clean is the withheld mark instead.
pub(super) fn load_observation_window(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
    cap: usize,
) -> Result<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Ok(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned());
    }
    if output.raw_len <= cap as u64 {
        return load_utf8_output(storage, record, path);
    }
    let head = storage
        .read_code_run_raw_output_range(output, 0, cap)?
        .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    Ok(format!(
        "{}\n[the first {} of {} bytes; the whole result is stored as output:blake3:{}:{}]",
        String::from_utf8_lossy(&head),
        head.len(),
        output.raw_len,
        crate::entity_id::bytes_to_hex_lower(&output.raw_blake3),
        output.raw_len,
    ))
}

/// Bytes two windows of [`scan_output_windows`] share, so a read path or an
/// id that straddles a window's end is whole in the next one.
const OUTPUT_SCAN_OVERLAP_BYTES: usize = 1024;

/// Hands `each` the whole of one clean output, window by window, each read
/// by range and at most [`COMPACTION_OBSERVATION_WINDOW_BYTES`] long, the
/// windows overlapping by [`OUTPUT_SCAN_OVERLAP_BYTES`]. A body that is not
/// clean hands nothing: its refs never reach the model.
pub(super) fn scan_output_windows(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    output: &CodeRunRawOutput,
    mut each: impl FnMut(&str),
) -> Result<()> {
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Ok(());
    }
    let step = (COMPACTION_OBSERVATION_WINDOW_BYTES - OUTPUT_SCAN_OVERLAP_BYTES) as u64;
    let mut offset = 0_u64;
    loop {
        let window = storage
            .read_code_run_raw_output_range(output, offset, COMPACTION_OBSERVATION_WINDOW_BYTES)?
            .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
        each(&String::from_utf8_lossy(&window));
        let end = offset.saturating_add(window.len() as u64);
        if window.is_empty() || end >= output.raw_len {
            return Ok(());
        }
        offset = offset.saturating_add(step);
    }
}

/// Bytes of a finish answer a run's implicit bubble says (FIX 365). Past
/// them the bubble says nothing of the answer as prose: it carries the
/// stored answer as a typed result instead.
pub(super) const IMPLICIT_SPEECH_TEXT_BYTES: u64 = COMPACTION_OBSERVATION_WINDOW_BYTES as u64;

/// What a terminal checkpoint will say on a run's behalf (FIX 365): words,
/// or the typed result that names a stored answer too large to say. Stored
/// as its exact JSON, hashed into the checkpoint by those bytes, and decoded
/// from them by a recovery, never rebuilt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case")]
pub(super) enum ImplicitSpeechIntent {
    Text {
        text: String,
    },
    Result {
        attachment: crate::memory::MessageResultAttachment,
    },
}

impl ImplicitSpeechIntent {
    /// The bytes a checkpoint stores and hashes.
    pub(super) fn encode(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|_| Error::InvariantViolation("implicit speech intent encodes"))
    }

    pub(super) fn decode(stored: &str) -> Result<Self> {
        serde_json::from_str(stored)
            .map_err(|_| Error::CorruptedIndex("executor implicit speech intent"))
    }
}

/// The attachment of run `record`'s `output` as its result MESSAGE carries
/// it: the preview its card shows now, withheld while the body is not
/// clean, and the facets that read the rest.
pub(super) fn message_result_attachment(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    output: &CodeRunRawOutput,
) -> Result<crate::memory::MessageResultAttachment> {
    let read = crate::code_run::ResultRead::new(
        storage,
        record.run_id,
        output.clone(),
        None,
        None,
        false,
    )?
    .map_err(|_| Error::InvariantViolation("a whole result read is refused"))?;
    let card = read.card(storage)?;
    let preview = card["preview"]
        .as_str()
        .unwrap_or(CODE_RUN_OUTPUT_PREVIEW_WITHHELD)
        .to_owned();
    let truncated = output.preview.truncated || preview != output.preview.text;
    crate::memory::MessageResultAttachment::of(record.run_id, output, preview, truncated)
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
    let marker = CodeRunRawOutput::from_bytes(path, text.as_bytes())?;
    Ok((marker, text.into_bytes()))
}

fn fallback_speech_marker_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{FALLBACK_SPEECH_MARKER_SUFFIX}")
}

/// Maximum raw bytes handed to one guest read, read by range from the body.
pub(super) const RECOVERABLE_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

/// A model-facing, typed read-file affordance in the guest's existing output
/// mount. Neither the path nor its digest grants access without a matching
/// committed observation in the current run's routed replay store.
pub(super) fn recoverable_output_path(
    seq: u64,
    source: crate::compaction::output::OutputRef,
) -> String {
    format!(
        "/mnt/outputs/.oneiron-context-ref/{seq}/{}/{}",
        crate::entity_id::bytes_to_hex_lower(&source.hash),
        source.byte_len,
    )
}

pub(super) fn recoverable_chunk_path(
    seq: u64,
    source: crate::compaction::output::OutputRef,
    offset: u64,
) -> String {
    format!("{}/chunk/{offset}", recoverable_output_path(seq, source))
}

/// The provider's reply for step `seq`, kept as evidence.
pub(super) fn reply_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.reply.json")
}

/// A bridge call's result, stored as a body because it was too large for
/// one reply.
pub(crate) fn bridge_result_output_path(bridge_seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/bridge/{bridge_seq:06}.result.json")
}

/// A value a program passed to `store`, named by its digest and the run's
/// output ordinal: the same bytes stored twice are two outputs. The body
/// bytes are still stored once by content.
pub(crate) fn store_result_output_path(digest: &[u8; 32], ordinal: usize) -> String {
    format!(
        "{SCRIPT_OUTPUT_DIR}/store/{}.{ordinal:06}.result",
        crate::entity_id::bytes_to_hex_lower(digest)
    )
}

/// Whether `path` names a result of the run the guest may read back: a
/// stored bridge result, a stored value, the reply a parked call resumed
/// with, a step's observation, or a file a step wrote.
pub(crate) fn is_result_output_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(SCRIPT_OUTPUT_DIR) else {
        return false;
    };
    rest.strip_prefix("/bridge/")
        .is_some_and(|rest| rest.ends_with(".result.json"))
        || rest
            .strip_prefix("/store/")
            .is_some_and(|rest| rest.ends_with(".result"))
        || resumed_output_wait(path).is_some()
        || is_observation_output_path(path)
        || is_runtime_output_path(path)
}

/// Whether `path` names a step's observation.
fn is_observation_output_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(SCRIPT_OUTPUT_DIR) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    let Some(seq) = rest.strip_suffix(".observation.txt") else {
        return false;
    };
    !seq.is_empty() && seq.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `path` names a file a step wrote.
fn is_runtime_output_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(SCRIPT_OUTPUT_DIR) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    let Some((seq, rest)) = rest.split_once("/output/") else {
        return false;
    };
    if seq.is_empty() || !seq.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some((index, tail)) = rest.split_once('-') else {
        return false;
    };
    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) && !tail.is_empty()
}

/// Whether the run's output at `path` holds reply content an erase of the
/// run's actor takes (FIX 5718; CALLS "reply-bearing outputs"): every
/// output but the run's control bodies, which carry what it is and how it
/// stands: its config marker, its steps' terminal markers and their
/// trailing-speech markers. A result, a resumed reply, a provider's reply,
/// a program, an observation and each file a step wrote hold one.
pub(crate) fn holds_reply_content(path: &str) -> bool {
    path != CONFIG_OUTPUT_PATH
        && !is_terminal_output_path(path)
        && !path.ends_with(FALLBACK_SPEECH_MARKER_SUFFIX)
}

/// The reply the wait step `seq` parked on was answered with, published when
/// the run resumed from it: the result of the step's parked call. The path
/// names the wait, so the record alone counts the run's resumes from one.
pub(super) fn resumed_output_path(seq: u64, wait_id: EntityId) -> String {
    format!(
        "{SCRIPT_OUTPUT_DIR}/{seq:06}{RESUMED_OUTPUT_INFIX}{}.json",
        wait_id.to_hex()
    )
}

/// The step and the wait (lower-case hex) a resumed reply's path names.
pub(super) fn resumed_output_wait(path: &str) -> Option<(u64, &str)> {
    let rest = path.strip_prefix(SCRIPT_OUTPUT_DIR)?.strip_prefix('/')?;
    let (seq, rest) = rest.split_once(RESUMED_OUTPUT_INFIX)?;
    let wait = rest.strip_suffix(".json")?;
    let digits = !seq.is_empty() && seq.bytes().all(|byte| byte.is_ascii_digit());
    let hex = wait.len() == 32
        && wait
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !(digits && hex) {
        return None;
    }
    Some((seq.parse().ok()?, wait))
}

pub(super) fn script_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.generated.js")
}

pub(super) fn observation_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.observation.txt")
}

/// The JavaScript a TypeScript step's program ran as (FIX 8276).
pub(super) fn executed_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.executed.js")
}

/// A TypeScript step's preparation record: its position map and Oxc pin.
pub(super) fn source_map_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.source-map.json")
}

/// The JavaScript a turn program's pinned TypeScript call ran as, kept by
/// its first entry for every later one (FIX 8276).
pub(super) fn pinned_executed_output_path() -> String {
    format!("{SCRIPT_OUTPUT_DIR}/pinned.executed.js")
}

/// The preparation record of a turn program's pinned TypeScript call.
pub(super) fn pinned_source_map_output_path() -> String {
    format!("{SCRIPT_OUTPUT_DIR}/pinned.source-map.json")
}

/// The console lines of a step that finished, kept as evidence beside its
/// answer; the answer stays the step's observation and result.
pub(super) fn console_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.console.txt")
}

/// Where a step's type diagnostics past one reply are kept whole, in a
/// body the run owns and never in its replay record (FIX 8277).
pub(super) fn type_diagnostics_output_path(seq: u64, invocation: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.{invocation}.type-diagnostics.json")
}

/// The board frames a step's verb answers carried beside their outputs
/// (FIX 2135), kept for the model's view of that step.
pub(super) fn board_frames_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.board-frames.json")
}

pub(super) fn implicit_speak_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.implicit-speak.json")
}

pub(super) fn terminal_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{TERMINAL_OUTPUT_SUFFIX}")
}

pub(super) fn is_terminal_output_path(path: &str) -> bool {
    terminal_output_seq(path).is_some()
}

/// The step a terminal marker's path names.
pub(super) fn terminal_output_seq(path: &str) -> Option<u64> {
    let seq = path
        .strip_prefix(SCRIPT_OUTPUT_DIR)?
        .strip_prefix('/')?
        .strip_suffix(TERMINAL_OUTPUT_SUFFIX)?;
    if seq.is_empty() || !seq.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    seq.parse().ok()
}

fn runtime_output_path(seq: u64, index: usize, path: &str) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}/output/{index:03}-{path}")
}

pub(super) fn checkpoint_label(seq: u64) -> String {
    format!("executor.repl.step.{seq:06}")
}
