//! Reads of one result body of a code run (OF-190 B++): its card, with the
//! shape its head shows, and the `more` facets that read the rest of it,
//! `slice`, `search`, `query` and `chunks`. Each read is deterministic and
//! makes no model call. Its reply fits one message, and a read that stops
//! early says where to go on from; none answers "no match" for bytes it did
//! not scan.
//!
//! Neither the executor's host nor the MCP door is known here. Both resolve
//! the result in its run, check the reader's grant and the rows it was
//! served from, and read it through [`ResultRead`], which checks the taint
//! of the run's occurrence of it (Docs Q08). `can({read: r})` asks the same
//! checks for their verdict and reads no byte. A scoped child's read also
//! stops at its live cutoff (FIX 8233; see `run_body`).

mod arm;
mod chunks;
mod outside;
mod query;
mod run_body;
mod search;
mod shape;
mod slice;
mod unplaced;

pub(crate) use self::outside::{read_result_in, result_cards_in};
use self::run_body::{LiveCutoff, RunBody};
pub(crate) use self::unplaced::unplaced_answer;

use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunOutputKind,
    CodeRunRawOutput, CodeRunReplayRecord, CodeRunResultBinding, ExecutorStorage, RESPONSE_ERASED,
    ScopedCallControl,
};
use crate::engine_executor::{
    JsResultRef, JsResultTarget, RESULT_REPLY_INLINE_BYTES, is_result_output_path,
    result_handle_json,
};
use crate::entity_id::EntityId;
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::secret_rotation::ArtifactTaintState;
use crate::store::{BodySink, LINE_INDEX_BLOCK_BYTES};
use crate::{Error, Result, Vault};
use serde_json::{Value, json};

/// Live names a refusal for an unknown result lists, newest first.
const UNKNOWN_HANDLE_LIVE_NAMES: usize = 64;

/// Bytes one read of a body takes at most.
pub(super) const READ_PIECE_BYTES: usize = 1 << 20;

/// Bytes of a body's head its card's shape is sniffed from.
const SHAPE_HEAD_BYTES: usize = 64 * 1024;

/// Bytes of a range's head its card previews.
const RANGE_PREVIEW_BYTES: usize = 2 * 1024;

/// What a read of a body that is not clean says in place of its content.
const WITHHELD_REASON: &str = "this result holds a secret or sits under a custody hold, so no \
     read shows its content; this is not a size limit";

/// What a read of a body an erase of its run's actor took says in place of
/// its content (FIX 6536).
const ERASED_REASON: &str = "its owner's erase took this result's content, so no read shows \
     it; this is not a size limit";

pub use crate::memory::result_facet::ResultFacet;

/// A facet's answer.
pub(crate) enum Reply {
    /// What the reader reads: `{"output": value}` on the wire.
    Output(Value),
    /// A refusal, which the guest throws.
    Denied(Value),
    /// A selection too large for one reply, written whole to the sink the
    /// read was given: `count` values, and where a later read would go on.
    Spilled { count: u64, next: Option<Value> },
}

/// One result body as a facet reads it: the whole body, or the window of
/// it a range ref names. Offsets are the window's own.
pub(crate) trait ResultBody {
    /// The window's length.
    fn len(&self) -> u64;
    fn kind(&self) -> CodeRunOutputKind;
    /// Up to `len` bytes from `offset`, cut at the window's end.
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
    /// The whole body's sparse line index (the newline count before each
    /// 64 KiB block), when it has one.
    fn line_index(&self) -> Option<Vec<u64>>;
    /// Where the window starts in the whole body.
    fn base(&self) -> u64;
    /// Notes the scan-bound search credit issued for this window: the exact
    /// emitted (`offset`, `line`, `credit`) (FIX 1189 discount, #4311 P1-B).
    /// A run's body records it on its storage's vault; any other body keeps
    /// the no-op default and its resumes take no discount.
    fn note_search_credit(&self, _offset: u64, _line: u64, _credit: u64) {}
    /// Whether (`offset`, `line`, `credit`) is the credit last issued for
    /// this window: the full tuple must match, else the resume takes no
    /// discount. Only a run's body attests; the default denies.
    fn valid_search_credit(&self, _offset: u64, _line: u64, _credit: u64) -> bool {
        false
    }

    /// The live cutoff the read stops at (FIX 8233): a run's body read for
    /// a scoped child has one; any other body keeps the default, none.
    fn live_cutoff(&self) -> LiveCutoff<'_> {
        LiveCutoff::default()
    }
}

/// What one read may spend: the bytes of its reply, and the `[limits]`
/// rows of the vault its body is in.
struct ReadBounds<'w> {
    reply_bytes: usize,
    watch: &'w LimitWatch,
}

impl ReadBounds<'_> {
    /// Bytes a search, a query of a line table or a line lookup scans
    /// before it answers with a cursor.
    fn scan_bytes(&self) -> u64 {
        self.watch.bound(EngineLimit::CodeResultScanBytes)
    }
}

/// A result read as every read of one is: resolved in its run, the taint of
/// the run's occurrence of it read now, and its range inside its body. Its
/// reader's grant and the rows it was served from are the caller's to check
/// before it is made.
pub(crate) struct ResultRead {
    owner: EntityId,
    output: CodeRunRawOutput,
    name: Option<String>,
    range: Option<(u64, u64)>,
    state: ArtifactTaintState,
    secret: Option<String>,
    /// Whether the read is for a caller other than `owner`: a delegated
    /// source keeps its caller's name, while an unnamed child finding uses
    /// its exact occurrence.
    foreign: bool,
    /// The live cutoff of the scoped child the read is made for (FIX 8233).
    live_cutoff: Option<ScopedCallControl>,
}

impl ResultRead {
    /// `output` as `name` binds it in run `owner`, narrowed to `range`, the
    /// taint of the run's occurrence of it read now. A range that is not
    /// inside the body is refused. `foreign` says the read is for a caller
    /// other than `owner` (a delegated source or a finding). Delegated names
    /// stay local to that caller; findings keep their occurrence refs.
    pub(crate) fn new(
        storage: &ExecutorStorage<'_>,
        owner: EntityId,
        output: CodeRunRawOutput,
        name: Option<String>,
        range: Option<(u64, u64)>,
        foreign: bool,
    ) -> Result<std::result::Result<Self, Value>> {
        if let Some((start, end)) = range
            && (start >= end || end > output.raw_len)
        {
            let mut refused = refusal("invalid_range");
            refused["bytes"] = json!(output.raw_len);
            return Ok(Err(refused));
        }
        let (state, secret) = storage.code_run_result_taint(Some(owner), &output)?;
        Ok(Ok(Self {
            owner,
            output,
            name,
            range,
            state,
            secret,
            foreign,
            live_cutoff: None,
        }))
    }

    /// This read, stopped at `control`, the live cutoff of the scoped child
    /// it is made for (FIX 8233). Each piece of the body it reads, and each
    /// long loop of its facets, checks it first. A read it cuts stops with
    /// an error, and its caller answers `reader_task_settled` in its place.
    /// A read for any other reader holds none and reads no clock.
    pub(crate) fn with_live_cutoff(mut self, control: Option<&ScopedCallControl>) -> Self {
        self.live_cutoff = control.cloned();
        self
    }

    /// The result read.
    pub(crate) fn output(&self) -> &CodeRunRawOutput {
        &self.output
    }

    /// The run whose occurrence of the result is read.
    pub(crate) fn owner(&self) -> EntityId {
        self.owner
    }

    /// The range of its body the read is narrowed to, if any.
    pub(crate) fn range(&self) -> Option<(u64, u64)> {
        self.range
    }

    /// Whether the occurrence read is tainted now.
    pub(crate) fn is_tainted(&self) -> bool {
        self.state.is_tainted()
    }

    /// Whether this is a delegated source named in the caller's own run,
    /// rather than an unnamed child finding or one of the owner's results.
    fn caller_named(&self) -> bool {
        self.foreign && self.name.is_some()
    }

    /// Ranges and unnamed foreign findings keep the owner's exact occurrence.
    /// A delegated source keeps its caller's name; other whole results keep
    /// their name or content handle.
    fn reference(&self) -> String {
        // A range must not switch occurrences when a local name is rebound
        // or another child reports the same bytes. Delegated sources retain
        // the name the caller's job binds to its authorized source.
        let legacy = || {
            self.name
                .clone()
                .unwrap_or_else(|| self.output.handle.clone())
        };
        match self.range {
            Some((start, end)) if !self.caller_named() => {
                match occurrence_ref(self.owner, &self.output.path) {
                    Some(parent) => format!("{parent}#{start}-{end}"),
                    None => format!("{}#{start}-{end}", legacy()),
                }
            }
            Some((start, end)) => format!("{}#{start}-{end}", legacy()),
            None if self.foreign && !self.caller_named() => {
                occurrence_ref(self.owner, &self.output.path).unwrap_or_else(legacy)
            }
            None => legacy(),
        }
    }

    /// The result's card, from its manifest and taint sidecars and, while
    /// it is clean, its head: the handle facets, its name, its taint, the
    /// facets that read it and the shape its head shows. A range's card is
    /// its parent's, with the range's `ref`, bytes and preview. A body that
    /// is not clean shows no preview and no shape.
    pub(crate) fn card(&self, storage: &ExecutorStorage<'_>) -> Result<Value> {
        self.card_of(&RunBody::of(self, storage))
    }

    /// [`Self::card`] over `body`, the result's bytes where they are held: a
    /// run's storage, or a shadow arm's own store (`arm`).
    fn card_of(&self, body: &dyn ResultBody) -> Result<Value> {
        let mut card = result_handle_json(self.owner, &self.output);
        card["name"] = json!(self.name);
        card["taint"] = json!({"state": taint_word(self.state), "secret": self.secret});
        card["more"] = json!(ResultFacet::ALL.map(ResultFacet::as_str));
        if let Some((start, end)) = self.range {
            card["ref"] = json!(self.reference());
            card["range"] = json!([start, end]);
            card["bytes"] = json!(end - start);
            if let Some(fields) = card.as_object_mut() {
                fields.remove("lines");
            }
        }
        if self.caller_named() && self.range.is_none() {
            // Delegated sources keep their caller's name. An unnamed child
            // finding keeps the native card's exact occurrence ref.
            card["ref"] = json!(
                self.name
                    .clone()
                    .unwrap_or_else(|| self.output.handle.clone())
            );
        }
        if self.state.is_tainted() {
            card["preview"] = json!(withheld_preview(self.secret.as_deref()));
            return Ok(card);
        }
        let head = body.read(0, SHAPE_HEAD_BYTES)?;
        if self.range.is_some() {
            let cut = floor_boundary(&head, RANGE_PREVIEW_BYTES);
            card["preview"] = json!(String::from_utf8_lossy(&head[..cut]));
        }
        card["shape"] = shape::shape_of(body, head)?;
        if let Some(reason) = unmarked_secret(&json!([card["preview"], card["shape"]])) {
            card["preview"] = json!(CODE_RUN_OUTPUT_PREVIEW_WITHHELD);
            card["taint"] = json!({
                "state": taint_word(ArtifactTaintState::TaintedLive),
                "secret": reason,
            });
            if let Some(fields) = card.as_object_mut() {
                fields.remove("shape");
            }
        }
        Ok(card)
    }

    /// `can({read: r})`'s verdict on a read that passed every check before
    /// its taint: `can` while the body is clean, with its ref, size, kind
    /// and taint, else `tainted` with what a facet would say of it. No
    /// preview and no byte of the body either way.
    pub(crate) fn preflight(&self) -> Value {
        if self.state.is_tainted() {
            let mut verdict = self.withheld();
            if let Some(fields) = verdict.as_object_mut() {
                if let Some(detail) = fields.remove("reason") {
                    fields.insert("detail".to_owned(), detail);
                }
                fields.insert("can".to_owned(), json!(false));
                fields.insert("reason".to_owned(), json!("tainted"));
            }
            return verdict;
        }
        let (start, end) = self.range.unwrap_or((0, self.output.raw_len));
        json!({
            "can": true,
            "ref": self.reference(),
            "bytes": end - start,
            "kind": kind_word(self.output.kind),
            "taint": {"state": taint_word(self.state), "secret": self.secret},
        })
    }

    /// What any facet of a body that is not clean answers: its size and
    /// taint, none of its content.
    pub(crate) fn withheld(&self) -> Value {
        self.withheld_as(self.state, self.secret.as_deref())
    }

    /// [`Self::withheld`] under `state`, whose hit was `secret`.
    fn withheld_as(&self, state: ArtifactTaintState, secret: Option<&str>) -> Value {
        let (start, end) = self.range.unwrap_or((0, self.output.raw_len));
        json!({
            "withheld": taint_word(state),
            "ref": self.reference(),
            "bytes": end - start,
            "lines": self.range.is_none().then_some(self.output.lines),
            "kind": kind_word(self.output.kind),
            "taint": {"state": taint_word(state), "secret": secret},
            "reason": withheld_reason(secret),
        })
    }

    /// One facet of the result, read from `input`. A selection past one
    /// reply streams into `spill` when there is one; without one it pages.
    pub(crate) fn read(
        &self,
        storage: &ExecutorStorage<'_>,
        facet: ResultFacet,
        input: Value,
        spill: Option<&mut BodySink>,
    ) -> Result<Reply> {
        let body = RunBody::of(self, storage);
        self.read_of(&body, storage.limit_watch(), facet, input, spill)
    }

    /// [`Self::read`] over `body`, under the `[limits]` rows of `watch`.
    fn read_of(
        &self,
        body: &dyn ResultBody,
        watch: &LimitWatch,
        facet: ResultFacet,
        input: Value,
        spill: Option<&mut BodySink>,
    ) -> Result<Reply> {
        if self.state.is_tainted() {
            return Ok(Reply::Output(self.withheld()));
        }
        let bounds = ReadBounds {
            reply_bytes: RESULT_REPLY_INLINE_BYTES,
            watch,
        };
        let reference = self.reference();
        // Chunk and page refs name the same parent the ref above names: the
        // owner's immutable occurrence, so a page of a renamed result still
        // reparses to its occurrence, not to the first result with its
        // bytes. Only a named delegated source keeps the caller's name,
        // as its ref does.
        let parent = if self.caller_named() {
            self.name
                .clone()
                .unwrap_or_else(|| self.output.handle.clone())
        } else {
            occurrence_ref(self.owner, &self.output.path).unwrap_or_else(|| {
                self.name
                    .clone()
                    .unwrap_or_else(|| self.output.handle.clone())
            })
        };
        let reply = match facet {
            ResultFacet::Slice => slice::slice(body, &reference, input, &bounds),
            ResultFacet::Search => search::search(body, &reference, input, &bounds),
            ResultFacet::Query => query::query(body, &reference, &parent, input, &bounds, spill),
            ResultFacet::Chunks => chunks::chunks(body, &reference, &parent, input, &bounds),
        }?;
        // A spilled selection is a new body, which its own sink's scan marks.
        Ok(match reply {
            Reply::Output(answer) => match unmarked_secret(&answer) {
                None => Reply::Output(answer),
                Some(reason) => {
                    Reply::Output(self.withheld_as(ArtifactTaintState::TaintedLive, Some(reason)))
                }
            },
            other => other,
        })
    }

    /// One read for a caller outside the run, who has checked its grant and
    /// the rows the run's answers were served from: `output` as `name` binds
    /// it in run `owner`, narrowed to `range`, read under the taint of that
    /// occurrence now. Its card, with no guest read path, when `facet` is
    /// `None`, else that facet of it from `input`; a selection past one
    /// reply pages, as nothing outside a run binds a new result. The reply
    /// is the run's own: `{"output": ...}` or a `denied` refusal.
    pub(crate) fn outside_run(
        storage: &ExecutorStorage<'_>,
        owner: EntityId,
        output: CodeRunRawOutput,
        name: Option<String>,
        range: Option<(u64, u64)>,
        facet: Option<ResultFacet>,
        input: Value,
    ) -> Result<Value> {
        let read = match Self::new(storage, owner, output, name, range, false)? {
            Ok(read) => read,
            Err(refused) => return Ok(refused),
        };
        let Some(facet) = facet else {
            let mut card = read.card(storage)?;
            if let Some(fields) = card.as_object_mut() {
                fields.remove("read");
            }
            return Ok(json!({"output": card}));
        };
        Ok(match read.read(storage, facet, input, None)? {
            Reply::Output(output) => json!({"output": output}),
            Reply::Denied(refused) => refused,
            Reply::Spilled { .. } => {
                return Err(Error::InvariantViolation(
                    "a read with no sink spilled its selection",
                ));
            }
        })
    }
}

/// What the write door's rules find in what a read of a clean body shows
/// (OF-067): a body stored before its scan read every rule may hold a secret
/// no mark names, so a card or an answer that shows one is withheld as a
/// marked body's is. The body's row keeps its taint as it was.
pub(crate) fn unmarked_secret(shown: &Value) -> Option<&'static str> {
    crate::batch::secret_scan::write_payload_hit(shown.to_string().as_bytes())
}

/// The preview of a body that is not clean, whose hit was `secret`: erased
/// once an erase of its run's actor took it (FIX 6536), else withheld.
fn withheld_preview(secret: Option<&str>) -> &'static str {
    match secret {
        Some(RESPONSE_ERASED) => CODE_RUN_OUTPUT_PREVIEW_ERASED,
        _ => CODE_RUN_OUTPUT_PREVIEW_WITHHELD,
    }
}

/// What a facet of a body that is not clean, whose hit was `secret`, says in
/// place of its content (FIX 6536).
fn withheld_reason(secret: Option<&str>) -> &'static str {
    match secret {
        Some(RESPONSE_ERASED) => ERASED_REASON,
        _ => WITHHELD_REASON,
    }
}

/// A result's card in run `owner`, its taint read now (see
/// [`ResultRead::card`]).
pub(crate) fn card(
    storage: &ExecutorStorage<'_>,
    owner: EntityId,
    output: &CodeRunRawOutput,
    name: Option<&str>,
) -> Result<Value> {
    match ResultRead::new(
        storage,
        owner,
        output.clone(),
        name.map(str::to_owned),
        None,
        false,
    )? {
        Ok(read) => read.card(storage),
        Err(_) => Err(Error::InvariantViolation("a whole result has no range")),
    }
}

/// The immutable ref of run `owner`'s occurrence at `path`: `None` when the
/// derivation fails, which leaves the caller on the legacy name or handle.
fn occurrence_ref(owner: EntityId, path: &str) -> Option<String> {
    crate::code_run::ResultOccurrence::owned(owner, path)
        .ok()
        .map(|occurrence| format!("occurrence:{}", occurrence.id().to_hex()))
}

/// The run's result a reference names among `outputs`, and the live name
/// bound to it. `live` is the run's live names, oldest first. Only the
/// run's own results resolve: a handle names nothing else. An
/// `occurrence:<hex>` ref names the run's exact occurrence at `owner`'s
/// path, never the first occurrence that happens to hold the same bytes:
/// whole-result cards carry one because the guest prefers `ref` over
/// `handle`.
pub(crate) fn resolve<'r>(
    owner: EntityId,
    mut outputs: impl Iterator<Item = &'r CodeRunRawOutput>,
    live: &[&'r CodeRunResultBinding],
    reference: &JsResultRef,
) -> Option<(CodeRunRawOutput, Option<String>)> {
    match reference {
        JsResultRef::Name(name) => {
            let binding = live.iter().find(|binding| binding.name == *name)?;
            let output = outputs.find(|output| {
                output.handle == binding.handle
                    && (binding.path.is_empty() || output.path == binding.path)
            })?;
            Some((output.clone(), Some(binding.name.clone())))
        }
        JsResultRef::Handle(handle) => {
            if let Some(wanted) = handle.strip_prefix("occurrence:") {
                let mut selected: Option<CodeRunRawOutput> = None;
                for output in outputs {
                    let Ok(occurrence) =
                        crate::code_run::ResultOccurrence::owned(owner, &output.path)
                    else {
                        continue;
                    };
                    if occurrence.id().to_hex() == wanted {
                        selected = Some(output.clone());
                        break;
                    }
                }
                let output = selected?;
                let name = live
                    .iter()
                    .rev()
                    .find(|binding| {
                        binding.handle == output.handle
                            && (binding.path.is_empty() || binding.path == output.path)
                    })
                    .map(|binding| binding.name.clone());
                return Some((output, name));
            }
            let output = outputs.find(|output| names_result(output, handle))?;
            let name = live
                .iter()
                .rev()
                .find(|binding| {
                    binding.handle == output.handle
                        && (binding.path.is_empty() || binding.path == output.path)
                })
                .map(|binding| binding.name.clone());
            Some((output.clone(), name))
        }
    }
}

/// The refusal for a reference to no result of the run, with the live
/// names (`live`, oldest first) it could have meant.
pub(crate) fn unknown_handle(live: &[&CodeRunResultBinding]) -> Value {
    let names: Vec<&str> = live
        .iter()
        .rev()
        .take(UNKNOWN_HANDLE_LIVE_NAMES)
        .map(|binding| binding.name.as_str())
        .collect();
    json!({
        "denied": "unknown_handle",
        "reasonCodes": ["unknown_handle"],
        "live": names,
        "liveCount": live.len(),
    })
}

/// A result call's refusal, as the guest's thrown error carries it.
pub(crate) fn refusal(code: &str) -> Value {
    json!({"denied": code, "reasonCodes": [code]})
}

/// `can({read: r})`'s verdict on a read refused before its taint, with the
/// refusal's own detail: `unknown_handle` for a reference to no result of
/// the run, `withheld_rows` when the rows its answers were served from stay
/// where the reader is not, `outside_delegated_range` for a reader child's
/// range past what its parent delegated, `reader_task_settled` once a
/// child's job is settled or claimed again, else `denied`.
pub(crate) fn cannot(refused: Value) -> Value {
    let Value::Object(mut fields) = refused else {
        return json!({"can": false, "reason": "denied"});
    };
    let reason = match fields.get("denied").and_then(Value::as_str) {
        Some("unknown_handle") => "unknown_handle",
        Some("result_withheld") => "withheld_rows",
        Some("outside_delegated_range") => "outside_delegated_range",
        Some("reader_task_settled") => "reader_task_settled",
        _ => "denied",
    };
    fields.insert("can".to_owned(), json!(false));
    fields.insert("reason".to_owned(), json!(reason));
    Value::Object(fields)
}

/// Whether `handle` names `output`: its handle as its card gives it, or its
/// digest as model context cites it (`output:blake3:<hex>:<len>`).
pub(crate) fn names_result(output: &CodeRunRawOutput, handle: &str) -> bool {
    output.handle == handle
        || handle
            .strip_prefix("output:blake3:")
            .and_then(|rest| rest.split(':').next())
            .is_some_and(|hex| hex == crate::entity_id::bytes_to_hex_lower(&output.raw_blake3))
}

/// A taint state as a card spells it.
pub(crate) fn taint_word(state: ArtifactTaintState) -> &'static str {
    match state {
        ArtifactTaintState::Clean => "clean",
        ArtifactTaintState::TaintedLive => "tainted_live",
        ArtifactTaintState::TaintedStale => "tainted_stale",
    }
}

fn kind_word(kind: CodeRunOutputKind) -> &'static str {
    match kind {
        CodeRunOutputKind::Text => "text",
        CodeRunOutputKind::Binary => "binary",
    }
}

/// The refusal for a facet input that does not decode, with the reason.
fn invalid_input(error: impl std::fmt::Display) -> Value {
    let mut refused = refusal("invalid_result_input");
    refused["error"] = json!(error.to_string());
    refused
}

/// A facet's input, or the refusal that says why it is not one.
fn decode<T: serde::de::DeserializeOwned>(input: Value) -> std::result::Result<T, Value> {
    serde_json::from_value(input).map_err(invalid_input)
}

/// Bytes `value` takes as JSON.
fn encoded_len(value: &Value) -> usize {
    value.to_string().len()
}

/// The answer to a read that reached the scan bound: the row it stopped at.
fn scan_limit() -> Value {
    json!(EngineLimit::CodeResultScanBytes.key())
}

/// Bytes as a reply carries them: text as a string (`lossy` when a byte
/// was replaced), anything else as base64.
fn view(bytes: &[u8], text: bool) -> (Value, bool) {
    if !text {
        use base64::Engine as _;
        return (
            json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
            false,
        );
    }
    match String::from_utf8_lossy(bytes) {
        std::borrow::Cow::Borrowed(text) => (json!(text), false),
        std::borrow::Cow::Owned(text) => (json!(text), true),
    }
}

fn is_continuation(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

/// `at` moved back to a character boundary of `bytes`, by at most three.
fn floor_boundary(bytes: &[u8], at: usize) -> usize {
    let mut at = at.min(bytes.len());
    let floor = at.saturating_sub(3);
    while at > floor && at < bytes.len() && is_continuation(bytes[at]) {
        at -= 1;
    }
    at
}

/// `at` moved on to a character boundary of `bytes`, by at most three.
fn ceil_boundary(bytes: &[u8], at: usize) -> usize {
    let mut at = at.min(bytes.len());
    let ceil = at + 3;
    while at < ceil && at < bytes.len() && is_continuation(bytes[at]) {
        at += 1;
    }
    at
}

fn count_lf(bytes: &[u8]) -> u64 {
    bytes.iter().filter(|byte| **byte == b'\n').count() as u64
}

/// The index of the `n`-th newline (from one) in `bytes`.
fn nth_lf(bytes: &[u8], n: u64) -> Option<usize> {
    let mut seen = 0;
    bytes.iter().position(|byte| {
        if *byte == b'\n' {
            seen += 1;
        }
        seen == n && n > 0
    })
}

/// Bytes one call may still read of a body.
struct Scan {
    left: u64,
}

impl Scan {
    fn new(bound: u64) -> Self {
        Self { left: bound }
    }

    /// `bound` plus `credit` already-read bytes the resume re-reads: the
    /// first `credit` bytes are not charged twice. Reads stay sequential
    /// from the resume point, so `bound + credit` caps NEW bytes at `bound`
    /// (FIX 1189).
    fn with_credit(bound: u64, credit: u64) -> Self {
        Self {
            left: bound.saturating_add(credit),
        }
    }

    /// Up to `len` bytes from `offset`, as many as the bound still allows:
    /// none once it is spent.
    fn read(&mut self, body: &dyn ResultBody, offset: u64, len: usize) -> Result<Vec<u8>> {
        let len = usize::try_from(self.left.min(len as u64)).unwrap_or(len);
        let bytes = body.read(offset, len)?;
        self.left -= bytes.len() as u64;
        Ok(bytes)
    }
}

/// A place in a body and the newlines before it: the line it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinePos {
    offset: u64,
    lfs: u64,
}

impl LinePos {
    const START: Self = Self { offset: 0, lfs: 0 };
}

/// Where a line lookup ended.
enum Seek {
    /// The line starts here.
    At(u64),
    /// The body ended first; it holds this many newlines.
    End(LinePos),
    /// The scan bound ended it here.
    Limit(LinePos),
}

/// A window's line index, in its own offsets: the window-relative start of
/// each whole-body 64 KiB block inside it, with the newlines before that
/// start inside the window. Sorted by offset; a short tail has no later
/// entries. A missing, short, corrupt, single-block or tight-bound shape is
/// `None`, and the lookup scans (FIX 1186a). A ranged index sought from
/// inside its prefix stays pending: `blocks` empty until the seek builds
/// them once at the boundary, or freezes them empty on a failed build.
struct WindowIndex {
    blocks: Vec<LinePos>,
    pending: Option<PendingIndex>,
}

/// A ranged line index deferred to the seek (B2): pure window metadata —
/// the whole-body table, the window's base and end, its first block
/// number and its prefix length. No prefix bytes are read for setup; the
/// seek builds once at the boundary from its own scan.
struct PendingIndex {
    abs: Vec<u64>,
    base: u64,
    end: u64,
    k_block: usize,
    prefix_len: u64,
}

/// The bytes of the window's line-index prefix `[base, next_block)`
/// (B1/B2): the same no-read shape checks as the index plan, with no
/// `Scan` and no read. `Some(0)` for an aligned window; `None` for a
/// missing or empty index, a zero length, an unrepresentable `k`, a `k`
/// past the table, or a prefix past the window.
fn index_prefix_len(body: &dyn ResultBody) -> Option<u64> {
    let abs = body.line_index()?;
    if abs.is_empty() {
        return None;
    }
    let len = body.len();
    if len == 0 {
        return None;
    }
    let base = body.base();
    if base == 0 {
        return Some(0);
    }
    let block_bytes = LINE_INDEX_BLOCK_BYTES;
    let k = base.div_ceil(block_bytes);
    let next = k.checked_mul(block_bytes)?;
    let prefix_len = next.checked_sub(base)?;
    if k >= abs.len() as u64 || prefix_len >= len {
        return None;
    }
    Some(prefix_len)
}

/// The window's line index for a seek from `from`, in the window's own
/// offsets. A whole window maps its entries directly with no read. A range
/// sought from inside its prefix defers to a pending index with no setup
/// read; sought from at or past the prefix end it keeps the eager prefix
/// read/rebase, except a setup no block can use is skipped. An impossible
/// hand cursor, and any missing, short, corrupt or tight-bound shape, is
/// `None`: the lookup scans.
fn window_index(
    body: &dyn ResultBody,
    scan: &mut Scan,
    from: LinePos,
) -> Result<Option<WindowIndex>> {
    let Some(abs) = body.line_index() else {
        return Ok(None);
    };
    if abs.is_empty() {
        return Ok(None);
    }
    let len = body.len();
    if len == 0 {
        return Ok(None);
    }
    let base = body.base();
    let Some(end) = base.checked_add(len) else {
        return Ok(None);
    };
    if from.offset == 0 && from.lfs != 0 {
        // An inconsistent hand cursor: byte 0 holds no newlines before
        // it. A pending build would bake the lie into every block, so the
        // lookup pure-scans exactly as the old code.
        return Ok(None);
    }
    if base == 0 {
        let mut blocks = Vec::with_capacity(abs.len());
        let mut prev = 0_u64;
        for (i, &count) in abs.iter().enumerate() {
            let Some(start) = (i as u64).checked_mul(LINE_INDEX_BLOCK_BYTES) else {
                return Ok(None);
            };
            if start >= end {
                break;
            }
            if i == 0 && count != 0 {
                return Ok(None);
            }
            if count < prev {
                return Ok(None);
            }
            prev = count;
            blocks.push(LinePos {
                offset: start,
                lfs: count,
            });
        }
        if blocks.is_empty() {
            return Ok(None);
        }
        return Ok(Some(WindowIndex {
            blocks,
            pending: None,
        }));
    }
    let block_bytes = LINE_INDEX_BLOCK_BYTES;
    let k = base.div_ceil(block_bytes);
    let Some(next) = k.checked_mul(block_bytes) else {
        return Ok(None);
    };
    let Some(prefix_len) = next.checked_sub(base) else {
        return Ok(None);
    };
    if k >= abs.len() as u64 || prefix_len >= len {
        return Ok(None);
    }
    let k_block = k as usize;
    if from.offset < prefix_len {
        // The seek may end inside the prefix: defer the build to the
        // boundary, with no setup read.
        return Ok(Some(WindowIndex {
            blocks: Vec::new(),
            pending: Some(PendingIndex {
                abs,
                base,
                end,
                k_block,
                prefix_len,
            }),
        }));
    }
    // A setup no candidate can use is skipped: with no block starting
    // strictly after `from`, no jump can satisfy `candidate.offset >
    // at.offset`, so the index is provably useless and the pure scan is
    // old-exact. Block offsets need no prefix read.
    let mut after = false;
    for i in k_block..abs.len() {
        let Some(start) = (i as u64).checked_mul(block_bytes) else {
            break;
        };
        if start >= end {
            break;
        }
        if start - base > from.offset {
            after = true;
            break;
        }
    }
    if !after {
        return Ok(None);
    }
    let base_lfs = if prefix_len == 0 {
        abs[k_block]
    } else {
        if scan.left <= prefix_len {
            return Ok(None);
        }
        let Ok(take) = usize::try_from(prefix_len) else {
            return Ok(None);
        };
        let prefix = scan.read(body, 0, take)?;
        if prefix.len() != take {
            return Ok(None);
        }
        let counted = count_lf(&prefix);
        let Some(base_lfs) = abs[k_block].checked_sub(counted) else {
            return Ok(None);
        };
        base_lfs
    };
    let mut blocks = Vec::with_capacity(abs.len().saturating_sub(k_block));
    for (i, &count) in abs.iter().enumerate().skip(k_block) {
        let Some(start) = (i as u64).checked_mul(block_bytes) else {
            return Ok(None);
        };
        if start >= end {
            break;
        }
        if count < base_lfs {
            return Ok(None);
        }
        if i > k_block && count < abs[i - 1] {
            return Ok(None);
        }
        let Some(offset) = start.checked_sub(base) else {
            return Ok(None);
        };
        let Some(lfs) = count.checked_sub(base_lfs) else {
            return Ok(None);
        };
        blocks.push(LinePos { offset, lfs });
    }
    if blocks.is_empty() {
        return Ok(None);
    }
    Ok(Some(WindowIndex {
        blocks,
        pending: None,
    }))
}

/// The pending index's blocks from the seek's own prefix count (B2): the
/// existing re-base math over `counted` in place of a setup read. `None`
/// on underflow, invalid count, nonmonotonicity or emptiness: the seek
/// freezes empty blocks and continues its pure scan.
fn build_pending(meta: &PendingIndex, counted: u64) -> Option<Vec<LinePos>> {
    let base_lfs = meta.abs.get(meta.k_block)?.checked_sub(counted)?;
    let mut blocks = Vec::with_capacity(meta.abs.len().saturating_sub(meta.k_block));
    for (i, &count) in meta.abs.iter().enumerate().skip(meta.k_block) {
        let start = (i as u64).checked_mul(LINE_INDEX_BLOCK_BYTES)?;
        if start >= meta.end {
            break;
        }
        if count < base_lfs {
            return None;
        }
        if i > meta.k_block && count < meta.abs[i - 1] {
            return None;
        }
        let offset = start.checked_sub(meta.base)?;
        let lfs = count.checked_sub(base_lfs)?;
        blocks.push(LinePos { offset, lfs });
    }
    (!blocks.is_empty()).then_some(blocks)
}

/// Moves `at` to the last block whose count is below `lfs` — that newline
/// is in it — when the jump moves forward past what the scan reached.
fn jump_to_block(blocks: &[LinePos], at: &mut LinePos, lfs: u64) {
    let found = blocks.partition_point(|pos| pos.lfs < lfs);
    if found > 0 {
        let candidate = blocks[found - 1];
        if candidate.offset > at.offset && candidate.lfs >= at.lfs {
            *at = candidate;
        }
    }
}

/// Where the line after the `lfs`-th newline starts, looking forward from
/// `from` (a line start, or a place no earlier than the line's own start).
/// With the line index it reads only the block the line starts in. A
/// pending index builds once at the prefix boundary from the seek's own
/// scan: targets and limits inside the prefix return before any build
/// with old-exact charging, and a failed build freezes empty blocks and
/// continues the pure scan from the boundary. Each step checks the read's
/// live cutoff first (FIX 8233).
fn seek_line(
    body: &dyn ResultBody,
    mut index: Option<&mut WindowIndex>,
    from: LinePos,
    lfs: u64,
    scan: &mut Scan,
) -> Result<Seek> {
    if lfs <= from.lfs {
        return Ok(Seek::At(from.offset));
    }
    let mut at = from;
    if let Some(built) = index.as_deref()
        && built.pending.is_none()
    {
        jump_to_block(&built.blocks, &mut at, lfs);
    }
    let len = body.len();
    while at.offset < len {
        body.live_cutoff().check()?;
        let mut want = READ_PIECE_BYTES;
        if let Some(idx) = index.as_deref_mut()
            && let Some(prefix_len) = idx.pending.as_ref().map(|meta| meta.prefix_len)
        {
            if at.offset > prefix_len {
                // Past the boundary with no tiling count: the count is not
                // the prefix's, so the build is refused and the pure scan
                // continues. Unreachable from the window's own pending
                // tokens, which start below the boundary and consume at it.
                idx.pending = None;
            } else if at.offset == prefix_len {
                // The FIRST boundary crossing consumes pending whether the
                // build succeeds or falls back; it is never retried in
                // this call, and later seeks reuse the frozen blocks. At
                // this point `at.lfs` is exactly the eager setup's counted
                // prefix lines for a consistent `from`.
                match idx
                    .pending
                    .take()
                    .and_then(|meta| build_pending(&meta, at.lfs))
                {
                    Some(built) => {
                        idx.blocks = built;
                        jump_to_block(&idx.blocks, &mut at, lfs);
                    }
                    None => idx.blocks = Vec::new(),
                }
            } else {
                // Below the boundary with the build still ahead: cap the
                // read so it cannot cross `prefix_len` before the build.
                // Every byte still charges exactly once; only piece
                // boundaries move.
                want = want.min(usize::try_from(prefix_len - at.offset).unwrap_or(usize::MAX));
            }
        }
        let piece = scan.read(body, at.offset, want)?;
        if piece.is_empty() {
            return Ok(Seek::Limit(at));
        }
        if let Some(found) = nth_lf(&piece, lfs - at.lfs) {
            return Ok(Seek::At(at.offset + found as u64 + 1));
        }
        at.lfs += count_lf(&piece);
        at.offset += piece.len() as u64;
    }
    Ok(Seek::End(at))
}

/// The newlines before `offset`, from the line index's block when there is
/// one, else counted from the start. `None` past the scan bound. An
/// unbuilt pending index holds no blocks, so it pure-scans as `None` does.
/// Each step checks the read's live cutoff first (FIX 8233).
fn lfs_before(
    body: &dyn ResultBody,
    index: Option<&WindowIndex>,
    offset: u64,
    scan: &mut Scan,
) -> Result<Option<u64>> {
    let mut at = LinePos::START;
    if let Some(index) = index {
        let found = index.blocks.partition_point(|pos| pos.offset <= offset);
        if found > 0 {
            at = index.blocks[found - 1];
        }
    }
    while at.offset < offset {
        body.live_cutoff().check()?;
        let want = usize::try_from(offset - at.offset)
            .unwrap_or(READ_PIECE_BYTES)
            .min(READ_PIECE_BYTES);
        let piece = scan.read(body, at.offset, want)?;
        if piece.is_empty() {
            return Ok(None);
        }
        at.lfs += count_lf(&piece);
        at.offset += piece.len() as u64;
    }
    Ok(Some(at.lfs))
}
