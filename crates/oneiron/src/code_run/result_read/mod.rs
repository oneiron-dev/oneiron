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
//! checks for their verdict and reads no byte.

mod chunks;
mod query;
mod search;
mod shape;
mod slice;

use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunOutputKind, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, ExecutorStorage,
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
const READ_PIECE_BYTES: usize = 1 << 20;

/// Bytes of a body's head its card's shape is sniffed from.
const SHAPE_HEAD_BYTES: usize = 64 * 1024;

/// Bytes of a range's head its card previews.
const RANGE_PREVIEW_BYTES: usize = 2 * 1024;

/// What a read of a body that is not clean says in place of its content.
const WITHHELD_REASON: &str = "this result holds a secret or sits under a custody hold, so no \
     read shows its content; this is not a size limit";

/// One of a result's `more` facets: a deterministic read of its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFacet {
    /// A range of the body, by bytes or by lines.
    Slice,
    /// The matches of a literal or a regex, with their lines and context.
    Search,
    /// Values picked by a JSON path, or rows of a line table.
    Query,
    /// The body cut into range refs, a page at a time.
    Chunks,
}

impl ResultFacet {
    /// Every facet, in the order a card lists them.
    pub const ALL: [Self; 4] = [Self::Slice, Self::Search, Self::Query, Self::Chunks];

    /// The facet a call names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|facet| facet.as_str() == name)
    }

    /// The facet's name, as a program calls it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slice => "slice",
            Self::Search => "search",
            Self::Query => "query",
            Self::Chunks => "chunks",
        }
    }
}

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
}

/// One result body of a run, read by range through the run's storage.
pub(crate) struct RunBody<'s, 'a> {
    storage: &'s ExecutorStorage<'a>,
    output: &'s CodeRunRawOutput,
    base: u64,
    len: u64,
}

impl ResultBody for RunBody<'_, '_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.output.kind
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = usize::try_from(self.len.saturating_sub(offset).min(len as u64))
            .map_err(|_| Error::ArithmeticOverflow("code-run result read"))?;
        let mut bytes = Vec::with_capacity(take);
        while bytes.len() < take {
            let at = self.base + offset + bytes.len() as u64;
            let piece = self
                .storage
                .read_code_run_raw_output_range(
                    self.output,
                    at,
                    (take - bytes.len()).min(READ_PIECE_BYTES),
                )?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
            if piece.is_empty() {
                break;
            }
            bytes.extend_from_slice(&piece);
        }
        Ok(bytes)
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        self.storage.code_run_line_index(self.output).ok().flatten()
    }

    fn base(&self) -> u64 {
        self.base
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
    output: CodeRunRawOutput,
    name: Option<String>,
    range: Option<(u64, u64)>,
    state: ArtifactTaintState,
    secret: Option<String>,
}

impl ResultRead {
    /// `output` as `name` binds it in run `owner`, narrowed to `range`, the
    /// taint of the run's occurrence of it read now. A range that is not
    /// inside the body is refused.
    pub(crate) fn new(
        storage: &ExecutorStorage<'_>,
        owner: EntityId,
        output: CodeRunRawOutput,
        name: Option<String>,
        range: Option<(u64, u64)>,
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
            output,
            name,
            range,
            state,
            secret,
        }))
    }

    /// The result read.
    pub(crate) fn output(&self) -> &CodeRunRawOutput {
        &self.output
    }

    /// The range of its body the read is narrowed to, if any.
    pub(crate) fn range(&self) -> Option<(u64, u64)> {
        self.range
    }

    /// Whether the occurrence read is tainted now.
    pub(crate) fn is_tainted(&self) -> bool {
        self.state.is_tainted()
    }

    /// The reference a reply names the result by: a range by its parent's
    /// handle, a whole result by its name, or its handle when it has none.
    fn reference(&self) -> String {
        match self.range {
            Some((start, end)) => format!("{}#{start}-{end}", self.output.handle),
            None => self
                .name
                .clone()
                .unwrap_or_else(|| self.output.handle.clone()),
        }
    }

    fn body<'s, 'a>(&'s self, storage: &'s ExecutorStorage<'a>) -> RunBody<'s, 'a> {
        let (base, end) = self.range.unwrap_or((0, self.output.raw_len));
        RunBody {
            storage,
            output: &self.output,
            base,
            len: end - base,
        }
    }

    /// The result's card, from its manifest and taint sidecars and, while
    /// it is clean, its head: the handle facets, its name, its taint, the
    /// facets that read it and the shape its head shows. A range's card is
    /// its parent's, with the range's `ref`, bytes and preview. A body that
    /// is not clean shows no preview and no shape.
    pub(crate) fn card(&self, storage: &ExecutorStorage<'_>) -> Result<Value> {
        let mut card = result_handle_json(&self.output);
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
        if self.state.is_tainted() {
            card["preview"] = json!(CODE_RUN_OUTPUT_PREVIEW_WITHHELD);
            return Ok(card);
        }
        let body = self.body(storage);
        let head = body.read(0, SHAPE_HEAD_BYTES)?;
        if self.range.is_some() {
            let cut = floor_boundary(&head, RANGE_PREVIEW_BYTES);
            card["preview"] = json!(String::from_utf8_lossy(&head[..cut]));
        }
        card["shape"] = shape::shape(&head, body.kind(), head.len() as u64 == body.len());
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
    fn withheld(&self) -> Value {
        let (start, end) = self.range.unwrap_or((0, self.output.raw_len));
        json!({
            "withheld": taint_word(self.state),
            "ref": self.reference(),
            "bytes": end - start,
            "lines": self.range.is_none().then_some(self.output.lines),
            "kind": kind_word(self.output.kind),
            "taint": {"state": taint_word(self.state), "secret": self.secret},
            "reason": WITHHELD_REASON,
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
        if self.state.is_tainted() {
            return Ok(Reply::Output(self.withheld()));
        }
        let body = self.body(storage);
        let bounds = ReadBounds {
            reply_bytes: RESULT_REPLY_INLINE_BYTES,
            watch: storage.limit_watch(),
        };
        let reference = self.reference();
        match facet {
            ResultFacet::Slice => slice::slice(&body, &reference, input, &bounds),
            ResultFacet::Search => search::search(&body, &reference, input, &bounds),
            ResultFacet::Query => query::query(
                &body,
                &reference,
                &self.output.handle,
                input,
                &bounds,
                spill,
            ),
            ResultFacet::Chunks => {
                chunks::chunks(&body, &reference, &self.output.handle, input, &bounds)
            }
        }
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
    )? {
        Ok(read) => read.card(storage),
        Err(_) => Err(Error::InvariantViolation("a whole result has no range")),
    }
}

/// The run's result a reference names among `outputs`, and the live name
/// bound to it. `live` is the run's live names, oldest first. Only the
/// run's own results resolve: a handle names nothing else.
pub(crate) fn resolve<'r>(
    mut outputs: impl Iterator<Item = &'r CodeRunRawOutput>,
    live: &[&'r CodeRunResultBinding],
    reference: &JsResultRef,
) -> Option<(CodeRunRawOutput, Option<String>)> {
    match reference {
        JsResultRef::Name(name) => {
            let binding = live.iter().find(|binding| binding.name == *name)?;
            let output = outputs.find(|output| output.handle == binding.handle)?;
            Some((output.clone(), Some(binding.name.clone())))
        }
        JsResultRef::Handle(handle) => {
            let output = outputs.find(|output| names_result(output, handle))?;
            let name = live
                .iter()
                .rev()
                .find(|binding| binding.handle == output.handle)
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

/// The whole body's line index, for a lookup in a window that is the whole
/// body; a window of it counts its own lines.
fn whole_index(body: &dyn ResultBody) -> Option<Vec<u64>> {
    if body.base() == 0 {
        body.line_index()
    } else {
        None
    }
}

/// Where the line after the `lfs`-th newline starts, looking forward from
/// `from` (a line start, or a place no earlier than the line's own start).
/// With the line index it reads only the block the line starts in.
fn seek_line(
    body: &dyn ResultBody,
    index: Option<&[u64]>,
    from: LinePos,
    lfs: u64,
    scan: &mut Scan,
) -> Result<Seek> {
    if lfs <= from.lfs {
        return Ok(Seek::At(from.offset));
    }
    let mut at = from;
    if let Some(index) = index {
        // The last block whose count is below `lfs`: that newline is in it.
        let block = index
            .partition_point(|count| *count < lfs)
            .saturating_sub(1);
        if let Some(&count) = index.get(block) {
            let start = block as u64 * LINE_INDEX_BLOCK_BYTES;
            if start > at.offset {
                at = LinePos {
                    offset: start,
                    lfs: count,
                };
            }
        }
    }
    let len = body.len();
    while at.offset < len {
        let piece = scan.read(body, at.offset, READ_PIECE_BYTES)?;
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
/// one, else counted from the start. `None` past the scan bound.
fn lfs_before(
    body: &dyn ResultBody,
    index: Option<&[u64]>,
    offset: u64,
    scan: &mut Scan,
) -> Result<Option<u64>> {
    let block = offset / LINE_INDEX_BLOCK_BYTES;
    let mut at = usize::try_from(block)
        .ok()
        .and_then(|block| index.and_then(|index| index.get(block)))
        .map_or(LinePos::START, |&count| LinePos {
            offset: block * LINE_INDEX_BLOCK_BYTES,
            lfs: count,
        });
    while at.offset < offset {
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

impl Vault {
    /// The cards of a code run's named results, newest first and at most
    /// `limit` of them, and how many names it has: for a caller outside the
    /// run, who releases them under the run's own checks. A card shows a
    /// preview and a shape only of a clean body, and no guest read path.
    pub fn code_run_result_cards(
        &self,
        record: &CodeRunReplayRecord,
        limit: usize,
    ) -> Result<(Vec<Value>, usize)> {
        let storage = ExecutorStorage::Canonical(self);
        let mut cards = Vec::new();
        for binding in record.bindings.iter().rev().take(limit) {
            let Some(output) = record.outputs.iter().find(|output| {
                output.handle == binding.handle && is_result_output_path(&output.path)
            }) else {
                continue;
            };
            let mut card = card(&storage, record.run_id, output, Some(binding.name.as_str()))?;
            if let Some(fields) = card.as_object_mut() {
                fields.remove("read");
            }
            cards.push(card);
        }
        Ok((cards, record.bindings.len()))
    }

    /// One read of a code run's result for a caller outside the run (the
    /// MCP door): its card when `facet` is `None`, else that facet of it,
    /// with `input` less the reference. Only `run_id`'s own results resolve,
    /// by a name it bound, a handle or a range of either. `withholds` says
    /// whether the rows the run's answers were served from (`None` when one
    /// kept no set) stay where the caller is not; then the result's taint
    /// is checked as in the run. A selection past one reply pages, as
    /// nothing outside a run binds a new result, and one picked value past
    /// one reply comes back as a range ref over its own bytes, with its
    /// first page. The reply is the run's own: `{"output": ...}` or a
    /// `denied` refusal.
    pub fn read_code_run_result(
        &self,
        run_id: EntityId,
        reference: &str,
        facet: Option<ResultFacet>,
        input: Value,
        withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
    ) -> Result<Value> {
        let Some(record) = self.get_code_run_replay_record(&run_id)? else {
            return Ok(unknown_handle(&[]));
        };
        let live: Vec<&CodeRunResultBinding> = record.bindings.iter().collect();
        let target = JsResultTarget::parse(reference);
        let outputs = record
            .outputs
            .iter()
            .filter(|output| is_result_output_path(&output.path));
        let Some((output, name)) = resolve(outputs, &live, &target.reference) else {
            return Ok(unknown_handle(&live));
        };
        if withholds(record.agent_verb_rows().as_deref())? {
            return Ok(refusal("result_withheld"));
        }
        let storage = ExecutorStorage::Canonical(self);
        let read = match ResultRead::new(&storage, run_id, output, name, target.range)? {
            Ok(read) => read,
            Err(refused) => return Ok(refused),
        };
        let Some(facet) = facet else {
            let mut card = read.card(&storage)?;
            if let Some(fields) = card.as_object_mut() {
                fields.remove("read");
            }
            return Ok(json!({"output": card}));
        };
        Ok(match read.read(&storage, facet, input, None)? {
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
