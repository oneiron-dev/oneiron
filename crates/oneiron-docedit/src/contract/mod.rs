//! The document engine's contract (ARCH-0075 section 2, "an organ crate with a
//! hosted API"): one versioned, typed op table over this crate's native
//! functions. The OSS crate and the paid hosted documents API in oneiron-cloud
//! serve the same table; `docs/ops/documents-api-handoff.md` is the handoff.
//!
//! A [`Call`] is typed JSON args plus byte inputs the args name by index. A
//! [`Done`] is a typed [`Reply`] plus named byte outputs with their media
//! types. The contract keeps no session or handle store, writes nowhere and
//! holds no limits of its own: the caller supplies every ceiling and owns
//! storage, authorization and metering. An op only proposes bytes; the caller
//! decides what lands, and a refusal changes nothing. `xlsx.recalc` runs
//! through the caller's [`RecalcPort`], because the formula engine depends on
//! this crate and not the other way round.

mod args;
mod description;
mod run;

pub use args::{
    AssetMedia, AssetOrigin, DeckAsset, DeckCreateArgs, DeckNames, DeckReadArgs,
    DeckTransactionArgs, DocumentLocationArgs, DocxLimits, DocxProjectArgs, DocxReadArgs,
    DocxReviseArgs, DocxValidateArgs, GraphicSettings, KeptBriefArgs, PackageLimits,
    PptxCommentsArgs, PptxCommentsInspectArgs, RecalcClockArgs, SlideCreationId, XlsxProjectArgs,
    XlsxReadArgs, XlsxRecalcArgs,
};
pub use description::{call_schema, describe, reply_schema};

use crate::docx_body::{DocxBlock, DocxStory};
use crate::pptx_comments::{PptxAnchorOutcome, PptxSlideIdentity};
use crate::resource::{CapacityHit, ResourceRefusal, Resources};
use crate::retained_opc::Limits;
use crate::xlsx_body::XlsxBook;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The op table's version. A call naming another refuses before any op runs.
pub const CONTRACT_SCHEMA: u32 = 5;

/// Error detail ceiling in bytes, as an organ's error detail.
pub const MAX_DETAIL_BYTES: usize = 512;

pub const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
pub const XLSX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
pub const PPTX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation";
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// One call: the contract schema, the op and its args.
/// `{"schema": 5, "op": "docx.read", "args": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Call {
    pub schema: u32,
    #[serde(flatten)]
    pub op: Op,
}

/// The schema-5 op table. Each op names its byte inputs by index into the
/// call's inputs, and every op that reads a package takes the caller's limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", content = "args")]
pub enum Op {
    /// The op table, its media types and the call and reply JSON schemas.
    #[serde(rename = "contract.describe")]
    Describe,
    /// The body blocks and native non-body stories of a DOCX. Story block
    /// ids are local to their explicit story scope.
    #[serde(rename = "docx.read")]
    DocxRead(DocxReadArgs),
    /// One tracked Word revision transaction, written as Word's own marks.
    #[serde(rename = "docx.revise")]
    DocxRevise(DocxReviseArgs),
    /// The blocking OOXML linker over a package, and optionally the
    /// transaction grammar a settlement replays.
    #[serde(rename = "docx.validate")]
    DocxValidate(DocxValidateArgs),
    /// Block-level changes against a read, as one tracked revision.
    #[serde(rename = "docx.project")]
    DocxProject(DocxProjectArgs),
    /// Every worksheet's cells, the defined names and the cell formats.
    #[serde(rename = "xlsx.read")]
    XlsxRead(XlsxReadArgs),
    /// Cell and defined-name changes, formulas written without cached values.
    #[serde(rename = "xlsx.project")]
    XlsxProject(XlsxProjectArgs),
    /// Have the opening application recalculate the whole workbook.
    #[serde(rename = "xlsx.mark_full_calc")]
    XlsxMarkFullCalc(XlsxReadArgs),
    /// Native recalculation through the caller's [`RecalcPort`].
    #[serde(rename = "xlsx.recalc")]
    XlsxRecalc(XlsxRecalcArgs),
    /// The slides and shapes a deck transaction addresses, and the id marks.
    #[serde(rename = "deck.read")]
    DeckRead(DeckReadArgs),
    /// One checked deck transaction (schema 2) over a base deck.
    #[serde(rename = "deck.transaction")]
    DeckTransaction(DeckTransactionArgs),
    /// A new deck from a kept brief over a template.
    #[serde(rename = "deck.create")]
    DeckCreate(DeckCreateArgs),
    /// Modern comment threads, replies and resolutions, written byte for byte.
    #[serde(rename = "pptx.comments")]
    PptxComments(PptxCommentsArgs),
    /// The slide and shape identities a comment anchors to, and the threads
    /// whose anchor is unknown.
    #[serde(rename = "pptx.comments.inspect")]
    PptxCommentsInspect(PptxCommentsInspectArgs),
}

impl Op {
    /// The op's wire name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Describe => "contract.describe",
            Self::DocxRead(_) => "docx.read",
            Self::DocxRevise(_) => "docx.revise",
            Self::DocxValidate(_) => "docx.validate",
            Self::DocxProject(_) => "docx.project",
            Self::XlsxRead(_) => "xlsx.read",
            Self::XlsxProject(_) => "xlsx.project",
            Self::XlsxMarkFullCalc(_) => "xlsx.mark_full_calc",
            Self::XlsxRecalc(_) => "xlsx.recalc",
            Self::DeckRead(_) => "deck.read",
            Self::DeckTransaction(_) => "deck.transaction",
            Self::DeckCreate(_) => "deck.create",
            Self::PptxComments(_) => "pptx.comments",
            Self::PptxCommentsInspect(_) => "pptx.comments.inspect",
        }
    }
}

/// Where a new thread landed, by its root comment GUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ThreadAnchor {
    pub thread_id: String,
    pub anchor: PptxAnchorOutcome,
}

/// What an op returns beside its byte outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Described(Description),
    DocxBlocks {
        blocks: Vec<DocxBlock>,
        stories: Vec<DocxStory>,
    },
    DocxRevised {
        /// The transaction as applied, its revision date pinned: a settlement
        /// replays exactly this.
        transaction: Value,
        notes: Vec<String>,
    },
    /// The checks passed.
    Checked,
    /// The op wrote its one output.
    Written,
    XlsxBook {
        book: XlsxBook,
    },
    /// The workbook written, and what the projection adapted as Excel would.
    XlsxProjected {
        effects: Vec<String>,
    },
    Recalculated {
        engine: String,
        version: String,
        formula_count: usize,
    },
    Deck(DeckRead),
    DeckTransaction {
        /// The deck transaction report (schema 2): candidate hash, part diff,
        /// per-step effects, the marks after the run and the handoff hash.
        report: Value,
    },
    /// No rung could hold these pages; the person decides each.
    DeckAsk {
        pages: Vec<String>,
    },
    DeckCreated(DeckCreated),
    PptxComments {
        /// The parts the edits changed, every one of them declared by an edit.
        touched_parts: Vec<String>,
        /// Replay these to write the same bytes again.
        slide_creation_ids: Vec<SlideCreationId>,
        anchors: Vec<ThreadAnchor>,
    },
    PptxCommentsInspected {
        slides: Vec<PptxSlideIdentity>,
        /// Parts that sign the package; a signed deck takes no comment edit.
        signature_parts: Vec<String>,
        /// Root comment GUIDs exported with no resolved anchor.
        unknown_anchor_threads: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Description {
    pub schema: u32,
    pub ops: Vec<OpInfo>,
    pub call_schema: Value,
    pub reply_schema: Value,
    pub error_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpInfo {
    pub name: String,
    pub summary: String,
    pub inputs: Vec<InputInfo>,
    pub outputs: Vec<OutputSpec>,
    /// The host port the op runs through, when it needs one.
    pub port: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InputInfo {
    /// The args field that holds the input index.
    pub field: String,
    pub media_types: Vec<String>,
    /// The field holds a list of indices, or a map of them.
    pub repeated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutputSpec {
    pub name: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Editability {
    Unsigned,
    /// Reported, never edited.
    Signed,
    MetadataUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeckRead {
    pub editability: Editability,
    /// The deck's native-id marks, a transaction's `marks` seed.
    pub marks: Value,
    pub slides: Vec<DeckSlide>,
    /// Ids the deck repeats; a step addressing one refuses.
    pub ambiguities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeckSlide {
    /// The slide part, a step target's `slide`.
    pub part: String,
    pub sld_id: u32,
    pub creation_id: Option<u32>,
    pub layout: Option<String>,
    /// BLAKE3 hex.
    pub content_fingerprint: String,
    pub shapes: Vec<DeckShape>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeckShape {
    /// `p:cNvPr/@id`, a step target's `shape`.
    pub id: Option<u32>,
    pub creation_id: Option<String>,
    pub name: Option<String>,
    pub kind: ShapeKind,
    pub placeholder: Option<DeckPlaceholder>,
    /// Indices of the enclosing groups, outermost first.
    pub group_path: Vec<usize>,
    /// Slide-space top-left in EMU, through every enclosing group.
    pub top_left: Option<(i64, i64)>,
    /// Declared or inherited extent in EMU.
    pub extent: Option<(i64, i64)>,
    /// 60,000ths of a degree.
    pub rotation: Option<i64>,
    pub paragraphs: Vec<String>,
    /// BLAKE3 hex, a step target's `expected`.
    pub content_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeKind {
    Shape,
    Picture,
    GraphicFrame,
    Connector,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeckPlaceholder {
    pub kind: String,
    pub idx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeckCreated {
    /// BLAKE3 hex of the deck output.
    pub hash: String,
    pub slides: Vec<CreatedSlide>,
    /// Parts the deck writes differently from the template.
    pub write_set: Vec<String>,
    /// Optional blocks the plan omitted.
    pub omitted: Vec<String>,
    /// Units whose laid-out text has no rendered fit proof.
    pub fit_unverified: Vec<UnverifiedUnit>,
    /// The `fit_unverified` units PowerPoint measured running past their
    /// frame. Absent from a reply written before receipts were read.
    #[serde(default)]
    pub fit_overflows: Vec<UnverifiedUnit>,
    /// SHA-256 hex of the stored Office receipt that measured this exact
    /// deck, when one does.
    #[serde(default)]
    pub fit_receipt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CreatedSlide {
    pub part: String,
    pub sld_id: u32,
    pub page: String,
    pub layout: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnverifiedUnit {
    pub slide: String,
    pub block: String,
    pub shape: u32,
}

/// A finished op: its reply and the bytes it proposes.
#[derive(Debug, Clone, PartialEq)]
pub struct Done {
    pub reply: Reply,
    pub outputs: Vec<Output>,
}

impl Done {
    fn reply(reply: Reply) -> Self {
        Self {
            reply,
            outputs: Vec::new(),
        }
    }

    fn with(reply: Reply, output: Output) -> Self {
        Self {
            reply,
            outputs: vec![output],
        }
    }

    /// The outputs' names, media types, sizes and hashes, as a reply lists them.
    #[must_use]
    pub fn manifest(&self) -> Vec<OutputInfo> {
        self.outputs
            .iter()
            .map(|output| OutputInfo {
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                size: output.bytes.len() as u64,
                blake3: blake3::hash(&output.bytes).to_hex().to_string(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl Output {
    fn new(name: &str, media_type: &str, bytes: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            media_type: media_type.to_owned(),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutputInfo {
    pub name: String,
    pub media_type: String,
    pub size: u64,
    pub blake3: String,
}

/// Why a call did not finish. Nothing was written, and no output exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct ContractError {
    pub code: ErrorCode,
    /// At most [`MAX_DETAIL_BYTES`].
    pub detail: String,
    /// The machine's floor (what the work needed and what was available)
    /// or the deadline, when memory or a deadline stopped the call: the
    /// typed cause behind [`ErrorCode::MemoryFloor`] and
    /// [`ErrorCode::ResourceDeadline`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRefusal>,
    /// The ceiling a well-formed package passed, its dimension, what the
    /// package has and the limit: the typed cause behind
    /// [`ErrorCode::CapacityExceeded`] (FIX 5354).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityHit>,
}

impl ContractError {
    /// The error a resource refusal ends a call with: its own code, and the
    /// refusal itself as the cause. A host may run the call again.
    #[must_use]
    pub fn resource(refusal: ResourceRefusal) -> Self {
        let code = match refusal {
            ResourceRefusal::MemoryFloor { .. } => ErrorCode::MemoryFloor,
            ResourceRefusal::Deadline => ErrorCode::ResourceDeadline,
        };
        Self {
            resource: Some(refusal),
            ..Self::new(code, refusal.to_string())
        }
    }

    /// The error a ceiling ends a call with: [`ErrorCode::CapacityExceeded`],
    /// and the ceiling itself as the cause, never an invalid document.
    #[must_use]
    pub fn capacity(hit: CapacityHit) -> Self {
        Self {
            capacity: Some(hit),
            ..Self::new(ErrorCode::CapacityExceeded, hit.to_string())
        }
    }

    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > MAX_DETAIL_BYTES {
            let mut end = MAX_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self {
            code,
            detail,
            resource: None,
            capacity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The call does not parse, fails an op's args, or names a missing input.
    BadRequest,
    /// The call names a contract schema this crate does not serve.
    UnsupportedSchema,
    /// An input is not a package the op reads within the caller's limits.
    InvalidDocument,
    /// The input moved since it was read: a base hash, a staleness guard or
    /// a kept brief no longer matches.
    Stale,
    /// The native writer refuses the edit for the named reason.
    Refused,
    /// The package is signed or its metadata cannot be inspected.
    NotEditable,
    /// The workbook needs the precision fallback (LibreOffice in the host's
    /// session image); the native engine refuses it.
    NeedsFallback,
    /// The op needs a host port the caller did not supply.
    Unavailable,
    Internal,
    /// The machine cannot hold the memory the work needs: the error's
    /// `resource` names what was needed and what was available. A count in
    /// the document is never this reason.
    MemoryFloor,
    /// The host's wait for memory, or a deadline the caller gave, ran out;
    /// the call may run again.
    ResourceDeadline,
    /// A well-formed package passed a ceiling the caller set, or one its
    /// format has (classic ZIP's widths): the error's `capacity` names the
    /// dimension, what the package has and the limit. A count in the
    /// document is never this reason.
    CapacityExceeded,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidDocument => "invalid_document",
            Self::Stale => "stale",
            Self::Refused => "refused",
            Self::NotEditable => "not_editable",
            Self::NeedsFallback => "needs_fallback",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::MemoryFloor => "memory_floor",
            Self::ResourceDeadline => "resource_deadline",
            Self::CapacityExceeded => "capacity_exceeded",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The recalculation a host plugs in for `xlsx.recalc`. The formula engine
/// (oneiron-xlsx-formula) implements it; a host without one answers
/// `unavailable`. A host's precision fallback (LibreOffice headless, for
/// the workbooks the formula engine refuses) implements it too.
pub trait RecalcPort {
    fn recalculate(
        &self,
        workbook: &[u8],
        limits: Limits,
        clock: &RecalcClockArgs,
        location: Option<&DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError>;

    /// [`Self::recalculate`] for a caller that also names its zone, an IANA
    /// name (`Asia/Tokyo`) beside `clock`'s offset, which it read the offset
    /// from: a calculator that reads local time from a zone rather than an
    /// offset reads it there. The default reads the offset alone.
    fn recalculate_in_zone(
        &self,
        workbook: &[u8],
        limits: Limits,
        clock: &RecalcClockArgs,
        location: Option<&DocumentLocationArgs>,
        zone: Option<&str>,
    ) -> Result<Recalculated, ContractError> {
        let _ = zone;
        self.recalculate(workbook, limits, clock, location)
    }
}

/// A recalculated workbook and the engine that computed its caches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recalculated {
    pub bytes: Vec<u8>,
    pub engine: String,
    pub version: String,
    pub formula_count: usize,
}

/// The host ports a call may run through.
#[derive(Clone, Copy, Default)]
pub struct Ports<'a> {
    pub recalc: Option<&'a dyn RecalcPort>,
    /// The host's resource port the call's package and XML readers reserve
    /// their memory through; without one, the call measures and reserves
    /// nothing ([`Resources::measuring`]).
    pub resources: Option<&'a Resources>,
}

/// Run one call over `inputs`. The inputs are only read.
pub fn execute(call: &Call, inputs: &[&[u8]], ports: Ports<'_>) -> Result<Done, ContractError> {
    if call.schema != CONTRACT_SCHEMA {
        return Err(unsupported_schema(call.schema));
    }
    run::op(&call.op, inputs, ports)
}

/// [`execute`] over a call's JSON text. The schema is read before the op, so
/// a call from another contract version refuses as `unsupported_schema`.
pub fn execute_json(
    call: &[u8],
    inputs: &[&[u8]],
    ports: Ports<'_>,
) -> Result<Done, ContractError> {
    let value: Value = serde_json::from_slice(call)
        .map_err(|error| ContractError::new(ErrorCode::BadRequest, error.to_string()))?;
    match value.get("schema").and_then(Value::as_u64) {
        Some(schema) if schema == u64::from(CONTRACT_SCHEMA) => {}
        Some(schema) => {
            return Err(unsupported_schema(
                u32::try_from(schema).unwrap_or(u32::MAX),
            ));
        }
        None => {
            return Err(ContractError::new(
                ErrorCode::BadRequest,
                "the call has no numeric schema",
            ));
        }
    }
    let call: Call = serde_json::from_value(value)
        .map_err(|error| ContractError::new(ErrorCode::BadRequest, error.to_string()))?;
    execute(&call, inputs, ports)
}

fn unsupported_schema(schema: u32) -> ContractError {
    ContractError::new(
        ErrorCode::UnsupportedSchema,
        format!("contract schema {schema} is not served; this crate serves {CONTRACT_SCHEMA}"),
    )
}
