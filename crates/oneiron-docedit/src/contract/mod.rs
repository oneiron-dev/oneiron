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

mod run;

use crate::ArchiveLimits;
use crate::docx_body::{DocxBlock, DocxChange, DocxRevision};
use crate::retained_opc::{Limits, XmlLimits};
use crate::xlsx_body::{XlsxBook, XlsxChange};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The op table's version. A call naming another refuses before any op runs.
pub const CONTRACT_SCHEMA: u32 = 1;

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
/// `{"schema": 1, "op": "docx.read", "args": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Call {
    pub schema: u32,
    #[serde(flatten)]
    pub op: Op,
}

/// The schema-1 op table. Each op names its byte inputs by index into the
/// call's inputs, and every op that reads a package takes the caller's limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", content = "args")]
pub enum Op {
    /// The op table, its media types and the call and reply JSON schemas.
    #[serde(rename = "contract.describe")]
    Describe,
    /// The top-level blocks of a DOCX, with the ids a revision addresses.
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
    /// One checked deck transaction (schema 1) over a base deck.
    #[serde(rename = "deck.transaction")]
    DeckTransaction(DeckTransactionArgs),
    /// A new deck from a kept brief over a template.
    #[serde(rename = "deck.create")]
    DeckCreate(DeckCreateArgs),
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
        }
    }
}

/// DOCX archive ceilings, checked across every entry before any XML parser runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxLimits {
    pub max_entries: usize,
    pub max_part_bytes: u64,
    pub max_total_bytes: u64,
}

impl DocxLimits {
    #[must_use]
    pub fn archive(self) -> ArchiveLimits {
        ArchiveLimits {
            max_entries: self.max_entries,
            max_part_bytes: self.max_part_bytes,
            max_total_bytes: self.max_total_bytes,
        }
    }
}

/// OPC package ceilings for XLSX and PPTX, checked before decompression and
/// again after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageLimits {
    pub archive_bytes: usize,
    pub entries: usize,
    pub part_bytes: usize,
    pub expanded_bytes: usize,
    pub xml_depth: usize,
    pub xml_nodes: usize,
}

impl PackageLimits {
    #[must_use]
    pub fn package(self) -> Limits {
        Limits {
            archive_bytes: self.archive_bytes,
            entries: self.entries,
            part_bytes: self.part_bytes,
            expanded_bytes: self.expanded_bytes,
            xml: XmlLimits {
                max_depth: self.xml_depth,
                max_nodes: self.xml_nodes,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxReadArgs {
    /// Input index of the DOCX.
    pub document: u32,
    pub limits: DocxLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxReviseArgs {
    pub document: u32,
    /// The native writer's transaction grammar, tracked_change mode only. An
    /// absent revision date takes the host's clock; the reply pins it.
    pub transaction: Value,
    pub limits: DocxLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxValidateArgs {
    pub document: u32,
    #[serde(default)]
    pub transaction: Option<Value>,
    pub limits: DocxLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxProjectArgs {
    /// Input index of the DOCX the changes were read from.
    pub source: u32,
    pub changes: Vec<DocxChange>,
    pub revision: DocxRevision,
    pub limits: DocxLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxReadArgs {
    /// Input index of the XLSX.
    pub workbook: u32,
    pub limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxProjectArgs {
    pub source: u32,
    pub changes: Vec<XlsxChange>,
    pub limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxRecalcArgs {
    pub workbook: u32,
    pub limits: PackageLimits,
    pub clock: RecalcClockArgs,
    /// The folder and file name CELL("filename") reads; without one, the
    /// location Excel last saved in the workbook's caches stands in.
    #[serde(default)]
    pub location: Option<DocumentLocationArgs>,
}

/// The instant NOW() and TODAY() read, its local offset, and the seed of the
/// random functions: the same clock recalculates the same values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecalcClockArgs {
    /// Unix milliseconds, UTC.
    pub now_ms: i64,
    /// Minutes east of UTC, within ±840.
    pub utc_offset_minutes: i16,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentLocationArgs {
    /// Ends in `\` or `/`, as `C:\Reports\`.
    pub directory: String,
    /// No separator, bracket or control character.
    pub file_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckReadArgs {
    /// Input index of the PPTX.
    pub deck: u32,
    pub limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckTransactionArgs {
    pub deck: u32,
    /// The deck transaction grammar (schema 1). Its `base` is the BLAKE3 of
    /// the deck input; another base refuses `stale`.
    pub transaction: Value,
    /// The pictures a `set_picture` step names, by artifact and version.
    #[serde(default)]
    pub assets: Vec<DeckAsset>,
    pub limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckCreateArgs {
    pub brief: KeptBriefArgs,
    /// Input index of the template PPTX; it must hold layouts and no slides.
    pub template: u32,
    /// Input indices of the sfnt fonts text is measured with.
    #[serde(default)]
    pub fonts: Vec<u32>,
    /// The brief's assets, keyed by the brief's asset id.
    #[serde(default)]
    pub assets: BTreeMap<String, DeckAsset>,
    pub names: DeckNames,
    pub limits: PackageLimits,
}

/// The brief as the person kept it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptBriefArgs {
    /// Input index of the brief JSON.
    pub input: u32,
    /// The keep's version label, carried into the deck's report.
    pub version: String,
    /// BLAKE3 hex the keep froze. Bytes that no longer hash to it refuse
    /// `stale`; without it, the input is taken as kept.
    #[serde(default)]
    pub kept_hash: Option<String>,
}

/// One held asset version and its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckAsset {
    /// The caller's artifact identity; a step's asset reference names it.
    pub artifact: String,
    pub version: u64,
    /// Input index of the asset's bytes.
    pub input: u32,
    pub media: AssetMedia,
    #[serde(default)]
    pub origin: AssetOrigin,
    /// Provenance references, such as the version's producer claim.
    #[serde(default)]
    pub provenance: Vec<String>,
    /// Rights-evidence references, such as a licence claim.
    #[serde(default)]
    pub rights: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AssetMedia {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    /// The closed SVG subset, compiled to native shapes.
    #[serde(rename = "image/svg+xml")]
    Svg,
}

/// Where a held asset came from. A generated image carries adapter receipts
/// the engine keeps; schema 1 has no door for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssetOrigin {
    #[default]
    Held,
    Web,
    Stock,
    Diagram,
}

/// The localized names new shapes and the embedded workbooks' sheet take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckNames {
    pub text: String,
    pub table: String,
    pub chart: String,
    pub picture: String,
    pub figure: String,
    pub sheet: String,
}

/// What an op returns beside its byte outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Described(Description),
    DocxBlocks {
        blocks: Vec<DocxBlock>,
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
    Recalculated {
        engine: String,
        version: String,
        formula_count: usize,
    },
    Deck(DeckRead),
    DeckTransaction {
        /// The deck transaction report (schema 1): candidate hash, part diff,
        /// per-step effects, the marks after the run and the handoff hash.
        report: Value,
    },
    /// No rung could hold these pages; the person decides each.
    DeckAsk {
        pages: Vec<String>,
    },
    DeckCreated(DeckCreated),
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
}

impl ContractError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > MAX_DETAIL_BYTES {
            let mut end = MAX_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self { code, detail }
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
/// `unavailable`.
pub trait RecalcPort {
    fn recalculate(
        &self,
        workbook: &[u8],
        limits: Limits,
        clock: &RecalcClockArgs,
        location: Option<&DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError>;
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
            return Err(unsupported_schema(u32::try_from(schema).unwrap_or(u32::MAX)));
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

/// One op's discovery row: wire name, summary, inputs and outputs.
struct OpSpec {
    name: &'static str,
    summary: &'static str,
    inputs: &'static [(&'static str, &'static [&'static str], bool)],
    outputs: &'static [(&'static str, &'static str)],
    port: Option<&'static str>,
}

const DOCX: &[&str] = &[DOCX_MEDIA_TYPE];
const XLSX: &[&str] = &[XLSX_MEDIA_TYPE];
const PPTX: &[&str] = &[PPTX_MEDIA_TYPE];
const IMAGES: &[&str] = &["image/png", "image/jpeg", "image/svg+xml"];
const FONTS: &[&str] = &["font/ttf", "font/otf", "font/sfnt"];

const OPS: &[OpSpec] = &[
    OpSpec {
        name: "contract.describe",
        summary: "The op table, its media types and the call, reply and error schemas.",
        inputs: &[],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.read",
        summary: "The top-level blocks of a DOCX: ids, kinds, roles, text, table cells and locks.",
        inputs: &[("document", DOCX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.revise",
        summary: "Apply one tracked revision transaction as Word's own revision marks.",
        inputs: &[("document", DOCX, false)],
        outputs: &[("document", DOCX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "docx.validate",
        summary: "Run the blocking OOXML linker, and check a transaction's grammar when given.",
        inputs: &[("document", DOCX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.project",
        summary: "Write block changes onto the DOCX they were read from, as one tracked revision.",
        inputs: &[("source", DOCX, false)],
        outputs: &[("document", DOCX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.read",
        summary: "Every worksheet's cells, the defined names and the cell formats.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "xlsx.project",
        summary: "Write cell and defined-name changes; formulas land without cached values.",
        inputs: &[("source", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.mark_full_calc",
        summary: "Have the opening application recalculate the whole workbook.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.recalc",
        summary: "Recalculate formula caches natively at the caller's clock and location.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: Some("recalc"),
    },
    OpSpec {
        name: "deck.read",
        summary: "The slides and shapes a deck transaction targets, with fingerprints and marks.",
        inputs: &[("deck", PPTX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "deck.transaction",
        summary: "Run one checked deck transaction; the candidate is re-opened and diffed.",
        inputs: &[("deck", PPTX, false), ("assets[].input", IMAGES, true)],
        outputs: &[("deck", PPTX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "deck.create",
        summary: "Plan and emit a new deck from a kept brief over a template, or ask per page.",
        inputs: &[
            ("brief.input", &[JSON_MEDIA_TYPE], false),
            ("template", PPTX, false),
            ("fonts", FONTS, true),
            ("assets.*.input", IMAGES, true),
        ],
        outputs: &[("deck", PPTX_MEDIA_TYPE)],
        port: None,
    },
];

fn owned(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn schema_value<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("a JSON schema always serializes")
}

/// The JSON schema of a [`Call`].
#[must_use]
pub fn call_schema() -> Value {
    schema_value::<Call>()
}

/// The JSON schema of a [`Reply`].
#[must_use]
pub fn reply_schema() -> Value {
    schema_value::<Reply>()
}

/// The schema-1 op table, as `contract.describe` answers it.
#[must_use]
pub fn describe() -> Description {
    Description {
        schema: CONTRACT_SCHEMA,
        ops: OPS
            .iter()
            .map(|spec| OpInfo {
                name: spec.name.to_owned(),
                summary: spec.summary.to_owned(),
                inputs: spec
                    .inputs
                    .iter()
                    .map(|(field, media_types, repeated)| InputInfo {
                        field: (*field).to_owned(),
                        media_types: owned(media_types),
                        repeated: *repeated,
                    })
                    .collect(),
                outputs: spec
                    .outputs
                    .iter()
                    .map(|(name, media_type)| OutputSpec {
                        name: (*name).to_owned(),
                        media_type: (*media_type).to_owned(),
                    })
                    .collect(),
                port: spec.port.map(str::to_owned),
            })
            .collect(),
        call_schema: call_schema(),
        reply_schema: reply_schema(),
        error_schema: schema_value::<ContractError>(),
    }
}
