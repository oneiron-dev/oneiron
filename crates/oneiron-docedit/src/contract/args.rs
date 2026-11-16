//! The args of the op table's calls: the ceilings a caller supplies, each
//! op's typed args, and the types their fields name.

use crate::ArchiveLimits;
use crate::docx_body::{DocxChange, DocxRevision};
use crate::graphic::GraphicLimits;
use crate::pptx_comments::{PptxCommentEdit, PptxCommentLimits};
use crate::retained_opc::Limits;
use crate::xlsx_body::XlsxChange;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// DOCX archive ceilings: the byte ceilings checked across every entry
/// before any XML parser runs. `max_entries` is an observation, never a
/// reason to refuse: each entry's memory is reserved through the host's port
/// instead (FIX 8570).
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

/// OPC package byte ceilings for XLSX and PPTX, checked before decompression
/// and again after it (FIX 10590).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageLimits {
    pub archive_bytes: usize,
    pub part_bytes: usize,
    pub expanded_bytes: usize,
}

impl PackageLimits {
    #[must_use]
    pub fn package(self) -> Limits {
        Limits {
            archive_bytes: self.archive_bytes,
            part_bytes: self.part_bytes,
            expanded_bytes: self.expanded_bytes,
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
    /// The folder and file name the workbook is opened from: an external
    /// link whose path names it is the workbook's own, and a sheet rename or
    /// deletion carries the formulas through it and its sheet list.
    #[serde(default)]
    pub location: Option<DocumentLocationArgs>,
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
    /// The deck transaction grammar (schema 2). Its `base` is the BLAKE3 of
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
    /// The host's graphic ceilings for the brief's assets (FIX 5355); absent,
    /// the engine's defaults.
    #[serde(default)]
    pub graphics: Option<GraphicSettings>,
}

/// A host's graphic byte and pixel ceilings: an asset past one is refused,
/// not truncated (FIX 10590).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphicSettings {
    pub svg_bytes: usize,
    pub raster_bytes: usize,
    pub raster_pixels: u64,
}

impl GraphicSettings {
    #[must_use]
    pub fn graphic(self) -> GraphicLimits {
        GraphicLimits {
            svg_bytes: self.svg_bytes,
            raster_bytes: self.raster_bytes,
            raster_pixels: self.raster_pixels,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PptxCommentsArgs {
    /// Input index of the PPTX.
    pub deck: u32,
    /// Applied in order. None returns the deck unchanged.
    pub edits: Vec<PptxCommentEdit>,
    /// The slide creation IDs an earlier run of these edits minted, replayed
    /// exactly. Absent, a commented slide that lacks one gets a fresh ID
    /// drawn from `seed`.
    #[serde(default)]
    pub slide_creation_ids: Option<Vec<SlideCreationId>>,
    pub seed: u64,
    pub limits: PptxCommentLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PptxCommentsInspectArgs {
    /// Input index of the PPTX.
    pub deck: u32,
    pub limits: PptxCommentLimits,
}

/// A p14 creation ID written onto a slide that had none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlideCreationId {
    pub slide: u64,
    pub creation_id: u32,
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
/// the engine keeps; schema 5 has no door for them.
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
