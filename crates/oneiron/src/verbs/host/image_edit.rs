//! `vault.artifacts.image.edit`'s input and answer (L4-15; the Engine's
//! ruling of 13 Nov 09:34, IO-SHAPE A): crops and resizes of one image
//! artifact's version, run in order by the host's image organ, whose file
//! waits beside the artifact as one proposal for Keep, or is held with its
//! reason until one of the owner's nodes can export it. The file is in the
//! source's own format unless the request names another (FIX 23724,
//! IO-FORMAT C); a file in another format lands on a new artifact of that
//! format born from the source (IO-FORMAT B). An embedded handle has no
//! organ host and refuses the verb.
//!
//! `vault.artifacts.image.preview`'s input and answer too (L4-16): one
//! version with the same ops, scaled down to fit a side bound, answered as
//! PNG bytes. Nothing lands and nothing is held.
use serde::{Deserialize, Serialize};

use crate::edit_settle::{OrganWaitView, PendingProposalView};

/// `vault.artifacts.image.edit`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageEditRequest {
    /// The image artifact: a PNG, JPEG or WebP.
    pub artifact_ref: String,
    /// The version edited; the head when absent.
    #[serde(default)]
    pub version: Option<u64>,
    /// 1 to the vault owner's `organ_host.image.max_ops` steps (256 by
    /// default), applied in order. Each is in canvas pixels after the
    /// steps before it, from the top-left corner, after EXIF orientation.
    pub ops: Vec<ImageEditOp>,
    /// The export's format: the source's own when absent, so the file lands
    /// as its next version. A format other than the source's lands on a new
    /// artifact of that format, born from the source.
    #[serde(default)]
    pub format: Option<ImageExportFormat>,
    /// The proposal's ref, unique beside the artifact: a ref already waiting
    /// or settled there is refused.
    pub run_ref: String,
}

/// One step of an image edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImageEditOp {
    /// Keeps the `w` x `h` rectangle whose top-left corner is (`x`, `y`).
    Crop { x: u32, y: u32, w: u32, h: u32 },
    /// Scales the canvas to `w` x `h`.
    Resize {
        w: u32,
        h: u32,
        filter: ImageResizeFilter,
    },
}

/// How a resize samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImageResizeFilter {
    Nearest,
    Bilinear,
}

/// The format an image edit exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImageExportFormat {
    Png,
    /// Baseline JPEG at quality 90; refused for a source with alpha.
    Jpeg,
    /// Lossless WebP, at most 16384 pixels a side.
    Webp,
}

/// `vault.artifacts.image.edit`'s answer: where the file waits, and either
/// its proposal or the export held for a node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageEditAnswer {
    /// The artifact the file waits beside: the source itself, or a new
    /// artifact of the named format born from a source of another.
    pub artifact_ref: String,
    /// Whether `artifact_ref` is new, born from the source.
    pub born: bool,
    /// The proposal waiting for Keep; empty while the export is held.
    pub proposals: Vec<PendingProposalView>,
    /// The export held until a node can run it, with why; absent once it ran.
    pub held: Option<OrganWaitView>,
}

/// The longest side a preview has when the request names none.
pub const IMAGE_PREVIEW_DEFAULT_SIDE: u32 = 512;

const fn image_preview_default_side() -> u32 {
    IMAGE_PREVIEW_DEFAULT_SIDE
}

/// `vault.artifacts.image.preview`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImagePreviewRequest {
    /// The image artifact: a PNG, JPEG or WebP.
    pub artifact_ref: String,
    /// The version shown; the head when absent.
    #[serde(default)]
    pub version: Option<u64>,
    /// Up to 256 steps, applied in order, as an edit takes them; none shows
    /// the version as it is.
    #[serde(default)]
    pub ops: Vec<ImageEditOp>,
    /// The longest side the preview may have, 16 to 2048 pixels (512 when
    /// absent). A larger canvas is scaled down, its aspect kept.
    #[serde(default = "image_preview_default_side")]
    pub max_side: u32,
}

/// `vault.artifacts.image.preview`'s answer: the PNG, not in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePreviewAnswer {
    pub artifact_ref: String,
    /// The version it shows.
    pub version: u64,
    /// `image/png`.
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    /// The PNG's blake3, lowercase hex.
    pub image_hash: String,
    pub content_base64: String,
}
