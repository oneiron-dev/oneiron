//! Moved from `crates/oneiron/src/memory/asset_resolve/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::image::ImageBytes;
pub use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;
use serde::Deserialize;
use serde::Serialize;

/// The rung of the lazy-image ladder an asset read serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServedAssetForm {
    /// The image bytes, with the newest ASSET_TEXT beside them as a caption.
    Image,
    /// The audio clip, for a reader that declared audio input.
    Audio,
    /// A thumbnail of the image, beside its newest ASSET_TEXT and its view
    /// handle.
    Thumbnail,
    /// The newest ASSET_TEXT and the image's view handle; no bytes.
    AssetText,
    /// Nothing fit: the view handle alone.
    Ask,
}

/// `vault.images.view`'s request: the handle an image was served with, and
/// what of its full pixels to fetch. No region and no edge is the whole
/// image (a view); a region is a crop at the image's own resolution; an edge
/// scales the region, or the whole image, so its longer side is that many
/// pixels (a zoom).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageViewRequest {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<PixelRegion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<u32>,
}

/// Pixels fetched through an image's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PulledImage {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// `view`, `crop`, `zoom` or `ask_image`, as its receipt records it.
    pub pull: String,
    pub mime_type: String,
    /// Standard base64.
    pub bytes: String,
    /// The pixels' size, when their encoding says it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// The raw pixels, for an in-process caller that sends them on.
    #[serde(skip)]
    #[schemars(skip)]
    pub image: Option<ImageBytes>,
    /// The canonical stored blob, not a hash of masked, cropped or scaled pixels.
    #[serde(skip)]
    #[schemars(skip)]
    pub evidence: Option<super::EvidenceVersion>,
}
