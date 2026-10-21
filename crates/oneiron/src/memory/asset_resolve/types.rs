//! Asset resolution types.
//! Entry: ServedAssetForm.
//! Definitions: this module; the parent re-exports the old paths.

use super::{CallPurpose, Deserialize, EntityId, ImageBytes, LlmCapability, Serialize, ServedForm};

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

/// Who reads an asset: what the consumer's model takes in, and the call
/// purpose the read serves, which the host's per-image pick reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetConsumer {
    /// The consumer's input capabilities; image bytes need `image_input`.
    #[serde(default)]
    pub capabilities: Vec<LlmCapability>,
    /// The purpose the read serves.
    pub purpose: CallPurpose,
}

/// One asset as served to one consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsset {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// The rung served.
    pub form: ServedAssetForm,
    /// The pixels served: the full image's bytes, or its thumbnail's.
    pub image: Option<ImageBytes>,
    /// Audio media type and bytes, when served.
    pub audio: Option<(String, Vec<u8>)>,
    /// The ASSET_TEXT served: the whole text form, or the image's caption.
    pub text: Option<String>,
    /// 32-hex id of the ASSET_TEXT in `text`.
    pub asset_text_ref: Option<String>,
    /// The image's view handle; `None` for an ASSET that holds no image.
    pub handle: Option<String>,
}

/// A region of an image, in its own pixels from its top-left corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PixelRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
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
}

/// The rows one generated image landed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandedImage {
    /// 32-hex ASSET id; the ref every consumer resolves.
    pub asset_ref: String,
    /// 32-hex id of its precomputed ASSET_TEXT.
    pub asset_text_ref: String,
}

/// What a hydrate serves, for one ASSET its lane admitted live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydratedAsset {
    /// The door's stored body: an ASSET that holds no image, an image with no
    /// form this reader is served (its body still names the image, bytes
    /// nulled), or an asset gone since the door read it.
    Stored,
    /// A generated image, served at one rung of its ladder: its bytes, its
    /// thumbnail beside its text, or its text, each with its view handle.
    Served {
        /// The rung's body as MessagePack, any pixels as standard base64 so
        /// a JSON door carries them where it nulls a binary: the body the
        /// door projects in place of the stored one.
        body: Vec<u8>,
        /// The ASSET_TEXT the body names, a row the reader did not name.
        text: Option<EntityId>,
        /// The served-form record the door commits before it answers.
        form: ServedForm,
    },
    /// Nothing fit what the door may still decode: the door omits the
    /// ASSET's body, its ref (the image's handle) reads it whole, and the
    /// vault was asked whether everything is okay.
    Omitted {
        /// The served-form record the door commits before it answers.
        form: ServedForm,
    },
}

impl HydratedAsset {
    /// The served-form record this serving makes; `None` for a stored body.
    #[must_use]
    pub fn served_form(&self) -> Option<ServedForm> {
        match self {
            Self::Stored => None,
            Self::Served { form, .. } | Self::Omitted { form } => Some(*form),
        }
    }
}
