//! Asset resolution types.
//! Entry: ServedAssetForm.
//! Definitions: this module; the parent re-exports the old paths.

use super::{CallPurpose, Deserialize, EntityId, ImageBytes, LlmCapability, Serialize, ServedForm};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::asset_resolve::types::{
    ImageViewRequest, PulledImage, ServedAssetForm,
};

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

#[doc(hidden)]
pub use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;

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
