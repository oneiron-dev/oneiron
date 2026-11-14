//! Moved from `crates/oneiron/src/verbs/host/ask_image.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `ai.ask_image`'s input. The pixels are read, and the pull recorded,
/// through the caller's own lane before any model is called; the call runs
/// on the caller's budget line, as a chat turn does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskImageRequest {
    /// The view handle the image was served with (`<asset>@<hash>`).
    pub handle: String,
    /// What to ask about its pixels.
    pub question: String,
    /// A region to ask about, in the image's own pixels; the whole image
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<oneiron_wake_contract::memory::asset_resolve::types::PixelRegion>,
    /// The answer contract to ask under; a text answer when absent. The
    /// Local-vision slot answers a Box or a Point, over the whole image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<oneiron_store::model_decision::AnswerContract>,
}
