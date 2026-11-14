//! Moved from `crates/oneiron/src/memory/asset_resolve/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::CallPurpose;
use oneiron_model::llm::LlmCapability;
pub use oneiron_verb_wire::memory::asset_resolve::types::ImageViewRequest;
pub use oneiron_verb_wire::memory::asset_resolve::types::ServedAssetForm;
pub use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;
use serde::Deserialize;
use serde::Serialize;

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

/// The rows one generated image landed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandedImage {
    /// 32-hex ASSET id; the ref every consumer resolves.
    pub asset_ref: String,
    /// 32-hex id of its precomputed ASSET_TEXT.
    pub asset_text_ref: String,
}
