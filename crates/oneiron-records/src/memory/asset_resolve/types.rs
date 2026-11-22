//! Moved from `crates/oneiron/src/memory/asset_resolve/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::asset_resolve::types::ImageViewRequest;
pub use oneiron_verb_wire::memory::asset_resolve::types::ServedAssetForm;
pub use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;
use serde::Deserialize;
use serde::Serialize;

/// The rows one generated image landed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandedImage {
    /// 32-hex ASSET id; the ref every consumer resolves.
    pub asset_ref: String,
    /// 32-hex id of its precomputed ASSET_TEXT.
    pub asset_text_ref: String,
}
