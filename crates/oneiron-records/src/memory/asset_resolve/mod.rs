//! Moved from `crates/oneiron/src/memory/asset_resolve/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::asset_resolve::types::AssetConsumer;
pub use crate::memory::asset_resolve::types::LandedImage;
use crate::memory::*;
use base64::Engine as _;
use oneiron_model::llm::CallPurpose;
use oneiron_model::llm::LlmCapability;
pub use oneiron_verb_wire::memory::asset_resolve::types::ImageViewRequest;
pub use oneiron_verb_wire::memory::asset_resolve::types::ServedAssetForm;
pub use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::time::Duration;
use std::time::Instant;

impl AssetConsumer {
    /// A consumer that declared no capability: it is served text.
    #[must_use]
    pub fn text_only(purpose: CallPurpose) -> Self {
        Self {
            capabilities: Vec::new(),
            purpose,
        }
    }

    /// The reader a hydrate door serves: it reads for an answer, and reads
    /// images only when its request says its model takes them in.
    #[must_use]
    pub fn hydrate_reader(image_input: bool) -> Self {
        Self {
            capabilities: if image_input {
                vec![LlmCapability::ImageInput]
            } else {
                Vec::new()
            },
            purpose: CallPurpose::AnswerGen,
        }
    }

    fn reads_images(&self) -> bool {
        self.capabilities.contains(&LlmCapability::ImageInput)
    }
}
pub mod types;
