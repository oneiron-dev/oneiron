//! Deck edit attribution, answered thread and rendered review evidence.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// Which side of the diff a review image shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckRenderSide {
    /// The pinned base version.
    Base,
    /// The proposal's candidate bytes.
    Candidate,
}

/// Host-rendered review evidence for one slide. The engine renders nothing;
/// the renderer's identity is kept so LibreOffice evidence stays provisional
/// beside the PowerPoint oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRender {
    pub side: DeckRenderSide,
    /// The slide part the image shows.
    pub slide: String,
    /// BLAKE3 of the image bytes.
    pub image_hash: [u8; 32],
    pub renderer: String,
}

/// Who made the operations and what they answer; kept with the receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckEditContext {
    /// The actor the operations are attributed to (ARCH-0035 made_by).
    #[serde(default)]
    pub made_by: Option<EntityId>,
    /// The open anchored thread this proposal answers. A standing-grant
    /// settle must ride that thread's brief.
    #[serde(default)]
    pub thread: Option<EntityId>,
    /// Before/after review images, attached by the host after proposing.
    #[serde(default)]
    pub renders: Vec<DeckRender>,
}
