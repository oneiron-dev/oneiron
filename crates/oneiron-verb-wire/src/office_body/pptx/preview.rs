//! Moved from `crates/oneiron/src/office_body/pptx/preview.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;

/// `vault.artifacts.body.deck.preview`: the slides to draw, each named once,
/// 1-based in the deck's order (hidden slides count).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckPreviewRequest {
    pub artifact_ref: String,
    /// An open fork of the deck: its merge candidate over the head is drawn,
    /// as `vault.artifacts.body.deck.review` reviews it, instead of the head.
    #[serde(default)]
    pub fork_ref: Option<String>,
    pub slides: Vec<u64>,
    /// Why an agent needs a deck whose text holds a lifted secret drawn:
    /// with it, the deck draws for that agent once a grant covers its keys,
    /// for this read alone, and its ask goes to the owner otherwise.
    #[serde(default)]
    pub why: Option<String>,
}
