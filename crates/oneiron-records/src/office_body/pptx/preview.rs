//! Moved from `crates/oneiron/src/office_body/pptx/preview.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_docedit::live::deck_export::export_key;
pub use oneiron_verb_wire::office_body::pptx::preview::DeckPreviewRequest;
use serde::Deserialize;
use serde::Serialize;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

/// The slides a deck preview drew, and the projection they show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreview {
    /// The head the export projected; for a fork, the head its candidate
    /// replays onto.
    pub frontier: Vec<u8>,
    pub profile: String,
    pub projector: String,
    /// BLAKE3 of the export's memo key, in hex.
    pub export_key: String,
    /// The renderer's identity: its version and raster settings.
    pub renderer: String,
    /// Always true: fonts, autofit and image effects differ from
    /// PowerPoint's.
    pub provisional: bool,
    pub slides: Vec<DeckPreviewSlide>,
}

/// One drawn slide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreviewSlide {
    pub slide: u64,
    /// `image/png`, or `image/jpeg`.
    pub media_type: String,
    /// The image's BLAKE3 in hex, as a review image is keyed.
    pub image_hash: String,
    pub content_base64: String,
}
