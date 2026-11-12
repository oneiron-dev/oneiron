//! Moved from `crates/oneiron/src/office_body/pptx/preview.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_INTERNAL;
use oneiron_contracts::memory::MEMORY_CODE_MODEL_UNAVAILABLE;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::edit::transaction::AssetRef;
use oneiron_docedit::edit::transaction::Assets;
use oneiron_docedit::graphic::AssetRecord;
use oneiron_docedit::live::ExportKey;
use oneiron_docedit::live::ExportOutcome;
use oneiron_docedit::live::ExportProfile;
use oneiron_docedit::live::HeldAssets;
use oneiron_docedit::live::LiveDeck;
use oneiron_docedit::live::deck_export::export_key;
use oneiron_docedit::live::project;
use oneiron_docedit::retained_opc::Package;
use oneiron_store::blob_artifact::slide_review::SlideRenderer;
use oneiron_store::blob_artifact::slide_review::review_image_key;
use oneiron_store::file_secret_marks::SecretSight;
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
