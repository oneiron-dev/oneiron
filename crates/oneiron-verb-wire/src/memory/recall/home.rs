//! Moved from `crates/oneiron/src/memory/recall/home.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Who answered a recall's [`RecallResidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecallResidenceSource {
    /// The home answered the query.
    Home,
    /// The home was not asked, was out of reach or refused: the pack holds
    /// this device's own items alone.
    LocalOnly,
}

/// One reference the home holds that the local pack does not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallResidenceHit {
    /// The entity's full id, 32 lowercase hex.
    pub id: String,
    /// The home's own score: it orders the home's hits, and is never
    /// compared with a local item's.
    pub score: f32,
    /// The month window (`YYYY-MM`) that holds the hit; opening it opens
    /// the hit.
    pub window: String,
}
