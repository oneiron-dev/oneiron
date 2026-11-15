//! Moved from `crates/oneiron/src/share_travel/guest_window.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::share_travel::BornWithField;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Advisory metadata beside the signed export. The digest names the final
/// released update, and row keys are its transport keys after projection.
/// This is an export preparation, not recipient authority or delivery proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestWindowTravelNote {
    pub content_hash: String,
    pub travelled: BTreeMap<String, Vec<BornWithField>>,
    /// The receipt write failed. Its one retry is held only in this open
    /// vault's memory; neither this flag nor that queue is a durable ledger.
    pub receipt_owed: bool,
}
