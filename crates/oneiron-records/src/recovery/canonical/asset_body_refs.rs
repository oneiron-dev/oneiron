//! Moved from `crates/oneiron/src/recovery/canonical/asset_body_refs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One reference of a window's map: its owner's id, and the reference's
/// bytes as the map holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAssetBodyRef {
    pub id: [u8; 16],
    pub value: Vec<u8>,
}
