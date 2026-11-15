//! Moved from `crates/oneiron/src/lens/activation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::lens::proposal::LensSlot;
use serde::Deserialize;
use serde::Serialize;

/// `vault.lenses.activate`'s input: the proposal to select, the revision the
/// owner was shown, and the lens the slot held when they looked.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensActivateRequest {
    pub lens_ref: String,
    pub compiled_hash: String,
    /// The slot's active lens as shown, or none when it held none.
    #[serde(default)]
    pub expected_active_ref: Option<String>,
}

/// `vault.lenses.deactivate`'s input: the slot to clear and the lens it was
/// shown holding. It clears the selection only; the pack, its skill and the
/// proposal stay.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDeactivateRequest {
    pub slot: LensSlot,
    pub expected_active_ref: String,
}
