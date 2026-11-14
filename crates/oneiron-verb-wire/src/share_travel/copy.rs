//! Moved from `crates/oneiron/src/share_travel/copy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether a copy carries its vault refs. An absent choice, `{}` and
/// `{"refs": "preserve"}` all make today's copy.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct CopyTravelChoice {
    /// What happens to the copy's vault ref slots.
    #[serde(default)]
    pub refs: CopyRefs,
}

/// `Preserve` copies the vault refs as today. `Omit` is the user's explicit
/// request for a lossy copy: its typed ref slots are dropped, with
/// copy-local labels where a handle is needed.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CopyRefs {
    #[default]
    Preserve,
    Omit,
}
