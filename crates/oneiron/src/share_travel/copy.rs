//! The ref choice a copy door takes (FIX 1199). A copy keeps the vault refs
//! it carries today unless the user asks for a copy without them. This is
//! separate from the signed born-with [`super::TravelChoice`] (OF-491),
//! whose authority actions and meet stay as they are.

use serde::{Deserialize, Serialize};

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

/// The ref choice a copy runs under; no choice is `Preserve`.
#[must_use]
pub fn effective_copy_refs(choice: Option<&CopyTravelChoice>) -> CopyRefs {
    choice.map_or(CopyRefs::Preserve, |choice| choice.refs)
}
