//! The ref choice a copy door takes (FIX 1199). A copy keeps the vault refs
//! it carries today unless the user asks for a copy without them. This is
//! separate from the signed born-with [`super::TravelChoice`] (OF-491),
//! whose authority actions and meet stay as they are.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::share_travel::copy::{CopyRefs, CopyTravelChoice};

/// The ref choice a copy runs under; no choice is `Preserve`.
#[must_use]
pub fn effective_copy_refs(choice: Option<&CopyTravelChoice>) -> CopyRefs {
    choice.map_or(CopyRefs::Preserve, |choice| choice.refs)
}
