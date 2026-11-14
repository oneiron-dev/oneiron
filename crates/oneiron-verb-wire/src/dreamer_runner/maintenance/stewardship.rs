//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/stewardship.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::representation::RepresentationSourceRef;
use serde::Deserialize;
use serde::Serialize;

/// Where a drafted follow-up would go, and how the owner wants it written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StewardshipDraftRoute {
    pub verb: String,
    pub channel: String,
    pub target: String,
    /// The owner's own stated claims the draft's voice follows.
    pub voice: Vec<RepresentationSourceRef>,
    /// The owner's drafting instruction, handed to the host's model as is.
    pub instruction: String,
}

pub fn bad_text(text: &str) -> bool {
    text.trim().is_empty() || text.chars().any(char::is_control)
}
