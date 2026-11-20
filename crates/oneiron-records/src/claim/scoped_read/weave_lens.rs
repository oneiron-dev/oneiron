//! Moved from `crates/oneiron/src/claim/scoped_read/weave_lens.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::claim::scoped_read::weave_lens::WeaveLensPlanLine;
pub use oneiron_verb_wire::claim::scoped_read::weave_lens::WeaveLensPlanSection;
use serde::Deserialize;
use serde::Serialize;

/// Why a period has no render, saved on its digest row in the render's
/// place: the step's answer did not meet the period, and neither did the
/// answer to its repair turns. The period's data still serves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensRefusal {
    pub reason: String,
    pub skill_ref: String,
    pub skill_version: String,
    pub model: String,
    pub refused_at: u64,
}
