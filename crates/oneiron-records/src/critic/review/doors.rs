//! Moved from `crates/oneiron/src/critic/review/doors.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::critic::review::doors::CriticFindingsRequest;
pub use oneiron_verb_wire::critic::review::doors::CriticOutcomeAnchor;
pub use oneiron_verb_wire::critic::review::doors::CriticOutcomeSubmit;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A standing critique outcome as the engine recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticOutcomeRecord {
    /// `owner_verdict`, `seal_recheck`, `held_out_eval` or `beam`.
    pub source: String,
    /// Whether the critique held.
    pub accepted: bool,
    /// The sealed try a seal recheck judged, 32-hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_attempt_ref: Option<String>,
}
