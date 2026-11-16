//! Moved from `crates/oneiron/src/dreamer_consolidation/routing.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateKeyRule {
    pub normalize_text: bool,
    /// A question key in a structured value. Missing means the whole predicate
    /// question, never the answer; this conservatively sends ambiguity to judge.
    pub topic_field: Option<String>,
}
