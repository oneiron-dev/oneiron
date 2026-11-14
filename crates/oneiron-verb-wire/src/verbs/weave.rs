//! Moved from `crates/oneiron/src/verbs/weave.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Admit and enqueue a generated candidate weave recipe, pinned by the
/// engine to its version, content hash, subject and evidence. The recipe
/// executes on the host's workflow runtime, not in the HTTP handler.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveEnqueueRequest {
    pub skill_ref: String,
    pub subject_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveScheduleCleared {
    pub cleared: bool,
}
