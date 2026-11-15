//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/evaluation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessEvaluation {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub artifact: EntityId,
    pub version: u64,
    pub score: f64,
}
