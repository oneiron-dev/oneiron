//! Moved from `crates/oneiron/src/task_verb/symbol_lease/run.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// The leased run a declaration was made under: its try, that try's lease
/// owner and generation, and the repo and full ref its work is on. The
/// holder is the declaration's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolLeaseRun {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub generation: u32,
    /// The CODE anchor the run's work is on.
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
}
