//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/outcomes/review_state.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The DIAGNOSTICs and evidence one review state froze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReviewState {
    /// The card's DIAGNOSTICs when it was set, newest last.
    pub diagnostics: Vec<EntityId>,
    /// The card's receipt and attempt ids when it was set, newest last.
    pub evidence: Vec<EntityId>,
}
