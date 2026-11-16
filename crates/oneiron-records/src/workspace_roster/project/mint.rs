//! Moved from `crates/oneiron/src/workspace_roster/project/mint.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::gate_decision::types::GateDecisionId;
pub use oneiron_verb_wire::workspace_roster::project::mint::ProjectBudgetShare;
pub use oneiron_verb_wire::workspace_roster::project::mint::ProjectGoalRecord;
use serde::Deserialize;
use serde::Serialize;

/// A durable tap result; `grant_decision_id` identifies the Gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMintReceipt {
    pub project_id: String,
    pub card_id: String,
    pub grant_decision_id: GateDecisionId,
    pub grant_ref: String,
}
