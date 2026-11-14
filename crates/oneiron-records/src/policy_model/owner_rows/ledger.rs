//! Moved from `crates/oneiron/src/policy_model/owner_rows/ledger.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::owner_rows::notifications::PolicyNotificationTarget;
use oneiron_verb_wire::gate::owner_policy_mutation::PolicyRowScope;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangedEvent {
    pub kind: String,
    pub receipt_id: String,
    pub author: String,
    pub scope: Option<PolicyRowScope>,
    /// Notification-rule events name a rule target instead of pretending to
    /// name one world or project row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PolicyNotificationTarget>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProposalStatus {
    Pending,
    Approved { receipt_id: String, holder: String },
    Declined { holder: String },
}
