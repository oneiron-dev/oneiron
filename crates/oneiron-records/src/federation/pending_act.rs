//! Moved from `crates/oneiron/src/federation/pending_act.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::federation::pending_act::matured::PendingActMatured;
pub use oneiron_verb_wire::federation::pending_act::ActExecution;
pub use oneiron_verb_wire::federation::pending_act::SharedActPrecedence;
pub(super) use oneiron_verb_wire::federation::pending_act::invalid;
pub(super) use oneiron_verb_wire::federation::pending_act::key;
pub use oneiron_verb_wire::federation::pending_act::policy_change::SharedActPolicyChangeState;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

/// Durable, recipient-specific notification for a holder at the instant the act starts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActStarted {
    pub act_id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub act: String,
    pub recipient: String,
    pub deadline: u64,
}
pub mod matured;
