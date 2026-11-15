//! Moved from `crates/oneiron/src/task_verb/ask_soft_confirm_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::task_verb::ask_soft_confirm_types::TaskAskConfirmation;
pub use oneiron_verb_wire::task_verb::ask_soft_confirm_types::TaskAskConfirmationDecision;
use serde::Deserialize;
use serde::Serialize;

/// Delivery is separate from approval; a pending state never authorizes an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSoftConfirmDelivery {
    PendingRoute,
    PendingGate,
    Failed,
    Scheduled,
    Closed,
}
