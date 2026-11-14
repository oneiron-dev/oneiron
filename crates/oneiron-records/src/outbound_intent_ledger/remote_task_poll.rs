//! Moved from `crates/oneiron/src/outbound_intent_ledger/remote_task_poll.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

/// The credential a send presented, as a poll presents it again. A secret
/// grant's redemption or a run's own record cannot be presented after the
/// send, so such a send keeps no poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTaskCredential {
    /// The custody record the call named (`self.use`).
    Record(EntityId),
    /// What the connector route presents of its own (its secret, resolved
    /// again at each poll, or nothing when it names none).
    Route,
}
