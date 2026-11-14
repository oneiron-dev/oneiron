//! Moved from `crates/oneiron/src/calendar/prep/home_node.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::prep::wake::PrepWake;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The closed-vault due payload: small, deterministic, and self-describing.
///
/// Three scalars and nothing else. The raw context stays in the vault and is
/// re-read at execution time, so this payload can sit in a host queue across a
/// vault close without ever becoming stale prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepHomeNodeJob {
    /// Hex id of the EVENT the pack is about.
    pub event_ref: String,
    /// The exact instant the wake was planned for, unix seconds UTC.
    pub scheduled_for: u64,
    /// The wake id the host will report as due.
    pub wake_id: String,
}

impl PrepHomeNodeJob {
    /// Binds one planned wake to the EVENT it was planned for.
    ///
    /// Deterministic: the same EVENT and the same wake always produce the same
    /// payload, so a host that enqueues twice enqueues the same bytes.
    #[must_use]
    pub fn from_wake(event_ref: &EntityId, wake: &PrepWake) -> Self {
        Self {
            event_ref: event_ref.to_hex(),
            scheduled_for: wake.at_utc,
            wake_id: wake.id.clone(),
        }
    }
}
