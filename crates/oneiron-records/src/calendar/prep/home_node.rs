//! Moved from `crates/oneiron/src/calendar/prep/home_node.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_vault_contract::{Schedule, WakeEntry};
use serde::Deserialize;
use serde::Serialize;

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
    /// Binds one planned wake to the EVENT it was planned for, or `None` for
    /// a [`Schedule::Window`] entry: a prep wake is exact by construction
    /// (`oneiron::calendar::plan_prep_wake`), so a window names no instant
    /// this job could be due at.
    ///
    /// Deterministic: the same EVENT and the same wake always produce the same
    /// payload, so a host that enqueues twice enqueues the same bytes.
    #[must_use]
    pub fn from_wake(event_ref: &EntityId, wake: &WakeEntry) -> Option<Self> {
        let Schedule::Exact { at } = wake.at else {
            return None;
        };
        Some(Self {
            event_ref: event_ref.to_hex(),
            scheduled_for: at,
            wake_id: wake.id.clone(),
        })
    }
}
